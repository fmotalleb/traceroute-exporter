package traceroute

import (
	"sort"
	"strings"
)

// DetectLoop looks for a repeated contiguous suffix in the responding hop
// sequence. It detects both simple loops such as A,A,A,A and multi-hop loops
// such as A,B,C,A,B,C,A,B,C,A,B,C.
//
// maxRepeatedLoops is the give-up threshold. A value of 4 means the current
// suffix pattern must have appeared four consecutive times before GiveUp is
// true. A value <= 0 disables give-up and returns an empty LoopInfo.
func DetectLoop(hops []Hop, maxRepeatedLoops int) LoopInfo {
	if maxRepeatedLoops <= 0 {
		return LoopInfo{}
	}

	signatures := respondingHopSignatures(hops)
	n := len(signatures)
	if n < minLoopLength {
		return LoopInfo{}
	}

	best := LoopInfo{}
	for length := 1; length <= n/2; length++ {
		patternStart := n - length
		pattern := signatures[patternStart:n]
		repeats := 1
		start := patternStart

		for start-length >= 0 && sameSignaturePattern(signatures[start-length:start], pattern) {
			repeats++
			start -= length
		}

		if repeats < minLoopLength {
			continue
		}
		candidate := LoopInfo{
			Detected: true,
			GiveUp:   repeats >= maxRepeatedLoops,
			StartHop: signatures[start].Hop,
			EndHop:   signatures[n-1].Hop,
			Length:   length,
			Repeats:  repeats,
			Pattern:  joinSignaturePattern(pattern),
		}
		if candidate.Repeats > best.Repeats || (candidate.Repeats == best.Repeats && candidate.Length < best.Length) || !best.Detected {
			best = candidate
		}
	}

	if best.Detected && best.Repeats >= maxRepeatedLoops {
		best.GiveUp = true
	}
	return best
}

type hopSignature struct {
	Hop       int
	Signature string
}

func respondingHopSignatures(hops []Hop) []hopSignature {
	out := make([]hopSignature, 0, len(hops))
	for _, hop := range hops {
		sig := canonicalHopSignature(hop)
		if sig == "" {
			continue
		}
		out = append(out, hopSignature{Hop: hop.Number, Signature: sig})
	}
	return out
}

func canonicalHopSignature(hop Hop) string {
	parts := make([]string, 0, len(hop.Nodes))
	for _, node := range hop.Nodes {
		if node == nil || !node.Responded {
			continue
		}
		id := strings.TrimSpace(node.Address)
		if id == "" || id == "*" {
			id = strings.TrimSpace(node.ID)
		}
		if id == "" || strings.HasPrefix(id, "no-reply-hop-") {
			continue
		}
		parts = append(parts, id)
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

func sameSignaturePattern(a, b []hopSignature) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Signature != b[i].Signature {
			return false
		}
	}
	return true
}

func joinSignaturePattern(pattern []hopSignature) string {
	parts := make([]string, 0, len(pattern))
	for _, item := range pattern {
		parts = append(parts, item.Signature)
	}
	return strings.Join(parts, " -> ")
}
