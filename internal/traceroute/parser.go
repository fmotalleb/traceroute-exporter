package traceroute

import (
	"bufio"
	"net"
	"strconv"
	"strings"
)

// ParseTraceOutput parses raw traceroute output into structured data.
func ParseTraceOutput(output string, spec TargetSpec, resolved string, queries int) TraceResult {
	res := TraceResult{
		DestinationHost:    spec.Host,
		DestinationPort:    spec.Port,
		DestinationAddress: resolved,
		ResolvedAddress:    resolved,
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if m := headerRE.FindStringSubmatch(line); m != nil {
			if strings.TrimSpace(m[1]) != "" {
				res.DestinationHost = strings.TrimSpace(m[1])
			}
			if strings.TrimSpace(m[2]) != "" {
				res.DestinationAddress = strings.TrimSpace(m[2])
			}
			continue
		}
		if hop, ok := ParseHopLine(line, queries); ok {
			res.Hops = append(res.Hops, hop)
		}
	}
	return res
}

// ParseHopLine parses a single hop line from traceroute output.
func ParseHopLine(line string, queries int) (Hop, bool) {
	m := hopLineRE.FindStringSubmatch(line)
	if m == nil {
		return Hop{}, false
	}
	num, err := strconv.Atoi(m[1])
	if err != nil {
		return Hop{}, false
	}

	hop := Hop{Number: num, Raw: strings.TrimSpace(line)}
	tokens := strings.Fields(m[2])
	byID := map[string]*Node{}
	order := []string{}
	var current *Node

	upsert := func(hostname, address string) *Node {
		hostname = CleanName(hostname)
		address = CleanAddress(address)
		if hostname == "" && address != "" {
			hostname = address
		}
		if address == "" && IsAddressLike(hostname) {
			address = hostname
		}
		id := address
		if id == "" {
			id = hostname
		}
		if id == "" {
			id = NoReplyID(num)
		}
		if node, ok := byID[id]; ok {
			if node.Hostname == "" && hostname != "" {
				node.Hostname = hostname
			}
			if node.Address == "" && address != "" {
				node.Address = address
			}
			return node
		}
		node := &Node{
			ID:        id,
			Hop:       num,
			Hostname:  Fallback(hostname, id),
			Address:   address,
			Responded: true,
			Role:      nodeRoleHop,
		}
		byID[id] = node
		order = append(order, id)
		return node
	}

	for i := 0; i < len(tokens); i++ {
		tok := CleanToken(tokens[i])
		if tok == "" {
			continue
		}
		if tok == "*" {
			hop.Stars++
			current = nil
			continue
		}
		if rtt, ok, consumeNext := ParseRTT(tokens, i); ok {
			if current != nil {
				current.RTTs = append(current.RTTs, rtt)
			}
			if consumeNext {
				i++
			}
			continue
		}
		if strings.EqualFold(tok, "ms") || strings.HasPrefix(tok, "!") {
			continue
		}
		if i+1 < len(tokens) && IsParenAddress(tokens[i+1]) {
			current = upsert(tok, strings.Trim(tokens[i+1], "()"))
			i++
			continue
		}
		if IsParenAddress(tok) {
			current = upsert("", strings.Trim(tok, "()"))
			continue
		}
		if IsAddressLike(tok) {
			current = upsert(tok, tok)
			continue
		}
		if NextTokenIsRTT(tokens, i) {
			current = upsert(tok, "")
			continue
		}
	}

	for _, id := range order {
		node := byID[id]
		if node.Hostname == "" {
			node.Hostname = node.ID
		}
		if node.Address == "" && IsAddressLike(node.ID) {
			node.Address = node.ID
		}
		node.Stars = hop.Stars
		hop.Nodes = append(hop.Nodes, node)
	}

	if len(hop.Nodes) == 0 {
		id := NoReplyID(num)
		hop.Nodes = append(hop.Nodes, &Node{
			ID:        id,
			Hop:       num,
			Hostname:  id,
			Address:   "*",
			Responded: false,
			Role:      nodeRoleHop,
			Stars:     MaxInt(hop.Stars, queries),
		})
	}
	return hop, true
}

// ComputeReached determines if the traceroute reached its destination.
func ComputeReached(trace TraceResult, spec TargetSpec) bool {
	addresses := map[string]struct{}{}
	for _, addr := range []string{trace.DestinationAddress, trace.ResolvedAddress, spec.Host} {
		addr = strings.TrimSpace(strings.Trim(addr, "[]"))
		if addr != "" && IsAddressLike(addr) {
			addresses[addr] = struct{}{}
		}
	}

	hosts := map[string]struct{}{}
	for _, host := range []string{trace.DestinationHost, spec.Host} {
		host = strings.ToLower(strings.TrimSpace(host))
		if host != "" {
			hosts[host] = struct{}{}
		}
	}

	for _, hop := range trace.Hops {
		for _, node := range hop.Nodes {
			if !node.Responded {
				continue
			}
			addr := strings.Trim(strings.TrimSpace(node.Address), "[]")
			if _, ok := addresses[addr]; ok && addr != "" {
				return true
			}
			hostname := strings.ToLower(strings.TrimSpace(node.Hostname))
			if _, ok := hosts[hostname]; ok && hostname != "" {
				return true
			}
		}
	}
	return false
}

// BuildEdges constructs edges for the tree graph.
func BuildEdges(source *Node, hops []Hop) []Edge {
	var edges []Edge
	previous := []*Node{source}
	for _, hop := range hops {
		if len(hop.Nodes) == 0 {
			continue
		}
		for _, parent := range previous {
			for _, node := range hop.Nodes {
				edges = append(edges, Edge{Parent: parent, Node: node})
			}
		}
		previous = hop.Nodes
	}
	return edges
}

// ParseRTT parses a round-trip time from tokens.
func ParseRTT(tokens []string, i int) (seconds float64, ok bool, consumeNext bool) {
	if i >= len(tokens) {
		return 0, false, false
	}
	tok := strings.Trim(strings.TrimSpace(tokens[i]), ",")
	if strings.HasSuffix(strings.ToLower(tok), "ms") && len(tok) > 2 {
		number := strings.TrimSuffix(strings.TrimSuffix(tok, "ms"), "MS")
		if v, err := strconv.ParseFloat(number, 64); err == nil {
			return v / millisecondDivisor, true, false
		}
	}
	if i+1 < len(tokens) && strings.EqualFold(CleanToken(tokens[i+1]), "ms") {
		if v, err := strconv.ParseFloat(strings.Trim(tok, ","), 64); err == nil {
			return v / millisecondDivisor, true, true
		}
	}
	return 0, false, false
}

// NextTokenIsRTT checks if the next token is an RTT value.
func NextTokenIsRTT(tokens []string, i int) bool {
	if i+1 >= len(tokens) {
		return false
	}
	_, ok, _ := ParseRTT(tokens, i+1)
	return ok
}

// CleanToken removes whitespace and commas from a token.
func CleanToken(s string) string {
	return strings.Trim(strings.TrimSpace(s), ",")
}

// CleanName cleans a hostname token.
func CleanName(s string) string {
	s = CleanToken(s)
	s = strings.Trim(s, "[]")
	return s
}

// CleanAddress cleans an address token.
func CleanAddress(s string) string {
	s = CleanToken(s)
	s = strings.Trim(s, "()[]")
	return s
}

// IsParenAddress checks if a token is a parenthesized address.
func IsParenAddress(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") && IsAddressLike(strings.Trim(s, "()"))
}

// IsAddressLike checks if a string looks like an IP address.
func IsAddressLike(s string) bool {
	s = CleanAddress(strings.Split(s, "%")[0])
	return net.ParseIP(s) != nil
}
