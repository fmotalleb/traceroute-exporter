package traceroute

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// MergeLabels merges two label maps.
func MergeLabels(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// NormalizeMethod normalizes a traceroute method string.
func NormalizeMethod(method string) string {
	m := strings.ToLower(strings.TrimSpace(method))
	switch m {
	case "", methodAuto:
		return methodAuto
	case methodTCP, "t":
		return methodTCP
	case methodICMP, "i":
		return methodICMP
	case methodUDP, "u":
		return methodUDP
	default:
		return m
	}
}

// NormalizeIPFamily normalizes an IP family string.
func NormalizeIPFamily(family string) string {
	switch strings.TrimSpace(strings.ToLower(family)) {
	case "4", "ipv4":
		return "4"
	case "6", "ipv6":
		return "6"
	default:
		return ""
	}
}

// SecondsForTraceroute formats a duration for traceroute -w flag.
func SecondsForTraceroute(d time.Duration) string {
	if d <= 0 {
		d = time.Second
	}
	seconds := d.Seconds()
	if math.Abs(seconds-math.Round(seconds)) < 0.000001 {
		return strconv.Itoa(int(math.Round(seconds)))
	}
	return strconv.FormatFloat(seconds, 'f', 3, 64)
}

// LossRatio calculates the loss ratio for a hop.
func LossRatio(hop Hop, queries int) float64 {
	if queries <= 0 {
		queries = 1
	}
	if len(hop.Nodes) == 1 && !hop.Nodes[0].Responded {
		return 1
	}
	observed := hop.Stars
	for _, node := range hop.Nodes {
		observed += len(node.RTTs)
	}
	if observed <= 0 {
		return 0
	}
	denominator := MaxInt(queries, observed)
	return float64(hop.Stars) / float64(denominator)
}

// AvgRTT calculates the average RTT.
func AvgRTT(values []float64) (float64, bool) {
	if len(values) == 0 {
		return 0, false
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values)), true
}

// LastHop returns the highest hop number.
func LastHop(hops []Hop) int {
	last := 0
	for _, hop := range hops {
		if hop.Number > last {
			last = hop.Number
		}
	}
	return last
}

// NoReplyID generates an ID for a non-responding hop.
func NoReplyID(hop int) string {
	return fmt.Sprintf("no-reply-hop-%02d", hop)
}

// Fallback returns value if non-empty, otherwise returns fallback.
func Fallback(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

// BoolString converts a boolean to a string.
func BoolString(v bool) string {
	if v {
		return boolTrue
	}
	return boolFalse
}

// BoolFloat converts a boolean to a float64.
func BoolFloat(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

// ClampInt clamps an integer to a range.
func ClampInt(v, minVal, maxVal int) int {
	if v < minVal {
		return minVal
	}
	if v > maxVal {
		return maxVal
	}
	return v
}

// MaxInt returns the maximum of two integers.
func MaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// QueryString gets a string value from URL query parameters.
func QueryString(q interface{ Get(string) string }, name, def string) string {
	if value := strings.TrimSpace(q.Get(name)); value != "" {
		return value
	}
	return def
}

// QueryInt gets an integer value from URL query parameters.
func QueryInt(q interface{ Get(string) string }, name string, def int) int {
	if value := strings.TrimSpace(q.Get(name)); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return def
}

// QueryDuration gets a duration value from URL query parameters.
func QueryDuration(q interface{ Get(string) string }, name string, def time.Duration) time.Duration {
	value := strings.TrimSpace(q.Get(name))
	if value == "" {
		return def
	}
	if d, err := time.ParseDuration(value); err == nil {
		return d
	}
	if seconds, err := strconv.ParseFloat(value, 64); err == nil {
		return time.Duration(seconds * float64(time.Second))
	}
	return def
}

// TrimHopsAfter removes hops after the specified hop number.
func TrimHopsAfter(hops []Hop, lastHop int) []Hop {
	if lastHop <= 0 {
		return hops
	}
	out := hops[:0]
	for _, hop := range hops {
		if hop.Number <= lastHop {
			out = append(out, hop)
		}
	}
	return out
}
