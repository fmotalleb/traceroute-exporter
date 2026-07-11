// Package traceroute provides traceroute probe execution and result parsing.
package traceroute

import (
	"regexp"
	"time"
)

// Method constants used across the traceroute package.
const (
	methodAuto = "auto"
	methodTCP  = "tcp"
	methodICMP = "icmp"
	methodUDP  = "udp"

	nodeRoleHop    = "hop"
	nodeRoleSource = "source"
)

// Boolean string constants for metric labels.
const (
	boolTrue  = "true"
	boolFalse = "false"
)

// millisecondDivisor converts milliseconds to seconds (1000 ms = 1 s).
const millisecondDivisor = 1000

// minLoopLength is the minimum number of signatures needed to detect a loop pattern.
const minLoopLength = 2

// TraceOptions holds per-probe configuration.
type TraceOptions struct {
	Method         string
	MaxHops        int
	Queries        int
	Wait           time.Duration
	Timeout        time.Duration
	IPFamily       string
	LoopMaxRepeats int
	Debug          bool
}

// TargetSpec represents a parsed target specification.
type TargetSpec struct {
	Original string
	Host     string
	Port     string
}

// TraceResult holds the parsed traceroute output.
type TraceResult struct {
	DestinationHost    string
	DestinationAddress string
	DestinationPort    string
	ResolvedAddress    string
	Hops               []Hop
	Reached            bool
	RawOutput          string
	Loop               LoopInfo
}

// Hop represents a single hop in the traceroute.
type Hop struct {
	Number int
	Nodes  []*Node
	Stars  int
	Raw    string
}

// Node represents a single node at a hop.
type Node struct {
	ID        string
	Hop       int
	Hostname  string
	Address   string
	Responded bool
	Role      string
	RTTs      []float64
	Stars     int
}

// Edge represents a connection between two nodes.
type Edge struct {
	Parent *Node
	Node   *Node
}

// LoopInfo contains information about detected routing loops.
type LoopInfo struct {
	Detected bool
	GiveUp   bool
	StartHop int
	EndHop   int
	Length   int
	Repeats  int
	Pattern  string
}

var (
	hopLineRE = regexp.MustCompile(`^\s*(\d+)\s+(.*)$`)
	headerRE  = regexp.MustCompile(`^\s*traceroute(?:6)?\s+to\s+(.+?)\s+\(([^)]+)\)`)
)
