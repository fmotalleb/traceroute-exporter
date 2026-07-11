package traceroute

import (
	"regexp"
	"time"
)

// TraceOptions holds per-probe configuration
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

// TargetSpec represents a parsed target specification
type TargetSpec struct {
	Original string
	Host     string
	Port     string
}

// CommandResult holds the result of executing a traceroute command
type CommandResult struct {
	Output   string
	Args     []string
	Commands []string
	Duration time.Duration
	ExitCode int
	TimedOut bool
	Err      error
}

// TraceResult holds the parsed traceroute output
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

// Hop represents a single hop in the traceroute
type Hop struct {
	Number int
	Nodes  []*Node
	Stars  int
	Raw    string
}

// Node represents a single node at a hop
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

// Edge represents a connection between two nodes
type Edge struct {
	Parent *Node
	Node   *Node
}

// LoopInfo contains information about detected routing loops
type LoopInfo struct {
	Detected bool
	GiveUp   bool
	StartHop int
	EndHop   int
	Length   int
	Repeats  int
	Pattern  string
}

var hopLineRE = regexp.MustCompile(`^\s*(\d+)\s+(.*)$`)
var headerRE = regexp.MustCompile(`^\s*traceroute(?:6)?\s+to\s+(.+?)\s+\(([^)]+)\)`)
