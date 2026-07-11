package traceroute

import (
	"context"
	"net/url"
	"testing"
	"time"
)

func TestOptionsFromQuery_Defaults(t *testing.T) {
	q := url.Values{}
	defaults := Options{
		DefaultMethod:         "icmp",
		DefaultMaxHops:        30,
		DefaultQueries:        3,
		DefaultWait:           time.Second,
		DefaultTimeout:        30 * time.Second,
		DefaultIPFamily:       "",
		DefaultLoopMaxRepeats: 4,
	}
	opts := OptionsFromQuery(q, defaults)
	if opts.Method != "icmp" {
		t.Errorf("method = %q, want icmp", opts.Method)
	}
	if opts.MaxHops != 30 {
		t.Errorf("maxHops = %d, want 30", opts.MaxHops)
	}
	if opts.Queries != 3 {
		t.Errorf("queries = %d, want 3", opts.Queries)
	}
}

func TestOptionsFromQuery_Override(t *testing.T) {
	q := url.Values{
		"method":         {"tcp"},
		"max_hops":       {"10"},
		"queries":        {"1"},
		"loop_detection": {"0"},
	}
	defaults := Options{
		DefaultMethod:         "icmp",
		DefaultMaxHops:        30,
		DefaultQueries:        3,
		DefaultWait:           time.Second,
		DefaultTimeout:        30 * time.Second,
		DefaultLoopMaxRepeats: 4,
	}
	opts := OptionsFromQuery(q, defaults)
	if opts.Method != "tcp" {
		t.Errorf("method = %q, want tcp", opts.Method)
	}
	if opts.MaxHops != 10 {
		t.Errorf("maxHops = %d, want 10", opts.MaxHops)
	}
	if opts.LoopMaxRepeats != 0 {
		t.Errorf("loopMaxRepeats = %d, want 0 (disabled)", opts.LoopMaxRepeats)
	}
}

func TestBaseLabels(t *testing.T) {
	opts := TraceOptions{Method: "icmp", IPFamily: "4", LoopMaxRepeats: 5}
	spec := TargetSpec{Host: "example.com", Port: "443"}
	labels := BaseLabels(opts, spec)
	if labels["method"] != "icmp" {
		t.Errorf("method = %q", labels["method"])
	}
	if labels["target_host"] != "example.com" {
		t.Errorf("target_host = %q", labels["target_host"])
	}
	if labels["target_port"] != "443" {
		t.Errorf("target_port = %q", labels["target_port"])
	}
}

func TestNewTraceResult(t *testing.T) {
	spec := TargetSpec{Host: "example.com", Port: "443"}
	trace := NewTraceResult(spec, "1.2.3.4")
	if trace.DestinationHost != "example.com" {
		t.Errorf("host = %q", trace.DestinationHost)
	}
	if trace.ResolvedAddress != "1.2.3.4" {
		t.Errorf("resolved = %q", trace.ResolvedAddress)
	}
}

func TestMergeTraceDestination(t *testing.T) {
	dst := TraceResult{}
	src := TraceResult{
		DestinationHost:    "example.com",
		DestinationAddress: "1.2.3.4",
		DestinationPort:    "443",
		ResolvedAddress:    "1.2.3.4",
	}
	MergeTraceDestination(&dst, src)
	if dst.DestinationHost != "example.com" {
		t.Errorf("host = %q", dst.DestinationHost)
	}
	if dst.DestinationAddress != "1.2.3.4" {
		t.Errorf("address = %q", dst.DestinationAddress)
	}
}

func TestResolveTarget_IPAddress(t *testing.T) {
	ctx := context.Background()
	got := ResolveTarget(ctx, "192.168.1.1", "")
	if got != "192.168.1.1" {
		t.Errorf("ResolveTarget = %q, want %q", got, "192.168.1.1")
	}
}

func TestResolveTarget_IPv6(t *testing.T) {
	ctx := context.Background()
	got := ResolveTarget(ctx, "::1", "")
	if got != "::1" {
		t.Errorf("ResolveTarget = %q, want %q", got, "::1")
	}
}
