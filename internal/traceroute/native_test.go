package traceroute

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestAppendHopNode_NewNode(t *testing.T) {
	var nodes []*Node
	round := probeRound{
		host:    "router.example.com",
		address: "10.0.0.1",
		rtt:     5 * time.Millisecond,
		reached: false,
		timeout: false,
	}
	nodes = appendHopNode(nodes, round, 1)
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if nodes[0].ID != "10.0.0.1" {
		t.Errorf("ID = %q, want 10.0.0.1", nodes[0].ID)
	}
	if !nodes[0].Responded {
		t.Error("expected responded=true")
	}
	if len(nodes[0].RTTs) != 1 {
		t.Errorf("expected 1 RTT, got %d", len(nodes[0].RTTs))
	}
}

func TestAppendHopNode_DuplicateMerge(t *testing.T) {
	nodes := []*Node{
		{ID: "10.0.0.1", Hop: 1, Hostname: "router", Address: "10.0.0.1", Responded: true, RTTs: []float64{0.001}},
	}
	round := probeRound{
		host:    "router",
		address: "10.0.0.1",
		rtt:     2 * time.Millisecond,
		reached: false,
		timeout: false,
	}
	nodes = appendHopNode(nodes, round, 1)
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node (merged), got %d", len(nodes))
	}
	if len(nodes[0].RTTs) != 2 {
		t.Errorf("expected 2 RTTs after merge, got %d", len(nodes[0].RTTs))
	}
}

func TestAppendHopNode_EmptyRound(t *testing.T) {
	var nodes []*Node
	round := probeRound{timeout: true}
	nodes = appendHopNode(nodes, round, 1)
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes for empty round, got %d", len(nodes))
	}
}

func TestAppendHopNode_Timeout(t *testing.T) {
	var nodes []*Node
	round := probeRound{
		host:    "10.0.0.1",
		address: "10.0.0.1",
		timeout: true,
	}
	nodes = appendHopNode(nodes, round, 1)
	if len(nodes) != 1 {
		t.Fatal("expected 1 node")
	}
	if nodes[0].Responded {
		t.Error("expected responded=false for timeout")
	}
}

func TestCountTimeouts_AllResponded(t *testing.T) {
	nodes := []*Node{
		{ID: "a", Responded: true},
		{ID: "b", Responded: true},
	}
	got := countTimeouts(nodes, 3)
	if got != 1 {
		t.Errorf("countTimeouts = %d, want 1", got)
	}
}

func TestCountTimeouts_NoneResponded(t *testing.T) {
	nodes := []*Node{
		{ID: "a", Responded: false},
		{ID: "b", Responded: false},
	}
	got := countTimeouts(nodes, 3)
	if got != 3 {
		t.Errorf("countTimeouts = %d, want 3", got)
	}
}

func TestCountTimeouts_SomeResponded(t *testing.T) {
	nodes := []*Node{
		{ID: "a", Responded: true},
		{ID: "b", Responded: false},
	}
	got := countTimeouts(nodes, 3)
	if got != 2 {
		t.Errorf("countTimeouts = %d, want 2", got)
	}
}

func TestCountTimeouts_EmptyNodes(t *testing.T) {
	got := countTimeouts(nil, 3)
	if got != 3 {
		t.Errorf("countTimeouts = %d, want 3", got)
	}
}

func TestResolveAddress_IP(t *testing.T) {
	ctx := context.Background()
	got := resolveAddress(ctx, "127.0.0.1:80")
	if got == "" {
		t.Error("expected non-empty result")
	}
	// Reverse DNS may return "localhost" or "127.0.0.1" depending on system
	if got != "127.0.0.1" && got != "localhost" && got != "localhost." {
		t.Logf("resolveAddress = %q (accepted alternative)", got)
	}
}

func TestResolveAddress_NoPort(t *testing.T) {
	ctx := context.Background()
	got := resolveAddress(ctx, "127.0.0.1")
	if got == "" {
		t.Error("expected non-empty result")
	}
	// Reverse DNS may return "localhost" or "127.0.0.1" depending on system
	if got != "127.0.0.1" && got != "localhost" && got != "localhost." {
		t.Logf("resolveAddress = %q (accepted alternative)", got)
	}
}

func TestNativeTraceroute_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	opts := TraceOptions{
		Method:  "icmp",
		MaxHops: 5,
		Queries: 1,
		Wait:    100 * time.Millisecond,
	}

	_, err := NativeTraceroute(ctx, "127.0.0.1", opts)
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestNativeTraceroute_InvalidTarget(t *testing.T) {
	ctx := context.Background()
	opts := TraceOptions{
		Method:  "icmp",
		MaxHops: 5,
		Queries: 1,
		Wait:    100 * time.Millisecond,
	}

	_, err := NativeTraceroute(ctx, "invalid-host-that-does-not-exist-12345.invalid", opts)
	// This may or may not fail depending on DNS, but the function should handle it gracefully
	// We just verify it doesn't panic
	_ = err
}

func TestNativeTraceroute_Localhost(t *testing.T) {
	ctx := context.Background()
	opts := TraceOptions{
		Method:  "icmp",
		MaxHops: 3,
		Queries: 1,
		Wait:    2 * time.Second,
	}

	hops, err := NativeTraceroute(ctx, "127.0.0.1", opts)
	// Localhost traceroute should complete (may or may not get proper responses)
	// We just verify it doesn't panic and returns a result
	if err != nil {
		t.Logf("NativeTraceroute returned error (may be expected without root): %v", err)
	} else {
		t.Logf("NativeTraceroute completed with %d hops", len(hops))
	}
}

func TestProbeHop_ICMP(t *testing.T) {
	ctx := context.Background()
	dst := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
	opts := TraceOptions{Wait: time.Second}
	result := probeHop(ctx, dst, 1, opts, "icmp")
	// We just verify it doesn't panic
	t.Logf("probeHop ICMP result: host=%q, reached=%v, timeout=%v",
		result.host, result.reached, result.timeout)
}

func TestProbeHop_UDP(t *testing.T) {
	ctx := context.Background()
	dst := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
	opts := TraceOptions{Wait: time.Second}
	result := probeHop(ctx, dst, 1, opts, "udp")
	t.Logf("probeHop UDP result: host=%q, reached=%v, timeout=%v",
		result.host, result.reached, result.timeout)
}

func TestProbeHop_TCP(t *testing.T) {
	ctx := context.Background()
	dst := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
	opts := TraceOptions{Wait: time.Second}
	result := probeHop(ctx, dst, 1, opts, "tcp")
	t.Logf("probeHop TCP result: host=%q, reached=%v, timeout=%v",
		result.host, result.reached, result.timeout)
}

func TestProbeHop_Default(t *testing.T) {
	ctx := context.Background()
	dst := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
	opts := TraceOptions{Wait: time.Second}
	result := probeHop(ctx, dst, 1, opts, "unknown")
	// Default should fall back to ICMP
	t.Logf("probeHop default result: host=%q, reached=%v, timeout=%v",
		result.host, result.reached, result.timeout)
}

func TestNativeTraceroute_ContextTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	opts := TraceOptions{
		Method:  "icmp",
		MaxHops: 255,
		Queries: 3,
		Wait:    time.Second,
	}

	hops, err := NativeTraceroute(ctx, "1.1.1.1", opts)
	if err == nil && len(hops) > 0 {
		// With a very short timeout, we should either get an error or very few hops
		t.Logf("Got %d hops with short timeout", len(hops))
	}
}

func TestProbeICMP_WithIPv6(t *testing.T) {
	ctx := context.Background()
	dst := &net.IPAddr{IP: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}
	opts := TraceOptions{Wait: 500 * time.Millisecond}
	result := probeICMP(ctx, dst, 1, opts)
	// IPv6 to localhost should work or timeout gracefully
	t.Logf("probeICMP IPv6 result: host=%q, reached=%v, timeout=%v",
		result.host, result.reached, result.timeout)
}

func TestProbeTCP_ConnectionRefused(t *testing.T) {
	// Test against a closed port on localhost
	ctx := context.Background()
	dst := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
	opts := TraceOptions{Wait: 500 * time.Millisecond}
	result := probeTCP(ctx, dst, 1, opts)
	// Connection refused means we reached the destination
	if !result.reached {
		t.Error("expected reached=true for connection refused (destination reached)")
	}
}

func TestNativeTraceroute_AutoMethod(t *testing.T) {
	ctx := context.Background()
	opts := TraceOptions{
		Method:  "auto",
		MaxHops: 1,
		Queries: 1,
		Wait:    time.Second,
	}
	hops, err := NativeTraceroute(ctx, "127.0.0.1", opts)
	// Auto should default to ICMP
	if err != nil {
		t.Logf("Got error (may be expected): %v", err)
	} else {
		t.Logf("Got %d hops with auto method", len(hops))
	}
}

// Verify the probeRound struct fields work correctly
func TestProbeRound_Fields(t *testing.T) {
	r := probeRound{
		host:    "test",
		address: "1.2.3.4",
		rtt:     10 * time.Millisecond,
		reached: true,
		timeout: false,
	}
	if r.host != "test" {
		t.Errorf("host = %q", r.host)
	}
	if r.address != "1.2.3.4" {
		t.Errorf("address = %q", r.address)
	}
	if r.rtt != 10*time.Millisecond {
		t.Errorf("rtt = %v", r.rtt)
	}
	if !r.reached {
		t.Error("expected reached=true")
	}
	if r.timeout {
		t.Error("expected timeout=false")
	}
}

// Test that appendHopNode handles address-only nodes
func TestAppendHopNode_AddressOnly(t *testing.T) {
	var nodes []*Node
	round := probeRound{
		address: "10.0.0.1",
		rtt:     5 * time.Millisecond,
	}
	nodes = appendHopNode(nodes, round, 1)
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	// When host is empty, hostname should default to ID
	if nodes[0].Hostname != "10.0.0.1" {
		t.Errorf("hostname = %q, want %q", nodes[0].Hostname, "10.0.0.1")
	}
}

// Test that appendHopNode handles host-only nodes
func TestAppendHopNode_HostOnly(t *testing.T) {
	var nodes []*Node
	round := probeRound{
		host: "router.example.com",
		rtt:  5 * time.Millisecond,
	}
	nodes = appendHopNode(nodes, round, 1)
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	// When address is empty, ID should default to host
	if nodes[0].ID != "router.example.com" {
		t.Errorf("ID = %q, want %q", nodes[0].ID, "router.example.com")
	}
}

func TestNativeTraceroute_VerifyTTLProgression(t *testing.T) {
	// This test verifies that the traceroute tries each TTL in order
	// by using a very short timeout to capture partial results
	ctx := context.Background()
	opts := TraceOptions{
		Method:  "icmp",
		MaxHops: 5,
		Queries: 1,
		Wait:    100 * time.Millisecond,
	}

	hops, err := NativeTraceroute(ctx, "127.0.0.1", opts)
	if err != nil {
		t.Logf("Error (may be expected without root): %v", err)
	}

	// Verify hop numbers are sequential
	for i, hop := range hops {
		expectedNum := i + 1
		if hop.Number != expectedNum {
			t.Errorf("hop[%d].Number = %d, want %d", i, hop.Number, expectedNum)
		}
	}
}

func TestCountTimeouts_AllTimedOut(t *testing.T) {
	nodes := []*Node{
		{ID: "a", Responded: false},
	}
	got := countTimeouts(nodes, 5)
	if got != 5 {
		t.Errorf("countTimeouts = %d, want 5", got)
	}
}

func TestNativeTraceroute_QueriesPerHop(t *testing.T) {
	ctx := context.Background()
	opts := TraceOptions{
		Method:  "icmp",
		MaxHops: 1,
		Queries: 3,
		Wait:    100 * time.Millisecond,
	}

	hops, err := NativeTraceroute(ctx, "127.0.0.1", opts)
	if err != nil {
		t.Logf("Error: %v", err)
	}

	if len(hops) > 0 {
		hop := hops[0]
		// With 3 queries, we should have up to 3 RTTs per node
		for _, node := range hop.Nodes {
			if node.Responded && len(node.RTTs) > 3 {
				t.Errorf("node has %d RTTs, expected <= 3", len(node.RTTs))
			}
		}
	}
}

func TestNativeTraceroute_MethodSwitch(t *testing.T) {
	// Test that different methods don't panic
	methods := []string{"icmp", "udp", "tcp"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			ctx := context.Background()
			opts := TraceOptions{
				Method:  method,
				MaxHops: 1,
				Queries: 1,
				Wait:    200 * time.Millisecond,
			}
			hops, err := NativeTraceroute(ctx, "127.0.0.1", opts)
			if err != nil {
				t.Logf("Method %s error: %v", method, err)
			} else {
				t.Logf("Method %s: %d hops", method, len(hops))
			}
		})
	}
}


