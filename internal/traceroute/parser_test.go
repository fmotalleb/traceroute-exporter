package traceroute

import (
	"testing"
)

func TestParseTarget_SimpleHost(t *testing.T) {
	spec, err := ParseTarget("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Host != "example.com" {
		t.Errorf("host = %q, want %q", spec.Host, "example.com")
	}
	if spec.Port != "" {
		t.Errorf("port = %q, want empty", spec.Port)
	}
}

func TestParseTarget_HostAndPort(t *testing.T) {
	spec, err := ParseTarget("example.com:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Host != "example.com" {
		t.Errorf("host = %q, want %q", spec.Host, "example.com")
	}
	if spec.Port != "443" {
		t.Errorf("port = %q, want %q", spec.Port, "443")
	}
}

func TestParseTarget_IPv4Address(t *testing.T) {
	spec, err := ParseTarget("192.168.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Host != "192.168.1.1" {
		t.Errorf("host = %q, want %q", spec.Host, "192.168.1.1")
	}
}

func TestParseTarget_IPv6Address(t *testing.T) {
	spec, err := ParseTarget("2001:db8::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Host != "2001:db8::1" {
		t.Errorf("host = %q, want %q", spec.Host, "2001:db8::1")
	}
}

func TestParseTarget_URLWithScheme(t *testing.T) {
	spec, err := ParseTarget("http://example.com:8080/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Host != "example.com" {
		t.Errorf("host = %q, want %q", spec.Host, "example.com")
	}
	if spec.Port != "8080" {
		t.Errorf("port = %q, want %q", spec.Port, "8080")
	}
}

func TestParseTarget_Empty(t *testing.T) {
	_, err := ParseTarget("")
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestParseTarget_EmptyHost(t *testing.T) {
	_, err := ParseTarget(":8080")
	if err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestParseTarget_InvalidPort(t *testing.T) {
	_, err := ParseTarget("example.com:99999")
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}

func TestParseTarget_InvalidCharacters(t *testing.T) {
	_, err := ParseTarget("example.com/path")
	if err == nil {
		t.Fatal("expected error for invalid characters")
	}
}

func TestParseTarget_BracketedIPv6WithPort(t *testing.T) {
	spec, err := ParseTarget("[::1]:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Host != "::1" {
		t.Errorf("host = %q, want %q", spec.Host, "::1")
	}
	if spec.Port != "8080" {
		t.Errorf("port = %q, want %q", spec.Port, "8080")
	}
}

func TestParseTarget_Whitespace(t *testing.T) {
	spec, err := ParseTarget("  example.com:443  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Host != "example.com" {
		t.Errorf("host = %q, want %q", spec.Host, "example.com")
	}
}

func TestParseRTT_WithMsSuffix(t *testing.T) {
	tokens := []string{"1.234ms"}
	rtt, ok, consume := ParseRTT(tokens, 0)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if rtt != 0.001234 {
		t.Errorf("rtt = %f, want 0.001234", rtt)
	}
	if consume {
		t.Error("expected consumeNext=false")
	}
}

func TestParseRTT_WithMsSeparate(t *testing.T) {
	tokens := []string{"1.5", "ms"}
	rtt, ok, consume := ParseRTT(tokens, 0)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if rtt != 0.0015 {
		t.Errorf("rtt = %f, want 0.0015", rtt)
	}
	if !consume {
		t.Error("expected consumeNext=true")
	}
}

func TestParseRTT_NotRTT(t *testing.T) {
	tokens := []string{"hello"}
	_, ok, _ := ParseRTT(tokens, 0)
	if ok {
		t.Error("expected ok=false for non-RTT token")
	}
}

func TestParseRTT_OutOfBounds(t *testing.T) {
	tokens := []string{}
	_, ok, _ := ParseRTT(tokens, 0)
	if ok {
		t.Error("expected ok=false for out of bounds")
	}
}

func TestParseRTT_CapitalMS(t *testing.T) {
	tokens := []string{"2.5MS"}
	rtt, ok, _ := ParseRTT(tokens, 0)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if rtt != 0.0025 {
		t.Errorf("rtt = %f, want 0.0025", rtt)
	}
}

func TestIsAddressLike_IPv4(t *testing.T) {
	if !IsAddressLike("192.168.1.1") {
		t.Error("expected true for IPv4 address")
	}
}

func TestIsAddressLike_IPv6(t *testing.T) {
	if !IsAddressLike("::1") {
		t.Error("expected true for IPv6 address")
	}
}

func TestIsAddressLike_NotAddress(t *testing.T) {
	if IsAddressLike("example.com") {
		t.Error("expected false for hostname")
	}
}

func TestIsAddressLike_IPv4WithZone(t *testing.T) {
	if !IsAddressLike("192.168.1.1%eth0") {
		t.Error("expected true for IPv4 with zone")
	}
}

func TestIsParenAddress_True(t *testing.T) {
	if !IsParenAddress("(192.168.1.1)") {
		t.Error("expected true")
	}
}

func TestIsParenAddress_False(t *testing.T) {
	if IsParenAddress("(example.com)") {
		t.Error("expected false for hostname")
	}
}

func TestIsParenAddress_NoParens(t *testing.T) {
	if IsParenAddress("192.168.1.1") {
		t.Error("expected false without parens")
	}
}

func TestComputeReached_ByAddress(t *testing.T) {
	trace := TraceResult{
		ResolvedAddress: "1.2.3.4",
		Hops: []Hop{
			{Number: 1, Nodes: []*Node{
				{ID: "1.2.3.4", Hop: 1, Address: "1.2.3.4", Responded: true},
			}},
		},
	}
	spec := TargetSpec{Host: "example.com"}
	if !ComputeReached(trace, spec) {
		t.Error("expected reached=true by address match")
	}
}

func TestComputeReached_ByHostname(t *testing.T) {
	trace := TraceResult{
		DestinationHost: "example.com",
		Hops: []Hop{
			{Number: 1, Nodes: []*Node{
				{ID: "example.com", Hop: 1, Hostname: "example.com", Responded: true},
			}},
		},
	}
	spec := TargetSpec{Host: "example.com"}
	if !ComputeReached(trace, spec) {
		t.Error("expected reached=true by hostname match")
	}
}

func TestComputeReached_NotReached(t *testing.T) {
	trace := TraceResult{
		ResolvedAddress: "1.2.3.4",
		Hops: []Hop{
			{Number: 1, Nodes: []*Node{
				{ID: "5.6.7.8", Hop: 1, Address: "5.6.7.8", Responded: true},
			}},
		},
	}
	spec := TargetSpec{Host: "example.com"}
	if ComputeReached(trace, spec) {
		t.Error("expected reached=false")
	}
}

func TestBuildEdges_SingleHop(t *testing.T) {
	source := &Node{ID: "src", Hop: 0}
	hops := []Hop{
		{Number: 1, Nodes: []*Node{
			{ID: "n1", Hop: 1},
		}},
	}
	edges := BuildEdges(source, hops)
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if edges[0].Parent.ID != "src" || edges[0].Node.ID != "n1" {
		t.Errorf("unexpected edge: %s -> %s", edges[0].Parent.ID, edges[0].Node.ID)
	}
}

func TestBuildEdges_MultipleHops(t *testing.T) {
	source := &Node{ID: "src", Hop: 0}
	hops := []Hop{
		{Number: 1, Nodes: []*Node{{ID: "a", Hop: 1}}},
		{Number: 2, Nodes: []*Node{{ID: "b", Hop: 2}}},
	}
	edges := BuildEdges(source, hops)
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(edges))
	}
}

func TestBuildEdges_MultiNodeHops(t *testing.T) {
	source := &Node{ID: "src", Hop: 0}
	hops := []Hop{
		{Number: 1, Nodes: []*Node{
			{ID: "a", Hop: 1},
			{ID: "b", Hop: 1},
		}},
	}
	edges := BuildEdges(source, hops)
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges (src->a, src->b), got %d", len(edges))
	}
}

func TestCleanToken(t *testing.T) {
	tests := []struct{ in, want string }{
		{"hello", "hello"},
		{" hello ", "hello"},
		{",hello,", "hello"},
		{" hello , ", "hello "},
	}
	for _, tt := range tests {
		got := CleanToken(tt.in)
		if got != tt.want {
			t.Errorf("CleanToken(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCleanName(t *testing.T) {
	if got := CleanName("[example.com]"); got != "example.com" {
		t.Errorf("CleanName = %q, want %q", got, "example.com")
	}
}

func TestCleanAddress(t *testing.T) {
	if got := CleanAddress("(192.168.1.1)"); got != "192.168.1.1" {
		t.Errorf("CleanAddress = %q, want %q", got, "192.168.1.1")
	}
}

func TestNextTokenIsRTT_True(t *testing.T) {
	tokens := []string{"192.168.1.1", "1.5ms"}
	if !NextTokenIsRTT(tokens, 0) {
		t.Error("expected true")
	}
}

func TestNextTokenIsRTT_False(t *testing.T) {
	tokens := []string{"192.168.1.1", "hello"}
	if NextTokenIsRTT(tokens, 0) {
		t.Error("expected false")
	}
}

func TestParseHopLine_Simple(t *testing.T) {
	line := " 1  192.168.1.1 (192.168.1.1) 1.234 ms"
	hop, ok := ParseHopLine(line, 3)
	if !ok {
		t.Fatal("expected parseable")
	}
	if hop.Number != 1 {
		t.Errorf("hop number = %d, want 1", hop.Number)
	}
	if len(hop.Nodes) == 0 {
		t.Fatal("expected at least one node")
	}
	if hop.Nodes[0].Address != "192.168.1.1" {
		t.Errorf("address = %q, want %q", hop.Nodes[0].Address, "192.168.1.1")
	}
}

func TestParseHopLine_Stars(t *testing.T) {
	line := " 2  * * *"
	hop, ok := ParseHopLine(line, 3)
	if !ok {
		t.Fatal("expected parseable")
	}
	if hop.Stars != 3 {
		t.Errorf("stars = %d, want 3", hop.Stars)
	}
	if len(hop.Nodes) == 0 {
		t.Fatal("expected at least one node for no-reply")
	}
	if hop.Nodes[0].Responded {
		t.Error("expected responded=false for stars")
	}
}

func TestParseHopLine_HostnameAndAddress(t *testing.T) {
	line := " 3  router.example.com (10.0.0.1)  2.5 ms"
	hop, ok := ParseHopLine(line, 1)
	if !ok {
		t.Fatal("expected parseable")
	}
	if len(hop.Nodes) == 0 {
		t.Fatal("expected at least one node")
	}
	node := hop.Nodes[0]
	if node.Hostname != "router.example.com" {
		t.Errorf("hostname = %q, want %q", node.Hostname, "router.example.com")
	}
	if node.Address != "10.0.0.1" {
		t.Errorf("address = %q, want %q", node.Address, "10.0.0.1")
	}
}

func TestParseHopLine_NotParseable(t *testing.T) {
	line := "not a hop line"
	_, ok := ParseHopLine(line, 1)
	if ok {
		t.Error("expected not parseable")
	}
}

func TestParseTraceOutput_Simple(t *testing.T) {
	output := `traceroute to example.com (93.184.216.34), 30 hops max
 1  192.168.1.1  1.234 ms
 2  10.0.0.1  2.5 ms
 3  93.184.216.34  3.0 ms
`
	spec := TargetSpec{Host: "example.com"}
	result := ParseTraceOutput(output, spec, "93.184.216.34", 1)
	if len(result.Hops) != 3 {
		t.Errorf("expected 3 hops, got %d", len(result.Hops))
	}
	if result.DestinationHost != "example.com" {
		t.Errorf("destination = %q, want %q", result.DestinationHost, "example.com")
	}
}

func TestParseTraceOutput_Empty(t *testing.T) {
	spec := TargetSpec{Host: "example.com"}
	result := ParseTraceOutput("", spec, "1.2.3.4", 1)
	if len(result.Hops) != 0 {
		t.Errorf("expected 0 hops, got %d", len(result.Hops))
	}
}
