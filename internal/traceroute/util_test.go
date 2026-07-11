package traceroute

import (
	"testing"
	"time"
)

func TestNormalizeMethod(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", "auto"},
		{"auto", "auto"},
		{"tcp", "tcp"},
		{"t", "tcp"},
		{"icmp", "icmp"},
		{"i", "icmp"},
		{"udp", "udp"},
		{"u", "udp"},
		{"TCP", "tcp"},
		{"  tcp  ", "tcp"},
	}
	for _, tt := range tests {
		got := NormalizeMethod(tt.in)
		if got != tt.want {
			t.Errorf("NormalizeMethod(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeIPFamily(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"4", "4"},
		{"ipv4", "4"},
		{"6", "6"},
		{"ipv6", "6"},
		{"IPv4", "4"},
		{"invalid", ""},
	}
	for _, tt := range tests {
		got := NormalizeIPFamily(tt.in)
		if got != tt.want {
			t.Errorf("NormalizeIPFamily(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSecondsForTraceroute(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{time.Second, "1"},
		{2 * time.Second, "2"},
		{500 * time.Millisecond, "0.500"},
		{0, "1"}, // default to 1
	}
	for _, tt := range tests {
		got := SecondsForTraceroute(tt.d)
		if got != tt.want {
			t.Errorf("SecondsForTraceroute(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestLossRatio_NoQueries(t *testing.T) {
	hop := Hop{Nodes: []*Node{{Responded: false}}}
	got := LossRatio(hop, 0)
	if got != 1 {
		t.Errorf("LossRatio = %f, want 1", got)
	}
}

func TestLossRatio_AllResponded(t *testing.T) {
	hop := Hop{
		Nodes: []*Node{
			{Responded: true, RTTs: []float64{0.001}},
			{Responded: true, RTTs: []float64{0.002}},
		},
	}
	got := LossRatio(hop, 3)
	if got != 0 {
		t.Errorf("LossRatio = %f, want 0", got)
	}
}

func TestAvgRTT_Empty(t *testing.T) {
	_, ok := AvgRTT(nil)
	if ok {
		t.Error("expected ok=false for empty slice")
	}
}

func TestAvgRTT_Single(t *testing.T) {
	avg, ok := AvgRTT([]float64{0.001})
	if !ok {
		t.Fatal("expected ok=true")
	}
	if avg != 0.001 {
		t.Errorf("avg = %f, want 0.001", avg)
	}
}

func TestAvgRTT_Multiple(t *testing.T) {
	avg, ok := AvgRTT([]float64{0.001, 0.002, 0.003})
	if !ok {
		t.Fatal("expected ok=true")
	}
	if avg != 0.002 {
		t.Errorf("avg = %f, want 0.002", avg)
	}
}

func TestLastHop_Empty(t *testing.T) {
	if got := LastHop(nil); got != 0 {
		t.Errorf("LastHop = %d, want 0", got)
	}
}

func TestLastHop_Multiple(t *testing.T) {
	hops := []Hop{
		{Number: 1},
		{Number: 5},
		{Number: 3},
	}
	if got := LastHop(hops); got != 5 {
		t.Errorf("LastHop = %d, want 5", got)
	}
}

func TestNoReplyID(t *testing.T) {
	got := NoReplyID(5)
	if got != "no-reply-hop-05" {
		t.Errorf("NoReplyID(5) = %q, want %q", got, "no-reply-hop-05")
	}
}

func TestFallback(t *testing.T) {
	if got := Fallback("hello", "default"); got != "hello" {
		t.Errorf("Fallback = %q, want %q", got, "hello")
	}
	if got := Fallback("", "default"); got != "default" {
		t.Errorf("Fallback = %q, want %q", got, "default")
	}
}

func TestBoolString(t *testing.T) {
	if got := BoolString(true); got != "true" {
		t.Errorf("BoolString(true) = %q", got)
	}
	if got := BoolString(false); got != "false" {
		t.Errorf("BoolString(false) = %q", got)
	}
}

func TestBoolFloat(t *testing.T) {
	if got := BoolFloat(true); got != 1 {
		t.Errorf("BoolFloat(true) = %f", got)
	}
	if got := BoolFloat(false); got != 0 {
		t.Errorf("BoolFloat(false) = %f", got)
	}
}

func TestClampInt(t *testing.T) {
	if got := ClampInt(5, 1, 10); got != 5 {
		t.Errorf("ClampInt(5,1,10) = %d", got)
	}
	if got := ClampInt(0, 1, 10); got != 1 {
		t.Errorf("ClampInt(0,1,10) = %d", got)
	}
	if got := ClampInt(15, 1, 10); got != 10 {
		t.Errorf("ClampInt(15,1,10) = %d", got)
	}
}

func TestMaxInt(t *testing.T) {
	if got := MaxInt(3, 7); got != 7 {
		t.Errorf("MaxInt(3,7) = %d", got)
	}
	if got := MaxInt(7, 3); got != 7 {
		t.Errorf("MaxInt(7,3) = %d", got)
	}
}

func TestTrimHopsAfter(t *testing.T) {
	hops := []Hop{
		{Number: 1},
		{Number: 2},
		{Number: 3},
		{Number: 4},
	}
	result := TrimHopsAfter(hops, 2)
	if len(result) != 2 {
		t.Errorf("expected 2 hops, got %d", len(result))
	}
}

func TestTrimHopsAfter_Zero(t *testing.T) {
	hops := []Hop{{Number: 1}, {Number: 2}}
	result := TrimHopsAfter(hops, 0)
	if len(result) != 2 {
		t.Errorf("expected all hops preserved, got %d", len(result))
	}
}

func TestMergeLabels(t *testing.T) {
	a := map[string]string{"a": "1"}
	b := map[string]string{"b": "2"}
	got := MergeLabels(a, b)
	if got["a"] != "1" || got["b"] != "2" {
		t.Errorf("MergeLabels = %v", got)
	}
}

func TestQueryString_Default(t *testing.T) {
	q := mockValues{}
	got := QueryString(q, "key", "default")
	if got != "default" {
		t.Errorf("QueryString = %q, want %q", got, "default")
	}
}

func TestQueryString_Value(t *testing.T) {
	q := mockValues{"key": "value"}
	got := QueryString(q, "key", "default")
	if got != "value" {
		t.Errorf("QueryString = %q, want %q", got, "value")
	}
}

func TestQueryInt_Default(t *testing.T) {
	q := mockValues{}
	got := QueryInt(q, "key", 42)
	if got != 42 {
		t.Errorf("QueryInt = %d, want 42", got)
	}
}

func TestQueryInt_Value(t *testing.T) {
	q := mockValues{"key": "100"}
	got := QueryInt(q, "key", 42)
	if got != 100 {
		t.Errorf("QueryInt = %d, want 100", got)
	}
}

func TestQueryInt_Invalid(t *testing.T) {
	q := mockValues{"key": "abc"}
	got := QueryInt(q, "key", 42)
	if got != 42 {
		t.Errorf("QueryInt = %d, want 42", got)
	}
}

func TestQueryDuration_Default(t *testing.T) {
	q := mockValues{}
	got := QueryDuration(q, "key", time.Second)
	if got != time.Second {
		t.Errorf("QueryDuration = %v", got)
	}
}

func TestQueryDuration_Value(t *testing.T) {
	q := mockValues{"key": "5s"}
	got := QueryDuration(q, "key", time.Second)
	if got != 5*time.Second {
		t.Errorf("QueryDuration = %v, want 5s", got)
	}
}

// mockValues implements the interface for Get(string) string.
type mockValues map[string]string

func (m mockValues) Get(key string) string {
	return m[key]
}
