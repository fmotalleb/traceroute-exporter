package traceroute

import (
	"testing"
)

func TestDetectLoop_Disabled(t *testing.T) {
	hops := makeHops([]string{"A", "A", "A", "A"})
	result := DetectLoop(hops, 0)
	if result.Detected {
		t.Error("expected no detection when disabled")
	}
}

func TestDetectLoop_NoLoop(t *testing.T) {
	hops := makeHops([]string{"A", "B", "C", "D"})
	result := DetectLoop(hops, 4)
	if result.Detected {
		t.Error("expected no loop for unique hops")
	}
}

func TestDetectLoop_SimpleLoop(t *testing.T) {
	hops := makeHops([]string{"A", "B", "A", "B", "A", "B", "A", "B"})
	result := DetectLoop(hops, 4)
	if !result.Detected {
		t.Fatal("expected loop detection")
	}
	if result.Length != 2 {
		t.Errorf("length = %d, want 2", result.Length)
	}
	if result.Repeats < 2 {
		t.Errorf("repeats = %d, want >= 2", result.Repeats)
	}
}

func TestDetectLoop_SingleHopLoop(t *testing.T) {
	hops := makeHops([]string{"A", "A", "A", "A", "A"})
	result := DetectLoop(hops, 3)
	if !result.Detected {
		t.Fatal("expected loop detection")
	}
	if result.Length != 1 {
		t.Errorf("length = %d, want 1", result.Length)
	}
}

func TestDetectLoop_GiveUp(t *testing.T) {
	hops := makeHops([]string{"A", "B", "A", "B", "A", "B", "A", "B", "A", "B"})
	result := DetectLoop(hops, 3)
	if !result.Detected {
		t.Fatal("expected loop detection")
	}
	if !result.GiveUp {
		t.Error("expected GiveUp=true when repeats >= threshold")
	}
}

func TestDetectLoop_NoGiveUp(t *testing.T) {
	hops := makeHops([]string{"A", "B", "A", "B"})
	result := DetectLoop(hops, 10)
	if !result.Detected {
		t.Fatal("expected loop detection")
	}
	if result.GiveUp {
		t.Error("expected GiveUp=false when repeats < threshold")
	}
}

func makeHops(hosts []string) []Hop {
	hops := make([]Hop, len(hosts))
	for i, h := range hosts {
		hops[i] = Hop{
			Number: i + 1,
			Nodes: []*Node{
				{
					ID:        h,
					Hop:       i + 1,
					Hostname:  h,
					Address:   h,
					Responded: true,
				},
			},
		}
	}
	return hops
}
