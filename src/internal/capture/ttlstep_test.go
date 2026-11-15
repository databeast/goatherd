package capture

import "testing"

func TestGuessTTLStepCommonDefaults(t *testing.T) {
	for _, tt := range []struct {
		ttl, hops uint8
	}{
		{32, 0}, {29, 3}, {64, 0}, {61, 3}, {128, 0}, {125, 3}, {255, 0}, {252, 3},
	} {
		hops, err := guessTTLstep(tt.ttl)
		if err != nil || hops != tt.hops {
			t.Errorf("TTL %d: got %d, %v", tt.ttl, hops, err)
		}
	}
	for _, ttl := range []uint8{0, 1, 10, 20} {
		if _, err := guessTTLstep(ttl); err == nil {
			t.Errorf("TTL %d unexpectedly accepted", ttl)
		}
	}
}
