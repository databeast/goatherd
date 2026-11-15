package collector

import "testing"

func TestNewCapturePointAddsIndependentPoints(t *testing.T) {
	var collector collectorBase
	for i := 0; i < 2; i++ {
		if err := collector.NewCapturePoint(); err != nil {
			t.Fatal(err)
		}
	}
	if len(collector.cappoints) != 2 || collector.cappoints[0] == nil ||
		collector.cappoints[1] == nil || collector.cappoints[0] == collector.cappoints[1] {
		t.Fatalf("capture points not independently added: %v", collector.cappoints)
	}
}
