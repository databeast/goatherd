package subnets

import (
	"sync"
	"testing"

	"github.com/databeast/goatherd/internal/comm"
)

func TestTTLTrackerConcurrentCounts(t *testing.T) {
	tracker := ttltracker{count: make(ttlcount), mu: &sync.Mutex{}}
	const workers, iterations = 8, 100
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(ttl uint8) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				tracker.track(comm.PacketSummary{TTL: ttl})
			}
		}(uint8(60 + i%2))
	}
	wg.Wait()
	if len(tracker.count) != 2 || tracker.count[60] != workers/2*iterations || tracker.count[61] != workers/2*iterations {
		t.Fatalf("unexpected counts: %v", tracker.count)
	}
}
