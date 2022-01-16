// TTL Tracker monitors the differentials in TTL of comm matched to a given subnet
// by finding a common integer variance in them, it attempts to guess how many 'hops'
// the given downstream subnet is from the capturepoint network
package subnets

import (
	"github.com/databeast/goatherd/internal/comm"
	"sync"
)

// TTLs vary by OS, but are almost always derived from a bit boundary integer
type ttlcount map[uint8]int64

// List of observed TTL coming upstream through this subnet
type ttltracker struct {
	count ttlcount
	mu    *sync.Mutex
}

// track the ttl on a given packet
func (t *ttltracker) track(pkt comm.PacketSummary) {
	t.mu.Lock()
	t.count[pkt.TTL] += 1
	t.mu.Unlock()
}

// what is the largest number of probable hops it takes to reach this network from downstream subnets?
func (t *ttltracker) MaxHeight() {

}

// how many probable hops below the capturepoint is this subnet?
func (t *ttltracker) Depth() {

}
