package capture

import (
	"github.com/pkg/errors"
)

// TTL Step attempts to determine a rational variance from a possible default TTL variance
// TTL provides the best guess at how many routing hops a packet has already taken, to reach
// the point at which is was observed.

//TODO: see if we can determine downstream NAT gateways by variant TTL counts from it

var MaxSubnetHops uint8 = 6 // at what level do we consider the maximum number of possible routing hops

func guessTTLstep(ttl uint8) (step uint8, err error) {
	if ttl == 0 {
		return 255, errors.Errorf("missing ttl value")
	}

	if (ttl - MaxSubnetHops) > ttl { // unsigned overflow, current ttl lower than max hops
		//  This is a situation we might expect where packets from an upstream network are almost expiring
		// reaching their intended downstream destination
		return 0, errors.Errorf("unusable ttl")
	}

	// TTLs this high are rare, usually only from packets directly sourced from networking OSs
	if ttl > (255 - MaxSubnetHops) {
		step = 255-ttl
		return
	}

	// This is the most common setting today for most client systems.
	if ttl > (128 - MaxSubnetHops) {
		step = 128-ttl
		return
	}

	// common for several Unix variants, note that 60 is also a used base TTL in this range
	if ttl > (64 - MaxSubnetHops) {
		step = 64-ttl
		return
	}

	// mostly used by Legacy windows variants
	if ttl > (32 - MaxSubnetHops) {
		step = 32-ttl
		return
	}

	// Under 32 hops is very rare, but not impossible - however it more likely indicates that MaxSubnetHops is set too low

	return 255, errors.Errorf("unusable ttl")
}
