package capture

// TTL Step attempts to determine a rational variance from a possible default TTL variance
// TTL provides the best guess at how many routing hops a packet has already taken, to reach
// the point at which is was observed.

var MAX_SUBNET_HOPS uint8 = 6 // at what level do we consider the maximum number of possible routing hops

func guessTTLstep(ttl uint8) (step uint8, err error) {

	if (ttl - MAX_SUBNET_HOPS) > ttl { // unsigned overflow, current ttl lower than max hops
		//  This is a situation we might expect where packets from an upstream network are almost expiring
		// reaching their intended downstream destination

	}

	// TTLs this high are rare, usually only from packets directly sourced from networking OSs
	if ttl > (255 - MAX_SUBNET_HOPS) {

		return 0, nil
	}

	// This is the most common setting today for most client systems.
	if ttl > (128 - MAX_SUBNET_HOPS) {

		return 0, nil
	}

	// common for several Unix variants, note that 60 is also a used base TTL in this range
	if ttl > (64 - MAX_SUBNET_HOPS) {

		return 0, nil
	}

	// mostly used by Legacy windows variants
	if ttl > (32 - MAX_SUBNET_HOPS) {

		return 0, nil
	}

	// Under 32 hops is very rare, but not impossible - however it more likely indicates that MAX_SUBNET_HOPS is set too low

	return 0, nil
}
