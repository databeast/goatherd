package capture

// Capture Points define a point of observation from a local subnet
// Each capture point will attempt to process what its Upstream Gateway(s) are
// then proceed to analyze monitored traffic to determine what IP/MAC combinations
// are gateways to downstream subnets.
// each downstream gateway will attempt to discover a viable list of routable CIDR subnets
// that are available beyond the given gateway.

// Determine upstream via broadest range of variant bits.
