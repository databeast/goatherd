package mapper

// Create a Mapper
// Load a Collector
// Define a capturepoint for the collector
//

// Goatherd Mapping operates by mimicking the same boolean AND/XOR operations that IP routing uses
//
//
// Is this packet outbound from an address internal to our local subnet mask?

// find the network and broadcast addresses - bits to the right of the mask that do not change, and are on a valid boundary
// (AND testing here)

// observe traffic.

// find variant bits after the mask - these are hosts, communicating directly)
// find invariant bits after the mask - these are often unused addresses,

// but some of those unused addresses can be network or broadcast addresses
// if we calculate that we see no traffic from a pairing of a valid network/broadcast address, we mark this mask/prefix
// as a viable potential subnet
