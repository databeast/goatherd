// Identified Gateways on Observed sections
package mapper

import "net"

// Tracking of Identified gateways on the local subnet
type Gateway struct {
	arpaddr     net.HardwareAddr
	isUpstream  bool
	ttltracking *TTLtracker
	packetcount int64
}
