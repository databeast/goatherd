// Identified Gateways on Observed sections
package mapper

import "net"

// Tracking of Identified gateways on the local subnet
type Gateway struct {
	ipaddr 		net.IPAddr
	arpaddr     net.HardwareAddr
	isUpstream  bool
	ttltracking *ttltracker
	packetcount int64
}
