// Identified Gateways on Observed sections
package capture

import "net"

// Tracking of Identified gateways on the local subnet
type Gateway struct {
	ipaddr 		net.IP
	arpaddr     net.HardwareAddr
	isUpstream  bool
	ttltracking *ttltracker
	packetcount int64
	isnat	    bool
}

// the XORable bitmask that encompasses all traffic coming from this network
func (g *Gateway) BaseBitMask() uint32 {
	return 0
}

