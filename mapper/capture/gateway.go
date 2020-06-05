// Identified Gateways on Observed sections
package capture

import "net"

// Tracking of Identified gateways on the local subnet
type Gateway struct {
	ipaddr 		net.IP
	arpaddr     net.HardwareAddr
	isUpstream  bool
	tracking    BitMap
	packetcount int64
	isnat	    bool
}


func NewGateway(addr net.IP, arpaddr net.HardwareAddr) *Gateway {
	return &Gateway{
		ipaddr:      addr,
		arpaddr:     arpaddr,
		isUpstream:  false,
		tracking:    BitMap{},
		packetcount: 0,
		isnat:       false,
	}
}

// the XORable bitmask that encompasses all traffic coming from this network
func (g *Gateway) BaseBitMask() uint32 {
	return 0
}



