// Identified Gateways on Observed sections
package capture

import (
	"net"
	"sync"
)

// Tracking of Identified gateways on the local subnet
type Gateway struct {
	ipaddr  net.IP
	arpaddr net.HardwareAddr

	isUpstream bool
	isnat      bool

	packetcount int64

	bitmapping BitMap // TTL-Per-Bit tracking for this capture point
	bitmu      *sync.Mutex
}

func NewGateway(addr net.IP, arpaddr net.HardwareAddr) *Gateway {
	return &Gateway{
		ipaddr:      addr,
		arpaddr:     arpaddr,
		isUpstream:  false,
		bitmapping:  BitMap{},
		packetcount: 0,
		isnat:       false,
	}
}

// the XORable bitmask that encompasses all traffic coming from this network
func (g *Gateway) BaseBitMask() uint32 {
	return 0
}

func (c *CapturePoint) recheckGateways() {

}
