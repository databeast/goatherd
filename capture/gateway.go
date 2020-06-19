// Identified Gateways on Observed sections
package capture

import (
	"github.com/databeast/goatherd/packets"
	"github.com/pkg/errors"
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

	bmux 	*sync.Mutex
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
		bmux:  		 &sync.Mutex{},
	}
}

// the XORable bitmask that encompasses all traffic coming from this network
func (g *Gateway) BaseBitMask() uint32 {
	return 0
}

// process this packet summary, now we know its source host originated beyond this gateway
func (g *Gateway) processPacket(summary *packets.PacketSummary) (err error) {
	// sanity checks for developer oversight
	if summary.SrcMac.String() != string(g.arpaddr) && summary.DstMac.String() != string(g.arpaddr) {
		return errors.Errorf("summary incorrectly passed to wrong gateway to process")
	}
	// from here on out, we're just going to work with the IP address in a bitwise fashion. convert it to bitmap\
	bits, err := decomposeToBits(summary.SrcIP)
	if err != nil {
		return err
	}

	// first, lets figure out our variant bits from this gateway
	for i, b := range bits {
		switch g.bitmapping[bitposition(i)].value {
		case UNSET:  //
			if b {
				g.bitmapping[bitposition(i)].value = SET
			}
		case SET: // if we now encounter this bit unset again, we know it is variant
			if !b {
				g.bitmapping[bitposition(i)].value = VARIANT
			}
		case VARIANT: // we've already determined it's variant, once is enough

		}
	}




	return nil

}

// turn IP addresses into a bitmap style array of bools, its just easier to work with that way
func decomposeToBits(addr net.IP) (bits [32]bool, err error) {

	for i, x := range addr {
		for j := 0; j < 8; j++ {
			if (x<<uint(j))&0x80 == 0x80 {
				bits[8*i+j] = true
			}
		}
	}

	return bits, err
}

func (c *CapturePoint) recheckGateways() {

}
