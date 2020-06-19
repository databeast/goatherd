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

	bmux       *sync.Mutex
	bitmapping BitMap // TTL-Per-Bit tracking for this capture point
	bitmu      *sync.Mutex
}

func NewGateway(addr net.IP, arpaddr net.HardwareAddr) (g *Gateway) {
	g = &Gateway{
		ipaddr:      addr,
		arpaddr:     arpaddr,
		isUpstream:  false,
		bitmapping:  BitMap{},
		packetcount: 0,
		isnat:       false,
		bmux:        &sync.Mutex{},
	}
	for i := 0; i < 32; i += i {
		g.bitmapping[bitposition(i)] = &ttlbittrack{}
	}
	return g
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

	// We're going to be appling the perceived TTL steps to bits as we process them, lets get that now
	var ttlstep uint8
	ttlstep, err = guessTTLstep(summary.TTL)
	if err != nil {
		return err
	}

	// first, lets figure out our variant bits from this gateway
	for i, b := range bits {
		g.bmux.Lock() // might change this later if locking during the whole packet op is quicker
		switch g.bitmapping[bitposition(i)].value {
		case UNSET: //
			if b { // we're seeing this bit being set for the first time
				g.bitmapping[bitposition(i)].value = SET
				g.bitmapping[bitposition(i)].ttlcounts[ttlstep] += 1
			}
		case SET: // if we now encounter this bit unset again, we know it is variant
			if !b {
				g.bitmapping[bitposition(i)].value = VARIANT
				g.bitmapping[bitposition(i)].ttlcounts[ttlstep] += 1
			}
		case VARIANT: // we've already determined it's variant, once is enough to know that.
			g.bitmapping[bitposition(i)].ttlcounts[ttlstep] += 1
		}
		g.bmux.Unlock()
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
