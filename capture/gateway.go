// Identified Gateways on Observed sections
package capture

import (
	"fmt"
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
	for i := 0; i < 32; i += 1 {
		g.bitmapping[uint8(i)] = &ttlbittrack{
			value:     0,
			ttlcounts: make(map[uint8]int64),
		}
	}

	return g
}

// the XORable bitmask that encompasses all traffic coming from this network
func (g *Gateway) BaseBitMask() uint32 {
	return 0
}

// process this packet summary, now we know its source host originated beyond this gateway
func (g *Gateway) processPacket(summary packets.PacketSummary) (err error) {
	fmt.Printf("Processing Packet on Gateway: %s\n", g.arpaddr.String())
	// sanity checks for developer oversight
	if summary.SrcMac.String() != g.arpaddr.String() && summary.DstMac.String() != g.arpaddr.String() {
		errors.Errorf("summary incorrectly passed to wrong gateway to process")
		// TODO: needs to error properly once I'm finished with core
	}

	g.packetcount += 1

	// from here on out, we're just going to work with the IP address in a bitwise fashion. convert it to bitmap\
	bits, err := decomposeToBits(summary.SrcIP)
	if err != nil {
		fmt.Printf("%s\n", err.Error())
		return err
	}

	// We're going to be applying the perceived TTL steps to bits as we process them, lets get that now
	var ttlstep uint8
	ttlstep, err = guessTTLstep(summary.TTL)
	if err != nil {
		return err
	}

	// if the TTL step is 0, this is a local subnet-sourced packet, not originating via routing
	// e.g from the gateway host itself
	if ttlstep == 0 {

	}


	// first, lets figure out our variant bits from this gateway
	for i, b := range bits {
		g.bmux.Lock() // might change this later if locking during the whole packet op is quicker
		switch g.bitmapping[i].value {
		case UNSET: //
			if b { // we're seeing this bit being set for the first time
				g.bitmapping[uint8(i)].value = SET
			}
			g.trackBitTTL(uint8(i), ttlstep)
		case SET: // if we now encounter this bit unset again, we know it is variant
			if !b {
				g.bitmapping[uint8(i)].value = VARIANT
				g.trackBitTTL(uint8(i), ttlstep)
			}
		case VARIANT: // we've already determined it's variant, once is enough to know that.
			g.trackBitTTL(uint8(i), ttlstep)
		}
		g.bmux.Unlock()
	}

	for _, v := range g.bitmapping {
		fmt.Printf("%v\n", v)
	}

	return nil

}

// turn IP addresses into a bitmap style array of bools, its just easier to work with that way
func decomposeToBits(addr net.IP) (bits [32]bool, err error) {

	//ipint := binary.BigEndian.Uint32(addr)
	//NOTE: validate this goes bigendian in all archs
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
