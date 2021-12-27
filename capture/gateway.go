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

// how many leading bits are invariant?
func (g *Gateway) MaskBits() (maskbits uint8) {
	if g.bitmapping[0].value == VARIANT {
		return 0 // no discernable fixed mask for this gateway
	}
	for i, b := range g.bitmapping {
		if b.value == VARIANT {
			return uint8(i - 1) // everything up until this bit is fixed
		}
	}
	return 32 // we've only ever seen a single address from this gateway
}

// What are the leading invariant bits?
func (g *Gateway) FixedBits() (maskbits uint8) {
	return maskbits
}

// process this packet summary, now we know its source host originated beyond this gateway
func (g *Gateway) processPacket(summary packets.PacketSummary) (err error) {
	logger.Printf("Processing Packet on Gateway: %s\n", g.arpaddr.String())
	// sanity checks for developer oversight
	if summary.SrcMac.String() != g.arpaddr.String() && summary.DstMac.String() != g.arpaddr.String() {
		errors.Errorf("summary incorrectly passed to wrong gateway to process")
		// TODO: needs to error properly once I'm finished with core
	}

	g.packetcount += 1

	// from here on out, we're just going to work with the IP address in a bitwise fashion. convert it to bitmap\
	bits, err := decomposeToBits(summary.SrcIP)
	if err != nil {
		logger.Printf("%s\n", err.Error())
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

	return nil

}

// Re-examine our knowledge of IP/MAC mappings to see if we've identified a new gateway
func (c *CapturePoint) recheckGateways() {
	// TODO: Need a mutex strategy here
	for mac, ipmap := range c.macmappings {
		// if we already know this is a gateway, don't waste time rechecking it

		if _, ok := c.subnetGateways[mac]; ok {
			continue
		}

		if _, ok := c.supernetGateways[mac]; ok {
			continue
		}

		if len(ipmap.List()) > 1 { // more than one address served from here, potential gateway

			// TODO: are the addresses all on the local subnet? hosts with multiple interface IPs are not necessarily gateway

			// ok, time to create a new gateway
			ngip := net.ParseIP("")
			ngmac, err := net.ParseMAC(string(mac))
			if err != nil { //something bad has happened code-wise for things to be in this state

			}

			ng := NewGateway(ngip, ngmac)

			//subnet or supernet gateway? For now we're doing this the stupid way first
			//by assuming that the widest range of first-octect is upstream
			if len(ipmap) > 10 {
				c.supernetGateways[mac] = ng
			} else {
				c.subnetGateways[mac] = ng
			}
		}
	}
}

// pull subnet estimates just from this gateway
func (g *Gateway) calculateSubnets() {
	//for i, v := range g.bitmapping {
	//
	//}
}
