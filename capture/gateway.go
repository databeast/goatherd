// Identified Gateways on Observed sections
package capture

import (
	"github.com/databeast/goatherd/packets"
	"github.com/golang-collections/go-datastructures/bitarray"
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

// process this packet summary, now we know its source host originated beyond this gateway
func (g *Gateway) processPacket(summary *packets.PacketSummary) (err error) {
	// sanity checks for developer oversight
	if summary.SrcMac.String() != string(g.arpaddr) && summary.DstMac.String() != string(g.arpaddr) {
		return errors.Errorf("summary incorrectly passed to wrong gateway to process")
	}



	return nil

}

// turn IP addresses into a bitmap style array of bools, its just easier to work with that way
func decomposeToBits(addr net.IPAddr) (bits [32]bool, err error) {
	array := bitarray.NewBitArray()
	println(array)

	return bits, err
}

func (c *CapturePoint) recheckGateways() {

}
