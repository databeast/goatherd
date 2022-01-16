package capture

import (
	"encoding/binary"
	"fmt"
	"github.com/databeast/goatherd/internal/comm"
	"github.com/pkg/errors"
	"math/rand"
	"net"
	"sync"
)

type macaddrstr string

// sanity check for valid hex string representation of MAC addrs
func (m macaddrstr) validate() bool {
	// just check this is 40-bit Hex
	return true
}

type ipmap map[uint8]map[uint8]map[uint8]uint8

// convert map to list of IP addresses
func (m ipmap) List() (addrs []string) {
	var addrstring string
	for quad1, next1 := range m {
		for quad2, next2 := range next1 {
			for quad3, quad4 := range next2 {
				addrstring = fmt.Sprintf("%d.%d.%d.%d", quad1, quad2, quad3, quad4)
				addrs = append(addrs, addrstring)
			}
		}
	}

	return addrs
}

// An individual Capture Point
// Usually there will be only one of these, but distributed capture mode requires one for each capture node
type CapturePoint struct {
	ID       uint32    // unique ID for this capturepoint
	LocalNet net.IPNet // local subnet
	Nic      string    // displayname of the NIC this capturepoint is bound to

	macmappings map[macaddrstr]ipmap // primary data capture - IP address to MAC addrs
	mapmu       *sync.Mutex

	defaultGateway   *Gateway
	supernetGateways map[macaddrstr]*Gateway // gateways that lead to supernets
	subnetGateways   map[macaddrstr]*Gateway // gateways that lead to subnets

}

// Assign a given hardware Address as the known default Gateway
// TODO: multihomed support
func (c *CapturePoint) SetDefaultGateway(macaddr net.HardwareAddr) (err error) {
	// if we already know about this, just copy it over
	if gateway, ok := c.supernetGateways[macaddrstr(macaddr)]; ok { // default gateways art by definition upstream gateways
		c.defaultGateway = gateway
	}

	// TESTING ONLY
	gate := NewGateway(net.IP{192, 168, 0, 1}, macaddr)
	c.defaultGateway = gate
	// TESTING ONLY

	return err
}

func (c *CapturePoint) ProcessPacketSummary(summary comm.PacketSummary) (err error) {
	// input sanity checks
	if macaddrstr(summary.SrcMac).validate() == false {
		return errors.WithStack(errors.Errorf("unusable MAC addr %q", summary.SrcMac))
	}
	if macaddrstr(summary.DstMac).validate() == false {
		return errors.WithStack(errors.Errorf("unusable MAC addr %q", summary.DstMac))
	}

	// if the TTL Step is 0, we can likely assume this packet is from the local network.

	// track the IPs to the MAC they are reachable via
	c.trackAddrToMac(summary.SrcIP, summary.SrcMac)
	c.trackAddrToMac(summary.DstIP, summary.DstMac)

	// Now determine what gateway pairing we're working with
	// remember that packet summaries are always new connections from src to dst

	var srcgateway *Gateway
	var dstgateway *Gateway

	// if by virtue of our capturepoint, we know our Default Gateway, we know it is by definition and upstream gateway
	if c.defaultGateway != nil {
		if summary.DstMac.String() == c.defaultGateway.arpaddr.String() { //we know we're headed upstream
			dstgateway = c.defaultGateway
		}
	}

	if gateway, ok := c.supernetGateways[macaddrstr(summary.SrcMac)]; ok { // connection from upstream to downstream
		srcgateway = gateway
	} else if gateway, ok := c.subnetGateways[macaddrstr(summary.SrcMac)]; ok { // connection from upstream to downstream
		srcgateway = gateway
	} else { // gateway is not yet identified as either upstream or downstream

	}

	srcgateway.BaseBitMask()
	dstgateway.BaseBitMask()

	// TEST MODE ONLY
	c.defaultGateway.processPacket(summary)
	// we only care about Src Connections addresses on downstream gateways  for TTL-tracking bitmasks

	// now process the TTLs seen on our addressbits.

	return nil
}

// associate a given IP Address to the local Hardware Address (MAC) it was sent to
// This is the primary mechanism for determining Gateways
func (c *CapturePoint) trackAddrToMac(addr net.IP, mac net.HardwareAddr) {
	var ok bool
	var octet0 ipmap
	var octet1 map[uint8]map[uint8]uint8
	var octet2 map[uint8]uint8

	// seen this mac before? initialize if not
	c.mapmu.Lock()
	if octet0, ok = c.macmappings[macaddrstr(mac)]; !ok {
		c.macmappings[macaddrstr(mac)] = make(ipmap)
		octet0 = c.macmappings[macaddrstr(mac)]
	}
	c.mapmu.Unlock()

	c.mapmu.Lock()
	// see octet 0 before? initialize if not
	if octet1, ok = octet0[addr[0]]; !ok {
		octet0[addr[0]] = make(map[uint8]map[uint8]uint8)
		octet1 = octet0[addr[0]]
	}
	c.mapmu.Unlock()

	c.mapmu.Lock()
	if octet2, ok = octet1[addr[1]]; !ok {
		octet1[addr[1]] = make(map[uint8]uint8)
		octet2 = octet1[addr[1]]
	}
	c.mapmu.Unlock()

	c.mapmu.Lock()
	if _, ok = octet2[addr[2]]; !ok {
		octet2[addr[2]] = addr[3]
	}
	c.mapmu.Unlock()

	c.recheckGateways() // see if our updated knowledge identities new gateways

}

// the Base bitmask for this capture points local network
// all downstream networks must, by definition, XOR mask to 0 with these bits
func (c *CapturePoint) BaseBitMask() (bitmask uint32) {
	// 11000000.10101000.00000000 .00000001
	// 11111111.11111111.11111111

	//bitmask = c.LocalNet.Mask.
	return binary.BigEndian.Uint32(c.LocalNet.IP) // IP traffic is always calculated bigendian
}

func genCapPointID() uint32 {
	return rand.Uint32()
}

func NewCapturePoint() (point *CapturePoint, err error) {
	point = &CapturePoint{
		ID:               genCapPointID(),
		LocalNet:         net.IPNet{},
		Nic:              "",
		macmappings:      make(map[macaddrstr]ipmap),
		mapmu:            &sync.Mutex{},
		defaultGateway:   nil,
		supernetGateways: nil,
		subnetGateways:   nil,
	}
	return point, nil
}
