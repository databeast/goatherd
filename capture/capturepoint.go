package capture

import (
	"encoding/binary"
	"github.com/databeast/goatherd/packets"
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
func (c *CapturePoint) SetDefaultGateway(macddr net.HardwareAddr) (err error) {
	// if we already know about this, just copy it over
	if gateway, ok := c.supernetGateways[macaddrstr(macddr)]; ok { // default gateways art by definition upstream gateways
		c.defaultGateway = gateway
	}

	return err
}

func (c *CapturePoint) processPacketSummary(summary packets.PacketSummary) (err error) {
	// input sanity checks
	if macaddrstr(summary.SrcMac).validate() == false {
		return errors.WithStack(errors.Errorf("unusable MAC addr %q", summary.SrcMac))
	}
	if macaddrstr(summary.DstMac).validate() == false {
		return errors.WithStack(errors.Errorf("unusable MAC addr %q", summary.DstMac))
	}

	// track the IPs to the MAC they are reachable via
	c.trackAddrToMac(summary.SrcIP, summary.SrcMac)
	c.trackAddrToMac(summary.DstIP, summary.DstMac)

	// Now determine what gateway pairing we're working with

	var srcgateway *Gateway
	var dstgateway *Gateway

	// if by virtue of our capturepoint, we know our Default Gateway, we know it is by definition and upstream gateway
	if c.defaultGateway != nil {

	}

	if gateway, ok := c.supernetGateways[macaddrstr(summary.SrcMac)]; ok { // connection from upstream to downstream

		srcgateway = gateway

	}
	if gateway, ok := c.subnetGateways[macaddrstr(summary.SrcMac)]; ok { // connection from upstream to downstream

		srcgateway = gateway
	}

	srcgateway.BaseBitMask()
	dstgateway.BaseBitMask()
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
	if octet0, ok = c.macmappings[macaddrstr(mac)]; !ok {
		c.mapmu.Lock()
		c.macmappings[macaddrstr(mac)] = make(ipmap)
		octet0 = c.macmappings[macaddrstr(mac)]
		c.mapmu.Unlock()
	}

	// see octet 0 before? initialize if not
	if octet1, ok = octet0[addr[0]]; !ok {
		c.mapmu.Lock()
		octet0[addr[0]] = make(map[uint8]map[uint8]uint8)
		octet1 = octet0[addr[0]]
		c.mapmu.Unlock()
	}

	if octet2, ok = octet1[addr[1]]; !ok {
		c.mapmu.Lock()
		octet1[addr[1]] = make(map[uint8]uint8)
		octet2 = octet1[addr[1]]
		c.mapmu.Unlock()
	}

	if _, ok = octet2[addr[2]]; !ok {
		c.mapmu.Lock()
		octet2[addr[2]] = addr[3]
		c.mapmu.Unlock()
	}

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
