package capture

import (
	"encoding/binary"
	"github.com/databeast/goatherd/mapper/subnets"
	"github.com/databeast/goatherd/packets"
	"net"
	"sync"
)

type macaddrstr string

// sanity check for valid hex string representation of MAC addrs
func (m macaddrstr) validate() bool {

}


type ipmap map[uint8]map[uint8]map[uint8]uint8


// An individual Capture Point
// Usually there will be only one of these, but distributed capture mode requires one for each capture node
type CapturePoint struct {
	macmappings        map[macaddrstr]ipmap // primary data capture - IP address to MAC addrs
	mapmu 				*sync.Mutex

	SupernetGateways   map[macaddrstr]Gateway // gateways that lead to supernets
	SubnetGateways 	   map[macaddrstr]Gateway // gateways that lead to subnets
	LocalNet           net.IPNet		    // local subnet
	Nic  			   string   			// displayname of the NIC this capturepoint is bound to

	mapping   		   BitMap				// bitmask tracking for this capture point
	bitmu			   *sync.Mutex
}


func (c *CapturePoint) processPacketSummary(summary packets.PacketSummary) {

	// track the IPs to the MAC they are reachable via
	if _, ok := c.macmappings[macaddrstr(summary.SrcMac)] ; !ok {
		c.mapmu.Lock()
		c.macmappings[macaddrstr(summary.SrcMac)] = make(ipmap)
		c.mapmu.Unlock()
	}





	binary.BigEndian.Uint32(c.LocalNet.IP)
	record Mac to IP

	record IP Bits to mapping

}

func  (c *CapturePoint) trackAddrToMac(addr net.IP, mac net.HardwareAddr) {
	var ok bool
	var octet0 ipmap
	var octet1 map[uint8]map[uint8]uint8
	var octet2 map[uint8]uint8

	// seen this mac before? initialize if not
	if octet0, ok = c.macmappings[macaddrstr(mac)] ; !ok {
		c.mapmu.Lock()
		c.macmappings[macaddrstr(mac)] = make(ipmap)
		octet0 = c.macmappings[macaddrstr(mac)]
		c.mapmu.Unlock()
	}

	// see octet 0 before? initialize if not
	if octet1, ok = octet0[addr[0]] ; !ok {
		c.mapmu.Lock()
		octet0[addr[0]] = make(map[uint8]map[uint8]uint8)
		octet1 = octet0[addr[0]]
		c.mapmu.Unlock()
	}

	if octet2, ok = octet1[addr[1]] ; !ok {
		c.mapmu.Lock()
		octet1[addr[1]] = make(map[uint8]uint8)
		octet2 = octet1[addr[1]]
		c.mapmu.Unlock()
	}

	if _, ok = octet2[addr[2]] ; !ok {
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

	bitmask = c.LocalNet.Mask
	return binary.BigEndian.Uint32(c.LocalNet.IP) // IP traffic is always calculated bigendian
}

func (c *CapturePoint) testIfGateway(summary packets.PacketSummary) bool {

	// is this is an already known gateway MAC ?
	if _, ok := c.SupernetGateways[macaddrstr(summary.SrcMac.String())] ; ok {
		return true
	}
	if _, ok := c.SupernetGateways[macaddrstr(summary.DstMac.String())] ; ok {
		return true
	}

	// if src and destination are on the same Capturepoint subnet, this is absolutely not a gatewayyed packed
	if c.LocalNet.Contains(summary.SrcIP) == true && c.LocalNet.Contains(summary.DstIP) == true {
		return false
	}



	if c.LocalNet.Contains(summary.DstIP) == false {


	}

	// now check that its a downstream gateway to a subnet.


	// lastly, attempt to guess if this might be a NAT gateway, by looking for decremented TTL on a local address


	// is this IP address Src or Dst to an IP address other than the local subnet?
	net.HardwareAddr.String()

	return false
}

