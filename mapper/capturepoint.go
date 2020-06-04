package mapper

import (
	"github.com/databeast/goatherd/packets"
	"net"
)

type macaddrstr string

// sanity check for valid hex string representation of MAC addrs
func (m macaddrstr) validate() bool {

}

// An individual Capture Point
// Usually there will be only one of these, but distributed capture mode requires one for each capture node
type CapturePoint struct {
	SupernetGateways   map[macaddrstr]Gateway // gateways that lead to supernets
	SubnetGateways 	   map[macaddrstr]Gateway // gateways that lead to subnets
	LocalNet           net.IPNet		    // local subnet
	Nic  			   string   			// displayname of the NIC this capturepoint is bound to
	macmappings        map[macaddrstr]net.IP // mapping ARP to IP addresses on local network
}

// Add a known capturepoint to this collector - usually the subnet of the monitored NIC
func (c *CapturePoint) AddCapturePoint() error {

}

// the Base bitmask for this capture points local network
// all downstream networks must, by definition, XOR mask to 0 with these bits
func (c *CapturePoint) BaseBitMask() uint32 {

	return 0
}

func (c *CapturePoint) TestIfGateway(summary packets.PacketSummary) bool {
	// is this is an already known gateway MAC ?
	if _, ok := c.SupernetGateways[summary.DstMac.String()] ; ok {
		return true
	}
	if _, ok := c.SupernetGateways[summary.SrcMac.String()] ; ok {
		return true
	}

	// is this an upstream gateway? ie Src or Dst addresses are to an address that is not a subnet of the local net
	if c.LocalNet.Contains(summary.SrcIP) == false {


	}

	if c.LocalNet.Contains(summary.DstIP) == false {


	}

	// now check that its a downstream gateway to a subnet.


	// lastly, attempt to guess if this might be a NAT gateway, by looking for decremented TTL on a local address


	// is this IP address Src or Dst to an IP address other than the local subnet?
	net.HardwareAddr.String()

	return false
}