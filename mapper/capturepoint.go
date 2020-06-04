package mapper

import (
	"github.com/databeast/goatherd/packets"
	"net"
)

// An individual Capture Point
// Usually there will be only one of these, but distributed capture mode requires one for each capture node
type CapturePoint struct {
	UpstreamGateways   map[string]Gateway
	DownstreamGateways map[string]Gateway
	LocalNet           net.IPNet
	macmappings        map[string]net.IP // mapping ARP to IP addresses on local network
}

// the Base bitmask for this capture points local network
// all downstream networks must, by definition, XOR mask to 0 with these bits
func (c *CapturePoint) BaseBitMask() uint32 {

	return 0
}

func (c *CapturePoint) TestIfGateway(summary packets.PacketSummary) bool {
	// is this is an already known gateway MAC ?
	if _, ok := c.UpstreamGateways[summary.DstMac.String()] ; ok {
		return true
	}
	if _, ok := c.UpstreamGateways[summary.SrcMac.String()] ; ok {
		return true
	}

	// is this an upstream gateway? ie Src or Dst addresses are to an address that is not a subnet of the local net
	if c.LocalNet.Contains(summary.SrcIP) == false {


	}

	if c.LocalNet.Contains(summary.DstIP) == false {


	}

	// now check that its a downstream gateway.


	// lastly, attempt to guess if this might be a NAT gateway, by looking for decremented TTL on a local address


	// is this IP address Src or Dst to an IP address other than the local subnet?
	net.HardwareAddr.String()

	return false
}