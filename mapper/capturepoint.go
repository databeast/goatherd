package mapper

import "net"

// An individual Capture Point
// Usually there will be only one of these, but distributed capture mode requires one for each capture node
type CapturePoint struct {
	UpstreamGateways   []net.Addr
	DownstreamGateways []net.Addr
	LocalNet           net.IPNet
}
