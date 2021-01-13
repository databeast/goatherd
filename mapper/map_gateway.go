package mapper

import (
	"net"

	"github.com/databeast/goatherd/capture"
)

type direction bool

const (
	incoming direction = false
	outgoing direction = true
)

// primary calculator of possible downstream networks
func extractNetworksFromGateway(gate *capture.Gateway) (nets []net.IPNet, err error) {

	// start by identifying the leftmost portion with no variant bits

	return
}

type TrafficBitMask struct {
	Bits []bool
}

func (m *TrafficBitMask) observe(addr net.Addr) {

}

type GatewayBitMask struct {
	Incoming TrafficBitMask
	OutGoing TrafficBitMask
}

func (m *GatewayBitMask) ObserveAddress(dir direction, addr net.Addr) {
	switch dir {
	case incoming:
		m.Incoming.observe(addr)
	case outgoing:
		m.OutGoing.observe(addr)
	}

}
