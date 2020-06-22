package mapper

import (
	"github.com/databeast/goatherd/capture"
	"net"
)

// primary calculator of possible downstream networks
func extractNetworksFromGateway(gate *capture.Gateway) (nets []net.IPNet, err error) {

	// start by identifying the leftmost portion with no variant bits



	return
}