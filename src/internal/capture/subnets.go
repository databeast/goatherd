package capture

import (
	"github.com/databeast/goatherd/internal/subnets"
)

// remember that Network addresses must always be Even numbers (last bit must always be variant)

// Generate a Tree of currently-viable subnet calculation from this capturepoint
func (c CapturePoint) CalculateSubnets() (subs []subnets.Subnet, err error) {

	for _, g := range c.subnetGateways {
		g.calculateSubnets()
	}

	return nil, nil
}
