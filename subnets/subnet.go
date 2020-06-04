package subnets

import "net"

type Subnet struct {
	Base          uint32       // Integer of the base IP Address of this Subnet
	Mask          uint32       // base Integer for XOR masking matching packets to this subnet (ie the subnet Mask)

	ObservedCount int       // how many incoming packets have matched this Potential Subnet?
	Subnets       []*Subnet // Potential Subnets of this Subnet
}

// write this subnet out in CIDR notation
func (s Subnet) String() {

}

// does this packet's Address XOR match the given Base and Mask ?
func (s Subnet) Match() bool {
	return false
}

// Can the given pairing of addresses viably describe the network and broadcast address of a valid CIDR subnet?
func IsViableSubnet(networkaddr net.IP, broadcastaddr net.IP) (*net.IPNet, bool) {

	return nil, false
}
