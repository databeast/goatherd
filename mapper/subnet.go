package mapper

type Subnet struct {
	Base          int       // Integer of the base IP Address of this Subnet
	Mask          int       // base Integer for XOR masking matching packets to this subnet (ie the subnet Mask)
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
