package subnets

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"net"
)

// Subnet describes an IPv4 candidate prefix. Base and Mask use network byte order.
type Subnet struct {
	Base uint32
	Mask uint32

	ObservedCount int
	Subnets       []*Subnet
}

// String returns the subnet in CIDR notation.
func (s Subnet) String() string {
	var ip, mask [4]byte
	binary.BigEndian.PutUint32(ip[:], s.Base)
	binary.BigEndian.PutUint32(mask[:], s.Mask)
	return (&net.IPNet{IP: net.IP(ip[:]), Mask: net.IPMask(mask[:])}).String()
}

// Match reports whether addr belongs to this IPv4 subnet.
func (s Subnet) Match(addr net.IP) bool {
	ip := addr.To4()
	return ip != nil && binary.BigEndian.Uint32(ip)&s.Mask == s.Base
}

// IsViableSubnet checks whether the addresses are the inclusive endpoints of
// an IPv4 CIDR range. A /32 has identical endpoints; a /31 has two endpoints.
func IsViableSubnet(networkaddr net.IP, broadcastaddr net.IP) (*net.IPNet, bool) {
	first, last := networkaddr.To4(), broadcastaddr.To4()
	if first == nil || last == nil {
		return nil, false
	}
	base := binary.BigEndian.Uint32(first)
	end := binary.BigEndian.Uint32(last)
	hostMask := base ^ end
	if base&hostMask != 0 || hostMask&(hostMask+1) != 0 {
		return nil, false
	}
	mask := ^hostMask
	var address, maskBytes [4]byte
	binary.BigEndian.PutUint32(address[:], base)
	binary.BigEndian.PutUint32(maskBytes[:], mask)
	return &net.IPNet{IP: net.IP(address[:]), Mask: net.IPMask(maskBytes[:])}, true
}

// NewSubnet validates an IPv4 CIDR and normalizes its base address.
func NewSubnet(ipNet *net.IPNet) (*Subnet, error) {
	if ipNet == nil {
		return nil, errors.New("subnet is nil")
	}
	addr := ipNet.IP.To4()
	if addr == nil {
		return nil, errors.New("subnet address must be IPv4")
	}
	prefix, width := ipNet.Mask.Size()
	if width != 32 || len(ipNet.Mask) != net.IPv4len {
		return nil, errors.New("subnet mask must be a contiguous IPv4 mask")
	}
	mask := binary.BigEndian.Uint32(net.CIDRMask(prefix, 32))
	return &Subnet{Base: binary.BigEndian.Uint32(addr) & mask, Mask: mask}, nil
}

// FromVariance returns the narrowest CIDR containing a reference address and
// all addresses represented by a cumulative XOR variance mask.
func FromVariance(reference, variance uint32) Subnet {
	mask := binary.BigEndian.Uint32(net.CIDRMask(bits.LeadingZeros32(variance), 32))
	return Subnet{Base: reference & mask, Mask: mask}
}
