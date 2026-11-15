package subnets

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestNewSubnetAndMatch(t *testing.T) {
	tests := []struct {
		ip, mask, cidr, in, out string
	}{
		{"10.12.3.129", "255.255.255.128", "10.12.3.128/25", "10.12.3.255", "10.12.3.127"},
		{"192.0.2.3", "255.255.255.254", "192.0.2.2/31", "192.0.2.3", "192.0.2.4"},
		{"192.0.2.3", "255.255.255.255", "192.0.2.3/32", "192.0.2.3", "192.0.2.4"},
		{"192.0.2.3", "0.0.0.0", "0.0.0.0/0", "255.255.255.255", ""},
	}
	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			mask := net.IPMask(net.ParseIP(tt.mask).To4())
			s, err := NewSubnet(&net.IPNet{IP: net.ParseIP(tt.ip), Mask: mask})
			if err != nil {
				t.Fatal(err)
			}
			if got := s.String(); got != tt.cidr {
				t.Fatalf("got %s, want %s", got, tt.cidr)
			}
			if !s.Match(net.ParseIP(tt.in)) || s.Match(net.ParseIP(tt.out)) || s.Match(net.ParseIP("2001:db8::1")) {
				t.Fatal("incorrect subnet membership")
			}
		})
	}
}

func TestNewSubnetRejectsInvalidInputs(t *testing.T) {
	for _, ipNet := range []*net.IPNet{
		nil,
		{IP: net.ParseIP("::1"), Mask: net.CIDRMask(32, 32)},
		{IP: net.ParseIP("192.0.2.1"), Mask: net.IPMask{255, 0, 255, 0}},
		{IP: net.ParseIP("192.0.2.1"), Mask: net.CIDRMask(120, 128)},
		{IP: net.ParseIP("192.0.2.1"), Mask: nil},
	} {
		if _, err := NewSubnet(ipNet); err == nil {
			t.Errorf("expected error for %v", ipNet)
		}
	}
}

func TestIsViableSubnet(t *testing.T) {
	for _, tt := range []struct {
		first, last, want string
	}{
		{"10.0.0.0", "10.0.0.255", "10.0.0.0/24"},
		{"10.0.0.128", "10.0.0.255", "10.0.0.128/25"},
		{"192.0.2.2", "192.0.2.3", "192.0.2.2/31"},
		{"192.0.2.2", "192.0.2.2", "192.0.2.2/32"},
		{"0.0.0.0", "255.255.255.255", "0.0.0.0/0"},
		{"10.0.0.1", "10.0.0.255", ""},
		{"10.0.0.0", "10.0.0.254", ""},
		{"10.0.0.128", "10.0.0.127", ""},
		{"::1", "::1", ""},
		{"", "10.0.0.1", ""},
	} {
		t.Run(tt.first+"-"+tt.last, func(t *testing.T) {
			result, ok := IsViableSubnet(net.ParseIP(tt.first), net.ParseIP(tt.last))
			if ok != (tt.want != "") {
				t.Fatalf("got %v, %v", result, ok)
			}
			if ok && result.String() != tt.want {
				t.Fatalf("got %s, want %s", result, tt.want)
			}
		})
	}
}

func TestFromVariance(t *testing.T) {
	for _, tt := range []struct {
		reference, variance uint32
		want                string
	}{
		{0x0a000001, 0, "10.0.0.1/32"},
		{0x0a000001, 0x00000003, "10.0.0.0/30"},
		{0x0a040001, 0x00000303, "10.4.0.0/22"},
		{0x0a000001, 0x80000000, "0.0.0.0/0"},
	} {
		if got := FromVariance(tt.reference, tt.variance).String(); got != tt.want {
			t.Errorf("got %s, want %s", got, tt.want)
		}
	}
}

func TestAllIPv4PrefixLengths(t *testing.T) {
	const reference uint32 = 0xc63364b7
	for prefix := 0; prefix <= 32; prefix++ {
		mask := binary.BigEndian.Uint32(net.CIDRMask(prefix, 32))
		base, end := reference&mask, reference&mask|^mask
		var first, last [4]byte
		binary.BigEndian.PutUint32(first[:], base)
		binary.BigEndian.PutUint32(last[:], end)
		ipNet, ok := IsViableSubnet(net.IP(first[:]), net.IP(last[:]))
		if !ok {
			t.Fatalf("/%d range rejected", prefix)
		}
		network, err := NewSubnet(ipNet)
		if err != nil || network.Base != base || network.Mask != mask {
			t.Fatalf("/%d: got %+v, %v", prefix, network, err)
		}
		candidate := FromVariance(reference, ^mask)
		if candidate.Base != base || candidate.Mask != mask {
			t.Fatalf("/%d: got %+v", prefix, candidate)
		}
	}
}
