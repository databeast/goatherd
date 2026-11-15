package discovery

import (
	"net"
	"testing"
)

func TestAddressPrefixTree(t *testing.T) {
	tree, err := AddressPrefixTree([]string{"10.0.0.3", "10.0.0.1", "10.0.0.3"})
	if err != nil || tree == nil || tree.Prefix != "10.0.0.0/30" || tree.DistinctAddresses != 2 || len(tree.Children) != 2 {
		t.Fatalf("unexpected tree: %+v, %v", tree, err)
	}
	if tree, err := AddressPrefixTree(nil); err != nil || tree != nil {
		t.Fatalf("empty tree: %+v, %v", tree, err)
	}
	for _, invalid := range []string{"not-an-ip", "::1"} {
		if _, err := AddressPrefixTree([]string{invalid}); err == nil {
			t.Fatalf("accepted invalid IPv4 %q", invalid)
		}
	}
}

func TestEvidenceFiltersInvalidAndKeepsARPOnlyAddresses(t *testing.T) {
	a := New(6)
	gateway := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	a.ObserveARP(gateway, net.IPv4(192, 0, 2, 1))
	a.ObserveARP(net.HardwareAddr{1, 0, 0, 0, 0, 1}, net.IPv4(192, 0, 2, 2))
	a.ObserveIPv4(gateway, net.IPv4(0, 0, 0, 0), net.IPv4(8, 8, 8, 8), 63)
	a.ObserveIPv4(gateway, net.IPv4(198, 51, 100, 1), net.IPv4(8, 8, 8, 8), 63)
	got := a.Evidence(gateway.String())
	if len(got.Addresses) != 2 || got.Addresses[0].Address != "192.0.2.1" ||
		got.Addresses[1].Address != "198.51.100.1" || got.Topology.DistinctAddresses != 2 ||
		got.Topology.Packets != 1 || got.Addresses[1].Destinations[0].TowardUpstream != 1 {
		t.Fatalf("unexpected evidence: %+v", got)
	}
}
