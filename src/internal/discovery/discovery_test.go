package discovery

import (
	"net"
	"testing"
)

func mac(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestReportRetainsEvidenceAndSplitsHopLayers(t *testing.T) {
	a := New(6)
	gateway := mac(t, "02:00:00:00:00:01")
	other := mac(t, "02:00:00:00:00:02")
	dst := net.ParseIP("203.0.113.5")
	for _, v := range []struct {
		source string
		ttl    uint8
	}{
		{"10.4.0.1", 61},
		{"10.4.0.2", 125},
		{"10.4.1.1", 252},
		{"10.4.2.1", 63},
		{"10.4.3.1", 17},
	} {
		a.ObserveIPv4(gateway, net.ParseIP(v.source), dst, v.ttl)
	}
	a.ObserveIPv4(gateway, net.ParseIP("192.0.2.20"), net.ParseIP("192.0.2.1"), 64)
	a.ObserveIPv4(other, net.ParseIP("172.16.0.1"), dst, 64)
	// ARP arrives after the traffic and still affects both scoring and filtering.
	a.ObserveARP(gateway, net.ParseIP("192.0.2.1"))
	a.ObserveARP(other, net.ParseIP("192.0.2.2"))

	report, err := a.Report(nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.UpstreamMAC != gateway.String() || report.ForwardedPackets != 5 || report.UnknownTTL != 1 {
		t.Fatalf("unexpected gateway or counts: %+v", report)
	}
	if len(report.Candidates) != 2 || report.Candidates[0].Packets != 5 || report.Candidates[1].Packets != 1 {
		t.Fatalf("unexpected candidate scores: %+v", report.Candidates)
	}
	if report.Overall.Prefix != "10.4.0.0/22" || report.Overall.VarianceMask != "0.0.3.3" ||
		report.Overall.DistinctAddresses != 5 {
		t.Fatalf("unexpected overall evidence: %+v", report.Overall)
	}
	if len(report.Layers) != 2 || *report.Layers[0].Hops != 1 || *report.Layers[1].Hops != 3 {
		t.Fatalf("unexpected layers: %+v", report.Layers)
	}
	layer := report.Layers[1]
	if layer.Prefix != "10.4.0.0/23" || layer.Packets != 3 || layer.DistinctAddresses != 3 {
		t.Fatalf("unexpected 3-hop layer: %+v", layer)
	}
	if tree := layer.Topology; tree.Prefix != "10.4.0.0/23" || len(tree.Children) != 2 ||
		tree.Children[0].Prefix != "10.4.0.0/30" || tree.Children[0].Packets != 2 ||
		tree.Children[1].Prefix != "10.4.1.1/32" {
		t.Fatalf("unexpected prefix topology: %+v", tree)
	}
	// The least significant bit is zero for one source and one for two.
	counts := layer.Bits[31].TTL
	if len(counts) != 3 || counts[0].Zero != 0 || counts[0].One != 1 ||
		*counts[0].Initial != 64 || *counts[1].Initial != 128 || *counts[2].Initial != 255 ||
		counts[1].Zero != 1 || counts[2].One != 1 {
		t.Fatalf("unexpected bit TTL counts: %+v", counts)
	}
	if ttl := report.Overall.Bits[0].TTL; len(ttl) != 5 || ttl[4].Observed != 17 || ttl[4].Hops != nil {
		t.Fatalf("unknown TTL evidence missing: %+v", ttl)
	}
}

func TestGatewaySelectionAndOverride(t *testing.T) {
	a := New(6)
	first := mac(t, "02:00:00:00:00:01")
	second := mac(t, "02:00:00:00:00:02")
	source, dest := net.ParseIP("10.0.0.1"), net.ParseIP("203.0.113.1")
	a.ObserveIPv4(first, source, dest, 64)
	a.ObserveIPv4(second, source, dest, 64)
	if _, err := a.Report(nil); err == nil {
		t.Fatal("expected missing ARP error")
	}
	report, err := a.Report(first)
	if err != nil || report.Selection != "configured" || report.Overall.Prefix != "10.0.0.1/32" {
		t.Fatalf("override: %+v, %v", report, err)
	}
	a.ObserveARP(first, net.ParseIP("192.0.2.1"))
	a.ObserveARP(second, net.ParseIP("192.0.2.2"))
	if _, err := a.Report(nil); err == nil {
		t.Fatal("expected tie error")
	}
	a.ObserveIPv4(first, net.ParseIP("10.0.0.2"), dest, 64)
	report, err = a.Report(nil)
	if err != nil || report.UpstreamMAC != first.String() {
		t.Fatalf("winner: %+v, %v", report, err)
	}
	if _, err := a.Report(mac(t, "ff:ff:ff:ff:ff:ff")); err == nil {
		t.Fatal("expected invalid MAC error")
	}
}

func TestEstimateTTL(t *testing.T) {
	for _, tc := range []struct {
		ttl, max, initial, hops uint8
		ok                      bool
	}{
		{29, 6, 32, 3, true}, {61, 6, 64, 3, true},
		{125, 6, 128, 3, true}, {252, 6, 255, 3, true},
		{58, 6, 64, 6, true}, {57, 6, 0, 0, false},
		{0, 255, 0, 0, false}, {64, 0, 64, 0, true},
		{63, 0, 0, 0, false},
	} {
		initial, hops, ok := estimateTTL(tc.ttl, tc.max)
		if initial != tc.initial || hops != tc.hops || ok != tc.ok {
			t.Errorf("ttl %d max %d: got %d,%d,%v", tc.ttl, tc.max, initial, hops, ok)
		}
	}
}

func TestInvalidAndBroadcastTrafficIgnored(t *testing.T) {
	a := New(6)
	gateway := mac(t, "02:00:00:00:00:01")
	a.ObserveIPv4(mac(t, "ff:ff:ff:ff:ff:ff"), net.IPv4(10, 0, 0, 1), net.IPv4(8, 8, 8, 8), 64)
	a.ObserveIPv4(gateway, net.ParseIP("::1"), net.IPv4(8, 8, 8, 8), 64)
	a.ObserveIPv4(gateway, net.IPv4(10, 0, 0, 1), net.IPv4(224, 0, 0, 1), 64)
	if _, err := a.Report(gateway); err == nil {
		t.Fatal("expected no usable packets")
	}
}

func TestPrefixTreeSpansIPv4SpaceAndCountsDuplicates(t *testing.T) {
	a := New(6)
	gateway := mac(t, "02:00:00:00:00:01")
	dst := net.ParseIP("203.0.113.1")
	a.ObserveIPv4(gateway, net.ParseIP("10.0.0.1"), dst, 61)
	a.ObserveIPv4(gateway, net.ParseIP("10.0.0.1"), dst, 61)
	a.ObserveIPv4(gateway, net.ParseIP("200.0.0.1"), dst, 61)
	report, err := a.Report(gateway)
	if err != nil {
		t.Fatal(err)
	}
	tree := report.Overall.Topology
	if tree.Prefix != "0.0.0.0/0" || tree.Packets != 3 || tree.DistinctAddresses != 2 ||
		len(tree.Children) != 2 || tree.Children[0].Packets != 2 || tree.Children[1].Packets != 1 {
		t.Fatalf("unexpected topology: %+v", tree)
	}
}
