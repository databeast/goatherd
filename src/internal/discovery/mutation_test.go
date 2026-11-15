package discovery

import (
	"net"
	"reflect"
	"testing"
)

func TestReportOrdersCandidatesAndIgnoresUnconfirmedTraffic(t *testing.T) {
	a := New(6)
	first := mac(t, "02:00:00:00:00:01")
	second := mac(t, "02:00:00:00:00:02")
	winner := mac(t, "02:00:00:00:00:03")
	unconfirmed := mac(t, "02:00:00:00:00:04")
	dest := net.IPv4(203, 0, 113, 1)
	for _, gateway := range []net.HardwareAddr{first, second, winner} {
		a.ObserveARP(gateway, net.IPv4(192, 0, 2, gateway[5]))
		a.ObserveIPv4(gateway, net.IPv4(10, 0, 0, 1), dest, 61)
	}
	a.ObserveIPv4(winner, net.IPv4(10, 0, 0, 1), dest, 61)
	for i := 0; i < 3; i++ {
		a.ObserveIPv4(unconfirmed, net.IPv4(10, 0, 0, 2), dest, 61)
	}

	report, err := a.Report(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []Candidate{
		{MAC: winner.String(), Packets: 2},
		{MAC: first.String(), Packets: 1},
		{MAC: second.String(), Packets: 1},
	}
	if report.UpstreamMAC != winner.String() || !reflect.DeepEqual(report.Candidates, want) {
		t.Fatalf("selection %s, candidates %+v; want %s, %+v", report.UpstreamMAC, report.Candidates, winner, want)
	}
	if report.ForwardedPackets != 2 || report.Overall.Packets != 2 || report.Overall.DistinctAddresses != 1 {
		t.Fatalf("unexpected winner evidence: %+v", report.Overall)
	}
}

func TestReportTTLCountsOrderedAndWeighted(t *testing.T) {
	a := New(6)
	gateway := mac(t, "02:00:00:00:00:01")
	dst := net.IPv4(203, 0, 113, 1)
	for _, ttl := range []uint8{17, 127, 61, 10, 63, 63} {
		a.ObserveIPv4(gateway, net.IPv4(10, 0, 0, 1), dst, ttl)
	}
	report, err := a.Report(gateway)
	if err != nil {
		t.Fatal(err)
	}
	if report.ForwardedPackets != 6 || report.UnknownTTL != 2 || len(report.Layers) != 2 ||
		*report.Layers[0].Hops != 1 || report.Layers[0].Packets != 3 ||
		*report.Layers[1].Hops != 3 || report.Layers[1].Packets != 1 {
		t.Fatalf("unexpected hop layers: %+v", report)
	}
	counts := report.Overall.Bits[31].TTL
	wantObserved := []uint8{63, 127, 61, 10, 17}
	wantOnes := []uint64{2, 1, 1, 1, 1}
	if len(counts) != len(wantObserved) {
		t.Fatalf("got TTL counts %+v", counts)
	}
	for i, count := range counts {
		if count.Observed != wantObserved[i] || count.One != wantOnes[i] || count.Zero != 0 {
			t.Errorf("count %d: %+v", i, count)
		}
		if i < 3 {
			if count.Hops == nil || count.Initial == nil {
				t.Errorf("count %d missing estimate: %+v", i, count)
			}
		} else if count.Hops != nil || count.Initial != nil {
			t.Errorf("count %d has unexpected estimate: %+v", i, count)
		}
	}
}

func TestReportReferenceUsesLowestSourceAddress(t *testing.T) {
	a := New(6)
	gateway := mac(t, "02:00:00:00:00:01")
	dst := net.IPv4(203, 0, 113, 1)
	for _, source := range []net.IP{net.IPv4(10, 0, 0, 9), net.IPv4(10, 0, 0, 2), net.IPv4(10, 0, 0, 5)} {
		a.ObserveIPv4(gateway, source, dst, 61)
	}
	report, err := a.Report(gateway)
	if err != nil {
		t.Fatal(err)
	}
	if report.Overall.Reference != "10.0.0.2" || report.Overall.VarianceMask != "0.0.0.15" {
		t.Fatalf("unexpected reference or variance: %+v", report.Overall)
	}
}
