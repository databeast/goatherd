package discovery

import (
	"net"
	"testing"
)

func TestPreviousHopEvidence(t *testing.T) {
	a := New(6)
	upstream := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	hopA := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	hopB := net.HardwareAddr{2, 0, 0, 0, 0, 3}
	internal := net.HardwareAddr{2, 0, 0, 0, 0, 4}
	source := net.IPv4(10, 0, 0, 10)
	other := net.IPv4(10, 0, 0, 11)
	dest := net.IPv4(203, 0, 113, 1)
	gatewayIP := net.IPv4(10, 0, 0, 1)
	a.ObserveARP(upstream, gatewayIP)
	a.ObserveARP(hopA, source)
	a.ObserveIPv4Ethernet(hopA, upstream, source, dest, 63)
	a.ObserveIPv4Ethernet(hopA, upstream, other, gatewayIP, 64)
	a.ObserveIPv4Ethernet(hopA, internal, other, dest, 62)
	a.ObserveIPv4Ethernet(hopB, upstream, source, dest, 63)
	a.ObserveIPv4(upstream, other, dest, 64)
	a.ObserveIPv4Ethernet(net.HardwareAddr{1, 0, 0, 0, 0, 1}, upstream, other, dest, 64)
	report, err := a.Report(upstream)
	if err != nil {
		t.Fatal(err)
	}
	if report.UnknownPreviousHopPackets != 2 || len(report.PreviousHops) != 2 || report.PreviousHops[0].MAC != hopA.String() ||
		report.PreviousHops[1].MAC != hopB.String() {
		t.Fatalf("unexpected previous hops: %+v", report.PreviousHops)
	}
	first := report.PreviousHops[0]
	if first.Overall.Packets != 3 || first.Overall.Prefix != "10.0.0.10/31" ||
		first.TowardUpstream == nil || first.TowardUpstream.Packets != 1 ||
		len(first.Sources) != 2 || !first.Sources[0].ARPSenderMatch || first.Sources[1].ARPSenderMatch ||
		first.Sources[1].TowardUpstream != 0 || first.Sources[1].Packets != 2 {
		t.Fatalf("incorrect previous hop: %+v", first)
	}
	if report.PreviousHops[1].Sources[0].Address != first.Sources[0].Address {
		t.Fatal("same address must remain associated with both previous hops")
	}
	unclassified := a.Evidence("")
	if len(unclassified.PreviousHops) != 2 || unclassified.PreviousHops[0].TowardUpstream != nil {
		t.Fatalf("unselected upstream inferred: %+v", unclassified.PreviousHops)
	}
}
