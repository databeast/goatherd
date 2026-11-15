package coordination

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/databeast/goatherd/internal/quality"
)

func TestInventoryAcrossCapturePoints(t *testing.T) {
	server := NewServer()
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	other := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	a, err := server.register(&Registration{CapturePoint: "a", UpstreamMac: mac})
	if err != nil {
		t.Fatal(err)
	}
	b, err := server.register(&Registration{CapturePoint: "b"})
	if err != nil {
		t.Fatal(err)
	}
	shared := net.IPv4(10, 0, 0, 10)
	external := net.IPv4(203, 0, 113, 9)
	gateway := net.IPv4(10, 0, 0, 1)
	a.point.ObserveARP(mac, gateway)
	a.point.ObserveIPv4(mac, shared, external, 63)
	a.point.ObserveIPv4(mac, shared, gateway, 63)
	a.point.ObserveIPv4(other, external, shared, 55)
	b.point.ObserveIPv4(other, shared, external, 64)
	b.health.streamStatus = "disconnected"
	b.health.streamError = "connection lost"
	b.health.quality = &quality.Snapshot{Status: "running", Packets: 1}

	got, err := server.snapshot(true, false)
	if err != nil {
		t.Fatal(err)
	}
	var result inventory
	if err := json.Unmarshal(got.InventoryJson, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Addresses) != 3 || result.Addresses[0].Address != "10.0.0.1" ||
		result.Addresses[1].Address != "10.0.0.10" || result.Addresses[2].Address != "203.0.113.9" {
		t.Fatalf("unexpected addresses: %+v", result.Addresses)
	}
	if len(result.Addresses[0].Sources[0].ARPMACs) != 1 {
		t.Fatal("ARP-only address missing")
	}
	sources := result.Addresses[1].Sources
	if len(sources) != 2 || sources[0].CapturePoint != "a" || sources[1].CapturePoint != "b" ||
		sources[0].Destinations[0].Packets != 2 || sources[0].Destinations[0].TowardUpstream != 1 ||
		sources[1].Destinations[0].Packets != 1 || sources[1].Destinations[0].TowardUpstream != 0 {
		t.Fatalf("bad per-capture evidence: %+v", sources)
	}
	if result.Topology == nil || result.Topology.DistinctAddresses != 3 ||
		len(result.CapturePoints) != 2 || result.CapturePoints[0].Topology.DistinctAddresses != 3 ||
		result.CapturePoints[0].Topology.Packets != 3 || result.CapturePoints[1].Topology.DistinctAddresses != 1 ||
		result.CapturePoints[1].InferenceError == "" || result.CapturePoints[1].StreamStatus != "disconnected" ||
		result.CapturePoints[1].StreamError == "" || result.CapturePoints[1].Capture.Packets != 1 {
		t.Fatalf("bad capture points: %+v", result.CapturePoints)
	}
}

func TestInventoryEmptyAndLateGatewayEvidence(t *testing.T) {
	server := NewServer()
	resp, err := server.snapshot(true, false)
	if err != nil || string(resp.InventoryJson) != `{"addresses":[],"capture_points":[]}` {
		t.Fatalf("empty inventory: %s, %v", resp.InventoryJson, err)
	}
	point, err := server.register(&Registration{CapturePoint: "sensor", MaxHops: 6})
	if err != nil {
		t.Fatal(err)
	}
	mac := net.HardwareAddr{2, 1, 2, 3, 4, 5}
	point.point.ObserveIPv4(mac, net.IPv4(10, 0, 0, 9), net.IPv4(8, 8, 8, 8), 63)
	read := func() inventory {
		t.Helper()
		resp, err := server.snapshot(true, false)
		if err != nil {
			t.Fatal(err)
		}
		var v inventory
		if err := json.Unmarshal(resp.InventoryJson, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := read()
	if before.CapturePoints[0].InferenceError == "" || before.Addresses[0].Sources[0].Destinations[0].TowardUpstream != 0 {
		t.Fatalf("expected unclassified evidence: %+v", before)
	}
	point.point.ObserveARP(mac, net.IPv4(10, 0, 0, 1))
	after := read()
	if after.CapturePoints[0].UpstreamMAC != mac.String() || after.CapturePoints[0].InferenceError != "" ||
		after.Addresses[1].Sources[0].Destinations[0].TowardUpstream != 1 {
		t.Fatalf("late ARP did not classify evidence: %+v", after)
	}
}
