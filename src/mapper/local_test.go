package mapper

import (
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/databeast/goatherd/reporter"
)

func TestLocalMapperCapturePoints(t *testing.T) {
	m := NewLocalMapper()
	first, err := m.AddCapturePoint(42, 6)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.AddCapturePoint(43, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddCapturePoint(42, 6); err == nil {
		t.Fatal("duplicate capture point accepted")
	}
	if _, err := m.CapturePoint(44); err == nil {
		t.Fatal("unknown capture point accepted")
	}
	point, err := m.CapturePoint(42)
	if err != nil || point != first {
		t.Fatalf("capture point lookup: %v", err)
	}
	gateway := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	dst := net.ParseIP("203.0.113.1")
	first.ObserveIPv4(gateway, net.ParseIP("10.0.0.1"), dst, 61)
	first.ObserveIPv4(gateway, net.ParseIP("10.0.0.2"), dst, 61)
	second.ObserveIPv4(gateway, net.ParseIP("172.16.0.1"), dst, 61)
	first.ObserveARP(gateway, net.ParseIP("192.0.2.1"))
	if _, err := second.Report(nil); err == nil {
		t.Fatal("ARP evidence leaked across capture points")
	}
	firstReport, err := first.Report(nil)
	if err != nil {
		t.Fatal(err)
	}
	secondReport, err := second.Report(gateway)
	if err != nil {
		t.Fatal(err)
	}
	if firstReport.Overall.Prefix != "10.0.0.0/30" || firstReport.ForwardedPackets != 2 ||
		len(firstReport.Layers) != 1 || *firstReport.Layers[0].Hops != 3 {
		t.Fatalf("unexpected first report: %+v", firstReport)
	}
	if secondReport.Overall.Prefix != "172.16.0.1/32" || secondReport.ForwardedPackets != 1 ||
		secondReport.UnknownTTL != 1 || len(secondReport.Layers) != 0 {
		t.Fatalf("unexpected second report: %+v", secondReport)
	}
	var output strings.Builder
	if err := reporter.WriteJSON(&output, firstReport); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"candidate_prefix": "10.0.0.0/30"`) {
		t.Fatalf("missing prefix in report: %s", output.String())
	}
}

func TestLocalCapturePointConcurrentReportsAndObservations(t *testing.T) {
	m := NewLocalMapper()
	point, err := m.AddCapturePoint(1, 6)
	if err != nil {
		t.Fatal(err)
	}
	gateway := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	point.ObserveIPv4(gateway, net.IPv4(10, 0, 0, 1), net.IPv4(8, 8, 8, 8), 61)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				point.ObserveIPv4(gateway, net.IPv4(10, 0, 0, 1), net.IPv4(8, 8, 8, 8), 61)
				if _, err := point.Report(gateway); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	report, err := point.Report(gateway)
	if err != nil || report.ForwardedPackets != 81 {
		t.Fatalf("concurrent report: packets=%d error=%v", report.ForwardedPackets, err)
	}
	point.ObserveIPv4(gateway, net.IPv4(10, 0, 0, 2), net.IPv4(8, 8, 8, 8), 61)
	if report.Overall.Prefix != "10.0.0.1/32" || report.ForwardedPackets != 81 {
		t.Fatal("previous report changed after subsequent observation")
	}
	next, err := point.Report(gateway)
	if err != nil || next.Overall.Prefix != "10.0.0.0/30" || next.ForwardedPackets != 82 {
		t.Fatalf("updated report: %+v error=%v", next, err)
	}
}
