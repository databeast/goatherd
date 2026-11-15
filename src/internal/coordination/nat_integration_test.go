package coordination_test

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/databeast/goatherd/collector"
	"github.com/databeast/goatherd/internal/coordination"
	"github.com/databeast/goatherd/internal/discovery"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
)

func TestNATIndicatorInReportsAndInventory(t *testing.T) {
	serverTLS, clientTLS := testCertificates(t)
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	coordination.RegisterCoordinatorServer(server, coordination.NewServer())
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	conn, err := grpc.NewClient("passthrough:///localhost",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := coordination.NewCoordinatorClient(conn)
	stream, err := client.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	up := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	prev := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	sink, err := collector.NewRemoteSink(stream, "core", 6, up)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		ip  string
		ttl uint8
	}{{"10.0.0.1", 64}, {"10.0.0.2", 64}, {"10.0.0.1", 63}} {
		sink.ObserveIPv4Ethernet(prev, up, net.ParseIP(entry.ip), net.IPv4(8, 8, 8, 8), entry.ttl)
	}
	if _, err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	reports, err := readReports(ctx, client)
	if err != nil || len(reports.Reports) != 1 {
		t.Fatalf("reports: %+v, %v", reports, err)
	}
	var report discovery.Report
	if err := json.Unmarshal(reports.Reports[0].ReportJson, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Layers) != 2 || report.Layers[0].PossibleNAT == nil || !*report.Layers[0].PossibleNAT ||
		len(report.PreviousHops) != 1 || report.PreviousHops[0].HopLayers[0].PossibleNAT == nil ||
		!*report.PreviousHops[0].HopLayers[0].PossibleNAT {
		t.Fatalf("missing report indicator: %+v", report)
	}
	data, err := readInventory(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		CapturePoints []struct {
			HopLayers    []discovery.Layer       `json:"hop_layers"`
			PreviousHops []discovery.PreviousHop `json:"previous_hops"`
		} `json:"capture_points"`
	}
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatal(err)
	}
	if len(inventory.CapturePoints) != 1 || len(inventory.CapturePoints[0].HopLayers) != 2 ||
		inventory.CapturePoints[0].HopLayers[0].PossibleNAT == nil || !*inventory.CapturePoints[0].HopLayers[0].PossibleNAT ||
		len(inventory.CapturePoints[0].PreviousHops) != 1 || inventory.CapturePoints[0].PreviousHops[0].HopLayers[0].PossibleNAT == nil ||
		!*inventory.CapturePoints[0].PreviousHops[0].HopLayers[0].PossibleNAT {
		t.Fatalf("missing inventory indicator: %+v", inventory)
	}
}
