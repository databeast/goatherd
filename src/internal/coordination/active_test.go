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

func TestReportsWhileCollectorIsStreaming(t *testing.T) {
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
	gateway := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	sink, err := collector.NewRemoteSink(stream, "active", 6, gateway)
	if err != nil {
		t.Fatal(err)
	}
	sink.ObserveIPv4(gateway, net.IPv4(10, 0, 0, 1), net.IPv4(203, 0, 113, 1), 61)
	for {
		result, err := readReports(ctx, client)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Reports) == 1 && len(result.Reports[0].ReportJson) != 0 {
			var report discovery.Report
			if err := json.Unmarshal(result.Reports[0].ReportJson, &report); err != nil {
				t.Fatal(err)
			}
			if report.ForwardedPackets != 1 || report.Overall.Prefix != "10.0.0.1/32" {
				t.Fatalf("unexpected active report: %+v", report)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("observation did not appear before stream closed")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if result, err := sink.Close(); err != nil || result.Observations != 1 {
		t.Fatalf("close: %v, %v", result, err)
	}
}
