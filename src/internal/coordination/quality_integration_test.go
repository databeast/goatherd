package coordination_test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/databeast/goatherd/collector"
	"github.com/databeast/goatherd/internal/coordination"
	"github.com/databeast/goatherd/internal/quality"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
)

func TestQualityAvailableDuringAndAfterCaptureWithoutInference(t *testing.T) {
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
	sink, err := collector.NewRemoteSink(stream, "quiet", 6, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	snapshot := quality.Snapshot{Status: "running", Source: "eth0", StartedAt: now, UpdatedAt: now,
		Stats: &quality.Stats{Received: 7, Dropped: 2, InterfaceDropped: 1}}
	sink.ObserveQuality(snapshot)
	waitFor := func(status, streamStatus string) {
		t.Helper()
		for {
			reports, err := readReports(ctx, client)
			if err != nil {
				t.Fatal(err)
			}
			if len(reports.Reports) == 1 {
				entry := reports.Reports[0]
				var got quality.Snapshot
				if len(entry.QualityJson) != 0 {
					if err := json.Unmarshal(entry.QualityJson, &got); err != nil {
						t.Fatal(err)
					}
					if got.Status == status && entry.StreamStatus == streamStatus {
						if entry.Error == "" || got.Stats == nil || got.Stats.Dropped != 2 || got.Packets != 0 {
							t.Fatalf("unexpected report: %+v, %+v", entry, got)
						}
						return
					}
				}
			}
			select {
			case <-ctx.Done():
				t.Fatalf("snapshot %s/%s not observed: %v", status, streamStatus, ctx.Err())
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
	waitFor("running", "active")
	snapshot.Status = "completed"
	sink.ObserveQuality(snapshot)
	if _, err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor("completed", "completed")

	filename := filepath.Join(t.TempDir(), "empty.pcap")
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	if err := pcapgo.NewWriter(file).WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	stream, err = client.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	offline, err := collector.NewRemoteSink(stream, "offline", 6, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := collector.Observe(ctx, filename, "", offline); err != nil {
		t.Fatal(err)
	}
	if result, err := offline.Close(); err != nil || result.Observations != 0 {
		t.Fatalf("close empty capture: %+v, %v", result, err)
	}
	reports, err := readReports(ctx, client)
	if err != nil || len(reports.Reports) != 2 {
		t.Fatalf("offline reports: %+v, %v", reports, err)
	}
	entry := reports.Reports[0]
	var got quality.Snapshot
	if err := json.Unmarshal(entry.QualityJson, &got); err != nil {
		t.Fatal(err)
	}
	if entry.CapturePoint != "offline" || got.Status != "completed" || got.Stats != nil ||
		got.StatsError == "" || entry.Error == "" {
		t.Fatalf("offline quality unavailable: %+v, %+v", entry, got)
	}
}
