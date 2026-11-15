package coordination_test

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/databeast/goatherd/collector"
	"github.com/databeast/goatherd/internal/coordination"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
)

func TestInventoryOverGRPC(t *testing.T) {
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
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	for _, name := range []string{"a", "b"} {
		stream, err := client.Collect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		sink, err := collector.NewRemoteSink(stream, name, 6, mac)
		if err != nil {
			t.Fatal(err)
		}
		sink.ObserveIPv4Ethernet(net.HardwareAddr{2, 0, 0, 0, 0, 2}, mac, net.IPv4(198, 51, 100, 4), net.IPv4(8, 8, 8, 8), 63)
		if name == "b" {
			for {
				data, err := readInventory(ctx, client)
				if err != nil {
					t.Fatal(err)
				}
				var live struct {
					Addresses []struct {
						Sources []json.RawMessage `json:"sources"`
					} `json:"addresses"`
					CapturePoints []struct {
						CapturePoint string `json:"capture_point"`
						StreamStatus string `json:"stream_status"`
					} `json:"capture_points"`
				}
				if err := json.Unmarshal(data, &live); err != nil {
					t.Fatal(err)
				}
				if len(live.Addresses) == 1 && len(live.Addresses[0].Sources) == 2 &&
					len(live.CapturePoints) == 2 && live.CapturePoints[1].CapturePoint == "b" &&
					live.CapturePoints[1].StreamStatus == "active" {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatalf("live inventory not observed: %v", ctx.Err())
				case <-time.After(5 * time.Millisecond):
				}
			}
		}
		if _, err := sink.Close(); err != nil {
			t.Fatal(err)
		}
	}
	data, err := readInventory(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Addresses []struct {
			Address string `json:"address"`
			Sources []struct {
				CapturePoint string `json:"capture_point"`
			} `json:"sources"`
		} `json:"addresses"`
		CapturePoints []struct {
			PreviousHops []struct {
				MAC string `json:"mac"`
			} `json:"previous_hops"`
		} `json:"capture_points"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Addresses) != 1 || result.Addresses[0].Address != "198.51.100.4" ||
		len(result.Addresses[0].Sources) != 2 || result.Addresses[0].Sources[0].CapturePoint != "a" ||
		result.Addresses[0].Sources[1].CapturePoint != "b" || len(result.CapturePoints) != 2 ||
		len(result.CapturePoints[0].PreviousHops) != 1 || result.CapturePoints[0].PreviousHops[0].MAC != "02:00:00:00:00:02" {
		t.Fatalf("unexpected inventory: %+v", result)
	}
}
