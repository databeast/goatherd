package coordination

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/databeast/goatherd/internal/quality"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func reportsTestClient(t *testing.T, service *Server) (CoordinatorClient, context.Context) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	RegisterCoordinatorServer(server, service)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///reports",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return NewCoordinatorClient(conn), ctx
}

func collectReportsStream(t *testing.T, client CoordinatorClient, ctx context.Context, evidence bool) []byte {
	t.Helper()
	stream, err := client.StreamReports(ctx, &ReportsRequest{Evidence: evidence})
	if err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return data.Bytes()
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(chunk.Data) == 0 || len(chunk.Data) > 64*1024 {
			t.Fatalf("invalid chunk size: %d", len(chunk.Data))
		}
		data.Write(chunk.Data)
	}
}

func TestReportsStreamMatchesLocalOutput(t *testing.T) {
	service := NewServer()
	if _, err := service.register(&Registration{CapturePoint: "quiet"}); err != nil {
		t.Fatal(err)
	}
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	point, err := service.register(&Registration{CapturePoint: "observed", UpstreamMac: mac, MaxHops: 6})
	if err != nil {
		t.Fatal(err)
	}
	point.point.ObserveIPv4(mac, net.IPv4(10, 0, 0, 1), net.IPv4(203, 0, 113, 1), 63)
	point.health.quality = &quality.Snapshot{Status: "running", Packets: 1}
	client, ctx := reportsTestClient(t, service)
	var expected bytes.Buffer
	if err := service.WriteReports(&expected, false); err != nil {
		t.Fatal(err)
	}
	if actual := collectReportsStream(t, client, ctx, false); !bytes.Equal(actual, expected.Bytes()) {
		t.Fatalf("stream differs from local output: %s vs %s", actual, expected.Bytes())
	}
	summary := collectReportsStream(t, client, ctx, false)
	evidence := collectReportsStream(t, client, ctx, true)
	if bytes.Contains(summary, []byte(`"ttl_counts"`)) || !bytes.Contains(evidence, []byte(`"ttl_counts"`)) {
		t.Fatal("report summary and full evidence were not separated")
	}
}

func TestEmptyReportsStream(t *testing.T) {
	client, ctx := reportsTestClient(t, NewServer())
	if actual := string(collectReportsStream(t, client, ctx, false)); actual != "[]\n" {
		t.Fatalf("unexpected empty result: %q", actual)
	}
}

type failingReportServerStream struct {
	grpc.ServerStream
	err error
}

func (s *failingReportServerStream) Context() context.Context { return context.Background() }
func (s *failingReportServerStream) Send(*ReportsChunk) error { return s.err }

func TestReportsStreamPropagatesSendFailure(t *testing.T) {
	sentinel := errors.New("send failed")
	err := NewServer().StreamReports(&ReportsRequest{}, &failingReportServerStream{err: sentinel})
	if !errors.Is(err, sentinel) {
		t.Fatalf("send failure ignored: %v", err)
	}
}

func TestReportsStreamExceedsDefaultGRPCLimit(t *testing.T) {
	service := NewServer()
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	point, err := service.register(&Registration{CapturePoint: "large", UpstreamMac: mac, MaxHops: 6})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40000; i++ {
		point.point.ObserveIPv4(mac, net.IPv4(10, 1, byte(i>>8), byte(i)), net.IPv4(203, 0, 113, 1), 63)
	}
	client, ctx := reportsTestClient(t, service)
	data := collectReportsStream(t, client, ctx, true)
	if len(data) <= 4*1024*1024 || !json.Valid(data) {
		t.Fatalf("invalid large report: %d bytes", len(data))
	}
	var reports []struct {
		CapturePoint string `json:"capture_point"`
		Report       struct {
			ForwardedPackets uint64 `json:"forwarded_packets"`
		} `json:"report"`
	}
	if err := json.Unmarshal(data, &reports); err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || reports[0].CapturePoint != "large" || reports[0].Report.ForwardedPackets != 40000 {
		t.Fatalf("incorrect report: %+v", reports)
	}
}
