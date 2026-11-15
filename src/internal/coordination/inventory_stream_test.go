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

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestInventoryStreamExceedsDefaultGRPCLimit(t *testing.T) {
	service := NewServer()
	point, err := service.register(&Registration{CapturePoint: "large"})
	if err != nil {
		t.Fatal(err)
	}
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	for i := 0; i < 40000; i++ {
		point.point.ObserveARP(mac, net.IPv4(10, 1, byte(i>>8), byte(i)))
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	RegisterCoordinatorServer(server, service)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	conn, err := grpc.NewClient("passthrough:///inventory",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	stream, err := NewCoordinatorClient(conn).Inventory(ctx, &InventoryRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	chunks := 0
	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(chunk.Data) == 0 || len(chunk.Data) > 64*1024 {
			t.Fatalf("invalid chunk size: %d", len(chunk.Data))
		}
		chunks++
		data.Write(chunk.Data)
	}
	if data.Len() <= 4*1024*1024 || chunks < 2 || !json.Valid(data.Bytes()) {
		t.Fatalf("invalid large inventory: %d bytes in %d chunks", data.Len(), chunks)
	}
}
