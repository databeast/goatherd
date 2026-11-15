package cmd

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/databeast/goatherd/internal/coordination"
	"google.golang.org/grpc"
)

type inventoryTestStream struct {
	grpc.ClientStream
	chunks [][]byte
	err    error
}

func (s *inventoryTestStream) Recv() (*coordination.InventoryChunk, error) {
	if len(s.chunks) == 0 {
		if s.err != nil {
			return nil, s.err
		}
		return nil, io.EOF
	}
	data := s.chunks[0]
	s.chunks = s.chunks[1:]
	return &coordination.InventoryChunk{Data: data}, nil
}

func TestWriteInventoryStream(t *testing.T) {
	var out bytes.Buffer
	if err := writeInventoryStream(&out, &inventoryTestStream{chunks: [][]byte{[]byte(`{"a":`), []byte(`1}`)}}); err != nil ||
		out.String() != "{\"a\":1}\n" {
		t.Fatalf("unexpected output %q: %v", out.String(), err)
	}
	if err := writeInventoryStream(&out, &inventoryTestStream{}); err == nil {
		t.Fatal("empty stream accepted")
	}
	if err := writeInventoryStream(&out, &inventoryTestStream{chunks: [][]byte{nil}}); err == nil {
		t.Fatal("empty chunk accepted")
	}
	sentinel := errors.New("connection failed")
	if err := writeInventoryStream(&out, &inventoryTestStream{chunks: [][]byte{[]byte("{")}, err: sentinel}); !errors.Is(err, sentinel) {
		t.Fatalf("stream failure ignored: %v", err)
	}
	if err := writeInventoryStream(errorWriter{}, &inventoryTestStream{chunks: [][]byte{[]byte("{")}}); err == nil || !strings.Contains(err.Error(), "write inventory") {
		t.Fatalf("writer failure ignored: %v", err)
	}
}
