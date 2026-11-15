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

type reportsTestStream struct {
	grpc.ClientStream
	chunks [][]byte
	err    error
}

func (s *reportsTestStream) Recv() (*coordination.ReportsChunk, error) {
	if len(s.chunks) == 0 {
		if s.err != nil {
			return nil, s.err
		}
		return nil, io.EOF
	}
	data := s.chunks[0]
	s.chunks = s.chunks[1:]
	return &coordination.ReportsChunk{Data: data}, nil
}

type shortReportWriter struct{}

func (shortReportWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }

func TestWriteReportsStream(t *testing.T) {
	var out bytes.Buffer
	if err := writeReportsStream(&out, &reportsTestStream{chunks: [][]byte{[]byte("["), []byte("]\n")}}); err != nil || out.String() != "[]\n" {
		t.Fatalf("unexpected output %q: %v", out.String(), err)
	}
	if err := writeReportsStream(&out, &reportsTestStream{}); err == nil {
		t.Fatal("empty stream accepted")
	}
	if err := writeReportsStream(&out, &reportsTestStream{chunks: [][]byte{nil}}); err == nil {
		t.Fatal("empty chunk accepted")
	}
	sentinel := errors.New("connection failed")
	if err := writeReportsStream(&out, &reportsTestStream{chunks: [][]byte{[]byte("[")}, err: sentinel}); !errors.Is(err, sentinel) {
		t.Fatalf("stream failure ignored: %v", err)
	}
	if err := writeReportsStream(errorWriter{}, &reportsTestStream{chunks: [][]byte{[]byte("[")}}); err == nil || !strings.Contains(err.Error(), "write reports") {
		t.Fatalf("writer failure ignored: %v", err)
	}
	if err := writeReportsStream(shortReportWriter{}, &reportsTestStream{chunks: [][]byte{[]byte("[")}}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write ignored: %v", err)
	}
}
