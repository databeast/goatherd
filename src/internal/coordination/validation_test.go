package coordination

import (
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type testServerStream struct {
	grpc.ServerStream
	messages []*Observation
	readErr  error
	result   *CollectResult
	closeErr error
}

func (s *testServerStream) Recv() (*Observation, error) {
	if len(s.messages) == 0 {
		if s.readErr != nil {
			return nil, s.readErr
		}
		return nil, io.EOF
	}
	message := s.messages[0]
	s.messages = s.messages[1:]
	return message, nil
}

func (s *testServerStream) SendAndClose(result *CollectResult) error {
	s.result = result
	return s.closeErr
}

func TestRegisterValidation(t *testing.T) {
	validMAC := []byte{2, 1, 2, 3, 4, 5}
	for _, tt := range []struct {
		name string
		reg  *Registration
	}{
		{"nil", nil},
		{"empty", &Registration{}},
		{"whitespace", &Registration{CapturePoint: " \t "}},
		{"too-long", &Registration{CapturePoint: strings.Repeat("x", 257)}},
		{"max-hops", &Registration{CapturePoint: "a", MaxHops: 256}},
		{"short-mac", &Registration{CapturePoint: "a", UpstreamMac: []byte{2}}},
		{"multicast-mac", &Registration{CapturePoint: "a", UpstreamMac: []byte{1, 2, 3, 4, 5, 6}}},
		{"zero-mac", &Registration{CapturePoint: "a", UpstreamMac: make([]byte, 6)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewServer().register(tt.reg)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("got %v", err)
			}
		})
	}
	server := NewServer()
	state, err := server.register(&Registration{CapturePoint: strings.Repeat("x", 256), MaxHops: 255, UpstreamMac: validMAC})
	if err != nil {
		t.Fatal(err)
	}
	validMAC[0] = 4
	if state.upstream[0] != 2 {
		t.Fatal("registration did not copy upstream MAC")
	}
	server.nextID = uint64(math.MaxUint32) + 1
	if _, err := server.register(&Registration{CapturePoint: "overflow"}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected exhausted IDs, got %v", err)
	}
}

func TestCollectValidationAndErrors(t *testing.T) {
	registered := func() *Observation {
		return &Observation{Data: &Observation_Registration{Registration: &Registration{CapturePoint: "point"}}}
	}
	for _, tt := range []struct {
		name     string
		messages []*Observation
		code     codes.Code
	}{
		{"empty", nil, codes.InvalidArgument},
		{"first-ipv4", []*Observation{{Data: &Observation_Ipv4{Ipv4: &IPv4{}}}}, codes.InvalidArgument},
		{"second-registration", []*Observation{registered(), registered()}, codes.InvalidArgument},
		{"empty-message", []*Observation{registered(), {}}, codes.InvalidArgument},
		{"arp-ip", []*Observation{registered(), {Data: &Observation_Arp{Arp: &ARP{Mac: make([]byte, 6), Ip: []byte{1}}}}}, codes.InvalidArgument},
		{"ipv4-mac", []*Observation{registered(), {Data: &Observation_Ipv4{Ipv4: &IPv4{DestinationMac: []byte{2}, SourceIp: make([]byte, 4), DestinationIp: make([]byte, 4)}}}}, codes.InvalidArgument},
		{"ipv4-source", []*Observation{registered(), {Data: &Observation_Ipv4{Ipv4: &IPv4{DestinationMac: make([]byte, 6), DestinationIp: make([]byte, 4)}}}}, codes.InvalidArgument},
		{"ipv4-destination", []*Observation{registered(), {Data: &Observation_Ipv4{Ipv4: &IPv4{DestinationMac: make([]byte, 6), SourceIp: make([]byte, 4)}}}}, codes.InvalidArgument},
		{"ipv4-ttl", []*Observation{registered(), {Data: &Observation_Ipv4{Ipv4: &IPv4{DestinationMac: make([]byte, 6), SourceIp: make([]byte, 4), DestinationIp: make([]byte, 4), Ttl: 256}}}}, codes.InvalidArgument},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := NewServer().Collect(&testServerStream{messages: tt.messages})
			if status.Code(err) != tt.code {
				t.Fatalf("got %v, want %v", err, tt.code)
			}
		})
	}
	readErr := status.Error(codes.Canceled, "stream canceled")
	if err := NewServer().Collect(&testServerStream{readErr: readErr}); !errors.Is(err, readErr) {
		t.Fatalf("initial receive error lost: %v", err)
	}
	if err := NewServer().Collect(&testServerStream{messages: []*Observation{registered()}, readErr: readErr}); !errors.Is(err, readErr) {
		t.Fatalf("receive error lost: %v", err)
	}
	closeErr := errors.New("close failed")
	if err := NewServer().Collect(&testServerStream{messages: []*Observation{registered()}, closeErr: closeErr}); !errors.Is(err, closeErr) {
		t.Fatalf("close error lost: %v", err)
	}
}

func TestReportsSortedAndUnavailable(t *testing.T) {
	s := NewServer()
	for _, name := range []string{"z", "a"} {
		if _, err := s.register(&Registration{CapturePoint: name}); err != nil {
			t.Fatal(err)
		}
	}
	result, err := s.Reports(context.Background(), &ReportsRequest{})
	if err != nil || len(result.Reports) != 2 || result.Reports[0].CapturePoint != "a" ||
		result.Reports[1].CapturePoint != "z" || result.Reports[0].Error == "" || len(result.Reports[0].ReportJson) != 0 {
		t.Fatalf("unexpected reports: %+v, %v", result, err)
	}
}
