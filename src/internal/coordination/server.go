package coordination

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/databeast/goatherd/mapper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type captureState struct {
	point    *mapper.LocalCapturePoint
	upstream net.HardwareAddr
}

// Server accepts observations and keeps each capture point's evidence separate.
type Server struct {
	UnimplementedCoordinatorServer
	mu     sync.RWMutex
	mapper *mapper.LocalMapper
	points map[string]captureState
	nextID uint64
}

func NewServer() *Server {
	return &Server{mapper: mapper.NewLocalMapper(), points: make(map[string]captureState)}
}

func (s *Server) register(r *Registration) (captureState, error) {
	if r == nil || strings.TrimSpace(r.CapturePoint) == "" || len(r.CapturePoint) > 256 {
		return captureState{}, status.Error(codes.InvalidArgument, "capture point name is required and must be at most 256 bytes")
	}
	if r.MaxHops > 255 {
		return captureState{}, status.Error(codes.InvalidArgument, "max hops must not exceed 255")
	}
	if len(r.UpstreamMac) != 0 && (len(r.UpstreamMac) != 6 || r.UpstreamMac[0]&1 != 0 || net.HardwareAddr(r.UpstreamMac).String() == "00:00:00:00:00:00") {
		return captureState{}, status.Error(codes.InvalidArgument, "upstream MAC must be a unicast Ethernet address")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.points[r.CapturePoint]; exists {
		return captureState{}, status.Error(codes.AlreadyExists, "capture point already registered")
	}
	if s.nextID > math.MaxUint32 {
		return captureState{}, status.Error(codes.ResourceExhausted, "capture point IDs exhausted")
	}
	point, err := s.mapper.AddCapturePoint(uint32(s.nextID), uint8(r.MaxHops))
	if err != nil {
		return captureState{}, status.Error(codes.Internal, err.Error())
	}
	s.nextID++
	state := captureState{point: point, upstream: append(net.HardwareAddr(nil), r.UpstreamMac...)}
	s.points[r.CapturePoint] = state
	return state, nil
}

func (s *Server) Collect(stream Coordinator_CollectServer) error {
	first, err := stream.Recv()
	if errors.Is(err, io.EOF) {
		return status.Error(codes.InvalidArgument, "first message must register a capture point")
	}
	if err != nil {
		return err
	}
	state, err := s.register(first.GetRegistration())
	if err != nil {
		return err
	}
	var count uint64
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&CollectResult{Observations: count})
		}
		if err != nil {
			return err
		}
		switch data := msg.Data.(type) {
		case *Observation_Arp:
			if data.Arp == nil || len(data.Arp.Mac) != 6 || len(data.Arp.Ip) != 4 {
				return status.Error(codes.InvalidArgument, "ARP requires a six-byte MAC and four-byte IPv4 address")
			}
			state.point.ObserveARP(data.Arp.Mac, data.Arp.Ip)
		case *Observation_Ipv4:
			if data.Ipv4 == nil || len(data.Ipv4.DestinationMac) != 6 || len(data.Ipv4.SourceIp) != 4 ||
				len(data.Ipv4.DestinationIp) != 4 || data.Ipv4.Ttl > 255 {
				return status.Error(codes.InvalidArgument, "invalid IPv4 observation")
			}
			state.point.ObserveIPv4(data.Ipv4.DestinationMac, data.Ipv4.SourceIp, data.Ipv4.DestinationIp, uint8(data.Ipv4.Ttl))
		default:
			return status.Error(codes.InvalidArgument, "expected ARP or IPv4 observation")
		}
		count++
	}
}

func (s *Server) Reports(_ context.Context, _ *ReportsRequest) (*ReportsResponse, error) {
	s.mu.RLock()
	names := make([]string, 0, len(s.points))
	states := make(map[string]captureState, len(s.points))
	for name, point := range s.points {
		names = append(names, name)
		states[name] = point
	}
	s.mu.RUnlock()
	sort.Strings(names)
	response := &ReportsResponse{Reports: make([]*CaptureReport, 0, len(names))}
	for _, name := range names {
		state := states[name]
		entry := &CaptureReport{CapturePoint: name}
		report, err := state.point.Report(state.upstream)
		if err != nil {
			entry.Error = err.Error()
		} else {
			entry.ReportJson, err = json.Marshal(report)
			if err != nil {
				return nil, fmt.Errorf("marshal report for %s: %w", name, err)
			}
		}
		response.Reports = append(response.Reports, entry)
	}
	return response, nil
}
