package coordination

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/databeast/goatherd/internal/discovery"
	"github.com/databeast/goatherd/internal/quality"
	"github.com/databeast/goatherd/mapper"
	"github.com/databeast/goatherd/reporter"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type captureState struct {
	point    *mapper.LocalCapturePoint
	upstream net.HardwareAddr
	health   *captureHealth
}

type captureHealth struct {
	mu           sync.Mutex
	quality      *quality.Snapshot
	streamStatus string
	streamError  string
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
	state := captureState{point: point, upstream: append(net.HardwareAddr(nil), r.UpstreamMac...),
		health: &captureHealth{streamStatus: "active"}}
	s.points[r.CapturePoint] = state
	return state, nil
}

func (s *Server) Collect(stream Coordinator_CollectServer) (result error) {
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
	completed := false
	defer func() {
		state.health.mu.Lock()
		defer state.health.mu.Unlock()
		state.health.streamStatus = "disconnected"
		if completed {
			state.health.streamStatus = "completed"
		} else if result != nil {
			state.health.streamError = result.Error()
		}
	}()
	var count uint64
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			err := stream.SendAndClose(&CollectResult{Observations: count})
			completed = err == nil
			return err
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
				len(data.Ipv4.DestinationIp) != 4 || data.Ipv4.Ttl > 255 ||
				(len(data.Ipv4.SourceMac) != 0 && len(data.Ipv4.SourceMac) != 6) {
				return status.Error(codes.InvalidArgument, "invalid IPv4 observation")
			}
			state.point.ObserveIPv4Ethernet(data.Ipv4.SourceMac, data.Ipv4.DestinationMac, data.Ipv4.SourceIp, data.Ipv4.DestinationIp, uint8(data.Ipv4.Ttl))
		case *Observation_QualityJson:
			var snapshot quality.Snapshot
			if len(data.QualityJson) == 0 || json.Unmarshal(data.QualityJson, &snapshot) != nil ||
				(snapshot.Status != "starting" && snapshot.Status != "running" && snapshot.Status != "completed" && snapshot.Status != "failed") ||
				snapshot.StartedAt.IsZero() || snapshot.UpdatedAt.IsZero() || snapshot.DurationMS < 0 {
				return status.Error(codes.InvalidArgument, "invalid capture quality snapshot")
			}
			state.health.mu.Lock()
			state.health.quality = &snapshot
			state.health.mu.Unlock()
			continue
		default:
			return status.Error(codes.InvalidArgument, "expected ARP or IPv4 observation")
		}
		count++
	}
}

func (s *Server) snapshot(inventoryOnly bool, evidenceDump bool) (*ReportsResponse, error) {
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
	points := make([]inventoryPoint, 0, len(names))
	evidenceByPoint := make(map[string]discovery.Evidence, len(names))
	for _, name := range names {
		state := states[name]
		entry := &CaptureReport{CapturePoint: name}
		point := inventoryPoint{CapturePoint: name}
		state.health.mu.Lock()
		entry.StreamStatus = state.health.streamStatus
		entry.StreamError = state.health.streamError
		point.StreamStatus = state.health.streamStatus
		point.StreamError = state.health.streamError
		if state.health.quality != nil {
			snapshot := *state.health.quality
			point.Capture = &snapshot
			var err error
			entry.QualityJson, err = json.Marshal(state.health.quality)
			if err != nil {
				state.health.mu.Unlock()
				return nil, fmt.Errorf("marshal capture quality for %s: %w", name, err)
			}
		}
		state.health.mu.Unlock()
		var report discovery.Report
		var evidence discovery.Evidence
		var err error
		if inventoryOnly {
			report, evidence, err = state.point.ReportWithEvidence(state.upstream)
		} else {
			report, err = state.point.Report(state.upstream)
		}
		if len(state.upstream) != 0 {
			point.UpstreamMAC = state.upstream.String()
		}
		if err != nil {
			entry.Error = err.Error()
			point.InferenceError = err.Error()
		} else {
			point.UpstreamMAC = report.UpstreamMAC
			point.HopLayers = report.Layers
			if !inventoryOnly {
				if evidenceDump {
					entry.ReportJson, err = json.Marshal(report)
				} else {
					entry.ReportJson, err = json.Marshal(reporter.Summarize(report))
				}
				if err != nil {
					return nil, fmt.Errorf("marshal report for %s: %w", name, err)
				}
			}
		}
		if inventoryOnly {
			point.Topology = evidence.Topology
			point.PreviousHops = evidence.PreviousHops
			point.UnknownPreviousHopPackets = evidence.UnknownPreviousHopPackets
			points = append(points, point)
			evidenceByPoint[name] = evidence
		} else {
			response.Reports = append(response.Reports, entry)
		}
	}
	if inventoryOnly {
		inventory, err := buildInventory(points, evidenceByPoint)
		if err != nil {
			return nil, fmt.Errorf("build inventory: %w", err)
		}
		response.InventoryJson, err = json.Marshal(inventory)
		if err != nil {
			return nil, fmt.Errorf("marshal inventory: %w", err)
		}
	}
	return response, nil
}

// Inventory streams one snapshot in bounded messages so its size is not
// constrained by gRPC's per-message receive limit.
func (s *Server) Inventory(_ *InventoryRequest, stream Coordinator_InventoryServer) error {
	response, err := s.snapshot(true, false)
	if err != nil {
		return err
	}
	const chunkSize = 64 * 1024
	data := response.InventoryJson
	for len(data) > 0 {
		size := min(len(data), chunkSize)
		if err := stream.Send(&InventoryChunk{Data: data[:size]}); err != nil {
			return err
		}
		data = data[size:]
	}
	return nil
}

type reportsChunkWriter struct {
	stream Coordinator_StreamReportsServer
}

func (w reportsChunkWriter) Write(data []byte) (int, error) {
	const chunkSize = 64 * 1024
	written := 0
	for written < len(data) {
		end := min(written+chunkSize, len(data))
		if err := w.stream.Send(&ReportsChunk{Data: data[written:end]}); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

// StreamReports sends the same JSON array as the local report output.
func (s *Server) StreamReports(request *ReportsRequest, stream Coordinator_StreamReportsServer) error {
	response, err := s.snapshot(false, request.GetEvidence())
	if err != nil {
		return err
	}
	if err := WriteReportsJSON(reportsChunkWriter{stream: stream}, response); err != nil {
		return fmt.Errorf("stream reports: %w", err)
	}
	return nil
}

// WriteReports writes the coordinator's current reports without using gRPC.
func (s *Server) WriteReports(w io.Writer, evidenceDump bool) error {
	response, err := s.snapshot(false, evidenceDump)
	if err != nil {
		return err
	}
	return WriteReportsJSON(w, response)
}
