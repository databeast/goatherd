package collector

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/databeast/goatherd/internal/coordination"
	"github.com/databeast/goatherd/internal/quality"
)

// RemoteSink forwards capture observations to a coordinator stream.
type RemoteSink struct {
	stream coordination.Coordinator_CollectClient
	err    error
}

func NewRemoteSink(stream coordination.Coordinator_CollectClient, name string, maxHops uint8, upstream net.HardwareAddr) (*RemoteSink, error) {
	s := &RemoteSink{stream: stream}
	err := stream.Send(&coordination.Observation{Data: &coordination.Observation_Registration{
		Registration: &coordination.Registration{CapturePoint: name, MaxHops: uint32(maxHops), UpstreamMac: upstream},
	}})
	if err != nil {
		return nil, fmt.Errorf("register capture point: %w", err)
	}
	return s, nil
}

func (s *RemoteSink) ObserveARP(mac net.HardwareAddr, ip net.IP) {
	if s.err == nil {
		s.err = s.stream.Send(&coordination.Observation{Data: &coordination.Observation_Arp{
			Arp: &coordination.ARP{Mac: mac, Ip: ip.To4()},
		}})
	}
}

func (s *RemoteSink) ObserveIPv4(mac net.HardwareAddr, src, dst net.IP, ttl uint8) {
	s.ObserveIPv4Ethernet(nil, mac, src, dst, ttl)
}

func (s *RemoteSink) ObserveIPv4Ethernet(srcMAC, mac net.HardwareAddr, src, dst net.IP, ttl uint8) {
	if s.err == nil {
		s.err = s.stream.Send(&coordination.Observation{Data: &coordination.Observation_Ipv4{
			Ipv4: &coordination.IPv4{SourceMac: srcMAC, DestinationMac: mac, SourceIp: src.To4(), DestinationIp: dst.To4(), Ttl: uint32(ttl)},
		}})
	}
}

func (s *RemoteSink) Err() error { return s.err }

func (s *RemoteSink) ObserveQuality(snapshot quality.Snapshot) {
	if s.err != nil {
		return
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		s.err = fmt.Errorf("encode capture quality: %w", err)
		return
	}
	s.err = s.stream.Send(&coordination.Observation{Data: &coordination.Observation_QualityJson{QualityJson: data}})
}

func (s *RemoteSink) Close() (*coordination.CollectResult, error) {
	result, err := s.stream.CloseAndRecv()
	if err != nil {
		return nil, fmt.Errorf("complete observation stream: %w", err)
	}
	if s.err != nil {
		return nil, fmt.Errorf("send observation: %w", s.err)
	}
	return result, nil
}
