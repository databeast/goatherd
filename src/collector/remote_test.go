package collector

import (
	"errors"
	"net"
	"testing"

	"github.com/databeast/goatherd/internal/coordination"
	"google.golang.org/grpc"
)

type fakeCollectClient struct {
	grpc.ClientStream
	messages []*coordination.Observation
	sendErr  error
	closeErr error
	result   *coordination.CollectResult
}

func (s *fakeCollectClient) Send(message *coordination.Observation) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.messages = append(s.messages, message)
	return nil
}

func (s *fakeCollectClient) CloseAndRecv() (*coordination.CollectResult, error) {
	return s.result, s.closeErr
}

func TestRemoteSinkMessages(t *testing.T) {
	stream := &fakeCollectClient{result: &coordination.CollectResult{Observations: 2}}
	mac := net.HardwareAddr{2, 1, 2, 3, 4, 5}
	sink, err := NewRemoteSink(stream, "recorder", 6, mac)
	if err != nil {
		t.Fatal(err)
	}
	sink.ObserveARP(mac, net.ParseIP("192.0.2.1"))
	sink.ObserveIPv4(mac, net.ParseIP("10.0.0.1"), net.ParseIP("203.0.113.1"), 61)
	result, err := sink.Close()
	if err != nil || result.Observations != 2 || sink.Err() != nil {
		t.Fatalf("close: %v, %v", result, err)
	}
	reg, arp, ip := stream.messages[0].GetRegistration(), stream.messages[1].GetArp(), stream.messages[2].GetIpv4()
	if reg.CapturePoint != "recorder" || reg.MaxHops != 6 || net.HardwareAddr(reg.UpstreamMac).String() != mac.String() {
		t.Fatalf("registration: %+v", reg)
	}
	if !net.IP(arp.Ip).Equal(net.IPv4(192, 0, 2, 1)) || len(arp.Ip) != 4 ||
		!net.IP(ip.SourceIp).Equal(net.IPv4(10, 0, 0, 1)) || len(ip.DestinationMac) != 6 || ip.Ttl != 61 {
		t.Fatalf("observations: %+v, %+v", arp, ip)
	}
}

func TestRemoteSinkErrors(t *testing.T) {
	sendErr := errors.New("send failed")
	if _, err := NewRemoteSink(&fakeCollectClient{sendErr: sendErr}, "point", 6, nil); !errors.Is(err, sendErr) {
		t.Fatalf("registration error: %v", err)
	}
	stream := &fakeCollectClient{result: &coordination.CollectResult{}}
	sink, err := NewRemoteSink(stream, "point", 6, nil)
	if err != nil {
		t.Fatal(err)
	}
	stream.sendErr = sendErr
	sink.ObserveARP(net.HardwareAddr{2, 1, 2, 3, 4, 5}, net.IPv4(192, 0, 2, 1))
	stream.sendErr = nil
	sink.ObserveIPv4(net.HardwareAddr{2, 1, 2, 3, 4, 5}, net.IPv4(10, 0, 0, 1), net.IPv4(8, 8, 8, 8), 64)
	if !errors.Is(sink.Err(), sendErr) || len(stream.messages) != 1 {
		t.Fatalf("send error not retained: %v", sink.Err())
	}
	if _, err := sink.Close(); !errors.Is(err, sendErr) {
		t.Fatalf("send error not returned by close: %v", err)
	}
	closeErr := errors.New("close failed")
	stream.closeErr = closeErr
	if _, err := sink.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("close error lost: %v", err)
	}
}
