package collector

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type recordingSink struct {
	arp int
	ip  int
	err error
}

type ethernetRecordingSink struct {
	recordingSink
	source net.HardwareAddr
	dest   net.HardwareAddr
}

func (s *ethernetRecordingSink) ObserveIPv4Ethernet(src, dst net.HardwareAddr, _, _ net.IP, _ uint8) {
	s.source = append(net.HardwareAddr(nil), src...)
	s.dest = append(net.HardwareAddr(nil), dst...)
	s.ip++
}

func (s *recordingSink) ObserveARP(net.HardwareAddr, net.IP)                 { s.arp++ }
func (s *recordingSink) ObserveIPv4(net.HardwareAddr, net.IP, net.IP, uint8) { s.ip++ }
func (s *recordingSink) Err() error                                          { return s.err }

func makePacket(t *testing.T, data ...gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true}, data...); err != nil {
		t.Fatal(err)
	}

	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestObservePacketPreservesEthernetSource(t *testing.T) {
	src := net.HardwareAddr{2, 1, 2, 3, 4, 5}
	dst := net.HardwareAddr{2, 6, 7, 8, 9, 10}
	packet := makePacket(t, &layers.Ethernet{SrcMAC: src, DstMAC: dst, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, TTL: 63, SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(8, 8, 8, 8)})
	sink := &ethernetRecordingSink{}
	observePacket(sink, packet)
	if sink.ip != 1 || sink.source.String() != src.String() || sink.dest.String() != dst.String() {
		t.Fatalf("wrong Ethernet evidence: %+v", sink)
	}
}

func TestObservePacketValidatesARPSource(t *testing.T) {
	mac := net.HardwareAddr{2, 1, 2, 3, 4, 5}
	sink := &recordingSink{}
	makeARP := func(sender net.HardwareAddr) gopacket.Packet {
		return makePacket(t, &layers.Ethernet{SrcMAC: mac, DstMAC: net.HardwareAddr{2, 6, 7, 8, 9, 10}, EthernetType: layers.EthernetTypeARP},
			&layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4,
				Operation: layers.ARPReply, SourceHwAddress: sender, SourceProtAddress: net.IPv4(192, 0, 2, 1).To4(),
				DstHwAddress: mac, DstProtAddress: net.IPv4(192, 0, 2, 2).To4()})
	}
	observePacket(sink, makeARP(net.HardwareAddr{2, 9, 8, 7, 6, 5}))
	if sink.arp != 0 {
		t.Fatal("forged ARP sender accepted")
	}
	observePacket(sink, makeARP(mac))
	if sink.arp != 1 {
		t.Fatal("valid ARP sender ignored")
	}
	observePacket(sink, gopacket.NewPacket([]byte{0}, layers.LayerTypeIPv4, gopacket.Default))
	if sink.arp != 1 || sink.ip != 0 {
		t.Fatal("non-Ethernet packet accepted")
	}
}

func TestObserveMissingFile(t *testing.T) {
	err := Observe(context.Background(), filepath.Join(t.TempDir(), "missing.pcap"), "", &recordingSink{})
	if err == nil || !strings.Contains(err.Error(), "open capture") {
		t.Fatalf("got %v", err)
	}
}

func TestObservePropagatesSinkError(t *testing.T) {
	sentinel := errors.New("sink failure")
	filename := filepath.Join(t.TempDir(), "sample.pcap")
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	packet := makePacket(t, &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 1, 2, 3, 4, 5},
		DstMAC: net.HardwareAddr{2, 6, 7, 8, 9, 10}, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, TTL: 64, SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(8, 8, 8, 8)})
	data := packet.Data()
	if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: len(data), Length: len(data)}, data); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	err = Observe(context.Background(), filename, "", &recordingSink{err: sentinel})
	if !errors.Is(err, sentinel) {
		t.Fatalf("got %v, want sink failure", err)
	}
}
