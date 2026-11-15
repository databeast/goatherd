package collector

import (
	"io"
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

func TestPcapCollectorLoadFileFiltersSYN(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "traffic.pcap")
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for _, ack := range []bool{false, true} {
		packet := makePacket(t,
			&layers.Ethernet{SrcMAC: net.HardwareAddr{2, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{2, 6, 7, 8, 9, 10}, EthernetType: layers.EthernetTypeIPv4},
			&layers.IPv4{Version: 4, Protocol: layers.IPProtocolTCP, TTL: 64, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)},
			&layers.TCP{SrcPort: 1000, DstPort: 80, SYN: true, ACK: ack})
		data := packet.Data()
		if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: len(data), Length: len(data)}, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	collector := NewPcapCollector()
	if err := collector.LoadFile(filename); err != nil {
		t.Fatal(err)
	}
	defer collector.Stop()
	if err := collector.LoadFile(filename); err == nil || !strings.Contains(err.Error(), errMsgExistingPcapSource) {
		t.Fatalf("second source: %v", err)
	}
	source := gopacket.NewPacketSource(collector.pcapdata, collector.pcapdata.LinkType())
	packet, err := source.NextPacket()
	if err != nil {
		t.Fatal(err)
	}
	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || !tcp.SYN || tcp.ACK {
		t.Fatalf("unexpected packet: %v", packet)
	}
	if _, err := source.NextPacket(); err != io.EOF {
		t.Fatalf("expected filtered EOF, got %v", err)
	}
}

func TestPcapCollectorLoadMissingFile(t *testing.T) {
	collector := NewPcapCollector()
	if err := collector.LoadFile(filepath.Join(t.TempDir(), "missing.pcap")); err == nil {
		t.Fatal("missing capture accepted")
	}
}
