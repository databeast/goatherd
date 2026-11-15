package collector

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/databeast/goatherd/internal/discovery"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestObservePCAP(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "traffic.pcap")
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	gateway := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	host := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	write := func(layersToWrite ...gopacket.SerializableLayer) {
		t.Helper()
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true}, layersToWrite...); err != nil {
			t.Fatal(err)
		}
		data := buffer.Bytes()
		if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: len(data), Length: len(data)}, data); err != nil {
			t.Fatal(err)
		}
	}
	for _, source := range []net.IP{net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)} {
		write(&layers.Ethernet{SrcMAC: host, DstMAC: gateway, EthernetType: layers.EthernetTypeIPv4},
			&layers.IPv4{Version: 4, TTL: 61, Protocol: layers.IPProtocolUDP, SrcIP: source, DstIP: net.IPv4(203, 0, 113, 1)},
			&layers.UDP{SrcPort: 1000, DstPort: 2000})
	}
	write(&layers.Ethernet{SrcMAC: gateway, DstMAC: host, EthernetType: layers.EthernetTypeARP},
		&layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
			HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPReply,
			SourceHwAddress: gateway, SourceProtAddress: net.IPv4(192, 0, 2, 1).To4(),
			DstHwAddress: host, DstProtAddress: net.IPv4(192, 0, 2, 2).To4()})
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	a := discovery.New(6)
	if err := Observe(context.Background(), filename, "", a); err != nil {
		t.Fatal(err)
	}
	report, err := a.Report(nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.UpstreamMAC != gateway.String() || report.Overall.Prefix != "10.0.0.0/30" ||
		report.ForwardedPackets != 2 || len(report.Layers) != 1 || *report.Layers[0].Hops != 3 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestObserveRejectsNonEthernet(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "raw.pcap")
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	if err := pcapgo.NewWriter(file).WriteFileHeader(65535, layers.LinkTypeRaw); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Observe(context.Background(), filename, "", discovery.New(6)); err == nil {
		t.Fatal("expected unsupported link type error")
	}
}
