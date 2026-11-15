package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/databeast/goatherd/internal/discovery"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/cobra"
)

func TestStandalonePCAPJSON(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "sample.pcap")
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, TTL: 61, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(203, 0, 113, 1)},
		&layers.UDP{SrcPort: 1000, DstPort: 2000})
	if err != nil {
		t.Fatal(err)
	}
	packet := buffer.Bytes()
	if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: len(packet), Length: len(packet)}, packet); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	command := &cobra.Command{}
	command.SetContext(context.Background())
	var output bytes.Buffer
	command.SetOut(&output)
	command.Flags().String("pcap", filename, "")
	command.Flags().String("interface", "eth0", "")
	command.Flags().String("upstream-mac", "02:00:00:00:00:01", "")
	command.Flags().Uint8("max-hops", 6, "")
	command.Flags().String("format", "json", "")
	command.Flags().Bool("evidence", true, "")
	if err := standaloneMode(command, nil); err != nil {
		t.Fatal(err)
	}
	var report discovery.Report
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Selection != "configured" || report.Overall.Prefix != "10.0.0.1/32" ||
		len(report.Layers) != 1 || *report.Layers[0].Hops != 3 || report.Capture == nil ||
		report.Capture.Status != "completed" || report.Capture.Packets != 1 || report.Capture.IPv4Packets != 1 ||
		report.Capture.Stats != nil || report.Capture.StatsError == "" ||
		len(report.PreviousHops) != 1 || report.PreviousHops[0].MAC != "02:00:00:00:00:02" ||
		report.PreviousHops[0].TowardUpstream == nil {
		t.Fatalf("unexpected report: %+v", report)
	}
	output.Reset()
	if err := command.Flags().Set("format", "text"); err != nil {
		t.Fatal(err)
	}
	if err := standaloneMode(command, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Candidate: 10.0.0.1/32") ||
		!strings.Contains(output.String(), "Estimated prior hops: 3") {
		t.Fatalf("unexpected text report:\n%s", output.String())
	}
	output.Reset()
	if err := command.Flags().Set("format", "jsonld"); err != nil {
		t.Fatal(err)
	}
	if err := standaloneMode(command, nil); err != nil {
		t.Fatal(err)
	}
	var document map[string]interface{}
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document["@type"] != "schema:Dataset" || document["@context"] == nil {
		t.Fatalf("unexpected JSON-LD report: %+v", document)
	}
	output.Reset()
	if err := command.Flags().Set("upstream-mac", ""); err != nil {
		t.Fatal(err)
	}
	if err := command.Flags().Set("format", "json"); err != nil {
		t.Fatal(err)
	}
	if err := standaloneMode(command, nil); err != nil {
		t.Fatal(err)
	}
	var unavailable struct {
		Error    string             `json:"inference_error"`
		Evidence discovery.Evidence `json:"evidence"`
	}
	if err := json.Unmarshal(output.Bytes(), &unavailable); err != nil {
		t.Fatal(err)
	}
	if unavailable.Error == "" || len(unavailable.Evidence.PreviousHops) != 1 ||
		unavailable.Evidence.PreviousHops[0].TowardUpstream != nil {
		t.Fatalf("missing evidence without upstream: %+v", unavailable)
	}
	output.Reset()
	if err := command.Flags().Set("upstream-mac", "02:00:00:00:00:01"); err != nil {
		t.Fatal(err)
	}
	if err := command.Flags().Set("evidence", "false"); err != nil {
		t.Fatal(err)
	}
	if err := standaloneMode(command, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"candidate_prefix": "10.0.0.1/32"`) ||
		strings.Contains(output.String(), `"ttl_counts"`) || strings.Contains(output.String(), `"prefix_topology"`) {
		t.Fatalf("unexpected summary: %s", output.String())
	}
	if err := command.Flags().Set("format", "invalid"); err != nil {
		t.Fatal(err)
	}
	if err := standaloneMode(command, nil); err == nil || !strings.Contains(err.Error(), "unsupported report format") {
		t.Fatalf("expected format error, got %v", err)
	}
}
