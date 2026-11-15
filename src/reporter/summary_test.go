package reporter

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/databeast/goatherd/internal/discovery"
	"github.com/databeast/goatherd/internal/quality"
)

func TestSummaryAndEvidenceAreSeparate(t *testing.T) {
	analyzer := discovery.New(6)
	upstream := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	previous := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	for _, row := range []struct {
		ip  string
		ttl uint8
	}{{"10.0.0.1", 64}, {"10.0.0.2", 64}, {"10.0.0.1", 63}} {
		analyzer.ObserveIPv4Ethernet(previous, upstream, net.ParseIP(row.ip), net.IPv4(8, 8, 8, 8), row.ttl)
	}
	report, err := analyzer.Report(upstream)
	if err != nil {
		t.Fatal(err)
	}
	report.Capture = &quality.Snapshot{Status: "completed", Packets: 3}
	for _, format := range []string{"json", "jsonld", "text"} {
		t.Run(format, func(t *testing.T) {
			var out bytes.Buffer
			if err := WriteSummary(&out, format, report); err != nil {
				t.Fatal(err)
			}
			text := out.String()
			if !strings.Contains(text, "10.0.0.0/30") || !strings.Contains(text, "10.0.0.1") ||
				strings.Contains(text, "ttl_counts") || strings.Contains(text, "prefix_topology") ||
				strings.Contains(text, "Bit TTL evidence") {
				t.Fatalf("unexpected report: %s", text)
			}
			if format != "text" {
				var document struct {
					Type    string            `json:"@type"`
					Layers  []CandidateSubnet `json:"hop_layers"`
					Capture quality.Snapshot  `json:"capture"`
				}
				if err := json.Unmarshal(out.Bytes(), &document); err != nil {
					t.Fatal(err)
				}
				if document.Capture.Packets != 3 || len(document.Layers) != 2 || document.Layers[0].PossibleNAT == nil ||
					!*document.Layers[0].PossibleNAT || len(document.Layers[0].NATLeads) != 1 {
					t.Fatalf("missing summary evidence: %+v", document)
				}
				if format == "jsonld" && document.Type != "schema:Dataset" {
					t.Fatalf("missing JSON-LD type: %+v", document)
				}
			}
			if err := WriteSummary(failingWriter{}, format, report); !errors.Is(err, errWrite) {
				t.Fatalf("writer error: %v", err)
			}
		})
	}
	var evidence bytes.Buffer
	if err := WriteJSON(&evidence, report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(evidence.String(), "ttl_counts") || !strings.Contains(evidence.String(), "prefix_topology") {
		t.Fatal("full evidence omitted from dump")
	}
}
