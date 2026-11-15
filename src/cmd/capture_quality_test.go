package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/databeast/goatherd/internal/quality"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/cobra"
)

func TestStandaloneEmptyCaptureReportsQuality(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "empty.pcap")
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	if err := pcapgo.NewWriter(file).WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"json", "jsonld", "text"} {
		t.Run(format, func(t *testing.T) {
			command := &cobra.Command{}
			command.SetContext(context.Background())
			var output bytes.Buffer
			command.SetOut(&output)
			command.Flags().String("pcap", filename, "")
			command.Flags().String("interface", "", "")
			command.Flags().String("upstream-mac", "", "")
			command.Flags().Uint8("max-hops", 6, "")
			command.Flags().String("format", format, "")
			command.Flags().Bool("evidence", false, "")
			if err := standaloneMode(command, nil); err != nil {
				t.Fatal(err)
			}
			if format == "text" {
				if !strings.Contains(output.String(), "Captured packets: 0") || !strings.Contains(output.String(), "Inference unavailable:") {
					t.Fatalf("unexpected text: %s", output.String())
				}
				return
			}
			var document struct {
				Capture quality.Snapshot `json:"capture"`
				Error   string           `json:"inference_error"`
				Type    string           `json:"@type"`
			}
			if err := json.Unmarshal(output.Bytes(), &document); err != nil {
				t.Fatal(err)
			}
			if document.Capture.Status != "completed" || document.Capture.Packets != 0 ||
				document.Capture.Stats != nil || document.Capture.StatsError == "" || document.Error == "" {
				t.Fatalf("unexpected document: %+v", document)
			}
			if format == "jsonld" && document.Type != "schema:Dataset" {
				t.Fatalf("missing JSON-LD type: %+v", document)
			}
		})
	}
}
