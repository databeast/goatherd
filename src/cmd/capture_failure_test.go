package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/databeast/goatherd/internal/quality"
	"github.com/spf13/cobra"
)

func TestStandaloneCaptureFailureReportsQualityAndError(t *testing.T) {
	command := &cobra.Command{}
	command.SetContext(context.Background())
	var output bytes.Buffer
	command.SetOut(&output)
	command.Flags().String("pcap", filepath.Join(t.TempDir(), "missing"), "")
	command.Flags().String("interface", "", "")
	command.Flags().String("upstream-mac", "", "")
	command.Flags().Uint8("max-hops", 6, "")
	command.Flags().String("format", "json", "")
	command.Flags().Bool("evidence", false, "")
	if err := standaloneMode(command, nil); err == nil {
		t.Fatal("expected capture error")
	}
	var document struct {
		Capture quality.Snapshot `json:"capture"`
		Error   string           `json:"inference_error"`
	}
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.Capture.Status != "failed" || document.Capture.CaptureError == "" || document.Error == "" {
		t.Fatalf("unexpected failure report: %+v", document)
	}
}
