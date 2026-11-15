package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/databeast/goatherd/internal/coordination"
	"github.com/spf13/cobra"
)

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write failure") }

func TestWriteCoordinatorReports(t *testing.T) {
	response := &coordination.ReportsResponse{Reports: []*coordination.CaptureReport{
		{CapturePoint: "a", ReportJson: []byte(`{"forwarded_packets":3}`)},
		{CapturePoint: "b", Error: "not ready"},
	}}
	var output bytes.Buffer
	if err := writeCoordinatorReports(&output, response); err != nil {
		t.Fatal(err)
	}
	var decoded []struct {
		CapturePoint string                 `json:"capture_point"`
		Report       map[string]interface{} `json:"report"`
		Error        string                 `json:"error"`
	}
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].CapturePoint != "a" || decoded[0].Report["forwarded_packets"] != float64(3) ||
		decoded[1].CapturePoint != "b" || decoded[1].Error != "not ready" {
		t.Fatalf("unexpected reports: %+v", decoded)
	}
	if err := writeCoordinatorReports(errorWriter{}, response); err == nil {
		t.Fatal("writer error ignored")
	}
	if err := writeCoordinatorReports(&output, &coordination.ReportsResponse{Reports: []*coordination.CaptureReport{{ReportJson: []byte("{")}}}); err == nil {
		t.Fatal("invalid report JSON accepted")
	}
}

func TestCoordinatorCommandRequiredFlags(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("coordinator", "", "")
	tlsFlags(command)
	if _, err := connectCoordinator(command); err == nil || !strings.Contains(err.Error(), "--coordinator") {
		t.Fatalf("missing coordinator: %v", err)
	}

	if err := command.Flags().Set("coordinator", "localhost:8432"); err != nil {
		t.Fatal(err)
	}
	if _, err := connectCoordinator(command); err == nil || !strings.Contains(err.Error(), "--tls-cert") {
		t.Fatalf("missing TLS: %v", err)
	}
}

func TestTLSFlagsRequireCompleteOverride(t *testing.T) {
	command := &cobra.Command{}
	tlsFlags(command)
	if err := command.Flags().Set("tls-cert", "certificate.pem"); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsOptions(command, false); err == nil || !strings.Contains(err.Error(), "must be supplied together") {
		t.Fatalf("partial override: %v", err)
	}
}
