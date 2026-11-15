package reporter

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/databeast/goatherd/internal/discovery"
	"github.com/databeast/goatherd/internal/quality"
)

func TestQualityReports(t *testing.T) {
	snapshot := quality.Snapshot{Status: "running", Source: "eth0", Packets: 8,
		Stats: &quality.Stats{Received: 10, Dropped: 2}, StatsNote: "zero may mean unavailable"}
	report := discovery.Report{Capture: &snapshot}
	var output bytes.Buffer
	if err := WriteJSONLD(&output, report); err != nil {
		t.Fatal(err)
	}
	var document struct {
		Capture quality.Snapshot `json:"capture"`
	}
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.Capture.Stats == nil || document.Capture.Stats.Dropped != 2 || document.Capture.StatsNote == "" {
		t.Fatalf("JSON-LD quality: %+v", document.Capture)
	}
	output.Reset()
	if err := WriteText(&output, report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Captured packets: 8") ||
		!strings.Contains(output.String(), "dropped: 2") ||
		!strings.Contains(output.String(), "zero may mean unavailable") {
		t.Fatalf("text quality: %s", output.String())
	}
	for _, format := range []string{"json", "jsonld", "text"} {
		if err := WriteUnavailable(failingWriter{}, format, snapshot, "no gateway"); !errors.Is(err, errWrite) {
			t.Errorf("%s writer error: %v", format, err)
		}
	}
}
