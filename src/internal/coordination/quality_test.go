package coordination

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/databeast/goatherd/internal/quality"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestQualitySurvivesStreamDisconnect(t *testing.T) {
	now := time.Now().UTC()
	snapshot := quality.Snapshot{Status: "running", Source: "eth0", StartedAt: now, UpdatedAt: now,
		Packets: 4, StatsError: "unavailable"}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	stream := &testServerStream{messages: []*Observation{
		{Data: &Observation_Registration{Registration: &Registration{CapturePoint: "quiet"}}},
		{Data: &Observation_QualityJson{QualityJson: data}},
	}, readErr: status.Error(codes.Unavailable, "lost connection")}
	server := NewServer()
	if err := server.Collect(stream); status.Code(err) != codes.Unavailable {
		t.Fatalf("unexpected stream error: %v", err)
	}
	report, err := server.snapshot(false, false)
	if err != nil || len(report.Reports) != 1 {
		t.Fatalf("reports: %+v %v", report, err)
	}
	entry := report.Reports[0]
	var got quality.Snapshot
	if err := json.Unmarshal(entry.QualityJson, &got); err != nil {
		t.Fatal(err)
	}
	if entry.StreamStatus != "disconnected" || entry.StreamError == "" || entry.Error == "" || got.Status != "running" || got.Packets != 4 {
		t.Fatalf("unexpected disconnected capture: %+v, %+v", entry, got)
	}
}

func TestQualityRejectsMalformedSnapshot(t *testing.T) {
	stream := &testServerStream{messages: []*Observation{
		{Data: &Observation_Registration{Registration: &Registration{CapturePoint: "bad"}}},
		{Data: &Observation_QualityJson{QualityJson: []byte(`{"status":"running"}`)}},
	}}
	if err := NewServer().Collect(stream); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid snapshot accepted: %v", err)
	}
}
