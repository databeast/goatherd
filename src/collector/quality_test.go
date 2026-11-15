package collector

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/databeast/goatherd/internal/quality"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type qualitySink struct {
	recordingSink
	snapshots []quality.Snapshot
}

func (s *qualitySink) ObserveQuality(snapshot quality.Snapshot) {
	s.snapshots = append(s.snapshots, snapshot)
}

func TestOfflineCaptureQualityEmptyAndMissing(t *testing.T) {
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
	sink := &qualitySink{}
	if err := Observe(context.Background(), filename, "", sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.snapshots) != 3 {
		t.Fatalf("snapshots: %+v", sink.snapshots)
	}
	final := sink.snapshots[2]
	if sink.snapshots[0].Status != "starting" || sink.snapshots[1].Status != "running" ||
		final.Status != "completed" || final.Packets != 0 || final.Stats != nil ||
		final.StatsError == "" || final.StartedAt.IsZero() || final.UpdatedAt.Before(final.StartedAt) {
		t.Fatalf("unexpected empty capture: %+v", sink.snapshots)
	}
	sink = &qualitySink{}
	if err := Observe(context.Background(), filepath.Join(t.TempDir(), "missing"), "", sink); err == nil {
		t.Fatal("expected missing file error")
	}
	final = sink.snapshots[len(sink.snapshots)-1]
	if final.Status != "failed" || final.CaptureError == "" {
		t.Fatalf("missing capture failure: %+v", final)
	}
}

func TestRemoteQualityMessage(t *testing.T) {
	stream := &fakeCollectClient{}
	sink, err := NewRemoteSink(stream, "point", 6, net.HardwareAddr(nil))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := quality.Snapshot{Status: "running"}
	sink.ObserveQuality(snapshot)
	if len(stream.messages) != 2 || len(stream.messages[1].GetQualityJson()) == 0 {
		t.Fatalf("quality snapshot not sent: %+v", stream.messages)
	}
	sendErr := errors.New("quality send failed")
	stream.sendErr = sendErr
	sink.ObserveQuality(snapshot)
	if !errors.Is(sink.Err(), sendErr) {
		t.Fatalf("quality send error lost: %v", sink.Err())
	}
}
