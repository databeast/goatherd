package collector

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLiveCaptureQualityUpdates(t *testing.T) {
	iface := os.Getenv("GOATHERD_TEST_INTERFACE")
	if iface == "" {
		t.Skip("set GOATHERD_TEST_INTERFACE to test live capture with packet-capture privileges")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	sink := &qualitySink{}
	if err := Observe(ctx, "", iface, sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.snapshots) < 4 {
		t.Fatalf("missing periodic live update: %+v", sink.snapshots)
	}
	update := sink.snapshots[len(sink.snapshots)-2]
	final := sink.snapshots[len(sink.snapshots)-1]
	if update.Status != "running" || update.DurationMS < 5000 ||
		final.Status != "completed" || final.DurationMS < 5000 {
		t.Fatalf("unexpected live snapshots: %+v", sink.snapshots)
	}
	if update.Stats == nil || final.Stats == nil {
		t.Fatalf("live pcap stats unavailable: %+v", sink.snapshots)
	}
}
