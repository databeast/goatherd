package reporter

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/databeast/goatherd/internal/discovery"
)

func TestNATIndicatorTextAndJSONLD(t *testing.T) {
	a := discovery.New(6)
	up := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	a.ObserveIPv4(up, net.IPv4(10, 0, 0, 1), net.IPv4(8, 8, 8, 8), 64)
	a.ObserveIPv4(up, net.IPv4(10, 0, 0, 2), net.IPv4(8, 8, 8, 8), 64)
	a.ObserveIPv4(up, net.IPv4(10, 0, 0, 1), net.IPv4(8, 8, 8, 8), 63)
	report, err := a.Report(up)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := WriteText(&out, report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "10.0.0.0/30: may contain a NAT gateway") || !strings.Contains(out.String(), "bit 31 TTL 63") {
		t.Fatalf("missing indicator: %s", out.String())
	}
	out.Reset()
	if err := WriteJSONLD(&out, report); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Layers []discovery.Layer `json:"hop_layers"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Layers) != 2 || got.Layers[0].PossibleNAT == nil || !*got.Layers[0].PossibleNAT ||
		len(got.Layers[0].NATEvidence) != 1 {
		t.Fatalf("missing JSON-LD indicator: %+v", got)
	}
}
