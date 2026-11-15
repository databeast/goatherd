package reporter

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/databeast/goatherd/internal/discovery"
)

var errWrite = errors.New("write failed")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWrite }

func TestWriteText(t *testing.T) {
	initial, hops := uint8(64), uint8(3)
	layer := discovery.Layer{
		Prefix: "10.0.0.0/30", Reference: "10.0.0.1", VarianceMask: "0.0.0.3",
		Packets: 3, DistinctAddresses: 2,
		Topology: discovery.PrefixNode{Prefix: "10.0.0.0/30", Packets: 3, DistinctAddresses: 2,
			Children: []discovery.PrefixNode{{Prefix: "10.0.0.1/32", Packets: 2, DistinctAddresses: 1}}},
		Bits: []discovery.Bit{{Position: 31, TTL: []discovery.TTLCount{
			{Observed: 61, Initial: &initial, Hops: &hops, Zero: 1, One: 2},
			{Observed: 10, Zero: 1},
		}}},
	}
	report := discovery.Report{
		UpstreamMAC: "02:00:00:00:00:01", UpstreamIPs: []string{"192.0.2.1"},
		Selection: "observed", Candidates: []discovery.Candidate{{MAC: "02:00:00:00:00:01", Packets: 3}},
		ForwardedPackets: 3, UnknownTTL: 1, Overall: layer,
		Layers: []discovery.Layer{{Hops: &hops, Prefix: layer.Prefix, Topology: layer.Topology}},
	}
	var output bytes.Buffer
	if err := WriteText(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Upstream: 02:00:00:00:00:01 (observed)", "ARP addresses: 192.0.2.1",
		"Forwarded packets: 3", "Unestimated TTL packets: 1",
		"02:00:00:00:00:01: 3", "not verified routes",
		"Candidate: 10.0.0.0/30; packets: 3; distinct sources: 2",
		"Reference: 10.0.0.1; XOR variance: 0.0.0.3",
		"      10.0.0.1/32 (packets: 2; distinct sources: 1)",
		"bit 31: TTL 61, initial 64, hops 3, zero 1, one 2",
		"bit 31: TTL 10, initial unknown, hops unknown, zero 1, one 0",
		"Estimated prior hops: 3",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("missing %q in:\n%s", expected, output.String())
		}
	}
}

func TestWriteTextNoARPAndWriteError(t *testing.T) {
	var out bytes.Buffer
	if err := WriteText(&out, discovery.Report{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "ARP addresses: none observed") {
		t.Fatal("missing no ARP indicator")
	}
	if strings.Contains(out.String(), "Upstream candidates (forwarded packets):") {
		t.Fatal("candidate heading displayed without candidates")
	}
	if err := WriteText(failingWriter{}, discovery.Report{}); !errors.Is(err, errWrite) {
		t.Fatalf("got %v, want write error", err)
	}
}
