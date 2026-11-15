package reporter

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/databeast/goatherd/internal/discovery"
)

func TestWriteJSONLDPreservesReportAndTypes(t *testing.T) {
	initial, hops := uint8(64), uint8(3)
	report := discovery.Report{
		UpstreamMAC: "02:00:00:00:00:01", UpstreamIPs: []string{"192.0.2.1"},
		Selection: "observed", Candidates: []discovery.Candidate{{MAC: "02:00:00:00:00:01", Packets: 1<<63 + 1}},
		ForwardedPackets: 1<<63 + 1, UnknownTTL: 1,
		Overall: discovery.Layer{
			Prefix: "10.0.0.0/30", Reference: "10.0.0.1", VarianceMask: "0.0.0.3", Packets: 5,
			Bits: []discovery.Bit{{Position: 31, TTL: []discovery.TTLCount{
				{Observed: 61, Initial: &initial, Hops: &hops, One: 2},
				{Observed: 10, Zero: 1},
			}}},
			Topology: discovery.PrefixNode{Prefix: "10.0.0.0/30",
				Children: []discovery.PrefixNode{{Prefix: "10.0.0.1/32"}}},
		},
		Layers: []discovery.Layer{{Hops: &hops, Bits: []discovery.Bit{}, Topology: discovery.PrefixNode{Prefix: "10.0.0.1/32"}}},
	}
	var output bytes.Buffer
	if err := WriteJSONLD(&output, report); err != nil {
		t.Fatal(err)
	}
	decode := func(data []byte) map[string]interface{} {
		t.Helper()
		var value map[string]interface{}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	ld := decode(output.Bytes())
	context := ld["@context"].(map[string]interface{})
	if ld["@type"] != "schema:Dataset" || context["@vocab"] != jsonLDVocabulary || context["name"] != "schema:name" {
		t.Fatalf("unexpected JSON-LD context: %+v", ld)
	}
	for _, field := range []string{"upstream_arp_ips", "upstream_candidates", "hop_layers", "bits", "ttl_counts", "children"} {
		if context[field].(map[string]interface{})["@container"] != "@list" {
			t.Errorf("%s is not an ordered list", field)
		}
	}
	candidate := ld["upstream_candidates"].([]interface{})[0].(map[string]interface{})
	overall := ld["overall"].(map[string]interface{})
	bit := overall["bits"].([]interface{})[0].(map[string]interface{})
	ttl := bit["ttl_counts"].([]interface{})[0].(map[string]interface{})
	topology := overall["prefix_topology"].(map[string]interface{})
	child := topology["children"].([]interface{})[0].(map[string]interface{})
	for _, pair := range []struct {
		node map[string]interface{}
		kind string
	}{
		{candidate, "goatherd:GatewayCandidate"}, {overall, "goatherd:AddressLayer"},
		{bit, "goatherd:BitObservation"}, {ttl, "goatherd:TTLObservation"},
		{topology, "goatherd:PrefixCandidate"}, {child, "goatherd:PrefixCandidate"},
	} {
		if pair.node["@type"] != pair.kind {
			t.Errorf("type %v, want %s", pair.node["@type"], pair.kind)
		}
	}
	delete(ld, "@context")
	delete(ld, "name")
	var stripTypes func(interface{})
	stripTypes = func(value interface{}) {
		switch v := value.(type) {
		case map[string]interface{}:
			delete(v, "@type")
			for _, child := range v {
				stripTypes(child)
			}
		case []interface{}:
			for _, child := range v {
				stripTypes(child)
			}
		}
	}
	stripTypes(ld)
	ordinary, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if want := decode(ordinary); !reflect.DeepEqual(ld, want) {
		t.Fatalf("JSON-LD evidence differs:\ngot: %#v\nwant: %#v", ld, want)
	}
}

func TestWriteJSONLDPropagatesWriteError(t *testing.T) {
	if err := WriteJSONLD(failingWriter{}, discovery.Report{}); !errors.Is(err, errWrite) {
		t.Fatalf("got %v, want write error", err)
	}
}
