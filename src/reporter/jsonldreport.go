package reporter

import (
	"encoding/json"
	"io"

	"github.com/databeast/goatherd/internal/discovery"
)

// The project namespace identifies goatherd terms; it is not a hosted context.
const jsonLDVocabulary = "https://github.com/databeast/goatherd#"

type jsonLDCandidate struct {
	Type string `json:"@type"`
	discovery.Candidate
}

type jsonLDTTLCount struct {
	Type string `json:"@type"`
	discovery.TTLCount
}

type jsonLDBit struct {
	Type     string           `json:"@type"`
	Position int              `json:"position"`
	TTL      []jsonLDTTLCount `json:"ttl_counts"`
}

type jsonLDPrefix struct {
	Type              string         `json:"@type"`
	Prefix            string         `json:"candidate_prefix"`
	Packets           uint64         `json:"packets"`
	DistinctAddresses int            `json:"distinct_source_addresses"`
	Children          []jsonLDPrefix `json:"children,omitempty"`
}

type jsonLDLayer struct {
	discovery.Layer
	Type     string       `json:"@type"`
	Bits     []jsonLDBit  `json:"bits"`
	Topology jsonLDPrefix `json:"prefix_topology"`
}

type jsonLDReport struct {
	discovery.Report
	Context    map[string]interface{} `json:"@context"`
	Type       string                 `json:"@type"`
	Name       string                 `json:"name"`
	Candidates []jsonLDCandidate      `json:"upstream_candidates"`
	Overall    jsonLDLayer            `json:"overall"`
	Layers     []jsonLDLayer          `json:"hop_layers"`
}

func ldPrefix(node discovery.PrefixNode) jsonLDPrefix {
	result := jsonLDPrefix{
		Type: "goatherd:PrefixCandidate", Prefix: node.Prefix,
		Packets: node.Packets, DistinctAddresses: node.DistinctAddresses,
	}
	for _, child := range node.Children {
		result.Children = append(result.Children, ldPrefix(child))
	}
	return result
}

func ldLayer(layer discovery.Layer) jsonLDLayer {
	result := jsonLDLayer{Layer: layer, Type: "goatherd:AddressLayer", Topology: ldPrefix(layer.Topology)}
	if layer.Bits != nil {
		result.Bits = make([]jsonLDBit, 0, len(layer.Bits))
	}
	for _, bit := range layer.Bits {
		entry := jsonLDBit{Type: "goatherd:BitObservation", Position: bit.Position}
		if bit.TTL != nil {
			entry.TTL = make([]jsonLDTTLCount, 0, len(bit.TTL))
		}
		for _, count := range bit.TTL {
			entry.TTL = append(entry.TTL, jsonLDTTLCount{Type: "goatherd:TTLObservation", TTLCount: count})
		}
		result.Bits = append(result.Bits, entry)
	}
	return result
}

// WriteJSONLD writes the same discovery evidence with an inline JSON-LD context.
func WriteJSONLD(w io.Writer, report discovery.Report) error {
	context := map[string]interface{}{
		"@vocab":   jsonLDVocabulary,
		"schema":   "https://schema.org/",
		"goatherd": jsonLDVocabulary,
		"name":     "schema:name",
	}
	for _, term := range []string{"upstream_arp_ips", "upstream_candidates", "hop_layers", "bits", "ttl_counts", "children"} {
		context[term] = map[string]string{"@id": "goatherd:" + term, "@container": "@list"}
	}
	result := jsonLDReport{
		Report: report, Context: context, Type: "schema:Dataset",
		Name: "Goatherd network discovery report", Overall: ldLayer(report.Overall),
	}
	if report.Candidates != nil {
		result.Candidates = make([]jsonLDCandidate, 0, len(report.Candidates))
	}
	for _, candidate := range report.Candidates {
		result.Candidates = append(result.Candidates, jsonLDCandidate{Type: "goatherd:GatewayCandidate", Candidate: candidate})
	}
	if report.Layers != nil {
		result.Layers = make([]jsonLDLayer, 0, len(report.Layers))
	}
	for _, layer := range report.Layers {
		result.Layers = append(result.Layers, ldLayer(layer))
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
