package reporter

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/databeast/goatherd/internal/discovery"
	"github.com/databeast/goatherd/internal/quality"
)

type NATLead struct {
	EstimatedHops uint8    `json:"estimated_prior_hops"`
	Packets       uint64   `json:"packets"`
	Baseline      uint64   `json:"baseline_packets"`
	Addresses     []string `json:"source_addresses"`
}

type CandidateSubnet struct {
	Hops              *uint8    `json:"estimated_prior_hops,omitempty"`
	Prefix            string    `json:"candidate_prefix"`
	Packets           uint64    `json:"packets"`
	DistinctAddresses int       `json:"distinct_source_addresses"`
	PossibleNAT       *bool     `json:"may_contain_nat_gateway,omitempty"`
	NATLeads          []NATLead `json:"nat_evidence,omitempty"`
}

type PreviousHopSummary struct {
	MAC             string            `json:"mac"`
	ARPAddressCount int               `json:"arp_address_count"`
	Overall         CandidateSubnet   `json:"overall"`
	TowardUpstream  *CandidateSubnet  `json:"toward_selected_upstream,omitempty"`
	HopLayers       []CandidateSubnet `json:"toward_upstream_hop_layers,omitempty"`
}

type Summary struct {
	Capture                   *quality.Snapshot     `json:"capture,omitempty"`
	UpstreamMAC               string                `json:"upstream_mac"`
	UpstreamIPs               []string              `json:"upstream_arp_ips"`
	Selection                 string                `json:"selection"`
	Candidates                []discovery.Candidate `json:"upstream_candidates"`
	ForwardedPackets          uint64                `json:"forwarded_packets"`
	UnknownTTL                uint64                `json:"unknown_ttl_packets"`
	Overall                   CandidateSubnet       `json:"overall"`
	Layers                    []CandidateSubnet     `json:"hop_layers"`
	PreviousHops              []PreviousHopSummary  `json:"previous_hops,omitempty"`
	UnknownPreviousHopPackets uint64                `json:"unknown_previous_hop_packets"`
}

func summarizeLayer(layer discovery.Layer) CandidateSubnet {
	result := CandidateSubnet{Hops: layer.Hops, Prefix: layer.Prefix, Packets: layer.Packets,
		DistinctAddresses: layer.DistinctAddresses, PossibleNAT: layer.PossibleNAT}
	for _, lead := range layer.NATEvidence {
		result.NATLeads = append(result.NATLeads, NATLead{EstimatedHops: lead.EstimatedHops,
			Packets: lead.Packets, Baseline: lead.MajorityPackets, Addresses: lead.Addresses})
	}
	return result
}

func Summarize(report discovery.Report) Summary {
	result := Summary{Capture: report.Capture, UpstreamMAC: report.UpstreamMAC, UpstreamIPs: report.UpstreamIPs,
		Selection: report.Selection, Candidates: report.Candidates, ForwardedPackets: report.ForwardedPackets,
		UnknownTTL: report.UnknownTTL, UnknownPreviousHopPackets: report.UnknownPreviousHopPackets,
		Overall: summarizeLayer(report.Overall), Layers: make([]CandidateSubnet, 0, len(report.Layers))}
	for _, layer := range report.Layers {
		result.Layers = append(result.Layers, summarizeLayer(layer))
	}
	for _, hop := range report.PreviousHops {
		entry := PreviousHopSummary{MAC: hop.MAC, ARPAddressCount: len(hop.ARPAddresses), Overall: summarizeLayer(hop.Overall)}
		if hop.TowardUpstream != nil {
			layer := summarizeLayer(*hop.TowardUpstream)
			entry.TowardUpstream = &layer
		}
		for _, layer := range hop.HopLayers {
			entry.HopLayers = append(entry.HopLayers, summarizeLayer(layer))
		}
		result.PreviousHops = append(result.PreviousHops, entry)
	}
	return result
}

// WriteSummary writes the operator-facing report without diagnostic bit tables.
func WriteSummary(w io.Writer, format string, report discovery.Report) error {
	summary := Summarize(report)
	if format == "text" {
		out := bufio.NewWriter(w)
		if summary.Capture != nil {
			writeQuality(out, *summary.Capture)
		}
		fmt.Fprintf(out, "Upstream: %s (%s); ARP addresses: %s\n", summary.UpstreamMAC, summary.Selection, strings.Join(summary.UpstreamIPs, ", "))
		fmt.Fprintf(out, "Forwarded packets: %d; unestimated TTL packets: %d\n", summary.ForwardedPackets, summary.UnknownTTL)
		fmt.Fprintln(out, "Candidate prefixes are observed-address groupings, not verified subnet boundaries.")
		fmt.Fprintf(out, "Overall: %s (%d sources; %d packets)\n", summary.Overall.Prefix, summary.Overall.DistinctAddresses, summary.Overall.Packets)
		for _, layer := range report.Layers {
			depth := "unknown"
			if layer.Hops != nil {
				depth = fmt.Sprint(*layer.Hops)
			}
			fmt.Fprintf(out, "Estimated prior hops %s: %s (%d sources; %d packets)\n", depth, layer.Prefix, layer.DistinctAddresses, layer.Packets)
			if layer.PossibleNAT != nil && *layer.PossibleNAT {
				fmt.Fprintf(out, "  May contain a NAT gateway (candidate, not confirmation)\n")
				for _, lead := range layer.NATEvidence {
					fmt.Fprintf(out, "  Depth %d: %d packets versus %d baseline; sources: %s\n", lead.EstimatedHops, lead.Packets, lead.MajorityPackets, strings.Join(lead.Addresses, ", "))
				}
			}
		}
		for _, hop := range summary.PreviousHops {
			fmt.Fprintf(out, "Previous Ethernet hop %s (may be a host): %s (%d sources; %d packets)\n", hop.MAC, hop.Overall.Prefix, hop.Overall.DistinctAddresses, hop.Overall.Packets)
			for _, layer := range hop.HopLayers {
				if layer.PossibleNAT != nil && *layer.PossibleNAT {
					fmt.Fprintf(out, "  %s may contain a NAT gateway\n", layer.Prefix)
					for _, lead := range layer.NATLeads {
						fmt.Fprintf(out, "  Depth %d: %d packets versus %d baseline; sources: %s\n", lead.EstimatedHops, lead.Packets, lead.Baseline, strings.Join(lead.Addresses, ", "))
					}
				}
			}
		}
		return out.Flush()
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	switch format {
	case "json":
		return encoder.Encode(summary)
	case "jsonld":
		return encoder.Encode(struct {
			Context map[string]interface{} `json:"@context"`
			Type    string                 `json:"@type"`
			Name    string                 `json:"name"`
			Summary
		}{Context: map[string]interface{}{"@vocab": jsonLDVocabulary, "schema": "https://schema.org/", "name": "schema:name",
			"upstream_arp_ips":           map[string]string{"@id": "goatherd:upstream_arp_ips", "@container": "@list"},
			"upstream_candidates":        map[string]string{"@id": "goatherd:upstream_candidates", "@container": "@list"},
			"hop_layers":                 map[string]string{"@id": "goatherd:hop_layers", "@container": "@list"},
			"previous_hops":              map[string]string{"@id": "goatherd:previous_hops", "@container": "@list"},
			"toward_upstream_hop_layers": map[string]string{"@id": "goatherd:toward_upstream_hop_layers", "@container": "@list"},
			"nat_evidence":               map[string]string{"@id": "goatherd:nat_evidence", "@container": "@list"},
			"source_addresses":           map[string]string{"@id": "goatherd:source_addresses", "@container": "@list"}},
			Type: "schema:Dataset", Name: "Goatherd network discovery report", Summary: summary})
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
}
