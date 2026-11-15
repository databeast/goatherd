package reporter

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"

	"github.com/databeast/goatherd/internal/discovery"
	"github.com/databeast/goatherd/internal/quality"
)

func writeQuality(out *bufio.Writer, q quality.Snapshot) {
	fmt.Fprintf(out, "Capture: %s (%s)\nStarted: %s; updated: %s; duration: %d ms\n",
		q.Source, q.Status, q.StartedAt.Format("2006-01-02T15:04:05Z07:00"), q.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"), q.DurationMS)
	fmt.Fprintf(out, "Captured packets: %d; ARP: %d; IPv4: %d\n", q.Packets, q.ARPPackets, q.IPv4Packets)
	if q.Stats == nil {
		fmt.Fprintf(out, "libpcap statistics unavailable: %s\n", q.StatsError)
	} else {
		fmt.Fprintf(out, "libpcap received: %d; dropped: %d; interface dropped: %d\n",
			q.Stats.Received, q.Stats.Dropped, q.Stats.InterfaceDropped)
		if q.StatsNote != "" {
			fmt.Fprintln(out, q.StatsNote)
		}
	}
	if q.CaptureError != "" {
		fmt.Fprintf(out, "Capture error: %s\n", q.CaptureError)
	}
}

// WriteUnavailable writes capture quality when inference cannot produce a report.
func WriteUnavailable(w io.Writer, format string, snapshot quality.Snapshot, reason string) error {
	return WriteUnavailableEvidence(w, format, snapshot, reason, nil)
}

// WriteUnavailableEvidence preserves previous-hop evidence even if inference fails.
func WriteUnavailableEvidence(w io.Writer, format string, snapshot quality.Snapshot, reason string, evidence *discovery.Evidence) error {
	if format == "text" {
		out := bufio.NewWriter(w)
		writeQuality(out, snapshot)
		fmt.Fprintf(out, "Inference unavailable: %s\n", reason)
		if evidence != nil {
			writePreviousHops(out, evidence.PreviousHops, evidence.UnknownPreviousHopPackets)
		}
		return out.Flush()
	}
	if format != "json" && format != "jsonld" {
		return fmt.Errorf("unsupported report format %q", format)
	}
	result := struct {
		Context  map[string]interface{} `json:"@context,omitempty"`
		Type     string                 `json:"@type,omitempty"`
		Capture  quality.Snapshot       `json:"capture"`
		Error    string                 `json:"inference_error"`
		Evidence *discovery.Evidence    `json:"evidence,omitempty"`
	}{Capture: snapshot, Error: reason, Evidence: evidence}
	if format == "jsonld" {
		result.Context = map[string]interface{}{"@vocab": jsonLDVocabulary, "schema": "https://schema.org/"}
		result.Type = "schema:Dataset"
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
