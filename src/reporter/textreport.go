package reporter

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/databeast/goatherd/internal/discovery"
)

// WriteText writes the evidence and candidate prefixes in a human-readable form.
func WriteText(w io.Writer, report discovery.Report) error {
	out := bufio.NewWriter(w)
	fmt.Fprintf(out, "Upstream: %s (%s)\n", report.UpstreamMAC, report.Selection)
	if len(report.UpstreamIPs) == 0 {
		fmt.Fprintln(out, "ARP addresses: none observed")
	} else {
		fmt.Fprintf(out, "ARP addresses: %s\n", strings.Join(report.UpstreamIPs, ", "))
	}
	fmt.Fprintf(out, "Forwarded packets: %d\nUnestimated TTL packets: %d\n", report.ForwardedPackets, report.UnknownTTL)
	if len(report.Candidates) > 0 {
		fmt.Fprintln(out, "\nUpstream candidates (forwarded packets):")
		for _, candidate := range report.Candidates {
			fmt.Fprintf(out, "  %s: %d\n", candidate.MAC, candidate.Packets)
		}
	}
	fmt.Fprintln(out, "\nPrefixes are candidates based on observed addresses, not verified routes.")
	writeLayer(out, "Overall", report.Overall)
	for _, layer := range report.Layers {
		label := "Hop estimate unavailable"
		if layer.Hops != nil {
			label = fmt.Sprintf("Estimated prior hops: %d", *layer.Hops)
		}
		writeLayer(out, label, layer)
	}
	return out.Flush()
}

func writeLayer(out *bufio.Writer, label string, layer discovery.Layer) {
	fmt.Fprintf(out, "\n%s\n", label)
	fmt.Fprintf(out, "  Candidate: %s; packets: %d; distinct sources: %d\n", layer.Prefix, layer.Packets, layer.DistinctAddresses)
	fmt.Fprintf(out, "  Reference: %s; XOR variance: %s\n", layer.Reference, layer.VarianceMask)
	fmt.Fprintln(out, "  Prefix tree:")
	writePrefix(out, layer.Topology, "    ")
	fmt.Fprintln(out, "  Bit TTL evidence (bit 0 is most significant):")
	for _, bit := range layer.Bits {
		for _, count := range bit.TTL {
			estimate := "initial unknown, hops unknown"
			if count.Initial != nil && count.Hops != nil {
				estimate = fmt.Sprintf("initial %d, hops %d", *count.Initial, *count.Hops)
			}
			fmt.Fprintf(out, "    bit %d: TTL %d, %s, zero %d, one %d\n",
				bit.Position, count.Observed, estimate, count.Zero, count.One)
		}
	}
}

func writePrefix(out *bufio.Writer, node discovery.PrefixNode, indent string) {
	fmt.Fprintf(out, "%s%s (packets: %d; distinct sources: %d)\n", indent, node.Prefix, node.Packets, node.DistinctAddresses)
	for _, child := range node.Children {
		writePrefix(out, child, indent+"  ")
	}
}
