package reporter

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"strings"
)

// WriteSummarySVG renders a standalone JSON-LD summary without asserting topology.
func WriteSummarySVG(w io.Writer, input io.Reader) error {
	var doc struct {
		Type           string          `json:"@type"`
		Name           string          `json:"name"`
		Overall        json.RawMessage `json:"overall"`
		Layers         json.RawMessage `json:"hop_layers"`
		InferenceError string          `json:"inference_error"`
		Summary
	}
	decoder := json.NewDecoder(input)
	if err := decoder.Decode(&doc); err != nil {
		return fmt.Errorf("read JSON-LD report: %w", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("read JSON-LD report: unexpected trailing JSON value")
		}
		return fmt.Errorf("read JSON-LD report: %w", err)
	}
	if doc.InferenceError != "" {
		return fmt.Errorf("inference unavailable: %s", doc.InferenceError)
	}
	if doc.Type != "schema:Dataset" || doc.Name != "Goatherd network discovery report" ||
		len(doc.Overall) == 0 || string(doc.Overall) == "null" ||
		len(doc.Layers) == 0 || string(doc.Layers) == "null" {
		return fmt.Errorf("expected a Goatherd JSON-LD summary report with overall and hop_layers")
	}
	// Explicit fields above identify the document; decode them into the summary too.
	if err := json.Unmarshal(doc.Overall, &doc.Summary.Overall); err != nil {
		return fmt.Errorf("invalid overall candidate: %w", err)
	}
	if err := json.Unmarshal(doc.Layers, &doc.Summary.Layers); err != nil {
		return fmt.Errorf("invalid hop layers: %w", err)
	}
	var overallFields map[string]json.RawMessage
	if err := json.Unmarshal(doc.Overall, &overallFields); err != nil {
		return fmt.Errorf("invalid overall candidate: %w", err)
	}
	if _, evidence := overallFields["bits"]; evidence {
		return fmt.Errorf("expected a summary report, not an evidence dump")
	}
	if err := validateSVGCandidate(doc.Summary.Overall); err != nil {
		return err
	}
	for _, layer := range doc.Summary.Layers {
		if err := validateSVGCandidate(layer); err != nil {
			return err
		}
	}
	for _, hop := range doc.PreviousHops {
		if hop.TowardUpstream != nil {
			if err := validateSVGCandidate(*hop.TowardUpstream); err != nil {
				return err
			}
		}
		for _, layer := range hop.HopLayers {
			if err := validateSVGCandidate(layer); err != nil {
				return err
			}
		}
	}

	var body bytes.Buffer
	s := svgLayout{body: &body, y: 42}
	s.text("Goatherd | Candidate address space", "title")
	s.text("Directed evidence graph: overall grouping to hop layers to possible NAT evidence.", "subtitle")
	s.space(12)
	s.text("CAPTURE CONTEXT", "heading")
	if doc.Capture != nil {
		s.text(fmt.Sprintf("Source: %s | status: %s | captured packets: %d", doc.Capture.Source, doc.Capture.Status, doc.Capture.Packets), "normal")
		if doc.Capture.Stats == nil {
			s.text("Capture statistics unavailable: "+doc.Capture.StatsError, "muted")
		} else {
			s.text(fmt.Sprintf("libpcap received: %d | dropped: %d | interface dropped: %d", doc.Capture.Stats.Received, doc.Capture.Stats.Dropped, doc.Capture.Stats.InterfaceDropped), "normal")
			if doc.Capture.StatsNote != "" {
				s.text(doc.Capture.StatsNote, "muted")
			}
		}
		if doc.Capture.CaptureError != "" {
			s.text("Capture error: "+doc.Capture.CaptureError, "warning")
		}
	} else {
		s.text("Capture quality unavailable in this report.", "muted")
	}
	s.text(fmt.Sprintf("Selected upstream MAC: %s (%s) | ARP addresses: %s", doc.UpstreamMAC, doc.Selection, strings.Join(doc.UpstreamIPs, ", ")), "normal")
	s.text(fmt.Sprintf("Forwarded packets: %d | TTL not estimated: %d", doc.ForwardedPackets, doc.UnknownTTL), "normal")
	s.text("Arrows represent report grouping and evidence, not network links or packet paths.", "muted")
	s.space(15)
	s.text("ADDRESS SPACE TOWARD SELECTED UPSTREAM", "heading")
	s.diagram(doc.Summary.Overall, doc.Summary.Layers)
	for _, hop := range doc.PreviousHops {
		if len(hop.HopLayers) == 0 {
			continue
		}
		s.space(10)
		s.text("PREVIOUS ETHERNET HOP: "+hop.MAC, "heading")
		if hop.TowardUpstream != nil {
			s.diagram(*hop.TowardUpstream, hop.HopLayers)
		} else {
			s.diagram(hop.HopLayers[0], hop.HopLayers)
		}
	}
	s.space(8)
	s.text("Ranges are observed-address groupings, not verified subnet boundaries or topology.", "muted")
	s.text("NAT indicators are unconfirmed leads; no signal or no assessment does not prove NAT is absent.", "muted")
	s.text("Previous Ethernet hops may be hosts, bridges, proxies or routers. Group scales differ.", "muted")
	height := s.y + 24
	var svg bytes.Buffer
	fmt.Fprintf(&svg, `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="%d" viewBox="0 0 1200 %d" role="img" aria-labelledby="title desc">`+"\n", height, height)
	svg.WriteString("<title id=\"title\">Goatherd candidate address space</title>\n<desc id=\"desc\">Directed graph of observed groupings, hop layers, and possible NAT evidence; not verified topology.</desc>\n")
	svg.WriteString(`<style>text{font-family:monospace;font-size:14px;fill:#dce7f3}.title{font-size:25px;font-weight:bold;fill:#fff}.subtitle,.muted{fill:#aebfd0}.heading{font-weight:bold;fill:#79c9e8}.warning{fill:#ffd17a;font-weight:bold}.small{font-size:12px;fill:#aebfd0}</style>` + "\n")
	svg.WriteString(`<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#79c9e8"/></marker><marker id="nat-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#ffb54d"/></marker></defs>` + "\n")
	fmt.Fprintf(&svg, `<rect width="1200" height="%d" fill="#101c2a"/>`+"\n", height)
	svg.Write(body.Bytes())
	svg.WriteString("</svg>\n")
	n, err := w.Write(svg.Bytes())
	if err != nil {
		return err
	}
	if n != svg.Len() {
		return io.ErrShortWrite
	}
	return nil
}

func validateSVGCandidate(candidate CandidateSubnet) error {
	ip, subnet, err := net.ParseCIDR(candidate.Prefix)
	if err != nil || ip.To4() == nil {
		return fmt.Errorf("invalid IPv4 candidate prefix %q", candidate.Prefix)
	}
	for _, lead := range candidate.NATLeads {
		for _, address := range lead.Addresses {
			parsed := net.ParseIP(address)
			if parsed == nil || parsed.To4() == nil || !subnet.Contains(parsed) {
				return fmt.Errorf("invalid NAT evidence address %q for candidate %s", address, candidate.Prefix)
			}
		}
	}
	return nil
}

type svgLayout struct {
	body *bytes.Buffer
	y    int
}

func (s *svgLayout) space(n int) { s.y += n }

func (s *svgLayout) text(value, class string) {
	// Monospace text is wrapped to fit the fixed canvas, including long file paths.
	runes := []rune(value)
	for len(runes) > 0 {
		n := len(runes)
		if n > 110 {
			n = 110
			for i := n; i > 50; i-- {
				if runes[i] == ' ' {
					n = i
					break
				}
			}
		}
		fmt.Fprintf(s.body, `<text x="36" y="%d" class="%s">`, s.y, class)
		_ = xml.EscapeText(s.body, []byte(string(runes[:n])))
		s.body.WriteString("</text>\n")
		s.y += 21
		runes = runes[n:]
		if len(runes) > 0 && runes[0] == ' ' {
			runes = runes[1:]
		}
	}
}

func (s *svgLayout) label(x, y int, value, class string) {
	fmt.Fprintf(s.body, `<text x="%d" y="%d" class="%s">`, x, y, class)
	_ = xml.EscapeText(s.body, []byte(value))
	s.body.WriteString("</text>\n")
}

func (s *svgLayout) diagram(overall CandidateSubnet, layers []CandidateSubnet) {
	const overallX, layerX, evidenceX = 36, 402, 790
	const overallW, layerW, evidenceW = 270, 295, 360
	s.text("Overall grouping  →  estimated hop layers  →  possible NAT evidence", "muted")
	top := s.y + 8
	s.label(overallX+16, top-10, "OVERALL", "small")
	s.label(layerX+16, top-10, "HOP LAYER", "small")
	s.label(evidenceX+16, top-10, "NAT LEAD (UNCONFIRMED)", "small")

	type placedLayer struct {
		layer CandidateSubnet
		y     int
	}
	var placed []placedLayer
	y := top
	for _, layer := range layers {
		placed = append(placed, placedLayer{layer: layer, y: y})
		evidenceHeight := 0
		for _, lead := range layer.NATLeads {
			evidenceHeight += 86 + 18*len(wrapSVGText(strings.Join(lead.Addresses, ", "), 38)) + 12
		}
		if evidenceHeight < 110 {
			evidenceHeight = 110
		}
		y += evidenceHeight + 24
	}
	if y < top+110 {
		y = top + 110
	}
	overallY := top + (y-top-110)/2
	for _, item := range placed {
		fmt.Fprintf(s.body, `<path class="group-edge" d="M %d %d H %d V %d H %d" fill="none" stroke="#79c9e8" stroke-width="2" marker-end="url(#arrow)"/>`+"\n",
			overallX+overallW, overallY+55, overallX+overallW+40, item.y+55, layerX)
	}
	s.node(overallX, overallY, overallW, 110, "#53b8db", "Overall candidate", overall)
	if len(layers) == 0 {
		s.label(layerX, top+55, "No hop layers reported", "muted")
	}
	for _, item := range placed {
		layer := item.layer
		depth := "Hop unknown"
		if layer.Hops != nil {
			depth = fmt.Sprintf("Estimated prior hops: %d", *layer.Hops)
		}
		color := "#53b8db"
		if layer.PossibleNAT != nil && *layer.PossibleNAT {
			color = "#ffb54d"
		}
		s.node(layerX, item.y, layerW, 110, color, depth, layer)
		leadY := item.y
		for _, lead := range layer.NATLeads {
			lines := wrapSVGText(strings.Join(lead.Addresses, ", "), 38)
			height := 86 + 18*len(lines)
			fmt.Fprintf(s.body, `<path class="evidence-edge" d="M %d %d H %d V %d H %d" fill="none" stroke="#ffb54d" stroke-width="2" marker-end="url(#nat-arrow)"/>`+"\n",
				layerX+layerW, item.y+55, layerX+layerW+40, leadY+height/2, evidenceX)
			fmt.Fprintf(s.body, `<rect class="nat-evidence-node" x="%d" y="%d" width="%d" height="%d" rx="12" fill="#302b24" stroke="#ffb54d" stroke-width="2"/>`+"\n", evidenceX, leadY, evidenceW, height)
			s.label(evidenceX+16, leadY+25, fmt.Sprintf("Deeper: %d estimated hops", lead.EstimatedHops), "warning")
			s.label(evidenceX+16, leadY+47, fmt.Sprintf("%d packets / %d baseline", lead.Packets, lead.Baseline), "normal")
			s.label(evidenceX+16, leadY+68, "Source addresses:", "small")
			for i, line := range lines {
				s.label(evidenceX+16, leadY+88+18*i, line, "normal")
			}
			leadY += height + 12
		}
	}
	s.y = y + 20
}

func (s *svgLayout) node(x, y, width, height int, color, title string, candidate CandidateSubnet) {
	fmt.Fprintf(s.body, `<rect class="candidate-node" x="%d" y="%d" width="%d" height="%d" rx="12" fill="#1b3042" stroke="%s" stroke-width="2"/>`+"\n", x, y, width, height, color)
	s.label(x+16, y+23, title, "small")
	s.label(x+16, y+47, candidate.Prefix, "normal")
	s.label(x+16, y+69, fmt.Sprintf("%d sources | %d packets", candidate.DistinctAddresses, candidate.Packets), "small")
	status := "NAT: not assessed"
	class := "small"
	if candidate.PossibleNAT != nil {
		status = "NAT: no signal detected"
		if *candidate.PossibleNAT {
			status = "MAY CONTAIN A NAT GATEWAY"
			class = "warning"
		}
	}
	s.label(x+16, y+91, status, class)
}

func wrapSVGText(value string, limit int) []string {
	if value == "" {
		return []string{"(none reported)"}
	}
	var lines []string
	runes := []rune(value)
	for len(runes) > 0 {
		n := len(runes)
		if n > limit {
			n = limit
			for i := n; i > 0; i-- {
				if runes[i] == ' ' {
					n = i
					break
				}
			}
		}
		lines = append(lines, string(runes[:n]))
		runes = runes[n:]
		if len(runes) > 0 && runes[0] == ' ' {
			runes = runes[1:]
		}
	}
	return lines
}
