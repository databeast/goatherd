package reporter

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/databeast/goatherd/internal/discovery"
)

const svgReport = `{
  "@type":"schema:Dataset", "name":"Goatherd network discovery report",
  "capture":{"status":"completed","source":"a<&\".pcap","packets":12,"pcap_stats":null,"pcap_stats_unavailable":"offline"},
  "upstream_mac":"02:00:00:00:00:01","selection":"configured","upstream_arp_ips":[],
  "forwarded_packets":10,"unknown_ttl_packets":2,
  "overall":{"candidate_prefix":"10.0.0.0/24","packets":10,"distinct_source_addresses":2},
  "hop_layers":[
    {"candidate_prefix":"10.0.0.0/24","estimated_prior_hops":0,"packets":9,"distinct_source_addresses":2,
     "may_contain_nat_gateway":true,"nat_evidence":[{"estimated_prior_hops":4,"packets":1,"baseline_packets":9,"source_addresses":["10.0.0.1"]}]},
    {"candidate_prefix":"10.0.0.1/32","estimated_prior_hops":4,"packets":1,"distinct_source_addresses":1,"may_contain_nat_gateway":false}
  ],
  "previous_hops":[{"mac":"02:00:00:00:00:02","overall":{"candidate_prefix":"10.0.0.0/24"},
    "toward_upstream_hop_layers":[{"candidate_prefix":"10.0.0.0/24","estimated_prior_hops":0,"may_contain_nat_gateway":true}]}]
}`

func TestWriteSummarySVG(t *testing.T) {
	var out bytes.Buffer
	if err := WriteSummarySVG(&out, strings.NewReader(svgReport)); err != nil {
		t.Fatal(err)
	}
	content := out.String()
	for _, expected := range []string{
		`xmlns="http://www.w3.org/2000/svg"`, "10.0.0.0/24", "10.0.0.1/32",
		"Estimated prior hops: 4", "MAY CONTAIN A NAT GATEWAY", "1 packets / 9 baseline",
		"10.0.0.1", "02:00:00:00:00:02", "NAT: not assessed", "no signal detected",
		"not verified subnet boundaries", "Capture statistics unavailable: offline", "a&lt;&amp;&#34;.pcap",
		"not network links or packet paths", `class="candidate-node"`,
		`class="group-edge"`, `class="evidence-edge"`, `class="nat-evidence-node"`, `marker-end="url(#arrow)"`,
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("missing %q in SVG:\n%s", expected, content)
		}
	}
	decoder := xml.NewDecoder(strings.NewReader(content))
	for {
		_, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("invalid SVG XML: %v", err)
		}
	}
	if err := WriteSummarySVG(failingWriter{}, strings.NewReader(svgReport)); !errors.Is(err, errWrite) {
		t.Fatalf("writer error: %v", err)
	}
}

func TestSVGGraphRelationships(t *testing.T) {
	var out bytes.Buffer
	if err := WriteSummarySVG(&out, strings.NewReader(svgReport)); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	decoder := xml.NewDecoder(&out)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		element, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		for _, attr := range element.Attr {
			if attr.Name.Local == "class" {
				counts[attr.Value]++
			}
		}
	}
	for class, expected := range map[string]int{
		"candidate-node": 5, "group-edge": 3, "nat-evidence-node": 1, "evidence-edge": 1,
	} {
		if counts[class] != expected {
			t.Errorf("%s: got %d, want %d", class, counts[class], expected)
		}
	}
}

func TestSVGSummaryRoundTrip(t *testing.T) {
	var report bytes.Buffer
	if err := WriteSummary(&report, "jsonld", discovery.Report{
		Overall: discovery.Layer{Prefix: "192.0.2.0/24", Packets: 42, DistinctAddresses: 3},
	}); err != nil {
		t.Fatal(err)
	}
	var svg bytes.Buffer
	if err := WriteSummarySVG(&svg, &report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(svg.String(), "192.0.2.0/24") || !strings.Contains(svg.String(), "42 packets") {
		t.Fatalf("summary data missing: %s", svg.String())
	}
}

func TestWriteSummarySVGRejectsInvalidReports(t *testing.T) {
	for _, input := range []string{
		`{}`,
		`{"@type":"schema:Dataset","inference_error":"no gateway"}`,
		strings.Replace(svgReport, `"candidate_prefix":"10.0.0.0/24"`, `"candidate_prefix":"bad"`, 1),
		strings.Replace(svgReport, `"candidate_prefix":"10.0.0.0/24"`, `"bits":[],"candidate_prefix":"10.0.0.0/24"`, 1),
		svgReport + `{}`,
		`{`,
	} {
		var out bytes.Buffer
		if err := WriteSummarySVG(&out, strings.NewReader(input)); err == nil {
			t.Errorf("accepted invalid report: %s", input)
		}
		if out.Len() != 0 {
			t.Error("invalid report produced output")
		}
	}
}

func TestSVGWrapsLongText(t *testing.T) {
	input := strings.Replace(svgReport, `a<&\".pcap`, strings.Repeat("x", 250), 1)
	var out bytes.Buffer
	if err := WriteSummarySVG(&out, strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), strings.Repeat("x", 110)) || strings.Contains(out.String(), strings.Repeat("x", 111)) {
		t.Fatal("long text was not wrapped")
	}
}
