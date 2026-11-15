package discovery

import (
	"net"
	"testing"
)

func TestNATCandidateByHopAndAddressBits(t *testing.T) {
	tests := []struct {
		name     string
		base     []string
		deeper   []string
		extra    []string
		want     bool
		assessed bool
	}{
		{"same address deeper", []string{"10.0.0.1", "10.0.0.2"}, []string{"10.0.0.1"}, nil, true, true},
		{"distinct address same candidate", []string{"10.0.0.1", "10.0.0.2"}, []string{"10.0.0.3"}, nil, true, true},
		{"deeper viable child", []string{"10.0.0.1", "10.0.0.18", "10.0.0.19"}, []string{"10.0.0.9", "10.0.0.10"}, nil, false, true},
		{"deeper 31 not viable", []string{"10.0.0.1", "10.0.0.18", "10.0.0.19"}, []string{"10.0.0.2", "10.0.0.3"}, nil, true, true},
		{"ties unassessed", []string{"10.0.0.1", "10.0.0.2"}, []string{"10.0.0.1", "10.0.0.2"}, nil, false, false},
		{"deeper majority unassessed", []string{"10.0.0.1", "10.0.0.2"}, []string{"10.0.0.1", "10.0.0.1", "10.0.0.1"}, nil, false, false},
		{"other depth larger unassessed", []string{"10.0.0.1", "10.0.0.2"}, []string{"10.0.0.1"}, []string{"10.0.0.2", "10.0.0.2", "10.0.0.2"}, false, false},
		{"no subnet evidence", []string{"10.0.0.1"}, []string{"10.0.0.1"}, nil, false, false},
		{"31 prefix unassessed", []string{"10.0.0.2", "10.0.0.3"}, []string{"10.0.0.2"}, nil, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := New(6)
			up := net.HardwareAddr{2, 0, 0, 0, 0, 1}
			previous := net.HardwareAddr{2, 0, 0, 0, 0, 2}
			for _, group := range []struct {
				addresses []string
				ttl       uint8
			}{{tt.base, 64}, {tt.deeper, 63}, {tt.extra, 62}} {
				for _, address := range group.addresses {
					a.ObserveIPv4Ethernet(previous, up, net.ParseIP(address), net.IPv4(8, 8, 8, 8), group.ttl)
				}
			}
			report, err := a.Report(up)
			if err != nil {
				t.Fatal(err)
			}
			layer := report.Layers[0]
			if (layer.PossibleNAT != nil) != tt.assessed || layer.PossibleNAT != nil && *layer.PossibleNAT != tt.want {
				t.Fatalf("unexpected NAT assessment: %+v", layer)
			}
			if len(report.PreviousHops) != 1 || len(report.PreviousHops[0].HopLayers) == 0 {
				t.Fatalf("missing previous-hop layers: %+v", report.PreviousHops)
			}
			prev := report.PreviousHops[0].HopLayers[0]
			if (prev.PossibleNAT != nil) != tt.assessed || prev.PossibleNAT != nil && *prev.PossibleNAT != tt.want {
				t.Fatalf("previous-hop assessment mismatch: %+v", prev)
			}
			if tt.want {
				if len(layer.NATEvidence) != 1 || layer.NATEvidence[0].EstimatedHops != 1 ||
					layer.NATEvidence[0].Packets != uint64(len(tt.deeper)) ||
					layer.NATEvidence[0].MajorityPackets != uint64(len(tt.base)) ||
					len(layer.NATEvidence[0].Bits) != 32-netPrefixBits(t, layer.Prefix) ||
					len(layer.NATEvidence[0].Addresses) != len(tt.deeper) {
					t.Fatalf("incorrect evidence: %+v", layer.NATEvidence)
				}
				last := layer.NATEvidence[0].Bits[len(layer.NATEvidence[0].Bits)-1]
				if last.Position != 31 || len(last.TTL) != 1 || last.TTL[0].Observed != 63 ||
					last.TTL[0].Hops == nil || *last.TTL[0].Hops != 1 ||
					last.TTL[0].Zero+last.TTL[0].One != uint64(len(tt.deeper)) {
					t.Fatalf("incorrect bit evidence: %+v", last)
				}
			}
		})
	}
}

func netPrefixBits(t *testing.T, prefix string) int {
	t.Helper()
	_, network, err := net.ParseCIDR(prefix)
	if err != nil {
		t.Fatal(err)
	}
	ones, _ := network.Mask.Size()
	return ones
}

func TestNATExcludesUnknownTTLAndOtherGateways(t *testing.T) {
	a := New(6)
	up := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	other := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	dst := net.IPv4(8, 8, 8, 8)
	a.ObserveIPv4(up, net.IPv4(10, 0, 0, 1), dst, 64)
	a.ObserveIPv4(up, net.IPv4(10, 0, 0, 2), dst, 64)
	a.ObserveIPv4(up, net.IPv4(10, 0, 0, 1), dst, 17)
	a.ObserveIPv4(other, net.IPv4(10, 0, 0, 1), dst, 63)
	report, err := a.Report(up)
	if err != nil {
		t.Fatal(err)
	}
	if report.UnknownTTL != 1 || len(report.Layers) != 1 || report.Layers[0].PossibleNAT == nil || *report.Layers[0].PossibleNAT {
		t.Fatalf("unknown or unrelated traffic influenced NAT: %+v", report)
	}
}
