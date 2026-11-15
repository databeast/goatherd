// Package discovery collects passive evidence for downstream IPv4 prefixes.
package discovery

import (
	"encoding/binary"
	"errors"
	"net"
	"sort"

	"github.com/databeast/goatherd/internal/subnets"
)

type observation struct {
	mac    string
	source uint32
	dest   uint32
	ttl    uint8
}

// Analyzer retains aggregated observations so late ARP evidence can change
// the selected gateway without losing earlier packets.
type Analyzer struct {
	arp          map[string]map[uint32]bool
	observations map[observation]uint64
	maxHops      uint8
}

func New(maxHops uint8) *Analyzer {
	return &Analyzer{
		arp:          make(map[string]map[uint32]bool),
		observations: make(map[observation]uint64),
		maxHops:      maxHops,
	}
}

func unicastMAC(mac net.HardwareAddr) bool {
	return len(mac) == 6 && mac[0]&1 == 0 && mac.String() != "00:00:00:00:00:00"
}

func ipv4(ip net.IP) (uint32, bool) {
	addr := ip.To4()
	if addr == nil || addr.IsUnspecified() || addr.IsMulticast() || addr.Equal(net.IPv4bcast) {
		return 0, false
	}
	return binary.BigEndian.Uint32(addr), true
}

// ObserveARP records the sender's advertised IPv4-to-MAC association.
func (a *Analyzer) ObserveARP(mac net.HardwareAddr, ip net.IP) {
	addr, ok := ipv4(ip)
	if !ok || !unicastMAC(mac) {
		return
	}
	key := mac.String()
	if a.arp[key] == nil {
		a.arp[key] = make(map[uint32]bool)
	}
	a.arp[key][addr] = true
}

// ObserveIPv4 records traffic addressed to a unicast Ethernet destination.
func (a *Analyzer) ObserveIPv4(dstMAC net.HardwareAddr, srcIP, dstIP net.IP, ttl uint8) {
	src, srcOK := ipv4(srcIP)
	dst, dstOK := ipv4(dstIP)
	if !unicastMAC(dstMAC) || !srcOK || !dstOK {
		return
	}
	a.observations[observation{dstMAC.String(), src, dst, ttl}]++
}

type TTLCount struct {
	Observed uint8  `json:"observed_ttl"`
	Initial  *uint8 `json:"assumed_initial_ttl"`
	Hops     *uint8 `json:"estimated_prior_hops"`
	Zero     uint64 `json:"zero"`
	One      uint64 `json:"one"`
}

type Bit struct {
	Position int        `json:"position"`
	TTL      []TTLCount `json:"ttl_counts"`
}

type Layer struct {
	Hops              *uint8     `json:"estimated_prior_hops,omitempty"`
	Prefix            string     `json:"candidate_prefix"`
	Reference         string     `json:"reference_address"`
	VarianceMask      string     `json:"variance_mask"`
	Packets           uint64     `json:"packets"`
	DistinctAddresses int        `json:"distinct_source_addresses"`
	Bits              []Bit      `json:"bits"`
	Topology          PrefixNode `json:"prefix_topology"`
}

// PrefixNode is the common-prefix tree of observed source addresses. Nodes
// are candidates, not assertions about configured routes or subnet masks.
type PrefixNode struct {
	Prefix            string       `json:"candidate_prefix"`
	Packets           uint64       `json:"packets"`
	DistinctAddresses int          `json:"distinct_source_addresses"`
	Children          []PrefixNode `json:"children,omitempty"`
}

type Report struct {
	UpstreamMAC      string      `json:"upstream_mac"`
	UpstreamIPs      []string    `json:"upstream_arp_ips"`
	Selection        string      `json:"selection"`
	Candidates       []Candidate `json:"upstream_candidates"`
	ForwardedPackets uint64      `json:"forwarded_packets"`
	UnknownTTL       uint64      `json:"unknown_ttl_packets"`
	Overall          Layer       `json:"overall"`
	Layers           []Layer     `json:"hop_layers"`
}

type Candidate struct {
	MAC     string `json:"mac"`
	Packets uint64 `json:"forwarded_packets"`
}

func ipString(addr uint32) string {
	var ip [4]byte
	binary.BigEndian.PutUint32(ip[:], addr)
	return net.IP(ip[:]).String()
}

// estimateTTL chooses the nearest common initial TTL within maxHops.
func estimateTTL(ttl, maxHops uint8) (initial, hops uint8, ok bool) {
	if ttl == 0 {
		return 0, 0, false
	}
	for _, start := range []uint8{32, 64, 128, 255} {
		if ttl <= start && start-ttl <= maxHops {
			return start, start - ttl, true
		}
	}
	return 0, 0, false
}

type ttlKey struct {
	observed, initial, hops uint8
	estimated               bool
}

type layerBuilder struct {
	reference uint32
	variance  uint32
	packets   uint64
	addresses map[uint32]uint64
	counts    [32]map[ttlKey]*TTLCount
}

func (b *layerBuilder) add(addr uint32, ttl, maxHops uint8, count uint64) {
	if b.addresses == nil {
		b.addresses = make(map[uint32]uint64)
		b.reference = addr
	}
	b.addresses[addr] += count
	b.variance |= b.reference ^ addr
	b.packets += count
	initial, hops, ok := estimateTTL(ttl, maxHops)
	key := ttlKey{ttl, initial, hops, ok}
	for i := 0; i < 32; i++ {
		if b.counts[i] == nil {
			b.counts[i] = make(map[ttlKey]*TTLCount)
		}
		entry := b.counts[i][key]
		if entry == nil {
			entry = &TTLCount{Observed: ttl}
			if ok {
				initialValue, hopValue := initial, hops
				entry.Initial, entry.Hops = &initialValue, &hopValue
			}
			b.counts[i][key] = entry
		}
		if addr&(uint32(1)<<uint(31-i)) == 0 {
			entry.Zero += count
		} else {
			entry.One += count
		}
	}
}

func (b *layerBuilder) result(hops *uint8) Layer {
	prefix := subnets.FromVariance(b.reference, b.variance)
	layer := Layer{
		Hops: hops, Prefix: prefix.String(),
		Reference: ipString(b.reference), VarianceMask: ipString(b.variance),
		Packets: b.packets, DistinctAddresses: len(b.addresses), Bits: make([]Bit, 32),
	}
	addresses := make([]uint32, 0, len(b.addresses))
	for addr := range b.addresses {
		addresses = append(addresses, addr)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i] < addresses[j] })
	layer.Topology = prefixTree(addresses, b.addresses)
	for i := range b.counts {
		layer.Bits[i].Position = i
		layer.Bits[i].TTL = make([]TTLCount, 0, len(b.counts[i]))
		for _, count := range b.counts[i] {
			layer.Bits[i].TTL = append(layer.Bits[i].TTL, *count)
		}
		sort.Slice(layer.Bits[i].TTL, func(x, y int) bool {
			a, c := layer.Bits[i].TTL[x], layer.Bits[i].TTL[y]
			if a.Hops == nil || c.Hops == nil {
				if a.Hops == nil && c.Hops != nil {
					return false
				}
				if a.Hops != nil && c.Hops == nil {
					return true
				}
				return a.Observed < c.Observed
			}
			if *a.Hops != *c.Hops {
				return *a.Hops < *c.Hops
			}
			if *a.Initial != *c.Initial {
				return *a.Initial < *c.Initial
			}
			return a.Observed < c.Observed
		})
	}
	return layer
}

func prefixTree(addresses []uint32, counts map[uint32]uint64) PrefixNode {
	prefix := subnets.FromVariance(addresses[0], addresses[0]^addresses[len(addresses)-1])
	node := PrefixNode{
		Prefix:            prefix.String(),
		DistinctAddresses: len(addresses),
	}
	for _, addr := range addresses {
		node.Packets += counts[addr]
	}
	if prefix.Mask != ^uint32(0) {
		bit := ^prefix.Mask - (^prefix.Mask >> 1)
		split := sort.Search(len(addresses), func(i int) bool { return addresses[i]&bit != 0 })
		node.Children = []PrefixNode{
			prefixTree(addresses[:split], counts),
			prefixTree(addresses[split:], counts),
		}
	}
	return node
}

// Report selects the MAC with the largest volume of ARP-confirmed forwarded
// traffic, or uses an explicitly supplied upstream MAC.
func (a *Analyzer) Report(override net.HardwareAddr) (Report, error) {
	scores := make(map[string]uint64)
	for obs, count := range a.observations {
		if len(a.arp[obs.mac]) > 0 && !a.arp[obs.mac][obs.dest] {
			scores[obs.mac] += count
		}
	}
	mac, selection := "", "observed"
	if override != nil {
		if !unicastMAC(override) {
			return Report{}, errors.New("upstream MAC must be a unicast Ethernet address")
		}
		mac, selection = override.String(), "configured"
	} else {
		var highest uint64
		tied := false
		for candidate, count := range scores {
			if count > highest {
				mac, highest, tied = candidate, count, false
			} else if count == highest {
				tied = true
			}
		}
		if highest == 0 {
			return Report{}, errors.New("no upstream candidate: capture ARP traffic or specify --upstream-mac")
		}
		if tied {
			return Report{}, errors.New("upstream candidates are tied; specify --upstream-mac")
		}
	}

	report := Report{UpstreamMAC: mac, Selection: selection, UpstreamIPs: []string{}, Layers: []Layer{}, Candidates: []Candidate{}}
	for candidate, count := range scores {
		report.Candidates = append(report.Candidates, Candidate{MAC: candidate, Packets: count})
	}
	sort.Slice(report.Candidates, func(i, j int) bool {
		if report.Candidates[i].Packets != report.Candidates[j].Packets {
			return report.Candidates[i].Packets > report.Candidates[j].Packets
		}
		return report.Candidates[i].MAC < report.Candidates[j].MAC
	})
	for ip := range a.arp[mac] {
		report.UpstreamIPs = append(report.UpstreamIPs, ipString(ip))
	}
	sort.Strings(report.UpstreamIPs)
	var all layerBuilder
	layers := make(map[uint8]*layerBuilder)
	// Sorting makes the chosen reference address reproducible.
	observations := make([]observation, 0, len(a.observations))
	for obs := range a.observations {
		if obs.mac == mac && !a.arp[mac][obs.dest] {
			observations = append(observations, obs)
		}
	}
	sort.Slice(observations, func(i, j int) bool {
		a, b := observations[i], observations[j]
		if a.source != b.source {
			return a.source < b.source
		}
		if a.dest != b.dest {
			return a.dest < b.dest
		}
		return a.ttl < b.ttl
	})
	for _, obs := range observations {
		count := a.observations[obs]
		report.ForwardedPackets += count
		all.add(obs.source, obs.ttl, a.maxHops, count)
		_, hops, ok := estimateTTL(obs.ttl, a.maxHops)
		if !ok {
			report.UnknownTTL += count
			continue
		}
		if layers[hops] == nil {
			layers[hops] = &layerBuilder{}
		}
		layers[hops].add(obs.source, obs.ttl, a.maxHops, count)
	}
	if all.packets == 0 {
		return Report{}, errors.New("no forwarded IPv4 packets observed for upstream MAC")
	}
	report.Overall = all.result(nil)
	hopValues := make([]int, 0, len(layers))
	for hop := range layers {
		hopValues = append(hopValues, int(hop))
	}
	sort.Ints(hopValues)
	for _, h := range hopValues {
		hop := uint8(h)
		report.Layers = append(report.Layers, layers[hop].result(&hop))
	}
	return report, nil
}
