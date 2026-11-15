package discovery

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
)

// AddressEvidence describes observations at one capture point, not unique
// packets or proof that the address belongs to the monitored network.
type AddressEvidence struct {
	Address      string             `json:"address"`
	ARPMACs      []string           `json:"arp_macs"`
	Destinations []DestinationCount `json:"destination_macs"`
}

type DestinationCount struct {
	MAC            string `json:"mac"`
	Packets        uint64 `json:"packets"`
	TowardUpstream uint64 `json:"toward_selected_upstream_packets"`
}

type Evidence struct {
	Addresses                 []AddressEvidence `json:"addresses"`
	Topology                  *EvidencePrefix   `json:"candidate_prefix_tree,omitempty"`
	PreviousHops              []PreviousHop     `json:"previous_hops,omitempty"`
	UnknownPreviousHopPackets uint64            `json:"unknown_previous_hop_packets"`
}

type EvidencePrefix struct {
	Prefix            string           `json:"candidate_prefix"`
	Packets           uint64           `json:"ipv4_source_packets"`
	DistinctAddresses int              `json:"distinct_observed_addresses"`
	Children          []EvidencePrefix `json:"children,omitempty"`
}

// AddressPrefix is a grouping of distinct addresses, without packet totals.
type AddressPrefix struct {
	Prefix            string          `json:"candidate_prefix"`
	DistinctAddresses int             `json:"distinct_observed_addresses"`
	Children          []AddressPrefix `json:"children,omitempty"`
}

func addressPrefix(node PrefixNode) AddressPrefix {
	out := AddressPrefix{Prefix: node.Prefix, DistinctAddresses: node.DistinctAddresses}
	for _, child := range node.Children {
		out.Children = append(out.Children, addressPrefix(child))
	}
	return out
}

// AddressPrefixTree groups addresses without assuming the same address at
// different capture points is the same host.
func AddressPrefixTree(addresses []string) (*AddressPrefix, error) {
	unique := make(map[uint32]uint64, len(addresses))
	for _, text := range addresses {
		ip, err := netip.ParseAddr(text)
		if err != nil || !ip.Is4() {
			return nil, fmt.Errorf("invalid IPv4 address %q", text)
		}
		raw := ip.As4()
		unique[binary.BigEndian.Uint32(raw[:])] = 0
	}
	if len(unique) == 0 {
		return nil, nil
	}
	sorted := make([]uint32, 0, len(unique))
	for ip := range unique {
		sorted = append(sorted, ip)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	result := addressPrefix(prefixTree(sorted, unique))
	return &result, nil
}

func evidencePrefix(node PrefixNode) EvidencePrefix {
	out := EvidencePrefix{Prefix: node.Prefix, Packets: node.Packets, DistinctAddresses: node.DistinctAddresses}
	for _, child := range node.Children {
		out.Children = append(out.Children, evidencePrefix(child))
	}
	return out
}

// Evidence returns all accepted source-IP and ARP sender evidence, including
// traffic whose direction cannot be established.
func (a *Analyzer) Evidence(selected string) Evidence {
	type entry struct {
		arp  []string
		macs map[string]*DestinationCount
	}
	entries := make(map[uint32]*entry)
	get := func(addr uint32) *entry {
		if entries[addr] == nil {
			entries[addr] = &entry{macs: make(map[string]*DestinationCount)}
		}
		return entries[addr]
	}
	for mac, ips := range a.arp {
		for ip := range ips {
			e := get(ip)
			e.arp = append(e.arp, mac)
		}
	}
	counts := make(map[uint32]uint64)
	for obs, count := range a.observations {
		e := get(obs.source)
		if e.macs[obs.mac] == nil {
			e.macs[obs.mac] = &DestinationCount{MAC: obs.mac}
		}
		d := e.macs[obs.mac]
		d.Packets += count
		if obs.mac == selected && !a.arp[obs.mac][obs.dest] {
			d.TowardUpstream += count
		}
		counts[obs.source] += count
	}
	addresses := make([]uint32, 0, len(entries))
	for addr := range entries {
		addresses = append(addresses, addr)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i] < addresses[j] })
	result := Evidence{Addresses: make([]AddressEvidence, 0, len(addresses))}
	for _, addr := range addresses {
		e := entries[addr]
		sort.Strings(e.arp)
		item := AddressEvidence{Address: ipString(addr), ARPMACs: e.arp, Destinations: make([]DestinationCount, 0, len(e.macs))}
		if item.ARPMACs == nil {
			item.ARPMACs = []string{}
		}
		for _, d := range e.macs {
			item.Destinations = append(item.Destinations, *d)
		}
		sort.Slice(item.Destinations, func(i, j int) bool { return item.Destinations[i].MAC < item.Destinations[j].MAC })
		result.Addresses = append(result.Addresses, item)
	}
	if len(addresses) > 0 {
		tree := evidencePrefix(prefixTree(addresses, counts))
		result.Topology = &tree
	}
	result.PreviousHops = a.previousHops(selected)
	result.UnknownPreviousHopPackets = a.unknownPreviousHopPackets()
	return result
}
