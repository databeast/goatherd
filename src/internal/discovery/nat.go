package discovery

import (
	"net/netip"
	"sort"
)

type NATEvidence struct {
	EstimatedHops     uint8    `json:"estimated_prior_hops"`
	Packets           uint64   `json:"packets"`
	MajorityPackets   uint64   `json:"baseline_packets"`
	DistinctAddresses int      `json:"distinct_source_addresses"`
	ObservedPrefix    string   `json:"observed_candidate_prefix"`
	Addresses         []string `json:"source_addresses"`
	Bits              []Bit    `json:"address_bit_ttl_counts"`
}

type weightedObservation struct {
	obs   observation
	count uint64
}

// hopLayers groups source observations by estimated hop, then compares each
// subnet-forming layer with deeper evidence contained within that candidate.
func hopLayers(observations []weightedObservation, maxHops uint8) []Layer {
	builders := make(map[uint8]*layerBuilder)
	for _, item := range observations {
		_, hops, ok := estimateTTL(item.obs.ttl, maxHops)
		if !ok {
			continue
		}
		if builders[hops] == nil {
			builders[hops] = &layerBuilder{}
		}
		builders[hops].add(item.obs.source, item.obs.ttl, maxHops, item.count)
	}
	keys := make([]int, 0, len(builders))
	for hops := range builders {
		keys = append(keys, int(hops))
	}
	sort.Ints(keys)
	result := make([]Layer, 0, len(keys))
	for _, h := range keys {
		hop := uint8(h)
		base := builders[hop]
		layer := base.result(&hop)
		prefix := netip.MustParsePrefix(layer.Prefix)
		if len(base.addresses) >= 2 && prefix.Bits() <= 30 {
			buckets := make(map[uint8]*layerBuilder)
			for _, item := range observations {
				_, depth, ok := estimateTTL(item.obs.ttl, maxHops)
				if !ok || !prefix.Contains(netip.AddrFrom4([4]byte{
					byte(item.obs.source >> 24), byte(item.obs.source >> 16), byte(item.obs.source >> 8), byte(item.obs.source),
				})) {
					continue
				}
				if buckets[depth] == nil {
					buckets[depth] = &layerBuilder{}
				}
				buckets[depth].add(item.obs.source, item.obs.ttl, maxHops, item.count)
			}
			majority := true
			for depth, bucket := range buckets {
				if depth != hop && bucket.packets >= base.packets {
					majority = false
				}
			}
			if !majority {
				result = append(result, layer)
				continue
			}
			possible := false
			layer.PossibleNAT = &possible
			for _, d := range keys {
				depth := uint8(d)
				bucket := buckets[depth]
				if depth <= hop || bucket == nil {
					continue
				}
				observed := bucket.result(&depth)
				child := netip.MustParsePrefix(observed.Prefix)
				if len(bucket.addresses) >= 2 && child.Bits() > prefix.Bits() && child.Bits() <= 30 {
					continue
				}
				addresses := make([]uint32, 0, len(bucket.addresses))
				for addr := range bucket.addresses {
					addresses = append(addresses, addr)
				}
				sort.Slice(addresses, func(i, j int) bool { return addresses[i] < addresses[j] })
				evidence := NATEvidence{EstimatedHops: depth, Packets: bucket.packets, MajorityPackets: base.packets,
					DistinctAddresses: len(addresses), ObservedPrefix: observed.Prefix, Addresses: make([]string, 0, len(addresses)),
					Bits: observed.Bits[prefix.Bits():]}
				for _, addr := range addresses {
					evidence.Addresses = append(evidence.Addresses, ipString(addr))
				}
				layer.NATEvidence = append(layer.NATEvidence, evidence)
			}
		}
		if layer.PossibleNAT != nil {
			*layer.PossibleNAT = len(layer.NATEvidence) > 0
		}
		result = append(result, layer)
	}
	return result
}
