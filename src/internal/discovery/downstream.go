package discovery

import "sort"

// PreviousHop is an Ethernet sender observed at one capture point. It may be
// a router, a directly attached host, or another type of forwarding device.
type PreviousHop struct {
	MAC            string      `json:"mac"`
	ARPAddresses   []string    `json:"arp_addresses"`
	Sources        []HopSource `json:"sources"`
	Overall        Layer       `json:"overall"`
	TowardUpstream *Layer      `json:"toward_selected_upstream,omitempty"`
	HopLayers      []Layer     `json:"toward_upstream_hop_layers,omitempty"`
}

type HopSource struct {
	Address        string `json:"address"`
	Packets        uint64 `json:"packets"`
	TowardUpstream uint64 `json:"toward_selected_upstream_packets"`
	ARPSenderMatch bool   `json:"arp_sender_matches_previous_hop"`
}

func (a *Analyzer) unknownPreviousHopPackets() uint64 {
	var count uint64
	for obs, packets := range a.observations {
		if obs.srcMAC == "" {
			count += packets
		}
	}
	return count
}

func (a *Analyzer) previousHops(selected string) []PreviousHop {
	type group struct {
		all          layerBuilder
		upstream     layerBuilder
		sources      map[uint32]*HopSource
		observations []weightedObservation
	}
	groups := make(map[string]*group)
	// layerBuilder's reference is order-sensitive; sort for stable output.
	observations := make([]observation, 0, len(a.observations))
	for obs := range a.observations {
		if obs.srcMAC != "" {
			observations = append(observations, obs)
		}
	}
	sort.Slice(observations, func(i, j int) bool {
		a, b := observations[i], observations[j]
		if a.srcMAC != b.srcMAC {
			return a.srcMAC < b.srcMAC
		}
		if a.source != b.source {
			return a.source < b.source
		}
		if a.dest != b.dest {
			return a.dest < b.dest
		}
		if a.mac != b.mac {
			return a.mac < b.mac
		}
		return a.ttl < b.ttl
	})
	for _, obs := range observations {
		g := groups[obs.srcMAC]
		if g == nil {
			g = &group{sources: make(map[uint32]*HopSource)}
			groups[obs.srcMAC] = g
		}
		count := a.observations[obs]
		g.all.add(obs.source, obs.ttl, a.maxHops, count)
		source := g.sources[obs.source]
		if source == nil {
			source = &HopSource{Address: ipString(obs.source), ARPSenderMatch: a.arp[obs.srcMAC][obs.source]}
			g.sources[obs.source] = source
		}
		source.Packets += count
		if selected != "" && obs.mac == selected && !a.arp[selected][obs.dest] {
			source.TowardUpstream += count
			g.upstream.add(obs.source, obs.ttl, a.maxHops, count)
			g.observations = append(g.observations, weightedObservation{obs: obs, count: count})
		}
	}
	macs := make([]string, 0, len(groups))
	for mac := range groups {
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	result := make([]PreviousHop, 0, len(macs))
	for _, mac := range macs {
		g := groups[mac]
		hop := PreviousHop{MAC: mac, ARPAddresses: []string{}, Sources: []HopSource{}, Overall: g.all.result(nil)}
		for ip := range a.arp[mac] {
			hop.ARPAddresses = append(hop.ARPAddresses, ipString(ip))
		}
		sort.Strings(hop.ARPAddresses)
		ips := make([]uint32, 0, len(g.sources))
		for ip := range g.sources {
			ips = append(ips, ip)
		}
		sort.Slice(ips, func(i, j int) bool { return ips[i] < ips[j] })
		for _, ip := range ips {
			hop.Sources = append(hop.Sources, *g.sources[ip])
		}
		if g.upstream.packets > 0 {
			layer := g.upstream.result(nil)
			hop.TowardUpstream = &layer
			hop.HopLayers = hopLayers(g.observations, a.maxHops)
		}
		result = append(result, hop)
	}
	return result
}
