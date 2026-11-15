package coordination

import (
	"net/netip"
	"sort"

	"github.com/databeast/goatherd/internal/discovery"
	"github.com/databeast/goatherd/internal/quality"
)

type inventorySource struct {
	CapturePoint string                       `json:"capture_point"`
	ARPMACs      []string                     `json:"arp_macs"`
	Destinations []discovery.DestinationCount `json:"destination_macs"`
}

type inventoryAddress struct {
	Address string            `json:"address"`
	Sources []inventorySource `json:"sources"`
}

type inventoryPoint struct {
	CapturePoint              string                    `json:"capture_point"`
	StreamStatus              string                    `json:"stream_status"`
	StreamError               string                    `json:"stream_error,omitempty"`
	Capture                   *quality.Snapshot         `json:"capture,omitempty"`
	UpstreamMAC               string                    `json:"selected_upstream_mac,omitempty"`
	InferenceError            string                    `json:"inference_error,omitempty"`
	Topology                  *discovery.EvidencePrefix `json:"candidate_prefix_tree,omitempty"`
	PreviousHops              []discovery.PreviousHop   `json:"previous_hops,omitempty"`
	UnknownPreviousHopPackets uint64                    `json:"unknown_previous_hop_packets"`
	HopLayers                 []discovery.Layer         `json:"hop_layers,omitempty"`
}

type inventory struct {
	Addresses     []inventoryAddress       `json:"addresses"`
	CapturePoints []inventoryPoint         `json:"capture_points"`
	Topology      *discovery.AddressPrefix `json:"candidate_prefix_tree,omitempty"`
}

func buildInventory(points []inventoryPoint, evidence map[string]discovery.Evidence) (inventory, error) {
	addresses := make(map[string][]inventorySource)
	for _, point := range points {
		for _, address := range evidence[point.CapturePoint].Addresses {
			addresses[address.Address] = append(addresses[address.Address], inventorySource{
				CapturePoint: point.CapturePoint, ARPMACs: address.ARPMACs, Destinations: address.Destinations,
			})
		}
	}
	result := inventory{Addresses: make([]inventoryAddress, 0, len(addresses)), CapturePoints: points}
	for addr, sources := range addresses {
		result.Addresses = append(result.Addresses, inventoryAddress{Address: addr, Sources: sources})
	}
	sort.Slice(result.Addresses, func(i, j int) bool {
		return netip.MustParseAddr(result.Addresses[i].Address).Less(netip.MustParseAddr(result.Addresses[j].Address))
	})
	addressList := make([]string, 0, len(result.Addresses))
	for _, item := range result.Addresses {
		addressList = append(addressList, item.Address)
	}
	var err error
	result.Topology, err = discovery.AddressPrefixTree(addressList)
	if err != nil {
		return inventory{}, err
	}
	return result, nil
}
