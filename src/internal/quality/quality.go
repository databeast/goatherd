// Package quality describes capture health separately from inferred network evidence.
package quality

import "time"

// Stats are libpcap's platform-dependent live capture counters.
type Stats struct {
	Received         uint64 `json:"received"`
	Dropped          uint64 `json:"dropped"`
	InterfaceDropped uint64 `json:"interface_dropped"`
}

// Snapshot describes the last completed update from a capture source.
type Snapshot struct {
	Status       string    `json:"status"`
	Source       string    `json:"source"`
	StartedAt    time.Time `json:"started_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	DurationMS   int64     `json:"duration_ms"`
	Packets      uint64    `json:"packets"`
	ARPPackets   uint64    `json:"arp_packets"`
	IPv4Packets  uint64    `json:"ipv4_packets"`
	Stats        *Stats    `json:"pcap_stats"`
	StatsNote    string    `json:"pcap_stats_note,omitempty"`
	StatsError   string    `json:"pcap_stats_unavailable,omitempty"`
	CaptureError string    `json:"capture_error,omitempty"`
}
