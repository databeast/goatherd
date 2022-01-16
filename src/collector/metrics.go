package collector

import "fmt"

// TODO: When Processing PCap Files, pre-process them for available SYN comm to predict viability

// TODO: Render out to console on observed SYN Packets

// TODO: Render out on Console dropped comm from live Capture

// TODO: Track Overall Packet Stats for End-Of-Run debriefing.

var packetCount int
var packetErr int

func CollectorStats() {
	fmt.Printf("%d total comm collected\n", packetCount)
	fmt.Printf("%d total collection errors\n", packetErr)
}
