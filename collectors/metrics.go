package collectors

import "fmt"

// TODO: When Processing PCap Files, pre-process them for available SYN packets to predict viability

// TODO: Render out to console on observed SYN Packets

// TODO: Render out on Console dropped packets from live Capture

// TODO: Track Overall Packet Stats for End-Of-Run debriefing.


var packetCount int
var packetErr int

func CollectorStats() {
	fmt.Printf("%d total packets collected\n", packetCount)
	fmt.Printf("%d total collection errors\n", packetErr)
}