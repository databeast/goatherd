package packets

import "net"

type PacketSummary struct {
	SrcIP  net.IP
	SrcMac net.HardwareAddr
	DstIP  net.IP
	DstMac net.HardwareAddr
	TTL    uint8
}
