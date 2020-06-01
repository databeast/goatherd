package collectors

import "net"

// Pairing of source and destination address, with accompanying metas
type AddressPairing struct {
	Src net.Addr
	Dst net.Addr
	Ttl int8
}

// Base Packet Collector
type Collector struct {
	MapperHost  string // Mapper this collector is sending to
	PacketCount int    //running count of observed packets
	pipeline    chan *AddressPairing
}

func (c *Collector) Start() {

}

func (c *Collector) Stop() {

}

func (c *Collector) Ingest(packet []byte) {

}
