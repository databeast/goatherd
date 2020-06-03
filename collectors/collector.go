package collectors

import "net"

// Pairing of source and destination address, with accompanying metas
type AddressPairing struct {
	Src net.Addr
	Dst net.Addr
	Ttl int8
}

type Collector interface {
	Start()
}
// Base Packet Collector
type collectorBase struct {
	MapperHost  string // Mapper this collector is sending to
	PacketCount int    //running count of observed packets
	pipeline    chan *AddressPairing
}



func (c *collectorBase) Start() {

}

func (c *collectorBase) Stop() {

}

func (c *collectorBase) Ingest(packet []byte) {

}
