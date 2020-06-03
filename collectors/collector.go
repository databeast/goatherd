package collectors

import (
	"github.com/databeast/goatherd/packets"
)


type Collector interface {
	Start()
	Packets() chan packets.PacketSummary
}
// Base Packet Collector
type collectorBase struct {
	MapperHost  string // Mapper this collector is sending to
	PacketCount int    //running count of observed packets
	pipeline    chan   packets.PacketSummary
}



func (c *collectorBase) Start() {

}

func (c *collectorBase) Stop() {

}

func (c *collectorBase) Ingest(packet []byte) {

}
