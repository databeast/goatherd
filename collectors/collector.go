package collectors

import (
	"github.com/databeast/goatherd/packets"
)

type Collector interface {
	Start() error
	Stop() error
	Packets() <-chan packets.PacketSummary
}

// Base Packet Collector
type collectorBase struct {
	MapperHost  string // Mapper this collector is sending to
	PacketCount int    //running count of observed packets
	pipeline    chan packets.PacketSummary
}

func (c *collectorBase) Start() error {
	return nil
}

func (c *collectorBase) Stop() error {
	return nil
}
