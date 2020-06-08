package mapper

import (
	"github.com/databeast/goatherd/packets"
)

// Incoming Packet Summary Routing and Channels
type ingester struct {
	incoming chan packets.PacketSummary
}

// Channel for Ingesting processed packets into the Mapper
func (i *ingester) Ingest() (ingestchannel chan packets.PacketSummary) {

	return nil
}
