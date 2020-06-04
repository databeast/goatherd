package mapper

import "github.com/databeast/goatherd/packets"

type PacketIngester struct {
	incoming chan packets.PacketSummary
}



// Channel for Ingesting processed packets into the Mapper
func (i *PacketIngester) Ingest() (ingestchannel chan packets.PacketSummary) {

	return nil
}
