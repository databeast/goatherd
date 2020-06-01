package mapper

type PacketIngester struct {
	incoming chan *PacketSummary
}

type PacketSummary struct {
	SrcIP  string
	SrcMac string
	DstIP  string
	DstMac string
	TTL    int8
}

// Channel for Ingesting processed packets into the Mapper
func (i PacketIngester) Ingest() (ingestchannel <-chan (*PacketSummary)) {

	return nil
}
