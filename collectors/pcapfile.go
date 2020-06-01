package collectors

import (
	"os"

	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
)

type PcapFileCollector struct {
}

// Load PCap data from file and start piping it into the collector channel
func (c *PcapFileCollector) Load(filename string) {
	pcapfile := os.Open("/path/to/pcapfile")
	handle, err := pcap.OpenOfflineFile(pcapfile)
	if err != nil {
		return errors.WithStack(err)
	}

	// start reading packets one by one
	nextpacket, err := handle.ReadPacketData()

}
