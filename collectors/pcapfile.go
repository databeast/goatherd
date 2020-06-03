package collectors

import (
	"os"

	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
)

type PcapFileCollector struct {
	collectorBase
	pcapdata *pcap.Handle
}

func NewPcapFileCollector() (collector *PcapFileCollector, err error) {
	return &PcapFileCollector{}, nil
}

// Load PCap data from file and start piping it into the collector channel
func (c *PcapFileCollector) Load(filename string) (err error) {
	pcapfile, err := os.Open("/path/to/pcapfile")
	if err != nil {
		return errors.WithStack(err)
	}
	c.pcapdata, err = pcap.OpenOfflineFile(pcapfile)
	if err != nil {
		return errors.WithStack(err)
	}

	// everything succesful, start sending packets to the mapper
	go c.ingestFile()
	return nil
}

func (c *PcapFileCollector) ingestFile() {
	// start reading packets one by one
	for {
		_, _, err := c.pcapdata.ReadPacketData()
		if err != nil {
			return
		}

	}
}
