package collectors

import (
	"github.com/databeast/goatherd/packets"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
	"os"
)

// NOTE: PcapFiles have no requirements to contain packets only from a single NIC
// For this reason, no local subnet can be assumed, as multiple pcapfiles can easily be merged into one
// for this reason, PCapFile CapturePoints cannot be assumed to have a single local subnet

type PcapFileCollector struct {
	collectorBase
	pcapdata *pcap.Handle
	packets  chan packets.PacketSummary
}

func NewPcapFileCollector() (collector *PcapFileCollector, err error) {
	return &PcapFileCollector{
		collectorBase: collectorBase{
			MapperHost:  "",
			PacketCount: 0,
			pipeline:    make(chan packets.PacketSummary),
		},
		pcapdata: nil,
	}, nil
}

// Load PCap data from file and start piping it into the collector channel
func (c *PcapFileCollector) Load(filename string) (err error) {
	pcapfile, err := os.Open(filename)
	if err != nil {
		return errors.WithStack(err)
	}
	c.pcapdata, err = pcap.OpenOfflineFile(pcapfile)
	if err != nil {
		return errors.WithStack(err)
	}

	// everything is successful, start making packets available to the mapper
	go c.ingestFile()
	return err
}

func (c *PcapFileCollector) Start() (err error) {
	go c.ingestFile()
	return nil

}

func (c *PcapFileCollector) ingestFile() {
	packetSource := gopacket.NewPacketSource(c.pcapdata, c.pcapdata.LinkType())
	var packet gopacket.Packet
	var summary packets.PacketSummary
	// start reading packets one by one
	for {
		packet = <-packetSource.Packets()

		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer == nil {
			continue // can't work with this
		}
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		summary.SrcMac = ethernetPacket.SrcMAC
		summary.DstMac = ethernetPacket.DstMAC

		// Let's see if the packet is IP (even though the ether type told us)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue //cant work with this
		}
		ip, _ := ipLayer.(*layers.IPv4)
		summary.SrcIP = ip.SrcIP
		summary.DstIP = ip.DstIP

		summary.TTL = ip.TTL

		c.packets <- summary

	}

}

// Interface Declaration to
func (c *PcapFileCollector) Packets() <-chan packets.PacketSummary {
	return c.pipeline
}
