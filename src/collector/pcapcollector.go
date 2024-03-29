package collector

import (
	"fmt"
	"github.com/databeast/goatherd/internal/capture"
	"github.com/databeast/goatherd/internal/comm"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
	"log"
	"time"
)

// BPF Filter syntax to only capture TCP SYN (open new connection) comm
const (
	synFlagFilter = "tcp[tcpflags] == tcp-syn"
)

const (
	errMsgExistingPcapSource = "collector has already been initialized with pcap source"
)

var (
	packetbuffer int32         = 1024
	device       string        = "eth0"
	snapshot_len int32         = 1024
	promiscuous  bool          = false
	timeout      time.Duration = 30 * time.Second
)

func NewPcapCollector() (collector *PcapCollector) {
	collector = &PcapCollector{
		collectorBase: collectorBase{
			MapperHost:  "",
			PacketCount: 0,
			pipeline:    make(chan comm.PacketSummary, packetbuffer),
			mapperconn:  nil,
			disconnect:  make(chan struct{}),
		},
		pcapdata: nil,
	}
	return collector
}

type PcapCollector struct {
	collectorBase
	pcapdata *pcap.Handle
}

// Load PCap data from file and start piping it into the collector channel
func (c *PcapCollector) LoadFile(filename string) (err error) {
	if c.pcapdata != nil {
		return errors.Errorf(errMsgExistingPcapSource)
	}

	c.pcapdata, err = pcap.OpenOffline(filename)
	if err != nil {
		return errors.WithStack(err)
	}
	err = c.pcapdata.SetBPFFilter(synFlagFilter)

	//	LOAD CAPTURE POINT

	return nil
}

// Open local NIC as Packet Data Source
func (c *PcapCollector) OpenNic(nicname string) (err error) {
	if c.pcapdata != nil {
		return errors.Errorf(errMsgExistingPcapSource)
	}

	c.pcapdata, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		return err
	}

	err = c.pcapdata.SetBPFFilter(synFlagFilter)
	if err != nil {
		return err
	}

	println("Listening on Eth0")
	packetSource := gopacket.NewPacketSource(c.pcapdata, c.pcapdata.LinkType())
	for packet := range packetSource.Packets() {
		// Do something with a packet here.
		fmt.Println("recieved packet")
		fmt.Println(packet)
	}
	return nil
}

func (c *PcapCollector) Start(point *capture.CapturePoint) {
	c.cappoints = append(c.cappoints, point)
	go c.collect()
}

func (c *PcapCollector) Stop() {
	c.pcapdata.Close()
}

// Interface Declaration to pull comm from the Collector
func (c *PcapCollector) Packets() <-chan comm.PacketSummary {
	return c.pipeline
}

// check available NICs to match against requested one
func (c *PcapCollector) ListNics() {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Print device information
	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
}

func (c *PcapCollector) collect() {
	var packet gopacket.Packet
	var summary comm.PacketSummary

	// TODO: support for multiple capturepoints on a single connectors
	if len(c.cappoints) == 0 {
		panic("no capture point defined")
	}
	summary.CapID = c.cappoints[0].ID

	packetSource := gopacket.NewPacketSource(c.pcapdata, c.pcapdata.LinkType())
	println("loaded packet source")
	// start reading comm one by one
	for packet = range packetSource.Packets() {

		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer == nil {
			packetErr += 1
			continue // can't work with this
		}

		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		summary.SrcMac = ethernetPacket.SrcMAC
		summary.DstMac = ethernetPacket.DstMAC

		// Let's see if the packet is IP (even though the ether type told us)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			packetErr += 1
			continue //cant work with this
		}
		ip, _ := ipLayer.(*layers.IPv4)
		summary.SrcIP = ip.SrcIP
		summary.DstIP = ip.DstIP

		summary.TTL = ip.TTL

		println("read packet")
		c.pipeline <- summary
		packetCount += 1
	}
	CollectorStats()
}
