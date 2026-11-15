package collector

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/databeast/goatherd/internal/quality"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ObservationSink receives the ARP and IPv4 evidence from one capture point.
type ObservationSink interface {
	ObserveARP(mac net.HardwareAddr, ip net.IP)
	ObserveIPv4(dstMAC net.HardwareAddr, srcIP, dstIP net.IP, ttl uint8)
}

// Observe reads Ethernet IPv4 and ARP traffic until EOF or cancellation.
func Observe(ctx context.Context, filename, iface string, sink ObservationSink) (result error) {
	if sink == nil {
		return fmt.Errorf("observation sink is required")
	}
	start := time.Now()
	snapshot := quality.Snapshot{Status: "starting", Source: iface, StartedAt: start.UTC(),
		StatsError: "statistics have not been sampled"}
	if filename != "" {
		snapshot.Source = filename
		snapshot.StatsError = "statistics are unavailable for offline captures"
	}
	update := func(status string) {
		snapshot.Status = status
		now := time.Now()
		snapshot.UpdatedAt = now.UTC()
		snapshot.DurationMS = now.Sub(start).Milliseconds()
		if observer, ok := sink.(interface{ ObserveQuality(quality.Snapshot) }); ok {
			observer.ObserveQuality(snapshot)
		}
	}
	sinkError := func() error {
		if checked, ok := sink.(interface{ Err() error }); ok {
			if err := checked.Err(); err != nil {
				return fmt.Errorf("send observation: %w", err)
			}
		}
		return nil
	}
	update("starting")
	defer func() {
		status := "completed"
		if result != nil {
			status = "failed"
			snapshot.CaptureError = result.Error()
		}
		update(status)
		if err := sinkError(); result == nil && err != nil {
			result = err
		}
	}()
	if err := sinkError(); err != nil {
		return err
	}
	var handle *pcap.Handle
	var err error
	if filename != "" {
		handle, err = pcap.OpenOffline(filename)
	} else {
		handle, err = pcap.OpenLive(iface, 65535, true, time.Second)
	}
	if err != nil {
		return fmt.Errorf("open capture: %w", err)
	}
	defer handle.Close()
	linkType := handle.LinkType()
	if linkType != layers.LinkTypeEthernet {
		return fmt.Errorf("unsupported capture link type %s: Ethernet is required", linkType)
	}
	sample := func() {
		if filename == "" {
			stats, err := handle.Stats()
			if err != nil {
				snapshot.Stats = nil
				snapshot.StatsError = err.Error()
				snapshot.StatsNote = ""
			} else {
				snapshot.Stats = &quality.Stats{Received: uint64(stats.PacketsReceived),
					Dropped: uint64(stats.PacketsDropped), InterfaceDropped: uint64(stats.PacketsIfDropped)}
				snapshot.StatsError = ""
				snapshot.StatsNote = "libpcap counters are platform-dependent; zero drop counts may mean unavailable"
			}
		}
	}
	update("running")
	lastUpdate := time.Now()
	source := gopacket.NewPacketSource(handle, linkType)
	for {
		if ctx.Err() != nil {
			sample()
			return nil
		}
		packet, readErr := source.NextPacket()
		if readErr == io.EOF {
			sample()
			return nil
		}
		if readErr != nil && readErr != pcap.NextErrorTimeoutExpired {
			sample()
			return fmt.Errorf("read capture: %w", readErr)
		}
		if readErr == nil {
			snapshot.Packets++
			if packet.Layer(layers.LayerTypeARP) != nil {
				snapshot.ARPPackets++
			}
			if packet.Layer(layers.LayerTypeIPv4) != nil {
				snapshot.IPv4Packets++
			}
			observePacket(sink, packet)
		}
		if err := sinkError(); err != nil {
			sample()
			return err
		}
		if time.Since(lastUpdate) >= 5*time.Second {
			sample()
			update("running")
			lastUpdate = time.Now()
			if err := sinkError(); err != nil {
				return err
			}
		}
	}
}

func observePacket(sink ObservationSink, packet gopacket.Packet) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return
	}
	ethernet := ethernetLayer.(*layers.Ethernet)
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		if arp.AddrType == layers.LinkTypeEthernet && arp.Protocol == layers.EthernetTypeIPv4 &&
			bytes.Equal(ethernet.SrcMAC, arp.SourceHwAddress) {
			sink.ObserveARP(net.HardwareAddr(arp.SourceHwAddress), net.IP(arp.SourceProtAddress))
		}
	}
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		if observer, ok := sink.(interface {
			ObserveIPv4Ethernet(net.HardwareAddr, net.HardwareAddr, net.IP, net.IP, uint8)
		}); ok {
			observer.ObserveIPv4Ethernet(ethernet.SrcMAC, ethernet.DstMAC, ip.SrcIP, ip.DstIP, ip.TTL)
		} else {
			sink.ObserveIPv4(ethernet.DstMAC, ip.SrcIP, ip.DstIP, ip.TTL)
		}
	}
}
