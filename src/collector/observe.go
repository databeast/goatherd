package collector

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/databeast/goatherd/internal/discovery"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type capturedPacket struct {
	packet gopacket.Packet
	err    error
}

// Observe reads Ethernet IPv4 and ARP traffic until EOF or cancellation.
func Observe(ctx context.Context, filename, iface string, analyzer *discovery.Analyzer) error {
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
	linkType := handle.LinkType()
	if linkType != layers.LinkTypeEthernet {
		handle.Close()
		return fmt.Errorf("unsupported capture link type %s: Ethernet is required", linkType)
	}
	packets := make(chan capturedPacket)
	go func() {
		defer handle.Close()
		defer close(packets)
		source := gopacket.NewPacketSource(handle, linkType)
		for {
			packet, readErr := source.NextPacket()
			if readErr == pcap.NextErrorTimeoutExpired {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			select {
			case packets <- capturedPacket{packet: packet, err: readErr}:
			case <-ctx.Done():
				return
			}
			if readErr != nil {
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case captured, ok := <-packets:
			if !ok {
				return nil
			}
			if captured.err == io.EOF {
				return nil
			}
			if captured.err != nil {
				return fmt.Errorf("read capture: %w", captured.err)
			}
			observePacket(analyzer, captured.packet)
		}
	}
}

func observePacket(analyzer *discovery.Analyzer, packet gopacket.Packet) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return
	}
	ethernet := ethernetLayer.(*layers.Ethernet)
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		if arp.AddrType == layers.LinkTypeEthernet && arp.Protocol == layers.EthernetTypeIPv4 &&
			bytes.Equal(ethernet.SrcMAC, arp.SourceHwAddress) {
			analyzer.ObserveARP(net.HardwareAddr(arp.SourceHwAddress), net.IP(arp.SourceProtAddress))
		}
	}
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		analyzer.ObserveIPv4(ethernet.DstMAC, ip.SrcIP, ip.DstIP, ip.TTL)
	}
}
