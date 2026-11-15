package cmd

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/databeast/goatherd/collector"
	"github.com/databeast/goatherd/internal/discovery"
	"github.com/databeast/goatherd/internal/quality"
	"github.com/databeast/goatherd/mapper"
	"github.com/databeast/goatherd/reporter"
	"github.com/spf13/cobra"
)

type captureQualitySink struct {
	collector.ObservationSink
	snapshot quality.Snapshot
}

func (s *captureQualitySink) ObserveQuality(snapshot quality.Snapshot) {
	s.snapshot = snapshot
}

func (s *captureQualitySink) ObserveIPv4Ethernet(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, ttl uint8) {
	if observer, ok := s.ObservationSink.(interface {
		ObserveIPv4Ethernet(net.HardwareAddr, net.HardwareAddr, net.IP, net.IP, uint8)
	}); ok {
		observer.ObserveIPv4Ethernet(srcMAC, dstMAC, srcIP, dstIP, ttl)
	} else {
		s.ObserveIPv4(dstMAC, srcIP, dstIP, ttl)
	}
}

var standaloneCmd = &cobra.Command{
	Use:   "standalone",
	Short: "infer downstream IPv4 prefixes from a local capture or pcap file",
	RunE:  standaloneMode,
}

func standaloneMode(cmd *cobra.Command, args []string) error {
	filename, err := cmd.Flags().GetString("pcap")
	if err != nil {
		return err
	}
	iface, err := cmd.Flags().GetString("interface")
	if err != nil {
		return err
	}
	macText, err := cmd.Flags().GetString("upstream-mac")
	if err != nil {
		return err
	}
	maxHops, err := cmd.Flags().GetUint8("max-hops")
	if err != nil {
		return err
	}
	format, err := cmd.Flags().GetString("format")
	if err != nil {
		return err
	}
	if format != "json" && format != "jsonld" && format != "text" {
		return fmt.Errorf("unsupported report format %q (choose json, jsonld or text)", format)
	}
	evidenceDump, err := cmd.Flags().GetBool("evidence")
	if err != nil {
		return err
	}
	var upstream net.HardwareAddr
	if macText != "" {
		upstream, err = net.ParseMAC(macText)
		if err != nil || len(upstream) != 6 || upstream[0]&1 != 0 {
			return fmt.Errorf("invalid unicast Ethernet upstream MAC %q", macText)
		}
	}
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	localMapper := mapper.NewLocalMapper()
	point, err := localMapper.AddCapturePoint(0, maxHops)
	if err != nil {
		return err
	}
	if filename == "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "Capturing on %s; interrupt to produce a report.\n", iface)
	}
	sink := &captureQualitySink{ObservationSink: point}
	if err := collector.Observe(ctx, filename, iface, sink); err != nil {
		var evidence *discovery.Evidence
		if evidenceDump {
			_, details, _ := point.ReportWithEvidence(upstream)
			evidence = &details
		}
		if writeErr := reporter.WriteUnavailableEvidence(cmd.OutOrStdout(), format, sink.snapshot, err.Error(), evidence); writeErr != nil {
			return fmt.Errorf("capture: %v; write report: %w", err, writeErr)
		}
		return err
	}
	report, err := point.Report(upstream)
	if err != nil {
		var evidence *discovery.Evidence
		if evidenceDump {
			_, details, _ := point.ReportWithEvidence(upstream)
			evidence = &details
		}
		return reporter.WriteUnavailableEvidence(cmd.OutOrStdout(), format, sink.snapshot, err.Error(), evidence)
	}
	report.Capture = &sink.snapshot
	if !evidenceDump {
		return reporter.WriteSummary(cmd.OutOrStdout(), format, report)
	}
	if format == "text" {
		return reporter.WriteText(cmd.OutOrStdout(), report)
	}
	if format == "jsonld" {
		return reporter.WriteJSONLD(cmd.OutOrStdout(), report)
	}
	return reporter.WriteJSON(cmd.OutOrStdout(), report)
}

func init() {
	rootCmd.AddCommand(standaloneCmd)
	standaloneCmd.Flags().String("pcap", "", "read an Ethernet pcap file instead of live capture")
	standaloneCmd.Flags().String("interface", "eth0", "live capture interface")
	standaloneCmd.Flags().String("upstream-mac", "", "use this upstream MAC instead of detecting it from ARP")
	standaloneCmd.Flags().Uint8("max-hops", 6, "maximum prior hops for a TTL estimate")
	standaloneCmd.Flags().String("format", "json", "report format: json, jsonld or text")
	standaloneCmd.Flags().Bool("evidence", false, "include full diagnostic evidence instead of the summary report")
}
