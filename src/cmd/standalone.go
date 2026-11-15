package cmd

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/databeast/goatherd/collector"
	"github.com/databeast/goatherd/mapper"
	"github.com/databeast/goatherd/reporter"
	"github.com/spf13/cobra"
)

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
	if err := collector.Observe(ctx, filename, iface, point); err != nil {
		return err
	}
	report, err := point.Report(upstream)
	if err != nil {
		return err
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
}
