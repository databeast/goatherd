package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/databeast/goatherd/collector"
	"github.com/databeast/goatherd/internal/discovery"
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
	var upstream net.HardwareAddr
	if macText != "" {
		upstream, err = net.ParseMAC(macText)
		if err != nil || len(upstream) != 6 || upstream[0]&1 != 0 {
			return fmt.Errorf("invalid unicast Ethernet upstream MAC %q", macText)
		}
	}
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	analyzer := discovery.New(maxHops)
	if filename == "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "Capturing on %s; interrupt to produce a report.\n", iface)
	}
	if err := collector.Observe(ctx, filename, iface, analyzer); err != nil {
		return err
	}
	report, err := analyzer.Report(upstream)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func init() {
	rootCmd.AddCommand(standaloneCmd)
	standaloneCmd.Flags().String("pcap", "", "read an Ethernet pcap file instead of live capture")
	standaloneCmd.Flags().String("interface", "eth0", "live capture interface")
	standaloneCmd.Flags().String("upstream-mac", "", "use this upstream MAC instead of detecting it from ARP")
	standaloneCmd.Flags().Uint8("max-hops", 6, "maximum prior hops for a TTL estimate")
}
