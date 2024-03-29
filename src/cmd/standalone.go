package cmd

import (
	"github.com/databeast/goatherd/collector"
	"github.com/databeast/goatherd/internal/capture"
	"github.com/databeast/goatherd/mapper"
	"github.com/spf13/cobra"
	"net"
)

// standaloneCmd represents the standalone command
var standaloneCmd = &cobra.Command{
	Use:   "standalone",
	Short: "run goatherd in local capture standalone mode",
	Long:  `goatherd will run the collector and mapper components simultaneously, from a local interface or .pcap file`,
	Run:   standaloneMode,
}

func standaloneMode(cmd *cobra.Command, args []string) {
	var err error
	logger.Printf("Goatherd Standalone Mode engaged")

	collector := collector.NewPcapCollector()

	if cmd.Flag("pcap").Value.String() != "" {
		logger.Printf("Loading pcap file: %q\n", cmd.Flag("pcap").Value.String())
		// file mode
		err = collector.LoadFile(cmd.Flag("pcap").Value.String())
		if err != nil {
			println(err.Error())
			return
		}
	} else {
		logger.Printf("Loading from Eth0\n")
		err = collector.OpenNic("eth0")
		if err != nil {
			println(err.Error())
			return
		}
	}

	standaloneMapper, err := mapper.NewMapper(mapper.MapperSettings{})
	if err != nil {
		logger.Printf(err.Error())
		return
	}

	println("Creating Default Capture Point")
	cappoint, err := capture.NewCapturePoint()
	if err != nil {
		println(err.Error())
		return
	}
	println("Setting Test Default Gateway")
	mac, err := net.ParseMAC("00:15:5d:4c:07:d8")
	if err != nil {
		logger.Printf(err.Error())
		return
	}

	err = cappoint.SetDefaultGateway(mac)
	if err != nil {
		logger.Printf(err.Error())
		return
	}

	println("attaching Default Capture Point")
	err = standaloneMapper.AttachCapturePoint(cappoint)
	if err != nil {
		println(err.Error())
		return
	}
	println("Commencing Ingestion")
	collector.Start(cappoint)

	println("Commencing Mapping")
	err = standaloneMapper.Begin()
	if err != nil {
		println(err.Error())
		return
	}
	err = standaloneMapper.Ingest(collector.Packets())
	if err != nil {
		println(err.Error())
		return
	}

}

func init() {
	rootCmd.AddCommand(standaloneCmd)
	standaloneCmd.PersistentFlags().String("pcap", "", "load from a .pcap file")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// standaloneCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// standaloneCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
