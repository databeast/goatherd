package cmd

import (
	"fmt"
	"github.com/databeast/goatherd/capture"
	"github.com/databeast/goatherd/collectors"
	"github.com/databeast/goatherd/mapper"
	"github.com/spf13/cobra"
)

// standaloneCmd represents the standalone command
var standaloneCmd = &cobra.Command{
	Use:   "standalone",
	Short: "run goatherd in local capture standalone mode",
	Long:  `goatherd will run the collector and mapper components simultaneously, from a local interface or .pcap file`,
	Run: standaloneMode,
}

func standaloneMode(cmd *cobra.Command, args []string) {
	var err error
	fmt.Println("Goatherd Standalone Mode engaged")

	collector := collectors.NewPcapCollector()

	if cmd.Flag("pcap").Value.String() != "" {
		fmt.Printf("Loading pcap file: %q\n", cmd.Flag("pcap").Value.String())
		// file mode
		err = collector.LoadFile( cmd.Flag("pcap").Value.String() )
		if err != nil {
			println(err.Error())
			return
		}
	} else {
		fmt.Printf("Loading from Eth0\n")
		err = collector.OpenNic("eth0")
		if err != nil {
			println(err.Error())
			return
		}
	}

	standaloneMapper, err := mapper.NewMapper(mapper.MapperSettings{})
	if err != nil {
		println(err.Error())
		return
	}

	println("Creating Default Capture Point")
	cappoint, err := capture.NewCapturePoint()
	if err != nil {
		println(err.Error())
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
