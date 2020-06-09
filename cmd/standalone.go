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
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		fmt.Println("standalone called")
		collector := collectors.NewPcapCollector()

		// file mode
		err = collector.LoadFile("sample.pcap")
		if err != nil {
			println(err.Error())
			return
		}
		mapper, err := mapper.NewMapper(mapper.MapperSettings{})
		if err != nil {
			println(err.Error())
			return
		}

		cappoint, err := capture.NewCapturePoint()
		if err != nil {
			println(err.Error())
			return
		}
		err = mapper.AttachCapturePoint(cappoint)
		mapper.Begin()
		if err != nil {
			println(err.Error())
			return
		}
	},
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
