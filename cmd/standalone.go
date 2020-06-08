package cmd

import (
	"fmt"
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
		fmt.Println("standalone called")
		collector, err := collectors.NewPcapFileCollector()
		if err != nil {
			println(err.Error())
			return
		}
		err = collector.Load("sample.pcap")
		if err != nil {
			println(err.Error())
			return
		}
		mapper := mapper.NewMapper()
		err = mapper.AddCollector(collector)
		mapper.Begin()
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
