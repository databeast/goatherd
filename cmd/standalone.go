// Standalone Mode - collector and processor in single instance.package, either from local interface or PCap data

package cmd

import "github.com/databeast/goatherd/collectors"

func StandaloneMode() {
	collector, err := collectors.NewPcapFileCollector()
	if err != nil {
		println(err.Error())
	}
	collector.Load("sample.pcap")
}
