package mapper

import (
	"github.com/databeast/goatherd/capture"
	"github.com/databeast/goatherd/collectors"
	"github.com/pkg/errors"
)

// The Mapper is the core processor for calculating possible subnet masks from collected traffic
type Mapper struct {
	collectors    []collectors.Collector // packet capture collector instances
	ingest        *ingester
	capturepoints []*capture.CapturePoint // packet capture source tracking for collectors
	events        chan MappingEvent       // meta-events from a given mapper
}

// Commence Packet processing and Mapping
func (m *Mapper) Begin() (err error) {

	if len(m.collectors) == 0 {
		return errors.Errorf("refusing to start with no collectors")
	}

	return nil
}

//subscribe to event messages from the mapper
func (m *Mapper) Events() (events <-chan MappingEvent) {
	return m.events
}

// Engage mapper with a
func (m *Mapper) AddCollector(collector collectors.Collector) (err error) {

	m.collectors = append(m.collectors, collector)
	err = collector.Start()
	if err != nil {
		return errors.WithStack(err)
	}

	go func() { // commence collector eventloop
		for {
			p := <-collector.Packets()
			println(p.TTL)
			m.ingest.Ingest() <- p
			// TODO: introduce select for sigv quit shutdown
		}
	}()
	return nil
}

func NewMapper() *Mapper {
	return &Mapper{
		collectors:    nil,
		capturepoints: nil,
		events:        nil,
	}
}

// information events from the mapping process
type MappingEvent struct {
	fromcollector collectors.Collector
	message       string
}

// Primary Process loop for the mapper
func (m *Mapper) processPacketSummary() {

}

// Add a known capturepoint to this collector - usually the subnet of the monitored NIC
func (m *Mapper) AddCapturePoint(point *capture.CapturePoint) error {
	if point == nil {
		return errors.Errorf("refusing to add nil capturepoint")
	}
	for _, p := range m.capturepoints {
		if p.LocalNet.IP.Equal(point.LocalNet.IP) {
			return errors.Errorf("capturepoint %s/%s already added", point.LocalNet.IP.String(), point.LocalNet.Mask.String())
		}
	}
	m.capturepoints = append(m.capturepoints, point)

	return nil
}
