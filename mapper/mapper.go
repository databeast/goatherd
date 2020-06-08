package mapper

import (
	"github.com/databeast/goatherd/capture"
	"github.com/pkg/errors"
)

// The Mapper is the core processor for calculating possible subnet masks from collected traffic
type Mapper struct {
	ingest        *ingester
	capturepoints []*capture.CapturePoint // packet capture source tracking for collectors
	events        chan MappingEvent       // meta-events from a given mapper
}

// Commence Packet processing and Mapping
func (m *Mapper) Begin() (err error) {

	if len(m.capturepoints) == 0 {
		return errors.Errorf("refusing to start with no capturepoints")
	}




	return nil
}

//subscribe to event messages from the mapper
func (m *Mapper) Events() (events <-chan MappingEvent) {
	return m.events
}



func NewMapper() *Mapper {
	return &Mapper{
		capturepoints: nil,
		events:        make(chan MappingEvent, 100),
	}
}

// information events from the mapping process
type MappingEvent struct {
	fromCapturePoint string  // CapID this came from
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
