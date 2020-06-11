package mapper

import (
	"github.com/databeast/goatherd/capture"
	"github.com/databeast/goatherd/packets"
	"github.com/pkg/errors"
)

type captureid uint32

const (
	mapperDefaultPort = 8432
)

// The Mapper is the core processor for calculating possible subnet masks from collected traffic
type Mapper struct {
	ingest *ingester
	events chan MappingEvent // meta-events from a given mapper
}

// Commence Packet processing and Mapping
func (m *Mapper) Begin() (err error) {

	if len(m.ingest.capturepoints) == 0 {
		return errors.Errorf("refusing to start with no capturepoints")
	}

	go func() {
	var p packets.PacketSummary
	for p = range m.ingest.Packets() {
		//p = <-m.ingest.Packets()
		println("Mapping Packet")
		// route to appropriate capturepoint
		if point, ok := m.ingest.capturepoints[captureid(p.CapID)]; ok {
			go func() {
				err = point.ProcessPacketSummary(p)
				if err != nil {
					//TODO: need error tracking through Events channel
				}
			}()
		} else {
			// why are we getting packets from an unregistered capturepoint?
		}
	}
	}()
	return
}

//subscribe to event messages from the mapper
func (m *Mapper) Events() (events <-chan MappingEvent) {
	return m.events
}

type MapperSettings struct {
	Remote string
}

func NewMapper(settings MapperSettings) (mapper *Mapper, err error) {
	mapper = &Mapper{
		ingest: nil,
		events: make(chan MappingEvent, 100),
	}
	if settings.Remote == "" {
		err = mapper.enableLocalIngest()
		if err != nil {
			return nil, err
		}
	}
	return mapper, nil
}

// information events from the mapping process
type MappingEvent struct {
	fromCapturePoint string // CapID this came from
	message          string
}

// Add a known capturepoint to this collector - usually the subnet of the monitored NIC
func (m *Mapper) AttachCapturePoint(point *capture.CapturePoint) error {
	if m.ingest == nil {
		return errors.Errorf("cannot add capture points until ingestor declared")
	}

	if point == nil {
		return errors.Errorf("refusing to add nil capturepoint")
	}

	for _, p := range m.ingest.capturepoints {
		if p.LocalNet.IP.Equal(point.LocalNet.IP) {
			return errors.Errorf("capturepoint %s/%s already added", point.LocalNet.IP.String(), point.LocalNet.Mask.String())
		}
	}

	m.ingest.capturepoints[captureid(point.ID)] = point

	return nil
}

