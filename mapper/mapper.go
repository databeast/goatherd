package mapper

import "github.com/databeast/goatherd/collectors"

type Mapper struct {
	ingester *PacketIngester
	capturenets []CapturePoint
	events chan MappingEvent
}

func (m *Mapper) Begin() {

}

//subscribe to event messages from the mapper
func (m *Mapper) Events() (chan MappingEvent){
	return nil
}

func (m *Mapper) Collect(collector collectors.Collector) error {
	return nil
}

func NewMapper() *Mapper {
	newmapper := &Mapper{ingester: &PacketIngester{}}
	return newmapper
}

// information events from the mapping process
type MappingEvent struct {
	message  string
}

