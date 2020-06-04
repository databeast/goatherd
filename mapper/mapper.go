package mapper

import "github.com/databeast/goatherd/collectors"

type Mapper struct {
	collector collectors.Collector
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
	m.collector = collector
	collector.Start()

	for {
		p := <- collector.Packets()
		m.ingester.Ingest() <- p

	}

	return nil
}

func NewMapper() *Mapper {
	newmapper := &Mapper{}
	return newmapper
}

// information events from the mapping process
type MappingEvent struct {
	message  string
}

