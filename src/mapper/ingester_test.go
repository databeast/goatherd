package mapper

import (
	"reflect"
	"testing"

	"github.com/databeast/goatherd/internal/comm"
)

func TestLocalIngestForwardsPackets(t *testing.T) {
	mapper := &Mapper{}
	if err := mapper.enableLocalIngest(); err != nil {
		t.Fatal(err)
	}
	if mapper.ingest.Packets() == nil || mapper.ingest.capturepoints == nil {
		t.Fatal("local ingester not initialized")
	}
	if err := mapper.enableLocalIngest(); err == nil {
		t.Fatal("duplicate ingester accepted")
	}
	packets := []comm.PacketSummary{{CapID: 1, TTL: 61}, {CapID: 2, TTL: 32}}
	incoming := make(chan comm.PacketSummary, len(packets))
	for _, packet := range packets {
		incoming <- packet
	}
	close(incoming)
	if err := mapper.Ingest(incoming); err != nil {
		t.Fatal(err)
	}
	for _, want := range packets {
		select {
		case got := <-mapper.ingest.Packets():
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		default:
			t.Fatal("forwarded packet missing")
		}
	}
}
