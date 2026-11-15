package comm

import (
	"net"
	"reflect"
	"testing"
)

func TestSummaryMessagePackRoundTrip(t *testing.T) {
	want := PacketSummary{SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(203, 0, 113, 9),
		SrcMac: net.HardwareAddr{2, 1, 2, 3, 4, 5}, DstMac: net.HardwareAddr{2, 6, 7, 8, 9, 10},
		TTL: 61, CapID: 0xfedcba98}
	data, err := want.Marshall()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshallSummary(data)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
}

func TestUnmarshallSummaryRejectsMalformedData(t *testing.T) {
	if _, err := UnmarshallSummary([]byte{0xc1}); err == nil {
		t.Fatal("malformed msgpack accepted")
	}
}
