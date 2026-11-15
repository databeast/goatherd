package capture

import (
	"net"
	"reflect"
	"testing"
)

func TestDecomposeIPv4Bits(t *testing.T) {
	bits, err := decomposeToBits(net.IP{192, 168, 1, 129})
	if err != nil {
		t.Fatal(err)
	}
	want := [32]bool{true, true, false, false, false, false, false, false,
		true, false, true, false, true, false, false, false,
		false, false, false, false, false, false, false, true,
		true, false, false, false, false, false, false, true}
	if bits != want {
		t.Fatalf("got %v, want %v", bits, want)
	}
}

func TestObservedTTLStepsUniqueAndSorted(t *testing.T) {
	gateway := NewGateway(net.IPv4(192, 0, 2, 1), net.HardwareAddr{2, 1, 2, 3, 4, 5})
	gateway.trackBitTTL(0, 3)
	gateway.trackBitTTL(1, 1)
	gateway.trackBitTTL(2, 3)
	if got := gateway.bitmapping.ObservedTTLsteps(); !reflect.DeepEqual(got, []uint8{1, 3}) {
		t.Fatalf("got %v", got)
	}
}
