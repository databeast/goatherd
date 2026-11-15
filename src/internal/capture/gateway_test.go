package capture

import (
	"net"
	"testing"
)

func TestNewGatewayInitializesBitTracking(t *testing.T) {
	ip := net.IP{192, 0, 2, 1}
	mac := net.HardwareAddr{2, 1, 2, 3, 4, 5}
	gateway := NewGateway(ip, mac)
	if !gateway.ipaddr.Equal(ip) || gateway.arpaddr.String() != mac.String() {
		t.Fatalf("gateway addresses: %v, %v", gateway.ipaddr, gateway.arpaddr)
	}
	for position, bit := range gateway.bitmapping {
		if bit == nil || bit.value != UNSET || bit.ttlcounts == nil || len(bit.ttlcounts) != 0 {
			t.Fatalf("bit %d not initialized: %+v", position, bit)
		}
	}
	gateway.trackBitTTL(0, 3)
	gateway.trackBitTTL(0, 3)
	gateway.trackBitTTL(31, 1)
	if gateway.bitmapping[0].ttlcounts[3] != 2 || gateway.bitmapping[31].ttlcounts[1] != 1 ||
		len(gateway.bitmapping[1].ttlcounts) != 0 {
		t.Fatal("bit TTL counts are not independent")
	}
}
