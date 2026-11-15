package discovery

import (
	"encoding/binary"
	"math/rand"
	"net"
	"reflect"
	"testing"
)

func TestVarianceMaskAndPrefixContainAllObservations(t *testing.T) {
	random := rand.New(rand.NewSource(42))
	mac := net.HardwareAddr{2, 1, 2, 3, 4, 5}
	dst := net.IPv4(203, 0, 113, 1)
	var addresses []net.IP
	for i := 0; i < 128; i++ {
		ip := net.IPv4(10, byte(random.Intn(16)), byte(random.Intn(256)), byte(random.Intn(256)))
		addresses = append(addresses, ip)
	}
	build := func(reverse bool) Report {
		t.Helper()
		analyzer := New(6)
		for i := range addresses {
			index := i
			if reverse {
				index = len(addresses) - 1 - i
			}
			analyzer.ObserveIPv4(mac, addresses[index], dst, 61)
		}
		report, err := analyzer.Report(mac)
		if err != nil {
			t.Fatal(err)
		}
		return report
	}
	report := build(false)
	if reversed := build(true); !reflect.DeepEqual(report, reversed) {
		t.Fatal("report depends on observation order")
	}
	_, prefix, err := net.ParseCIDR(report.Overall.Prefix)
	if err != nil {
		t.Fatal(err)
	}
	reference := net.ParseIP(report.Overall.Reference).To4()
	var expected uint32
	for _, address := range addresses {
		if !prefix.Contains(address) {
			t.Fatalf("%s not covered by %s", address, prefix)
		}
		expected |= binary.BigEndian.Uint32(reference) ^ binary.BigEndian.Uint32(address.To4())
	}
	actual := binary.BigEndian.Uint32(net.ParseIP(report.Overall.VarianceMask).To4())
	if actual != expected {
		t.Fatalf("variance %08x, want %08x", actual, expected)
	}
	for _, bit := range report.Overall.Bits {
		var count uint64
		for _, ttl := range bit.TTL {
			count += ttl.Zero + ttl.One
		}
		if count != uint64(len(addresses)) {
			t.Fatalf("bit %d has %d observations", bit.Position, count)
		}
	}
}
