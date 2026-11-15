package capture

import (
	"reflect"
	"sort"
	"testing"
)

func TestIPMapList(t *testing.T) {
	addresses := ipmap{
		10:  {0: {1: 2, 2: 3}, 1: {0: 4}},
		192: {168: {1: 1}},
	}
	got := addresses.List()
	sort.Strings(got)
	want := []string{"10.0.1.2", "10.0.2.3", "10.1.0.4", "192.168.1.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if len((ipmap{}).List()) != 0 {
		t.Fatal("empty map returned addresses")
	}
}

func TestNewCapturePointInitializesMapping(t *testing.T) {
	point, err := NewCapturePoint()
	if err != nil {
		t.Fatal(err)
	}
	if point == nil || point.macmappings == nil || point.mapmu == nil {
		t.Fatalf("capture point not initialized: %+v", point)
	}
}
