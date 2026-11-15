package reporter

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/databeast/goatherd/internal/discovery"
)

func TestWriteJSONPreservesEncoding(t *testing.T) {
	report := discovery.Report{UpstreamMAC: "02:00:00:00:00:01", ForwardedPackets: 3}
	var expected, actual bytes.Buffer
	encoder := json.NewEncoder(&expected)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&actual, report); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual.Bytes(), expected.Bytes()) {
		t.Fatalf("encoding changed:\n%s", actual.String())
	}
	if err := WriteJSON(failingWriter{}, report); !errors.Is(err, errWrite) {
		t.Fatalf("got %v, want write error", err)
	}
}
