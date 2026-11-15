package reporter

import (
	"encoding/json"
	"io"

	"github.com/databeast/goatherd/internal/discovery"
)

// WriteJSON writes the complete discovery report as indented JSON.
func WriteJSON(w io.Writer, report discovery.Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
