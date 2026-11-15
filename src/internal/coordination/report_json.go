package coordination

import (
	"encoding/json"
	"io"
)

type CaptureReport struct {
	CapturePoint string          `json:"capture_point"`
	ReportJson   json.RawMessage `json:"report,omitempty"`
	Error        string          `json:"error,omitempty"`
	StreamStatus string          `json:"stream_status"`
	StreamError  string          `json:"stream_error,omitempty"`
	QualityJson  json.RawMessage `json:"capture,omitempty"`
}

type ReportsResponse struct {
	Reports       []*CaptureReport
	InventoryJson []byte
}

// WriteReportsJSON writes the user-facing report array for both local and
// streamed reports.
func WriteReportsJSON(w io.Writer, response *ReportsResponse) error {
	reports := response.Reports
	if reports == nil {
		reports = []*CaptureReport{}
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(reports)
}
