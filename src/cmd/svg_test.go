package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRunSVG(t *testing.T) {
	report := `{"@type":"schema:Dataset","name":"Goatherd network discovery report","overall":{"candidate_prefix":"10.0.0.0/24"},"hop_layers":[]}`
	path := filepath.Join(t.TempDir(), "report.jsonld")
	if err := os.WriteFile(path, []byte(report), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{nil, {"-"}, {path}} {
		command := &cobra.Command{}
		command.SetIn(strings.NewReader(report))
		var out bytes.Buffer
		command.SetOut(&out)
		if err := runSVG(command, args); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "10.0.0.0/24") {
			t.Fatalf("missing candidate: %s", out.String())
		}
	}
	if err := runSVG(&cobra.Command{}, []string{filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("missing input file accepted")
	}
}
