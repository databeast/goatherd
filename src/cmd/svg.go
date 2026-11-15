package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/databeast/goatherd/reporter"
	"github.com/spf13/cobra"
)

func runSVG(cmd *cobra.Command, args []string) error {
	var input io.Reader = cmd.InOrStdin()
	if len(args) == 1 && args[0] != "-" {
		file, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("open JSON-LD report: %w", err)
		}
		defer file.Close()
		input = file
	}
	return reporter.WriteSummarySVG(cmd.OutOrStdout(), input)
}

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "svg [report.jsonld|-]",
		Short: "render a standalone JSON-LD summary as SVG",
		Long:  "Render a standalone JSON-LD summary as SVG on standard output. Read standard input when no file or - is specified.",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runSVG,
	})
}
