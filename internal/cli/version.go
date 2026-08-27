package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-shaka/internal/version"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print shaka version and build information",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			printVersion(version.GetInfo())
			return nil
		},
	}
}

func printVersion(i version.Info) {
	switch app.printer.Format() {
	case outputFormatJSON, outputFormatYAML:
		app.printer.Print(i)
	default:
		fmt.Fprintf(app.printer.Writer(), "shaka %s\n", version.String())
		fmt.Fprintf(app.printer.Writer(), "  framework:  %s\n", i.Framework)
		fmt.Fprintf(app.printer.Writer(), "  commit:     %s\n", shortCommit(i.Commit))
		fmt.Fprintf(app.printer.Writer(), "  built:      %s\n", emptyDash(i.Date))
		fmt.Fprintf(app.printer.Writer(), "  by:         %s\n", emptyDash(i.BuildUser))
		fmt.Fprintf(app.printer.Writer(), "  go:         %s %s/%s\n", i.GoVersion, i.OS, i.Arch)
	}
}

func shortCommit(c string) string {
	if c == "" {
		return "-"
	}
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

const (
	outputFormatJSON = "json"
	outputFormatYAML = "yaml"
	outputFormatHTML = "html"
	outputFormatMD   = "markdown"
	outputFormatTerm = "terminal"
)
