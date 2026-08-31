package cli

import (
	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-shaka/internal/capabilities"
)

func newCapabilitiesCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "capabilities",
		Aliases: []string{"caps"},
		Short:   "List shaka's machine-readable capabilities",
		Args:    cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			printCapabilitiesTable()
		},
	}
}

func printCapabilitiesTable() {
	list := capabilities.Catalog()
	switch app.printer.Format() {
	case outputFormatJSON, outputFormatYAML:
		app.printer.Print(list)
	default:
		app.printer.PrintTable(
			[]string{"id", "name", "category", "risk", "auth", "confirm"},
			toRows(list),
		)
	}
}

func toRows(tools []capabilities.Tool) [][]string {
	rows := make([][]string, 0, len(tools))
	for _, t := range tools {
		rows = append(rows, []string{
			t.ID, t.Name, t.Category,
			string(t.Risk), yes(t.AuthRequired), yes(t.Confirm),
		})
	}
	return rows
}

func yes(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
