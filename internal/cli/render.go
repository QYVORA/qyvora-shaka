package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/QYVORA/qyvora-shaka/internal/output"
	"github.com/QYVORA/qyvora-shaka/internal/reporting"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// renderSession renders a completed session in the active output format.
func renderSession(ctx context.Context, s *models.Session) error {
	if s == nil {
		return nil
	}
	switch app.printer.Format() {
	case output.FormatJSON, output.FormatYAML, output.FormatHTML, output.FormatMarkdown:
		_ = ctx
		return printSessionAs(s, app.printer.Format())
	default:
		printTerminalSession(s)
	}
	return nil
}

// renderObjectSlice prints a specific discovered-object collection.
func renderObjectSlice(ctx context.Context, s *models.Session, object string) error {
	if app.printer.Format() != output.FormatTerminal {
		return printSessionAs(s, app.printer.Format())
	}
	_ = ctx
	switch object {
	case "users":
		app.printer.PrintTable([]string{"sam", "name", "upn", "enabled", "admin"}, userRows(s.Users))
	case "groups":
		app.printer.PrintTable([]string{"sam", "name", "security", "admin", "members"}, groupRows(s.Groups))
	case "computers":
		app.printer.PrintTable([]string{"name", "os", "dns", "enabled"}, computerRows(s.Computers))
	case "ous":
		app.printer.PrintTable([]string{"name", "dn"}, ouRows(s.OUs))
	case "trusts":
		app.printer.PrintTable([]string{"source", "target", "direction", "type"}, trustRows(s.Trusts))
	default:
		printCounts(s)
	}
	return nil
}

// printSessionAs prints the whole session via the reporting renderers.
func printSessionAs(s *models.Session, format output.Format) error {
	rpt, err := reporting.Render(s, reporting.Format(format))
	if err != nil {
		return err
	}
	fmt.Fprintln(app.printer.Writer(), rpt)
	return nil
}

func printTerminalSession(s *models.Session) {
	printCounts(s)
	app.emitf("")
	app.emitf("graph nodes: %d, edges: %d", len(s.Nodes), len(s.Edges))
	app.emitf("risk: %s (%s)", s.RiskLevel, scoreOrDash(s.RiskScore))
	if len(s.Findings) > 0 {
		app.emitf("")
		app.emitf("findings (%d):", len(s.Findings))
		for _, f := range s.Findings {
			app.emitf("  [%s] %s (%s)", f.Severity, f.Title, f.RuleID)
		}
	}
}

func printCounts(s *models.Session) {
	app.emitf("session %s target=%s profile=%s", s.ID, orDash(s.TargetID), orDash(s.Profile))
	app.emitf("domains=%d dcs=%d users=%d groups=%d computers=%d ous=%d trusts=%d",
		len(s.Domains), len(s.DCS), len(s.Users), len(s.Groups), len(s.Computers), len(s.OUs), len(s.Trusts))
}

// renderFindings prints the findings table.
func renderFindings(s *models.Session) error {
	app.printer.PrintTable(
		[]string{"severity", "rule", "title", "confidence", "target"},
		findingRows(s.Findings),
	)
	return nil
}

// renderEvidence prints the evidence table.
func renderEvidence(s *models.Session) error {
	app.printer.PrintTable(
		[]string{"id", "type", "hash", "source"},
		evidenceRows(s.Evidence),
	)
	return nil
}

// renderGraph prints the relationship graph as an edge list.
func renderGraph(s *models.Session) error {
	app.printer.PrintTable(
		[]string{"from", "type", "to", "confidence"},
		edgeRows(s.Edges),
	)
	return nil
}

// writeReport renders a report in the given format to a file or stdout.
func writeReport(s *models.Session, format string, out string) error {
	rptFmt, err := output.ParseFormat(format)
	if err != nil {
		return err
	}
	rpt, err := reporting.Render(s, reporting.Format(rptFmt))
	if err != nil {
		return err
	}
	if out == "" {
		fmt.Fprintln(app.printer.Writer(), rpt)
		return nil
	}
	return os.WriteFile(out, []byte(rpt), 0o644)
}

func scoreOrDash(score int) string {
	if score == 0 {
		return "-"
	}
	return fmt.Sprintf("%d/100", score)
}
