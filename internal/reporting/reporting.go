// Package reporting renders a completed session into human- and
// machine-readable reports. It is transport- and policy-free: given a session
// it produces deterministic terminal, markdown, HTML, JSON and YAML output.
package reporting

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// Format enumerates supported report renderers.
type Format string

const (
	FormatTerminal Format = "terminal"
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
	FormatJSON     Format = "json"
	FormatYAML     Format = "yaml"
)

// ParseFormat maps a string to a Format.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(s)) {
	case FormatTerminal, FormatMarkdown, FormatHTML, FormatJSON, FormatYAML:
		return Format(strings.ToLower(s)), nil
	default:
		return "", fmt.Errorf("unsupported report format %q", s)
	}
}

// Render produces the report for a session in the given format.
func Render(s *models.Session, format Format) (string, error) {
	switch format {
	case FormatJSON:
		return renderJSON(s)
	case FormatYAML:
		return renderYAML(s)
	case FormatMarkdown:
		return renderMarkdown(s), nil
	case FormatHTML:
		return renderHTML(s), nil
	default:
		return renderTerminal(s), nil
	}
}

func renderJSON(s *models.Session) (string, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func renderYAML(s *models.Session) (string, error) {
	data, err := yaml.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func renderTerminal(s *models.Session) string {
	var b strings.Builder
	writef(&b, "shaka assessment report")
	writef(&b, "  session:  %s", s.ID)
	writef(&b, "  target:   %s", s.TargetID)
	writef(&b, "  profile:  %s", orDash(s.Profile))
	writef(&b, "  started:  %s", s.Start.Format(time.RFC3339))
	if !s.End.IsZero() {
		writef(&b, "  finished: %s", s.End.Format(time.RFC3339))
	}
	writef(&b, "  risk:     %s (%s)", s.RiskLevel, scoreDisplay(s.RiskScore))

	writef(&b, "")
	writef(&b, "discovered objects")
	writef(&b, "  domains            %d", len(s.Domains))
	writef(&b, "  domain controllers %d", len(s.DCS))
	writef(&b, "  users              %d", len(s.Users))
	writef(&b, "  groups             %d", len(s.Groups))
	writef(&b, "  computers          %d", len(s.Computers))
	writef(&b, "  organizational units %d", len(s.OUs))
	writef(&b, "  trusts             %d", len(s.Trusts))

	writef(&b, "")
	writef(&b, "relationship graph")
	writef(&b, "  nodes %d, edges %d", len(s.Nodes), len(s.Edges))

	if len(s.Findings) > 0 {
		writef(&b, "")
		writef(&b, "findings (%d)", len(s.Findings))
		for _, f := range s.Findings {
			writef(&b, "  [%s] %s (%s)", f.Severity, f.Title, f.RuleID)
			writef(&b, "      confidence=%s fp=%s", f.Confidence, f.Fingerprint())
		}
	}
	if len(s.Evidence) > 0 {
		writef(&b, "")
		writef(&b, "evidence (%d items)", len(s.Evidence))
	}
	return b.String()
}

func renderMarkdown(s *models.Session) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# shaka assessment report\n\n")
	fmt.Fprintf(&b, "| field | value |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| session | `%s` |\n", s.ID)
	fmt.Fprintf(&b, "| target | `%s` |\n", s.TargetID)
	fmt.Fprintf(&b, "| profile | %s |\n", orDash(s.Profile))
	fmt.Fprintf(&b, "| started | %s |\n", s.Start.Format(time.RFC3339))
	fmt.Fprintf(&b, "| risk | **%s** (%s) |\n", s.RiskLevel, scoreDisplay(s.RiskScore))
	b.WriteString("\n## Discovered objects\n\n")
	fmt.Fprintf(&b, "- domains: %d\n", len(s.Domains))
	fmt.Fprintf(&b, "- domain controllers: %d\n", len(s.DCS))
	fmt.Fprintf(&b, "- users: %d\n", len(s.Users))
	fmt.Fprintf(&b, "- groups: %d\n", len(s.Groups))
	fmt.Fprintf(&b, "- computers: %d\n", len(s.Computers))
	fmt.Fprintf(&b, "- organizational units: %d\n", len(s.OUs))
	fmt.Fprintf(&b, "- trusts: %d\n", len(s.Trusts))

	if len(s.Findings) > 0 {
		fmt.Fprintf(&b, "\n## Findings (%d)\n\n", len(s.Findings))
		b.WriteString("| severity | rule | title | confidence |\n| --- | --- | --- | --- |\n")
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "| %s | `%s` | %s | %s |\n", f.Severity, f.RuleID, f.Title, f.Confidence)
		}
	}
	return b.String()
}

func renderHTML(s *models.Session) string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>shaka report</title>")
	b.WriteString("<style>body{font-family:sans-serif;margin:2em}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:4px 8px;text-align:left}</style>")
	b.WriteString("</head><body>\n")
	fmt.Fprintf(&b, "<h1>shaka assessment report</h1>\n")
	fmt.Fprintf(&b, "<p>session <code>%s</code> · target <code>%s</code> · risk <b>%s</b> (%s)</p>\n",
		html.EscapeString(s.ID), html.EscapeString(s.TargetID), html.EscapeString(s.RiskLevel), scoreDisplay(s.RiskScore))
	fmt.Fprintf(&b, "<h2>Discovered objects</h2>\n<table>\n<tr><th>domains</th><th>DCs</th><th>users</th><th>groups</th><th>computers</th><th>OUs</th><th>trusts</th></tr>\n")
	fmt.Fprintf(&b, "<tr><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td></tr>\n</table>\n",
		len(s.Domains), len(s.DCS), len(s.Users), len(s.Groups), len(s.Computers), len(s.OUs), len(s.Trusts))
	if len(s.Findings) > 0 {
		fmt.Fprintf(&b, "<h2>Findings (%d)</h2>\n<table>\n<tr><th>severity</th><th>rule</th><th>title</th></tr>\n", len(s.Findings))
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "<tr><td>%s</td><td><code>%s</code></td><td>%s</td></tr>\n",
				html.EscapeString(string(f.Severity)), html.EscapeString(f.RuleID), html.EscapeString(f.Title))
		}
		b.WriteString("</table>\n")
	}
	b.WriteString("</body></html>\n")
	return b.String()
}

func writef(b *strings.Builder, format string, args ...any) {
	fmt.Fprintf(b, format+"\n", args...)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func scoreDisplay(score int) string {
	if score == 0 {
		return "-"
	}
	return fmt.Sprintf("%d/100", score)
}
