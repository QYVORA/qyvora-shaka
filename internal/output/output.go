// Package output renders structured data to the terminal or as machine
// readable JSON/YAML. The terminal renderer is a presentation layer only; it
// is never the source of truth — the underlying models are.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	yaml "go.yaml.in/yaml/v3"
)

// Format is a supported output format.
type Format string

const (
	FormatTerminal Format = "terminal"
	FormatJSON     Format = "json"
	FormatYAML     Format = "yaml"
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
)

// ParseFormat resolves a user-supplied output format name. The legacy names
// "table" and "text" normalize to "terminal". Unknown formats return a useful
// error rather than being silently accepted.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case FormatTerminal, "table", "text":
		return FormatTerminal, nil
	case FormatJSON:
		return FormatJSON, nil
	case FormatYAML:
		return FormatYAML, nil
	case FormatMarkdown, "md":
		return FormatMarkdown, nil
	case FormatHTML:
		return FormatHTML, nil
	}
	return "", fmt.Errorf("invalid output format %q: valid values are terminal, json, yaml, markdown, html", s)
}

// Printer renders values in a configured format.
type Printer struct {
	writer io.Writer
	format Format
	color  bool
}

// New returns a terminal printer writing to stdout.
func New() *Printer {
	return &Printer{writer: os.Stdout, format: FormatTerminal, color: true}
}

// SetWriter sets the output writer.
func (p *Printer) SetWriter(w io.Writer) { p.writer = w }

// SetFormat sets the active format.
func (p *Printer) SetFormat(f Format) { p.format = f }

// SetColor toggles ANSI color.
func (p *Printer) SetColor(c bool) { p.color = c }

// Format returns the active format.
func (p *Printer) Format() Format { return p.format }

// Writer returns the underlying output writer.
func (p *Printer) Writer() io.Writer { return p.writer }

// Print renders v in the active format.
func (p *Printer) Print(v any) {
	switch p.format {
	case FormatJSON:
		p.printJSON(v)
	case FormatYAML:
		p.printYAML(v)
	default:
		_, _ = fmt.Fprintln(p.writer, v)
	}
}

// PrintTable renders a table, or a JSON array of objects in JSON mode.
func (p *Printer) PrintTable(header []string, rows [][]string) {
	if p.format == FormatJSON {
		entries := make([]map[string]string, len(rows))
		for i, row := range rows {
			entry := make(map[string]string)
			for j, h := range header {
				if j < len(row) {
					entry[h] = row[j]
				}
			}
			entries[i] = entry
		}
		p.printJSON(entries)
		return
	}
	if p.format == FormatYAML {
		entries := make([]map[string]string, len(rows))
		for i, row := range rows {
			entry := make(map[string]string)
			for j, h := range header {
				if j < len(row) {
					entry[h] = row[j]
				}
			}
			entries[i] = entry
		}
		p.printYAML(entries)
		return
	}

	colWidths := make([]int, len(header))
	for i, h := range header {
		colWidths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	headerColor := color.New(color.FgWhite, color.Bold)
	altRowColor := color.New(color.FgBlack, color.BgWhite)

	for i, h := range header {
		if i > 0 {
			_, _ = fmt.Fprint(p.writer, "  ")
		}
		_, _ = headerColor.Fprintf(p.writer, "%-*s", colWidths[i], h)
	}
	_, _ = fmt.Fprintln(p.writer)

	totalWidth := 0
	for i, w := range colWidths {
		if i > 0 {
			totalWidth += 2
		}
		totalWidth += w
	}
	_, _ = fmt.Fprintln(p.writer, strings.Repeat("─", totalWidth))

	for idx, row := range rows {
		for i, cell := range row {
			if i > 0 {
				_, _ = fmt.Fprint(p.writer, "  ")
			}
			if p.color && idx%2 == 1 {
				_, _ = altRowColor.Fprintf(p.writer, "%-*s", colWidths[i], cell)
			} else {
				_, _ = fmt.Fprintf(p.writer, "%-*s", colWidths[i], cell)
			}
		}
		_, _ = fmt.Fprintln(p.writer)
	}
}

func (p *Printer) printJSON(v any) {
	enc := json.NewEncoder(p.writer)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "json error: %v\n", err)
	}
}

func (p *Printer) printYAML(v any) {
	out, err := yaml.Marshal(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "yaml error: %v\n", err)
		return
	}
	_, _ = p.writer.Write(out)
}
