package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseFormatAliases(t *testing.T) {
	cases := map[string]Format{
		"terminal": FormatTerminal,
		"table":    FormatTerminal,
		"text":     FormatTerminal,
		"json":     FormatJSON,
		"yaml":     FormatYAML,
		"markdown": FormatMarkdown,
		"md":       FormatMarkdown,
		"html":     FormatHTML,
		"MARKDOWN": FormatMarkdown,
	}
	for in, want := range cases {
		got, err := ParseFormat(in)
		if err != nil {
			t.Errorf("ParseFormat(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseFormat(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseFormatEmptyAndInvalid(t *testing.T) {
	if _, err := ParseFormat(""); err == nil {
		t.Fatal("empty format should error")
	}
	if _, err := ParseFormat("bogus"); err == nil {
		t.Fatal("invalid format should error")
	}
}

func TestPrintTableJSON(t *testing.T) {
	var buf bytes.Buffer
	p := New()
	p.SetWriter(&buf)
	p.SetFormat(FormatJSON)
	p.PrintTable([]string{"sam", "admin"}, [][]string{{"alice", "yes"}, {"bob", "no"}})
	var got []map[string]string
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("PrintTable JSON output invalid: %v", err)
	}
	if len(got) != 2 || got[0]["sam"] != "alice" || got[0]["admin"] != "yes" {
		t.Fatalf("unexpected JSON table: %+v", got)
	}
}

func TestPrintTableTerminalRendersContent(t *testing.T) {
	var buf bytes.Buffer
	p := New()
	p.SetWriter(&buf)
	p.SetColor(false)
	p.SetFormat(FormatTerminal)
	p.PrintTable([]string{"a", "b"}, [][]string{{"1", "2"}})
	s := buf.String()
	if !strings.Contains(s, "1") || !strings.Contains(s, "2") {
		t.Fatalf("terminal table missing content: %q", s)
	}
}
