package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/QYVORA/qyvora-shaka/internal/banner"
)

// ANSI style codes.
// Brand Royal Blue #0171D7 (RGB 1, 113, 215)
// Brand Shield Gold #D4AF37 (RGB 212, 175, 55)
// Cyan Highlight #00A3FF (RGB 0, 163, 255)
const (
	ansiReset = "\x1b[0m"
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
	ansiRed   = "\x1b[31m"
	ansiAmber = "\x1b[33m"
	ansiWhite = "\x1b[37m"
	ansiBlue  = "\x1b[38;2;1;113;215m"
	ansiGold  = "\x1b[38;2;212;175;55m"
	ansiCyan  = "\x1b[38;2;0;163;255m"
)

const consoleSectionWidth = 60

// consoleUI renders styled output for the interactive console.
type consoleUI struct {
	w     io.Writer
	color bool
	width int
}

func newConsoleUI(w io.Writer) *consoleUI {
	u := &consoleUI{w: w, width: consoleSectionWidth}
	if os.Getenv("NO_COLOR") == "" {
		u.color = writerIsTerminal(w)
	}
	return u
}

func (u *consoleUI) Enabled() bool { return u.color }

func (u *consoleUI) paint(s, code string) string {
	if !u.color || s == "" {
		return s
	}
	return code + s + ansiReset
}

func (u *consoleUI) Blue(s string) string      { return u.paint(s, ansiBlue) }
func (u *consoleUI) BoldBlue(s string) string  { return u.paint(s, ansiBold+ansiBlue) }
func (u *consoleUI) Gold(s string) string      { return u.paint(s, ansiGold) }
func (u *consoleUI) BoldGold(s string) string  { return u.paint(s, ansiBold+ansiGold) }
func (u *consoleUI) Cyan(s string) string      { return u.paint(s, ansiCyan) }
func (u *consoleUI) Red(s string) string       { return u.paint(s, ansiRed) }
func (u *consoleUI) Amber(s string) string     { return u.paint(s, ansiAmber) }
func (u *consoleUI) White(s string) string     { return u.paint(s, ansiWhite) }
func (u *consoleUI) BoldWhite(s string) string { return u.paint(s, ansiBold+ansiWhite) }
func (u *consoleUI) DimWhite(s string) string  { return u.paint(s, ansiDim+ansiWhite) }

func (u *consoleUI) Section(title string) {
	label := strings.TrimSpace(title)
	if label == "" {
		_, _ = fmt.Fprintln(u.w)
		return
	}
	_, _ = fmt.Fprintf(u.w, "\n  %s\n", u.BoldBlue(strings.ToUpper(label)))
}

func (u *consoleUI) Rule() {
	_, _ = fmt.Fprintln(u.w)
}

// kvLabelWidth is the fixed visible width used for "key: value" labels so the
// values of consecutive KV lines always line up in a column.
const kvLabelWidth = 22

func (u *consoleUI) KV(key, value string) {
	_, _ = fmt.Fprintf(u.w, "  %s %s\n", padTo(u.BoldWhite(key+":"), kvLabelWidth), u.White(value))
}

func (u *consoleUI) Glyph(glyph string) string {
	switch glyph {
	case "+":
		return u.paint("[+]", ansiBold+ansiBlue)
	case "*":
		return u.paint("[*]", ansiBold+ansiGold)
	case "!":
		return u.paint("[!]", ansiBold+ansiAmber)
	case "x", "X":
		return u.paint("[x]", ansiBold+ansiRed)
	case ">":
		return u.paint("[>]", ansiBold+ansiWhite)
	case "v":
		return u.paint("[v]", ansiDim+ansiWhite)
	case "-":
		return u.paint("[-]", ansiDim+ansiWhite)
	default:
		return u.paint("["+glyph+"]", ansiBold+ansiWhite)
	}
}

func (u *consoleUI) Status(glyph, format string, args ...any) {
	_, _ = fmt.Fprintf(u.w, "  %s %s\n", u.Glyph(glyph), u.White(fmt.Sprintf(format, args...)))
}

func (u *consoleUI) Err(format string, args ...any) {
	_, _ = fmt.Fprintf(u.w, "  %s %s\n", u.Glyph("x"), u.paint(fmt.Sprintf(format, args...), ansiBold+ansiRed))
}

func (u *consoleUI) Prompt(name string) string {
	return u.paint(name, ansiBold+ansiBlue) + u.paint(" > ", ansiBold+ansiWhite)
}

// bannerGlyph is gone. It mapped '@', '#' and '%' to blue, '*' and '+' to gold
// and the punctuation to cyan, a palette that belonged to the hand-drawn emblem
// this banner no longer uses. ansiBlue, ansiGold and ansiCyan stay: they are
// this console's general accents and are used by the prompt and the footers.

// Banner prints the canonical brand banner followed by the tagline, in the
// QYVORA accent.
//
// The colour comes from banner.Colorize, which is the single place the accent
// is defined, but the console's own colour decision still wins: when colours
// are off the plain art is printed even on a terminal that could show it, so
// NO_COLOR is honoured by this surface too.
func (u *consoleUI) Banner(tagline string) {
	fmt.Fprintln(u.w)
	for _, line := range banner.RenderCLI() {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if u.color {
			line = banner.Colorize(line)
		}
		fmt.Fprintln(u.w, line)
	}
	fmt.Fprintln(u.w)
	if tagline != "" {
		fmt.Fprintln(u.w, u.White("  "+tagline))
	}
	fmt.Fprintln(u.w, u.Blue("  QYVORA — https://qyvora.org"))
	fmt.Fprintln(u.w)
}

func (u *consoleUI) BannerFoot(ver string) {
	u.Status(">", "v %s", ver)
	fmt.Fprintln(u.w, u.DimWhite("  type 'help' for commands, 'exit' to leave."))
	fmt.Fprintln(u.w)
}

func (u *consoleUI) HUD(target, profile, cwd, ver string) {
	if !u.color {
		return
	}
	if target == "" {
		target = "sim:demo"
	}
	if profile == "" {
		profile = "full"
	}
	if cwd == "" {
		cwd = "?"
	}
	kv := func(k, v string) string {
		return u.DimWhite(k+" ") + u.White(v)
	}
	left := kv("target", target) + u.DimWhite("  ·  ") + kv("profile", profile) + u.DimWhite("  ·  ") + kv("cwd", cwd)
	right := u.Gold("v " + ver)

	cols := u.width
	if cols < 20 {
		cols = 80
	}
	pad := cols - runeWidth(left) - runeWidth(right) - 1
	if pad < 1 {
		pad = 1
	}
	fmt.Fprintf(u.w, "%s %s%s\n", u.paint("▮", ansiBold+ansiBlue), left, strings.Repeat(" ", pad)+right)
}

func (u *consoleUI) Table(headers []string, rows [][]string) {
	if len(headers) == 0 {
		return
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = runeWidth(h)
	}
	for _, r := range rows {
		for i := 0; i < len(headers) && i < len(r); i++ {
			if l := runeWidth(r[i]); l > widths[i] {
				widths[i] = l
			}
		}
	}

	var b strings.Builder
	for i, h := range headers {
		if i > 0 {
			b.WriteString("  ")
		}
		b.WriteString(padTo(u.BoldWhite(h), widths[i]))
	}
	fmt.Fprintln(u.w, b.String())

	for _, r := range rows {
		var rb strings.Builder
		for i := 0; i < len(headers); i++ {
			if i > 0 {
				rb.WriteString("  ")
			}
			var cell string
			if i < len(r) {
				cell = r[i]
			}
			rb.WriteString(padTo(u.White(cell), widths[i]))
		}
		fmt.Fprintln(u.w, rb.String())
	}
}

func runeWidth(s string) int {
	if strings.Contains(s, "\x1b") {
		s = stripANSI(s)
	}
	n := 0
	for _, r := range s {
		if isWideRune(r) {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func isWideRune(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115F,
		r >= 0x2329 && r <= 0x232A,
		r >= 0x2E80 && r <= 0xA4CF,
		r >= 0xAC00 && r <= 0xD7A3,
		r >= 0xF900 && r <= 0xFAFF,
		r >= 0xFE10 && r <= 0xFE19,
		r >= 0xFE30 && r <= 0xFE6F,
		r >= 0xFF00 && r <= 0xFF60,
		r >= 0xFFE0 && r <= 0xFFE6,
		r >= 0x1F300 && r <= 0x1F64F,
		r >= 0x1F900 && r <= 0x1F9FF:
		return true
	}
	return false
}

func stripANSI(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\x1b' {
			j := i + 1
			for j < len(s) && s[j] != 'm' {
				j++
			}
			if j < len(s) {
				j++
			}
			i = j
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

func padTo(s string, n int) string {
	pad := n - runeWidth(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

func writerIsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
