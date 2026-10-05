// Package banner provides the canonical SHAKA brand banner.
//
// The art below is generated from the tool name with `figlet -f slant` and is
// kept byte-for-byte in shaka-banner.txt in the tools repository root, so a
// plain-text copy exists that does not depend on this build.
//
// Art is deliberately plain: it is safe to write to a file, a log or a
// machine-readable stream. Render applies the QYVORA brand green for terminal
// output only, and degrades gracefully when the terminal cannot show it.
//
// Every surface of the tool renders this banner; never substitute custom art
// or a hand-written wordmark.
package banner

import (
	"os"

	"github.com/muesli/termenv"
)

// Green is the QYVORA brand accent, the colour every tool banner is drawn in.
const Green = "#06B66F"

// Art is the canonical SHAKA ASCII art banner.
const Art = `         __          __        
   _____/ /_  ____ _/ /______ _
  / ___/ __ \/ __ ` + "`" + `/ //_/ __ ` + "`" + `/
 (__  ) / / / /_/ / ,< / /_/ / 
/____/_/ /_/\__,_/_/|_|\__,_/  
                               
`

// Width is the widest row of Art, in columns.
//
// A caller that has to decide whether the banner fits before drawing it reads
// this rather than counting the art itself. It is generated with the art, so
// it cannot drift away from the constants above it.
const Width = 31

// Colorize returns s in the QYVORA brand green.
//
// The colour is resolved per call from the environment so a NO_COLOR request
// or a terminal without truecolor is honoured rather than assumed away: when
// the profile cannot show the brand colour s is returned unchanged.
//
// Callers that print the banner a line at a time, or crop the leading and
// trailing blank rows, use this rather than Render so the escape codes land on
// the rows actually drawn.
func Colorize(s string) string {
	if s == "" {
		return s
	}
	profile := termenv.EnvColorProfile()
	if profile == termenv.Ascii {
		return s
	}
	return termenv.String(s).Foreground(profile.Color(Green)).String()
}

// Render returns the whole banner in the QYVORA brand green.
func Render() string {
	return Colorize(Art)
}

// Print writes Render to stdout.
func Print() {
	_, _ = os.Stdout.WriteString(Render())
}
