// Package banner provides the canonical shaka brand banner (ASCII art).
//
// The art below is the exact byte-for-byte content of the single source of
// truth for the brand mark. Every surface of the tool (console, reports)
// renders this banner.
package banner

// Art is the shaka brand mark: a minimalist shield / identity mark evoking
// the shield of the Zulu warrior and the structure of a directory tree. It is
// monochrome-compatible and clean at small sizes.
const Art = `
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
       ▄█████████████████████████████████████████████████
     ▄█▀      ▀█▀      ▀█████      ▀█▀      ▀█▀      ▀██▄
    █▀         █         ████        █         █         ▀█
   █▀          █          ▀█▀        █          █          ▀█
  █            █           █         █           █           █
  █▄            █          █         █           █           ▄█
   █▄            █       ▄█▀▀█▄      █           █          ▄█▀
    █▄            █      █▀   █      █           █         ▄█▀
     ██▄           █▄    █     █    ▄█          ▄█        ▄██
      ▀██▄          █▄    ▀█▄▄▄█▀   ▄█         ▄█        ▄██▀
        ▀███▄▄▄▄▄▄▄▄▄████████████████▄▄▄▄▄▄▄▄▄▄█████████▀
           ▀███████████████████████████████████████████▀
`

// Wordmark is the text banner used by the CLI when a full terminal is
// desired. It mirrors the ASCII wordmark style of the ecosystem.
const Wordmark = ` _  _    ___
| || |  / __|
| __ | | (__
|_||_|  \___|
`
