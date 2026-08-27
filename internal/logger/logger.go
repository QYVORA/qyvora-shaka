// Package logger provides structured, leveled logging for shaka.
//
// Logs are kept conceptually separate from events, findings, reports and the
// terminal UI. Machine-readable output is produced by the output package; the
// event stream is produced by the events package.
package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// Level orders logging verbosity.
type Level int

const (
	// LevelSilent suppresses all output.
	LevelSilent Level = iota
	LevelError
	LevelWarn
	LevelInfo
	LevelDebug
)

var levelNames = map[Level]string{
	LevelError: "ERROR",
	LevelWarn:  "WARN",
	LevelInfo:  "INFO",
	LevelDebug: "DEBUG",
}

// ParseLevel converts a case-insensitive level name into a Level. Unknown
// names default to LevelInfo so configuration typos degrade to a usable log.
func ParseLevel(s string) Level {
	switch strings.ToLower(s) {
	case "silent":
		return LevelSilent
	case "error":
		return LevelError
	case "warn":
		return LevelWarn
	case "debug":
		return LevelDebug
	default:
		return LevelInfo
	}
}

// Logger writes leveled lines to an io.Writer. It is safe for concurrent use.
type Logger struct {
	mu      sync.Mutex
	w       io.Writer
	level   Level
	verbose bool
	quiet   bool
}

// New returns a logger writing to stderr at the info level.
func New() *Logger {
	return &Logger{w: os.Stderr, level: LevelInfo}
}

// SetWriter sets the output writer.
func (l *Logger) SetWriter(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.w = w
}

// SetLevel sets the minimum level that is emitted.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetVerbose toggles extra diagnostic output.
func (l *Logger) SetVerbose(v bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.verbose = v
}

// SetQuiet suppresses informational progress output below warn.
func (l *Logger) SetQuiet(q bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.quiet = q
}

// Errorf logs at the error level.
func (l *Logger) Errorf(format string, args ...any) { l.log(LevelError, format, args...) }

// Warnf logs at the warn level.
func (l *Logger) Warnf(format string, args ...any) { l.log(LevelWarn, format, args...) }

// Infof logs at the info level.
func (l *Logger) Infof(format string, args ...any) { l.log(LevelInfo, format, args...) }

// Debugf logs at the debug level.
func (l *Logger) Debugf(format string, args ...any) { l.log(LevelDebug, format, args...) }

func (l *Logger) log(level Level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if level > l.level {
		return
	}
	if level < LevelWarn && l.quiet && !l.verbose {
		return
	}
	name, ok := levelNames[level]
	if !ok {
		name = "INFO"
	}
	fmt.Fprintf(l.w, "[shaka][%s] %s\n", name, fmt.Sprintf(format, args...))
}
