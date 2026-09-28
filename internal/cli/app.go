package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/viper"

	errs "github.com/QYVORA/qyvora-shaka/internal/errors"
	"github.com/QYVORA/qyvora-shaka/internal/events"
	"github.com/QYVORA/qyvora-shaka/internal/logger"
	"github.com/QYVORA/qyvora-shaka/internal/output"
	"github.com/QYVORA/qyvora-shaka/internal/session"
	"github.com/QYVORA/qyvora-shaka/internal/target"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// app is the shared state wired once per process and used by every command.
type appState struct {
	cfg     *viper.Viper
	log     *logger.Logger
	printer *output.Printer
	targets *target.Manager
	store   *session.Store

	eventStream *events.Stream
	eventSink   io.Writer

	cfgFile   string
	verbose   bool
	quiet     bool
	jsonOut   bool
	outputFmt string
	eventsF   string
	dryRun    bool
	timeout   string

	// initErr surfaces fatal config/flag errors from cobra's OnInitialize.
	initErr error
}

func newAppState() *appState {
	return &appState{}
}

// requireTarget returns the current authorized target.
func (a *appState) requireTarget() (*models.Target, error) {
	t := a.targets.Current()
	if t == nil {
		return nil, errs.NewExitError(2, "no target selected; run 'shaka target set' first")
	}
	if !t.Authorized() {
		return nil, errs.NewExitError(2, "current target is not authorized: "+t.DisplayName())
	}
	return t, nil
}

// persistSession saves a session to the store and records the path.
func (a *appState) persistSession(sess *models.Session) (string, error) {
	path, err := a.store.Save(sess)
	if err != nil {
		return "", err
	}
	sess.OutputDir = a.store.Dir()
	return path, nil
}

func (a *appState) emitf(format string, args ...any) {
	fmt.Fprintf(a.printer.Writer(), format+"\n", args...)
}

// resolveEvents configures the event stream sink.
func (a *appState) resolveEvents(_ context.Context) error {
	var w io.Writer
	if eventsDisabled(a.eventsF) {
		return nil
	}
	switch strings.ToLower(a.eventsF) {
	case "stdout":
		w = os.Stdout
	case "stderr":
		w = os.Stderr
	default:
		// The destination is opened on the first event, not here. Creating it
		// eagerly meant a run that never emitted -- most visibly the
		// interactive session, which refuses a machine destination outright --
		// still left a truncated file behind, destroying whatever the path held
		// and then writing nothing to it.
		if err := checkEventsDir(a.eventsF); err != nil {
			return err
		}
		w = &lazyFile{path: a.eventsF}
	}
	a.eventStream = events.NewStream(w)
	a.eventSink = w
	return nil
}

// eventsDisabled reports whether a --events value asks for no stream at all.
//
// The interactive guard and the event plumbing both need this answer, so the
// words are named once. A value that turns the stream off must not read as a
// request to send it somewhere: `tool --events off` opens the session
// happily, because there is nothing for it to contradict.
func eventsDisabled(spec string) bool {
	switch strings.ToLower(spec) {
	case "", "off", "none", "disable", "disabled":
		return true
	}
	return false
}

// lazyFile opens its path on the first write, so a run that never emits an
// event never creates or truncates the destination.
//
// Events can be emitted from several goroutines at once, so the open and the
// write are serialised together: without that, two first events could both see
// a nil file and both open it, and the second would truncate the first's
// output.
type lazyFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

func (l *lazyFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		// Truncated, not appended, so one file holds exactly one run's
		// events. Appending left no run boundary in the file, which matters
		// to anything tailing it.
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return 0, fmt.Errorf("opening events file: %w", err)
		}
		l.f = f
	}
	return l.f.Write(p)
}

// Close is a no-op when nothing was ever written, so a run that created no
// file also has no descriptor to close.
func (l *lazyFile) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}

// checkEventsDir reports an unusable destination early, before the run does any
// work. It only proves the directory exists: the file itself is created on the
// first event, so a path that is merely unwritable still fails at that point.
func checkEventsDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("events file: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("events file: %s is not a directory", dir)
	}
	return nil
}
