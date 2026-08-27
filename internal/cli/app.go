package cli

import (
	"context"
	"fmt"
	"io"
	"os"

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
func (a *appState) resolveEvents(ctx context.Context) error {
	var w io.Writer
	switch a.eventsF {
	case "", "off":
		return nil
	case "stdout":
		w = os.Stdout
	case "stderr":
		w = os.Stderr
	default:
		f, err := os.OpenFile(a.eventsF, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("opening events file: %w", err)
		}
		w = f
	}
	a.eventStream = events.NewStream(w)
	a.eventSink = w
	return nil
}
