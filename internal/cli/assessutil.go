package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-shaka/internal/assess"
	"github.com/QYVORA/qyvora-shaka/internal/config"
	"github.com/QYVORA/qyvora-shaka/internal/directory"
	errs "github.com/QYVORA/qyvora-shaka/internal/errors"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// dirOptions collects the directory connection flags shared by the
// assessment commands.
type dirOptions struct {
	endpoint string
	baseDN   string
	username string
	password string
	useTLS   bool
	insecure bool
	sim      bool
}

func (d dirOptions) empty() bool {
	return d.endpoint == "" && d.baseDN == "" && !d.sim
}

// buildDirectory constructs a directory service for the target, using the
// offline simulator when requested or a live LDAP connection otherwise.
func (a *appState) buildDirectory(opts dirOptions) (directory.Service, error) {
	if opts.sim {
		return directory.New(context.Background(), directory.Options{Sim: directory.Demo()})
	}
	timeout := config.DefaultTimeout
	if v := a.timeout; v != "" {
		if d, err := parseDuration(v); err == nil {
			timeout = d
		}
	}
	return directory.New(context.Background(), directory.Options{
		Endpoint: opts.endpoint, BaseDN: opts.baseDN,
		Username: opts.username, Password: opts.password,
		UseTLS: opts.useTLS, Insecure: opts.insecure, Timeout: timeout,
	})
}

// establishTarget resolves the target for a command: the offline simulator
// always yields an authorized demo target; explicitly supplied connection
// flags are preferred; otherwise the current selected target is used.
func (a *appState) establishTarget(cmd *cobra.Command, opts dirOptions) (*models.Target, error) {
	if opts.sim {
		// The offline demo simulator is inherently safe: it requires no live
		// directory and performs no network I/O, so it is always authorized.
		t := &models.Target{
			Type: models.TargetDomain, Name: "demo:corp.example.com",
			Domain: "corp.example.com", Profile: "standard",
		}
		t.Auth = models.Authorization{
			Granted:   true,
			Scope:     "authorized Active Directory security assessment of " + t.DisplayName(),
			Method:    "demo",
			GrantedBy: userName(),
		}
		return t, nil
	}
	if !opts.empty() {
		t := &models.Target{
			Type: models.TargetDomain, Address: opts.endpoint,
			BaseDN: opts.baseDN, Username: opts.username, Password: opts.password,
			Profile: "standard",
		}
		if t.Domain == "" {
			t.Domain = opts.endpoint
		}
		return a.authorize(cmd, t)
	}
	t, err := a.requireTarget()
	if err != nil {
		return nil, err
	}
	return a.authorize(cmd, t)
}

func parseDuration(s string) (time.Duration, error) { return time.ParseDuration(s) }

// runAssessment runs the pipeline for a target and returns the finished
// session, persisting it to the store.
func (a *appState) runAssessment(ctx context.Context, cmd *cobra.Command, opts dirOptions, aopts assess.Options) (*models.Session, error) {
	t, err := a.establishTarget(cmd, opts)
	if err != nil {
		return nil, err
	}
	if a.dryRun {
		a.emitf("dry-run: would assess target %s", t.DisplayName())
		return nil, nil
	}

	dir, err := a.buildDirectory(opts)
	if err != nil {
		return nil, errs.NewExitError(1, fmt.Sprintf("connecting to directory: %v", err))
	}
	defer dir.Close()

	runner := assess.New(dir, t, a.log, a.cfg)
	runner.Options = aopts
	if a.eventSink != nil {
		runner.Options.EventsWriter = a.eventSink
	}
	res, err := runner.Run(ctx)
	if err != nil {
		return res.Session, errs.WrapExitError(1, "assessment failed", err)
	}
	if _, err := a.persistSession(res.Session); err != nil {
		return res.Session, errs.WrapExitError(1, "persisting session", err)
	}
	return res.Session, nil
}
