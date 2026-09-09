// Package cli implements the shaka command-line interface. The same binary is
// also the interactive console. The package wires configuration, logging,
// output formatting, the target manager and the assessment pipeline together
// and exposes the discovery/enumeration/analysis/reporting commands.
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-shaka/internal/config"
	errs "github.com/QYVORA/qyvora-shaka/internal/errors"
	"github.com/QYVORA/qyvora-shaka/internal/logger"
	"github.com/QYVORA/qyvora-shaka/internal/output"
	"github.com/QYVORA/qyvora-shaka/internal/session"
	"github.com/QYVORA/qyvora-shaka/internal/target"
	"github.com/QYVORA/qyvora-shaka/internal/version"
)

var app = newAppState()

const appDescription = `shaka is a terminal-first CLI for authorized Microsoft Active Directory
security assessment: discover, enumerate, correlate relationships, analyze
configurations, and produce evidence-driven reports.

Usage modes:
  shaka                                start the interactive console
  shaka assess --sim                   full pipeline against the offline demo directory
  shaka assess --endpoint dc:389 ...   full pipeline against a live authorized directory
  shaka discover                       discover domains and domain controllers
  shaka enumerate users|groups|...     enumerate directory objects
  shaka analyze                        run the rule engine against the current session
  shaka findings                       list findings from the latest session
  shaka report                         render the latest assessment report
  shaka target set|list|show           manage targets
  shaka updates                        check for and install updates

Every assessment requires explicit target authorization. shaka is scoped,
reversible, logged, and intended for use only on systems you are authorized
to assess.`

var rootCmd = &cobra.Command{
	Use:           "shaka",
	Short:         "Authorized Active Directory security assessment framework",
	Long:          appDescription,
	Version:       version.String(),
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		if app.initErr != nil {
			return errs.NewExitError(2, app.initErr.Error())
		}
		return nil
	},
	Args: func(_ *cobra.Command, args []string) error {
		if len(args) > 0 {
			return errs.NewExitError(2, fmt.Sprintf("unknown command %q (try 'shaka --help')", args[0]))
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runConsole(cmd.Context())
	},
}

// Execute runs the root command against os.Args and returns the process exit
// code. It never calls os.Exit itself so callers control termination.
func Execute() int {
	return ExecuteArgs(os.Args[1:])
}

// ExecuteArgs runs the root command with an explicit argument vector and
// returns the process exit code.
func ExecuteArgs(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	rootCmd.SetContext(ctx)
	rootCmd.SetArgs(args)

	if err := rootCmd.Execute(); err != nil {
		var exitErr *errs.ExitError
		if errors.As(err, &exitErr) {
			fmt.Fprintln(os.Stderr, wrapErr(exitErr.Message))
			if exitErr.Cause != nil {
				fmt.Fprintln(os.Stderr, "  "+exitErr.Cause.Error())
			}
			return exitErr.Code
		}
		fmt.Fprintln(os.Stderr, wrapErr(err.Error()))
		return 1
	}
	if app.initErr != nil {
		fmt.Fprintln(os.Stderr, wrapErr(app.initErr.Error()))
		return 2
	}
	return 0
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return errs.NewExitError(2, err.Error())
	})

	pf := rootCmd.PersistentFlags()
	pf.StringVarP(&app.cfgFile, "config", "c", "", "config file (default $HOME/.config/qyvora/shaka/config.yaml)")
	pf.BoolVarP(&app.verbose, "verbose", "v", false, "verbose output")
	pf.BoolVarP(&app.quiet, "quiet", "q", false, "suppress non-error output")
	pf.StringVarP(&app.outputFmt, "output", "o", "", "output format: terminal, json, markdown, html, yaml")
	pf.BoolVar(&app.jsonOut, "json", false, "output in JSON format (shorthand for --output json)")
	pf.StringVar(&app.eventsF, "events", "", "emit a JSONL event stream to stdout, stderr, or a file path")
	pf.BoolVar(&app.dryRun, "dry-run", false, "resolve and print the assessment plan without executing")
	pf.StringVar(&app.timeout, "timeout", "", "default timeout for directory operations (e.g. 30s)")

	rootCmd.PersistentFlags().BoolP("authorized", "y", false, "confirm authorization scope non-interactively")

	registerDirFlags(rootCmd.PersistentFlags())

	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newCapabilitiesCmd())
	rootCmd.AddCommand(newCompletionCmd())
	rootCmd.AddCommand(newUpdatesCmd())
	rootCmd.AddCommand(newTargetCmd())
	rootCmd.AddCommand(newAssessCmd())
	rootCmd.AddCommand(newDiscoverCmd())
	rootCmd.AddCommand(newEnumerateCmd())
	rootCmd.AddCommand(newAnalyzeCmd())
	rootCmd.AddCommand(newFindingsCmd())
	rootCmd.AddCommand(newEvidenceCmd())
	rootCmd.AddCommand(newGraphCmd())
	rootCmd.AddCommand(newReportCmd())
	rootCmd.AddCommand(newToolsCmd())

	rootCmd.SetVersionTemplate(fmt.Sprintf("shaka %s\n", version.String()))
}

// initConfig loads configuration and initializes the shared logger, printer,
// target manager and session store. Failures are recorded as init errors so
// ExecuteArgs can report them without calling os.Exit.
func initConfig() {
	v, err := config.Load(app.cfgFile)
	if err != nil {
		app.initErr = errs.WrapExitError(2, "loading config", err)
		return
	}
	app.cfg = v
	initLogger()
	initPrinter()
	app.targets = target.NewManager()
	app.store = session.NewStore(v.GetString("session.dir"))
	if app.eventsF != "" {
		if err := app.resolveEvents(rootCmd.Context()); err != nil {
			app.initErr = errs.WrapExitError(2, "configuring events", err)
			return
		}
	}
}

func initLogger() {
	app.log = logger.New()
	app.log.SetLevel(logger.ParseLevel(app.cfg.GetString("log.level")))
	if app.verbose || app.cfg.GetBool("verbose") {
		app.log.SetVerbose(true)
	}
	if app.quiet || app.cfg.GetBool("quiet") {
		app.log.SetQuiet(true)
	}
}

func initPrinter() {
	app.printer = output.New()
	format := "terminal"
	switch {
	case app.outputFmt != "":
		format = app.outputFmt
	case app.jsonOut:
		format = "json"
	case app.cfg.GetBool("json"):
		format = "json"
	case app.cfg.IsSet("output"):
		if v, ok := app.cfg.Get("output").(string); ok && v != "" {
			format = v
		}
	}
	parsed, err := output.ParseFormat(format)
	if err != nil {
		app.initErr = errs.WrapExitError(2, "invalid --output format", err)
		return
	}
	app.printer.SetFormat(parsed)
	// ANSI color is a terminal-only nicety: disable it when stdout is not an
	// interactive device or when the caller opts out via NO_COLOR, so no
	// escape sequences leak into redirected or piped output.
	color.NoColor = !stdoutIsTerminal() || os.Getenv("NO_COLOR") != ""
}

// stdoutIsTerminal reports whether standard output is an interactive
// character device.
func stdoutIsTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func wrapErr(msg string) string {
	return color.New(color.FgRed, color.Bold).Sprint("Error: ") + msg
}
