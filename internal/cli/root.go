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
var updateFlag bool

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
	return ExecuteArgsContext(ctx, args)
}

// ExecuteArgsContext runs the root command with an explicit argument vector
// under a caller-supplied context and returns the process exit code.
//
// The interactive TUI needs this form. It runs commands in-process on its own
// goroutine and must be able to cancel a single execution without tearing down
// the process, so the work is driven by a context the caller owns rather than
// by process-wide signal handling. That distinction is what makes Ctrl+C cancel
// the operation instead of the interface.
func ExecuteArgsContext(ctx context.Context, args []string) int {
	rootCmd.SetArgs(args)

	// If --update is passed, route to the update subcommand regardless of
	// other positional arguments.
	for _, a := range args {
		if a == "--update" || a == "-update" || a == "--update=true" {
			rootCmd.SetArgs([]string{"update"})
			break
		}
	}

	rootCmd.SetContext(ctx)
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
	// The default action opens the interactive TUI. It is assigned here rather
	// than in the rootCmd literal because Go's initialisation dependency
	// analysis follows references through function bodies: runTUI reaches
	// rootCmd, so naming it inside rootCmd's own initialiser is a cycle, while
	// init() is exempt from that analysis.
	rootCmd.RunE = func(cmd *cobra.Command, _ []string) error {
		return runTUI(cmd.Root(), cmd.Context())
	}
	// "console" is kept as an alias on commandTUI so existing invocations and
	// documentation keep working; both now open the same interface.
	rootCmd.AddCommand(commandTUI())

	cobra.OnInitialize(initConfig)

	rootCmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return errs.NewExitError(2, err.Error())
	})

	pf := rootCmd.PersistentFlags()
	pf.BoolVar(&updateFlag, "update", false, "update the CLI to the latest official release")
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
	// The interactive TUI runs this command tree repeatedly in one process, so
	// every invocation must start from clean state. Without this reset a failure
	// recorded by one run is reported as the outcome of every later run:
	// initErr is set but never cleared, so a single bad invocation would make
	// the rest of the session exit 2. The event stream and its sink are
	// dropped for the same reason, and so a file destination from an earlier run
	// cannot keep writing into a descriptor that is no longer current.
	app.initErr = nil
	app.eventStream = nil
	app.eventSink = nil

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