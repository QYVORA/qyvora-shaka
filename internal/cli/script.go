package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-script/ast"
	"github.com/QYVORA/qyvora-script/binding"
	"github.com/QYVORA/qyvora-script/interpreter"
	"github.com/QYVORA/qyvora-script/parser"

	"github.com/QYVORA/qyvora-shaka/internal/assess"
	"github.com/QYVORA/qyvora-shaka/internal/capabilities"
	errs "github.com/QYVORA/qyvora-shaka/internal/errors"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// newScriptCmd adds the flat `script` utility that runs the shared
// qyvora-script engine (ARCH-004 Part C). `script run <file>` executes a
// script; `script build <file>` prints a dry-run plan. A bare `script <file>`
// runs the file for convenience.
func newScriptCmd() *cobra.Command {
	run := func(dryRun bool) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, args []string) error {
			return runScriptFile(cmd, args[0], dryRun)
		}
	}
	cmd := &cobra.Command{
		Use:   "script <file>",
		Short: "run a .qs script with the shared scripting engine",
		Args:  cobra.ExactArgs(1),
		RunE:  run(false),
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "run <file>",
			Short: "execute a script file",
			Args:  cobra.ExactArgs(1),
			RunE:  run(false),
		},
		&cobra.Command{
			Use:   "build <file>",
			Short: "validate a script file and print a dry-run plan",
			Args:  cobra.ExactArgs(1),
			RunE:  run(true),
		},
	)
	return cmd
}

// runScriptFile parses (build) or executes (run) a script against shaka's
// binding.
func runScriptFile(cmd *cobra.Command, path string, dryRun bool) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading script: %w", err)
	}
	prog, err := parser.Parse(string(src))
	if err != nil {
		return errs.NewExitError(2, err.Error())
	}
	if dryRun {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "script plan "+path)
		for _, line := range ast.Describe(prog) {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  -", line)
		}
		return nil
	}
	b := &scriptBinding{
		ctx:   cmd.Context(),
		allow: allowShellOut,
		cfg:   map[string]string{},
	}
	engine := interpreter.NewEngine(b)
	engine.Events = os.Stderr
	if err := engine.RunProgram(prog); err != nil {
		return errs.NewExitError(2, err.Error())
	}
	return nil
}

// scriptBinding implements binding.Binding against shaka's Active Directory
// assessment pipeline. Every recognised module id runs the full assessment
// (discover->enumerate->graph->analyze->findings->risk), which covers the
// module; unknown ids are refused.
type scriptBinding struct {
	ctx   context.Context
	allow bool
	cfg   map[string]string
	last  *models.Session
}

var _ binding.Binding = (*scriptBinding)(nil)

// Capabilities lists the whole-assessment "assess" entry plus every
// capability in shaka's machine contract.
func (b *scriptBinding) Capabilities() []string {
	catalog := capabilities.Catalog()
	ids := make([]string, 0, 1+len(catalog))
	ids = append(ids, "assess")
	for _, t := range catalog {
		ids = append(ids, t.ID)
	}
	return ids
}

// AllowShellOut reports whether exec/run.cmd may run: only with the explicit
// flag or the shared opt-in environment variable.
func (b *scriptBinding) AllowShellOut() bool { return b.allow || shellOutEnv() }

func shellOutEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(interpreter.AllowShellOutEnv))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// Call dispatches one engine capability invocation.
func (b *scriptBinding) Call(capabilityID string, args []binding.Value) (binding.Value, error) {
	switch capabilityID {
	case binding.CapEcho:
		_, _ = fmt.Fprintln(os.Stdout, asStr(args, 0))
		return nil, nil

	case binding.CapSetConfig:
		b.cfg[asStr(args, 0)] = asStr(args, 1)
		return nil, nil

	case binding.CapGetConfig:
		return b.cfg[asStr(args, 0)], nil

	case binding.CapStart:
		return nil, b.start(asStr(args, 0))

	case binding.CapStop, binding.CapIsRunning:
		if capabilityID == binding.CapIsRunning {
			return false, nil
		}
		return nil, nil

	case binding.CapShow:
		return nil, b.show(asStr(args, 0))

	case binding.CapReport:
		return nil, b.report(asStr(args, 0))

	case binding.CapProp:
		return b.prop(asStr(args, 0)), nil

	case binding.CapExec:
		return nil, b.exec(asStr(args, 0))
	}
	return nil, fmt.Errorf("unknown capability %q", capabilityID)
}

// start resolves a directory target and runs the full assessment for a module
// id.
func (b *scriptBinding) start(id string) error {
	if id != "" && id != "assess" && !hasCapability(id) {
		return fmt.Errorf("unknown module %q", id)
	}
	return b.run()
}

// run builds the directory options and runs the full assessment, capturing the
// session for $(...) interpolation.
func (b *scriptBinding) run() error {
	opts := b.dirOptions()
	// A bare command carries the authorization flag shaka's live directory path
	// reads; the offline demo simulator needs none.
	cmd := &cobra.Command{}
	cmd.Flags().Bool("authorized", isTrue(b.cfg["assess.authorized"]), "")
	sess, err := app.runAssessment(b.ctx, cmd, opts, assess.Full())
	if err != nil {
		return err
	}
	b.last = sess
	if sess != nil {
		return renderSession(b.ctx, sess)
	}
	return nil
}

// dirOptions maps the script config onto shaka's shared directory connection
// options (the offline demo simulator when assess.sim is on).
func (b *scriptBinding) dirOptions() dirOptions {
	return dirOptions{
		endpoint: firstNonEmpty(b.cfg["assess.endpoint"], b.cfg["endpoint"]),
		baseDN:   firstNonEmpty(b.cfg["assess.basedn"], b.cfg["basedn"]),
		username: firstNonEmpty(b.cfg["assess.username"], b.cfg["username"]),
		password: firstNonEmpty(b.cfg["assess.password"], b.cfg["password"]),
		useTLS:   isTrue(b.cfg["assess.tls"]),
		insecure: isTrue(b.cfg["assess.insecure"]),
		sim:      isTrue(b.cfg["assess.sim"]) || isTrue(b.cfg["sim"]),
	}
}

// show prints capability metadata for a module/capability id.
func (b *scriptBinding) show(id string) error {
	catalog := capabilities.Catalog()
	rows := make([][]string, 0, len(catalog)+1)
	if id == "assess" || id == "" {
		rows = append(rows, []string{"assess", "run the full directory assessment pipeline", "recon"})
	}
	for _, t := range catalog {
		if id == "" || t.ID == id {
			rows = append(rows, []string{t.ID, t.Name, t.Category})
		}
	}
	if len(rows) == 0 {
		return fmt.Errorf("unknown module %q", id)
	}
	app.printer.PrintTable([]string{"capability", "name", "category"}, rows)
	return nil
}

// report writes a JSON session report for the most recent run.
func (b *scriptBinding) report(path string) error {
	if b.last == nil {
		return fmt.Errorf("no assessment to report; run a module first")
	}
	if path == "" {
		path = "shaka-report.json"
	}
	data, err := json.MarshalIndent(b.last, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(app.printer.Writer(), "report written to "+path)
	return nil
}

// prop resolves live properties for $(...) interpolation from the last run.
func (b *scriptBinding) prop(name string) binding.Value {
	s := b.last
	if s == nil {
		return nil
	}
	switch name {
	case "session.id", "result.id":
		return s.ID
	case "result.profile":
		return s.Profile
	case "result.domains":
		return fmt.Sprintf("%d", len(s.Domains))
	case "result.dcs":
		return fmt.Sprintf("%d", len(s.DCS))
	case "result.computers":
		return fmt.Sprintf("%d", len(s.Computers))
	case "result.users":
		return fmt.Sprintf("%d", len(s.Users))
	case "result.groups":
		return fmt.Sprintf("%d", len(s.Groups))
	case "result.ous":
		return fmt.Sprintf("%d", len(s.OUs))
	case "result.trusts":
		return fmt.Sprintf("%d", len(s.Trusts))
	case "result.nodes":
		return fmt.Sprintf("%d", len(s.Nodes))
	case "result.edges":
		return fmt.Sprintf("%d", len(s.Edges))
	case "result.findings":
		return fmt.Sprintf("%d", len(s.Findings))
	case "result.evidence":
		return fmt.Sprintf("%d", len(s.Evidence))
	case "result.risk_score":
		return fmt.Sprintf("%d", s.RiskScore)
	case "result.risk_level":
		return s.RiskLevel
	}
	return nil
}

// exec runs a one-shot shaka command line. The interpreter only reaches here
// after AllowShellOut reported true.
func (b *scriptBinding) exec(line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	if code := ExecuteArgs(strings.Fields(line)); code != 0 {
		return fmt.Errorf("command exited with code %d", code)
	}
	return nil
}

// hasCapability reports whether id is a registered shaka capability.
func hasCapability(id string) bool {
	for _, t := range capabilities.Catalog() {
		if t.ID == id {
			return true
		}
	}
	return false
}

func asStr(args []binding.Value, i int) string {
	if i >= len(args) || args[i] == nil {
		return ""
	}
	if s, ok := args[i].(string); ok {
		return s
	}
	return fmt.Sprintf("%v", args[i])
}

func isTrue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
