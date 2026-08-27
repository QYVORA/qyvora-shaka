package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-shaka/internal/assess"
	"github.com/QYVORA/qyvora-shaka/internal/banner"
	"github.com/QYVORA/qyvora-shaka/internal/version"
)

// shakaConsole is the interactive Metasploit-style console. Running bare
// "shaka" drops the operator into it; every one-shot CLI command remains
// available as a console command. Console assessment commands run against the
// built-in offline demo directory so the interactive flow is always available
// without a live directory.
type shakaConsole struct {
	ctx     context.Context
	out     *os.File
	history []string
}

// runConsole launches the interactive console. When stdin is not a terminal
// (pipes, scripts, CI) it degrades to plain line-by-line reading so command
// sequences can be fed in non-interactively.
func runConsole(ctx context.Context) error {
	c := &shakaConsole{ctx: ctx, out: os.Stdout}
	interactive := isTTY(os.Stdin)
	if interactive {
		c.banner()
	}
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		c.history = append(c.history, line)
		if quit, err := c.exec(ctx, line); err != nil {
			fmt.Fprintf(c.out, "error: %v\n", err)
		} else if quit {
			return nil
		}
		if interactive {
			fmt.Fprintf(c.out, "\rshaka> ")
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return nil
}

func (c *shakaConsole) banner() {
	fmt.Fprintln(c.out, color.New(color.Bold).Sprint(banner.Wordmark))
	fmt.Fprintln(c.out, color.New(color.Bold).Sprintf("shaka %s", version.String()))
	fmt.Fprintln(c.out, "authorized Active Directory security assessment")
	fmt.Fprintln(c.out, "type 'help' for commands, 'exit' to leave")
}

// exec dispatches a single console command line. It returns (quit, error).
func (c *shakaConsole) exec(ctx context.Context, line string) (bool, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false, nil
	}
	name, args := fields[0], fields[1:]

	switch name {
	case "exit", "quit", "q", "bye":
		return true, nil
	case "help", "?":
		c.help()
		return false, nil
	case "version", "ver":
		printVersion(version.GetInfo())
		return false, nil
	case "history":
		for i, h := range c.history {
			fmt.Fprintf(c.out, "%3d  %s\n", i+1, h)
		}
		return false, nil
	}
	return c.execCommand(ctx, name, args)
}

// execCommand dispatches a console command to the same underlying functions
// as the one-shot CLI so interactive and shell behavior never diverge.
// Console assessments run against the offline demo directory by default.
func (c *shakaConsole) execCommand(ctx context.Context, name string, args []string) (bool, error) {
	sim := simCommand()
	switch name {
	case "assess", "scan":
		return false, runAssess(ctx, sim, assess.Full(), 0, false)
	case "discover", "find":
		return false, runDiscover(ctx, sim)
	case "enumerate", "enum":
		obj := "all"
		if len(args) > 0 {
			obj = args[0]
		}
		return false, runEnumerate(ctx, sim, obj, 0)
	case "analyze", "rules":
		return false, runAnalyze(ctx, nil)
	case "findings", "finds":
		return false, runFindings(ctx)
	case "evidence", "ev":
		return false, runEvidence(ctx)
	case "graph", "path":
		return false, runGraph(ctx)
	case "report":
		return false, runReport(ctx, "", "")
	case "capabilities", "caps", "tools":
		printCapabilitiesTable()
		return false, nil
	case "updates", "update":
		return false, runUpdates(ctx, false)
	case "target", "tgt":
		return false, c.cmdTarget(args)
	default:
		fmt.Fprintf(c.out, "unknown command %q (type 'help')\n", name)
		return false, nil
	}
}

// simCommand returns a minimal command with the offline simulator flag set so
// the console assessment commands work out of the box.
func simCommand() *cobra.Command {
	cmd := &cobra.Command{}
	registerDirFlags(cmd.Flags())
	_ = cmd.Flags().Set("sim", "true")
	return cmd
}

// cmdTarget handles 'target' console commands with a helpful hint.
func (c *shakaConsole) cmdTarget(_ []string) error {
	_, _ = fmt.Fprintln(c.out, "target selection: use 'shaka target set --sim' or with --endpoint/--base-dn flags")
	return nil
}

func (c *shakaConsole) help() {
	rows := [][]string{
		{"assess", "run the full assessment pipeline (offline demo)"},
		{"discover", "discover domains and domain controllers"},
		{"enumerate", "enumerate directory objects"},
		{"analyze", "run the rule engine over the latest session"},
		{"findings", "list findings"},
		{"evidence", "list evidence"},
		{"graph", "render the relationship graph"},
		{"report", "render an assessment report"},
		{"target", "hint for selecting a target"},
		{"capabilities", "list AI-ready capabilities"},
		{"updates", "check for updates"},
		{"version", "print version"},
		{"history", "show command history"},
		{"exit", "leave the console"},
	}
	app.printer.PrintTable([]string{"command", "description"}, rows)
}
