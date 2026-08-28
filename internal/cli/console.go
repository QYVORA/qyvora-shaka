package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/chzyer/readline"
	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-shaka/internal/assess"
	"github.com/QYVORA/qyvora-shaka/internal/version"
)

// shakaConsole is the interactive, unified Metasploit-style console.
type shakaConsole struct {
	ctx     context.Context
	out     io.Writer
	ui      *consoleUI
	rl      *readline.Instance
	history []string
	cwd     string
	target  string
	profile string
}

func runConsole(ctx context.Context) error {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	c := &shakaConsole{
		ctx:     ctx,
		out:     os.Stdout,
		ui:      newConsoleUI(os.Stdout),
		cwd:     cwd,
		target:  "sim:demo",
		profile: "full",
	}

	if !writerIsTerminal(os.Stdin) {
		return c.runPlain()
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:       c.ui.Prompt("shaka"),
		HistoryFile:  c.historyPath(),
		AutoComplete: readline.NewPrefixCompleter(c.completer()...),
	})
	if err != nil {
		_, _ = fmt.Fprintf(c.out, "line editing unavailable (%v); continuing in plain mode\n", err)
		return c.runPlain()
	}
	c.rl = rl
	defer func() { _ = rl.Close() }()

	c.ui.Banner("Windows & Active Directory Security Assessment Framework")
	c.ui.BannerFoot(version.String())
	c.hud()
	c.ui.Status("*", "console ready. type 'help' for commands.")

	for {
		line, err := rl.Readline()
		if err != nil {
			if errors.Is(err, readline.ErrInterrupt) {
				continue
			}
			return nil // EOF / Ctrl-D
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		c.history = append(c.history, line)
		quit, e := c.exec(line)
		c.hud()
		if e != nil {
			c.ui.Err("%v", e)
		} else if quit {
			return nil
		}
	}
}

func (c *shakaConsole) runPlain() error {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		c.history = append(c.history, line)
		quit, err := c.exec(line)
		if err != nil {
			_, _ = fmt.Fprintf(c.out, "error: %v\n", err)
		}
		if quit {
			return nil
		}
	}
	return sc.Err()
}

func (c *shakaConsole) historyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".shaka_history"
	}
	dir := filepath.Join(home, ".qyvora")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ".shaka_history"
	}
	return filepath.Join(dir, "shaka_history")
}

func (c *shakaConsole) hud() {
	c.ui.HUD(c.target, c.profile, c.cwd, version.String())
}

func (c *shakaConsole) completer() []readline.PrefixCompleterInterface {
	return []readline.PrefixCompleterInterface{
		readline.PcItem("assess"),
		readline.PcItem("discover"),
		readline.PcItem("enumerate",
			readline.PcItem("all"),
			readline.PcItem("users"),
			readline.PcItem("groups"),
			readline.PcItem("computers"),
			readline.PcItem("ous"),
			readline.PcItem("trusts"),
		),
		readline.PcItem("analyze"),
		readline.PcItem("findings"),
		readline.PcItem("evidence"),
		readline.PcItem("graph"),
		readline.PcItem("report"),
		readline.PcItem("target"),
		readline.PcItem("capabilities"),
		readline.PcItem("updates"),
		readline.PcItem("version"),
		readline.PcItem("banner"),
		readline.PcItem("help"),
		readline.PcItem("clear"),
		readline.PcItem("history"),
		readline.PcItem("pwd"),
		readline.PcItem("cd"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	}
}

func (c *shakaConsole) exec(line string) (bool, error) {
	if strings.HasPrefix(line, "!") {
		cmdStr := strings.TrimSpace(strings.TrimPrefix(line, "!"))
		if cmdStr == "" {
			return false, errors.New("empty shell command after '!'")
		}
		c.runShell(cmdStr)
		return false, nil
	}

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
	case "clear", "cls":
		_, _ = fmt.Fprint(c.out, "\x1b[H\x1b[2J")
		return false, nil
	case "banner", "logo":
		c.ui.Banner("Windows & Active Directory Security Assessment Framework")
		return false, nil
	case "version", "ver":
		printVersion(version.GetInfo())
		return false, nil
	case "history":
		for i, h := range c.history {
			fmt.Fprintf(c.out, "  %3d  %s\n", i+1, h)
		}
		return false, nil
	case "pwd":
		c.ui.KV("working directory", c.cwd)
		return false, nil
	case "cd":
		return false, c.cmdCd(args)
	case "shell", "sh":
		if len(args) == 0 {
			return false, errors.New("usage: shell <command>")
		}
		c.runShell(strings.Join(args, " "))
		return false, nil
	case "target", "tgt":
		return false, c.cmdTarget(args)
	default:
		return c.execCommand(name, args)
	}
}

func (c *shakaConsole) execCommand(name string, args []string) (bool, error) {
	sim := simCommand()
	switch name {
	case "assess", "scan":
		return false, runAssess(c.ctx, sim, assess.Full(), 0, false)
	case "discover", "find":
		return false, runDiscover(c.ctx, sim)
	case "enumerate", "enum":
		obj := "all"
		if len(args) > 0 {
			obj = args[0]
		}
		return false, runEnumerate(c.ctx, sim, obj, 0)
	case "analyze", "rules":
		return false, runAnalyze(c.ctx, nil)
	case "findings", "finds":
		return false, runFindings(c.ctx)
	case "evidence", "ev":
		return false, runEvidence(c.ctx)
	case "graph", "path":
		return false, runGraph(c.ctx)
	case "report":
		return false, runReport(c.ctx, "", "")
	case "capabilities", "caps", "tools":
		printCapabilitiesTable()
		return false, nil
	case "updates", "update":
		return false, runUpdates(c.ctx, false)
	default:
		return false, fmt.Errorf("unknown command %q (type 'help')", name)
	}
}

func (c *shakaConsole) cmdCd(args []string) error {
	target := ""
	if len(args) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		target = home
	} else {
		target = args[0]
		if !filepath.IsAbs(target) {
			target = filepath.Join(c.cwd, target)
		}
	}
	target = filepath.Clean(target)
	info, err := os.Stat(target)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s: not a directory", target)
	}
	c.cwd = target
	c.ui.KV("cwd", c.cwd)
	return nil
}

func (c *shakaConsole) cmdTarget(args []string) error {
	if len(args) == 0 {
		c.ui.KV("current target", c.target)
		c.ui.Status("*", "target selection: 'target set <endpoint>' or use '--sim' for offline demo.")
		return nil
	}
	if args[0] == "set" && len(args) > 1 {
		c.target = args[1]
		c.ui.Status("+", "target set to: %s", c.target)
		return nil
	}
	c.target = args[0]
	c.ui.Status("+", "target set to: %s", c.target)
	return nil
}

func (c *shakaConsole) runShell(cmdStr string) {
	cmd := exec.CommandContext(c.ctx, "sh", "-c", cmdStr)
	cmd.Dir = c.cwd
	cmd.Stdout = c.out
	cmd.Stderr = c.out
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		c.ui.Err("command failed: %v", err)
	}
}

func simCommand() *cobra.Command {
	cmd := &cobra.Command{}
	registerDirFlags(cmd.Flags())
	_ = cmd.Flags().Set("sim", "true")
	return cmd
}

func (c *shakaConsole) help() {
	c.ui.Section("Core Commands")
	coreRows := [][]string{
		{"assess", "run full assessment pipeline against target (offline demo default)"},
		{"discover", "discover domains, domain controllers, and boundaries"},
		{"enumerate", "enumerate directory objects (users, groups, computers, ous, trusts)"},
		{"analyze", "evaluate identity posture and execute rule engine"},
		{"findings", "list discovered vulnerabilities and security findings"},
		{"evidence", "list cryptographically hashed evidence artifacts"},
		{"graph", "render typed Active Directory relationship graph"},
		{"report", "render structured assessment report"},
	}
	c.ui.Table([]string{"COMMAND", "DESCRIPTION"}, coreRows)

	c.ui.Section("Session & Utilities")
	utilRows := [][]string{
		{"target", "view or set current assessment target"},
		{"banner", "display the canonical brand ASCII banner"},
		{"capabilities", "list machine-readable capabilities"},
		{"updates", "check for official QYVORA releases"},
		{"version", "print version and runtime build info"},
		{"history", "show session command history"},
		{"pwd / cd", "view or navigate local filesystem"},
		{"shell / !cmd", "execute a host shell command"},
		{"clear", "clear console screen"},
		{"exit / quit", "leave the interactive console"},
	}
	c.ui.Table([]string{"COMMAND", "DESCRIPTION"}, utilRows)
	c.ui.Rule()
}
