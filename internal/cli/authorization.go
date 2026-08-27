package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	errs "github.com/QYVORA/qyvora-shaka/internal/errors"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// authorize gates a target behind explicit authorization. The gate is
// satisfied (in order) by the --authorized/-y flag, the QYVORA_AUTHORIZED
// environment variable, an interactive confirmation when stdin is a terminal,
// or a clean failure in non-interactive contexts. A target that has not been
// authorized can never become the assessment target.
func (a *appState) authorize(cmd *cobra.Command, t *models.Target) (*models.Target, error) {
	switch {
	case a.flagAuthorized(cmd) || a.cfg.GetBool("authorized"):
		t.Auth = a.granted(t)
		return t, nil
	case strings.EqualFold(os.Getenv("QYVORA_AUTHORIZED"), "true"):
		t.Auth = a.granted(t)
		return t, nil
	}

	if isTTY(os.Stdin) {
		fmt.Fprintf(os.Stderr, "\nAuthorized Active Directory security assessment\n")
		fmt.Fprintf(os.Stderr, "  Target: %s (%s)\n", t.DisplayName(), t.Type)
		fmt.Fprintf(os.Stderr, "  Scope:  authorized assessment only, scoped to this target\n")
		fmt.Fprintf(os.Stderr, "Confirm authorization? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		answer, err := reader.ReadString('\n')
		if err == nil && strings.EqualFold(strings.TrimSpace(answer), "y") {
			t.Auth = a.granted(t)
			return t, nil
		}
		return nil, errs.NewExitError(1, "authorization declined; assessment aborted")
	}

	return nil, errs.NewExitError(1,
		"target authorization required; re-run with --authorized to confirm scope non-interactively")
}

func (a *appState) granted(t *models.Target) models.Authorization {
	return models.Authorization{
		Granted:   true,
		Scope:     "authorized Active Directory security assessment of " + t.DisplayName(),
		Method:    "cli",
		GrantedBy: userName(),
	}
}

func (a *appState) flagAuthorized(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	f := cmd.Flags().Lookup("authorized")
	return f != nil && f.Changed && f.Value.String() == "true"
}

func userName() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "unknown"
}

// isTTY reports whether w is an interactive terminal. Non-TTY stdin means an
// interactive prompt would hang, so authorization must come from a flag or
// environment.
func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
