package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	errs "github.com/QYVORA/qyvora-shaka/internal/errors"
	"github.com/QYVORA/qyvora-shaka/internal/selfupdate"
	"github.com/QYVORA/qyvora-shaka/internal/version"
)

// shakaUpdateConfig pins the updater to the official shaka release source.
func shakaUpdateConfig() selfupdate.Config {
	return selfupdate.Config{
		Owner:          "QYVORA",
		Repo:           "qyvora-shaka",
		ToolName:       "shaka",
		CurrentVersion: version.String,
		// Release binaries use anansi-style names: macos (not darwin) and a
		// .exe suffix for windows.
		ArtifactName: func(goos, goarch string) string {
			name := fmt.Sprintf("shaka-%s-%s", goos, goarch)
			if goos == "darwin" {
				name = fmt.Sprintf("shaka-macos-%s", goarch)
			}
			if goos == "windows" {
				name += ".exe"
			}
			return name
		},
		ChecksumAsset: func(string) string { return "checksums.txt" },
	}
}

func newUpdatesCmd() *cobra.Command {
	var install bool
	cmd := &cobra.Command{
		Use:     "updates",
		Aliases: []string{"update", "selfupdate"},
		Short:   "Check for and install shaka updates",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUpdates(cmd.Context(), install)
		},
	}
	cmd.Flags().BoolVar(&install, "install", false, "download, verify and install the latest release")
	return cmd
}

func runUpdates(ctx context.Context, install bool) error {
	cfg := shakaUpdateConfig()
	if install {
		res, err := selfupdate.Run(ctx, cfg, selfupdate.Options{Out: app.printer.Writer()})
		if err != nil {
			return updaterExit(err)
		}
		app.emitf(resultLine(res))
		return nil
	}
	res, err := selfupdate.CheckForUpdates(ctx, cfg)
	if err != nil {
		return updaterExit(err)
	}
	app.emitf(resultLine(res))
	if res.Status == selfupdate.StatusUpdated {
		app.emitf("run 'shaka updates --install' to apply")
	}
	return nil
}

func resultLine(res selfupdate.Result) string {
	switch res.Status {
	case selfupdate.StatusUpdated:
		return fmt.Sprintf("update available: %s -> %s", res.Current, res.Latest)
	case selfupdate.StatusCurrent:
		return fmt.Sprintf("shaka %s is current", res.Current)
	case selfupdate.StatusNewerInstalled:
		return fmt.Sprintf("installed %s is newer than latest release %s", res.Current, res.Latest)
	default:
		return fmt.Sprintf("shaka %s", res.Current)
	}
}

// updaterExit maps a selfupdate error to a processed exit code.
func updaterExit(err error) error {
	var ue *selfupdate.UpdateError
	if errors.As(err, &ue) {
		switch ue.Kind {
		case selfupdate.KindDevBuild:
			return errs.NewExitError(0, err.Error())
		case selfupdate.KindChecksumMismatch, selfupdate.KindVerificationUnavailable:
			return errs.NewExitError(1, err.Error())
		default:
			return errs.NewExitError(1, err.Error())
		}
	}
	return err
}
