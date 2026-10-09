// Package selfupdate provides verified self-update for the shaka binary. It
// checks the QYVORA GitHub releases for a newer release, downloads the
// artifact for the current platform, verifies its SHA-256 checksum, and
// installs it atomically — or refuses cleanly when it cannot verify.
package selfupdate

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Status reports what an update run decided and did.
type Status int

const (
	// StatusUpdated means a newer release was downloaded, verified, installed.
	StatusUpdated Status = iota
	// StatusCurrent means the installed version equals the latest release.
	StatusCurrent
	// StatusNewerInstalled means the installed version is newer than the
	// latest release; downgrades are refused by design.
	StatusNewerInstalled
)

// Result reports what an update run decided and did.
type Result struct {
	Status   Status
	Current  string
	Latest   string
	Path     string
	Artifact string
}

// Options tune output for one update run. A nil Out disables progress output.
type Options struct {
	Out io.Writer
}

// Config pins shaka to its official QYVORA release source.
type Config struct {
	Owner    string
	Repo     string
	ToolName string
	// CurrentVersion returns the running binary's version.
	CurrentVersion func() string
	// ArtifactName maps the release version and GOOS/GOARCH to the release
	// asset name.
	ArtifactName func(version, goos, goarch string) string
	// ChecksumAsset returns the name of the manifest asset.
	ChecksumAsset func(artifact string) string
	// APIBaseURL overrides the GitHub API base (tests point it locally).
	APIBaseURL string
	// ExecutablePath resolves the path to replace. Empty uses os.Executable.
	ExecutablePath func() (string, error)
}

// maxArtifactSize bounds a downloaded artifact so a hostile endpoint cannot
// exhaust disk. shaka release binaries are a few tens of MB.
const maxArtifactSize = 512 << 20

// CheckForUpdates reports whether a newer release exists, without installing.
// When an update is available it returns the resolved release pointers through
// the returned update (an internal value the caller should treat opaquely).
func CheckForUpdates(ctx context.Context, cfg Config) (Result, error) {
	current := cfg.CurrentVersion()
	if isDev(current) {
		return Result{Current: current, Status: StatusCurrent},
			upErr(KindDevBuild, "", nil).withTool(cfg.ToolName)
	}
	client := &ReleasesClient{
		BaseURL: cfg.APIBaseURL, Owner: cfg.Owner, Repo: cfg.Repo,
		UserAgent: cfg.ToolName + "/" + current,
	}
	rel, err := client.Latest(ctx)
	if err != nil {
		return Result{Current: current}, err
	}
	latest := normalizeTag(rel.TagName)
	res := Result{Current: current, Latest: latest}
	switch cmp := CompareVersions(latest, current); {
	case cmp > 0:
		res.Status = StatusUpdated
	case cmp < 0:
		res.Status = StatusNewerInstalled
	default:
		res.Status = StatusCurrent
	}
	return res, nil
}

// Run executes the full update flow: check, resolve artifact, download,
// verify, install. It returns an *UpdateError on any failure and never
// replaces the binary unless download + verification succeeded.
func Run(ctx context.Context, cfg Config, opts Options) (Result, error) {
	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	current := cfg.CurrentVersion()
	res, err := CheckForUpdates(ctx, cfg)
	if err != nil {
		return res, err
	}
	if res.Status == StatusCurrent || res.Status == StatusNewerInstalled {
		return res, nil
	}

	artifact := cfg.ArtifactName(res.Latest, runtime.GOOS, runtime.GOARCH)
	if artifact == "" {
		return res, upErr(KindPlatform, "", nil).withTool(cfg.ToolName)
	}

	path, err := resolveExecutable(cfg)
	if err != nil {
		return res, err
	}

	client := &ReleasesClient{
		BaseURL: cfg.APIBaseURL, Owner: cfg.Owner, Repo: cfg.Repo,
		UserAgent: cfg.ToolName + "/" + current,
	}
	rel, err := client.Latest(ctx)
	if err != nil {
		return res, err
	}
	assetURL := findAssetURL(rel, artifact)
	if assetURL == "" {
		return res, upErr(KindAPI, "release does not expose asset "+artifact, nil).withTool(cfg.ToolName)
	}

	data, err := fetch(ctx, assetURL, out)
	if err != nil {
		return res, err
	}

	if cs := cfg.ChecksumAsset(artifact); cs != "" {
		csURL := findAssetURL(rel, cs)
		if csURL == "" {
			return res, upErr(KindVerificationUnavailable,
				"release does not publish a verifiable checksum for "+artifact, nil).withTool(cfg.ToolName)
		}
		manifest, ferr := fetch(ctx, csURL, io.Discard)
		if ferr != nil {
			return res, upErr(KindVerificationUnavailable, "downloading checksum manifest", ferr)
		}
		if err := verifyChecksumManifest(manifest, artifact, data); err != nil {
			return res, err
		}
	}

	bin, xerr := extractBinary(data, artifact, cfg.ToolName)
	if xerr != nil {
		return res, upErr(KindInstall, "extracting "+artifact, xerr).withTool(cfg.ToolName)
	}

	if err := atomicInstall(path, bin); err != nil {
		return res, err
	}
	res.Status = StatusUpdated
	res.Path = path
	res.Artifact = artifact
	return res, nil
}

// findAssetURL returns the download URL of the named release asset, or "".
func findAssetURL(rel *Release, name string) string {
	if rel == nil {
		return ""
	}
	for _, a := range rel.Assets {
		if a.Name == name {
			return a.URL
		}
	}
	return ""
}

// fetch downloads url into memory (capped), writing the body to out as it is
// read for progress visibility.
func fetch(ctx context.Context, url string, out io.Writer) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, upErr(KindNetwork, "building download request", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, upErr(KindNetwork, "download failed: "+err.Error(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, upErr(KindAPI, "download returned "+resp.Status, nil)
	}
	var buf bytes.Buffer
	lim := io.LimitReader(resp.Body, maxArtifactSize)
	if _, err := io.Copy(io.MultiWriter(out, &buf), lim); err != nil {
		return nil, upErr(KindNetwork, "reading download: "+err.Error(), err)
	}
	return buf.Bytes(), nil
}

func resolveExecutable(cfg Config) (string, error) {
	if cfg.ExecutablePath != nil {
		p, err := cfg.ExecutablePath()
		if err == nil && p != "" {
			return filepath.Clean(p), nil
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return "", upErr(KindInstall, "cannot resolve executable path", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved, nil
	}
	return exe, nil
}

func normalizeTag(tag string) string {
	return strings.TrimPrefix(tag, "v")
}
