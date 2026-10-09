package cli

import (
	"strings"
	"testing"
)

// TestReleaseArtifactName pins the release asset naming contract for shaka.
//
// The same names are produced in three places that can drift apart: the
// release workflow (.github/workflows/release.yml), install.sh, and this
// updater. When they disagree the updater requests an asset that no release
// has ever published and the user is told to reinstall by hand.
//
// The cases that have actually been wrong in this ecosystem:
//
//   - macOS assets are published as "macos", but Go reports GOOS "darwin".
//   - Android/Termux is its own target: GOOS is "android" for a GOOS=android
//     build and the asset is "shaka_<version>_android_<arch>". A linux/arm64
//     asset must never be substituted, because Android's bionic linker rejects
//     an ET_EXEC binary with "unexpected e_type: 2".
//   - The asset name embeds the release version, so the updater must pass the
//     resolved tag through to the naming function.
func TestReleaseArtifactName(t *testing.T) {
	cfg := shakaUpdateConfig()
	if cfg.ArtifactName == nil {
		t.Fatal("ArtifactName is nil; the updater cannot resolve a release asset")
	}

	tests := []struct {
		goos, goarch, want string
	}{
		{"linux", "amd64", "shaka_0.1.0_linux_amd64.tar.gz"},
		{"linux", "arm64", "shaka_0.1.0_linux_arm64.tar.gz"},
		{"darwin", "amd64", "shaka_0.1.0_macos_amd64.tar.gz"},
		{"darwin", "arm64", "shaka_0.1.0_macos_arm64.tar.gz"},
		{"windows", "amd64", "shaka_0.1.0_windows_amd64.zip"},
		{"windows", "arm64", "shaka_0.1.0_windows_arm64.zip"},
		{"android", "arm64", "shaka_0.1.0_android_arm64.tar.gz"},
	}

	for _, tt := range tests {
		if got := cfg.ArtifactName("v0.1.0", tt.goos, tt.goarch); got != tt.want {
			t.Errorf("ArtifactName(%q, %q, %q) = %q, want %q", "v0.1.0", tt.goos, tt.goarch, got, tt.want)
		}
	}
}

// TestReleaseArtifactNameStripsVersionPrefix pins that the leading "v" of a git
// tag is not carried into the asset name, and that a bare version produces the
// same name as its "v"-prefixed spelling.
func TestReleaseArtifactNameStripsVersionPrefix(t *testing.T) {
	cfg := shakaUpdateConfig()
	withV := cfg.ArtifactName("v0.1.0", "linux", "amd64")
	bare := cfg.ArtifactName("0.1.0", "linux", "amd64")
	if withV != bare {
		t.Errorf("ArtifactName(v0.1.0) = %q, ArtifactName(0.1.0) = %q; want equal", withV, bare)
	}
	const want = "shaka_0.1.0_linux_amd64.tar.gz"
	if bare != want {
		t.Errorf("ArtifactName(0.1.0, linux, amd64) = %q, want %q", bare, want)
	}
	if strings.Contains(bare, "_v") || strings.Contains(bare, "_V") {
		t.Errorf("ArtifactName(0.1.0, linux, amd64) = %q; version prefix was not stripped", bare)
	}
}

// TestReleaseArtifactNameIsAnArchive pins the archive naming contract: the
// updater extracts the executable entry from the archive before installing, so
// each platform must resolve to the archive suffix the pipeline publishes.
func TestReleaseArtifactNameIsAnArchive(t *testing.T) {
	cfg := shakaUpdateConfig()
	wantSuffix := map[string]string{
		"linux":   ".tar.gz",
		"darwin":  ".tar.gz",
		"android": ".tar.gz",
		"windows": ".zip",
	}
	for goos, suffix := range wantSuffix {
		name := cfg.ArtifactName("v0.1.0", goos, "arm64")
		if !strings.HasSuffix(name, suffix) {
			t.Errorf("ArtifactName(%q, \"arm64\") = %q, want a %q archive", goos, name, suffix)
		}
	}
}

// TestChecksumAssetIsTheReleaseManifest pins the checksum source. A per-artifact
// ".sha256" sidecar holds a bare digest, which does not match a manifest line of
// the form "<sha256>  <name>", so verification silently fails against it.
func TestChecksumAssetIsTheReleaseManifest(t *testing.T) {
	cfg := shakaUpdateConfig()
	if cfg.ChecksumAsset == nil {
		t.Fatal("ChecksumAsset is nil; the update would be unverified")
	}
	for _, artifact := range []string{
		"shaka_0.1.0_linux_amd64.tar.gz",
		"shaka_0.1.0_macos_arm64.tar.gz",
		"shaka_0.1.0_android_arm64.tar.gz",
	} {
		if got := cfg.ChecksumAsset(artifact); got != "checksums.txt" {
			t.Errorf("ChecksumAsset(%q) = %q, want \"checksums.txt\"", artifact, got)
		}
	}
}
