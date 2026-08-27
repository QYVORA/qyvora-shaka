// Package version holds build identity for the shaka binary.
//
// The values are compile-time defaults; release builds stamp them via:
//
//	go build -ldflags "-X github.com/QYVORA/qyvora-shaka/internal/version.Version=<tag> ..."
//
// Unstamped dev builds report "dev". Release artifacts must never report a
// dev build (QYVORA output spec, section 4).
package version

import "runtime"

// Framework is the canonical framework name carried in events and reports.
const Framework = "shaka"

var (
	Version   = "dev"
	Commit    = "none"
	Date      = "unknown"
	BuildUser = "unknown"
)

// Info is the machine-readable build identity.
type Info struct {
	Framework string `json:"framework"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	BuildUser string `json:"build_user"`
	GoVersion string `json:"go_version"`
	Arch      string `json:"arch"`
	OS        string `json:"os"`
}

// GetInfo returns the full build identity.
func GetInfo() Info {
	return Info{
		Framework: Framework,
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		BuildUser: BuildUser,
		GoVersion: runtime.Version(),
		Arch:      runtime.GOARCH,
		OS:        runtime.GOOS,
	}
}

// String returns the short version string used by the CLI and console.
func String() string { return Version }
