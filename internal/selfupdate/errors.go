package selfupdate

// Kind classifies updater failures so command layers can render them cleanly
// without matching on strings.
type Kind string

const (
	KindNetwork                 Kind = "network"
	KindAPI                     Kind = "api"
	KindRateLimited             Kind = "rate_limited"
	KindPlatform                Kind = "unsupported_platform"
	KindVerificationUnavailable Kind = "verification_unavailable"
	KindChecksumMismatch        Kind = "checksum_mismatch"
	KindPermission              Kind = "permission_denied"
	KindInstall                 Kind = "install_failed"
	KindDevBuild                Kind = "dev_build"
)

// UpdateError is the only error type the updater returns. The wrapped cause
// is kept for debug output but not dumped at ordinary CLI users.
type UpdateError struct {
	Kind     Kind
	err      error
	tool     string
	reason   string
	platform string
	path     string
	version  string
	current  string
}

func (e *UpdateError) Error() string {
	switch e.Kind {
	case KindDevBuild:
		return e.tool + " reports no release version (" + e.current + "); updates need a binary stamped by an official release"
	case KindPlatform:
		if e.reason != "" {
			return e.reason
		}
		return "no release exists for " + e.platform
	case KindVerificationUnavailable:
		return e.reason
	case KindChecksumMismatch:
		return "checksum mismatch for " + e.tool + " " + e.version + " (" + e.path + "); nothing was installed"
	case KindPermission:
		if e.reason != "" {
			return e.reason
		}
		return "cannot replace the installed binary at " + e.path + ": permission denied"
	default:
		if e.reason != "" {
			return e.reason
		}
		return "update failed"
	}
}

func (e *UpdateError) Unwrap() error { return e.err }

func upErr(kind Kind, reason string, err error) *UpdateError {
	return &UpdateError{Kind: kind, reason: reason, err: err}
}

func (e *UpdateError) withTool(t string) *UpdateError {
	e.tool = t
	return e
}
