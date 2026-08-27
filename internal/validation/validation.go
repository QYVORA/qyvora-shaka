// Package validation implements validation for every major subsystem: target,
// configuration, directory response, model and output validation. Required
// information that is invalid fails clearly rather than silently producing
// incomplete data.
package validation

import (
	"fmt"
	"strings"
)

// Result is the outcome of a validation.
type Result struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// Error returns a single combined error, or nil when valid.
func (r Result) Error() error {
	if r.Valid {
		return nil
	}
	return fmt.Errorf("validation failed: %s", strings.Join(r.Errors, "; "))
}

// Combine merges multiple results into one.
func Combine(rs ...Result) Result {
	out := Result{Valid: true}
	for _, r := range rs {
		out.Errors = append(out.Errors, r.Errors...)
		out.Warnings = append(out.Warnings, r.Warnings...)
	}
	out.Valid = len(out.Errors) == 0
	return out
}

// Hostname validates a target host/IP (non-empty, no whitespace).
func Hostname(h string) Result {
	r := Result{Valid: true}
	if strings.TrimSpace(h) == "" {
		r.Valid = false
		r.Errors = append(r.Errors, "target host is empty")
		return r
	}
	if strings.ContainsAny(h, " \t\r\n") {
		r.Valid = false
		r.Errors = append(r.Errors, "target host contains whitespace")
	}
	return r
}

// BaseDN validates a distinguished name is non-empty and looks like a DN.
func BaseDN(dn string) Result {
	r := Result{Valid: true}
	if strings.TrimSpace(dn) == "" {
		r.Valid = false
		r.Errors = append(r.Errors, "base DN is empty")
		return r
	}
	if !strings.Contains(dn, "=") {
		r.Valid = false
		r.Errors = append(r.Errors, "base DN does not look like a distinguished name")
	}
	return r
}

// Port validates a TCP port number.
func Port(p int) Result {
	r := Result{Valid: true}
	if p < 1 || p > 65535 {
		r.Valid = false
		r.Errors = append(r.Errors, fmt.Sprintf("invalid port %d", p))
	}
	return r
}
