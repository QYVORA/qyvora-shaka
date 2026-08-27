// Package transport abstracts how shaka reaches a directory service.
//
// A Transport establishes connections to a target and performs directory
// lookups. LDAP over TCP is the primary implementation; an in-memory
// simulator serves deterministic tests. The transport layer must not contain
// assessment policy.
package transport

import (
	"context"
	"time"
)

// Entry is one directory entry returned by a query.
type Entry struct {
	// DN is the distinguished name of the entry.
	DN string
	// Attributes maps an attribute name to its values.
	Attributes map[string][]string
}

// Value returns the first value for attribute name, or "".
func (e *Entry) Value(name string) string {
	if v, ok := e.Attributes[name]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

// Transport is the assessment-facing directory interface.
type Transport interface {
	// Connect establishes the connection/session to the target.
	Connect(ctx context.Context) error
	// Close tears down the connection.
	Close() error
	// Bind authenticates to the directory (may be a no-op for offline modes).
	Bind(ctx context.Context, user, password string) error
	// Search runs a subtree search at baseDN returning entries.
	Search(ctx context.Context, baseDN, filter string, attrs []string) ([]*Entry, error)
	// RootBaseDN returns the automatic root/base DN, if determinable.
	RootBaseDN() string
	// Pings returns true when the transport can reach its endpoint.
	Ping(ctx context.Context) error
	// Describe returns a human label for the endpoint.
	Describe() string
	// Timeout returns the operations timeout for this transport.
	Timeout() time.Duration
}
