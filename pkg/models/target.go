package models

import "time"

// TargetType distinguishes how an authorized domain is reached.
type TargetType string

const (
	// TargetDomain identifies a domain reached over LDAP in a live assessment.
	TargetDomain TargetType = "domain"
	// TargetConfig identifies an offline directory snapshot for static review.
	TargetConfig TargetType = "config"
)

// Authorization records the explicit consent state of a target. Every
// assessment must begin with an authorized target; the framework refuses to
// proceed otherwise.
type Authorization struct {
	Granted   bool      `json:"granted"`
	GrantedAt time.Time `json:"granted_at,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	GrantedBy string    `json:"granted_by,omitempty"`
	Method    string    `json:"method,omitempty"`
}

// Target is the normalized object an assessment operates on. It carries
// connection information, the discovered domain metadata, the assessment
// profile, and the explicit authorization gate.
type Target struct {
	ID        string        `json:"id"`
	Name      string        `json:"name,omitempty"`
	Type      TargetType    `json:"type"`
	Address   string        `json:"address,omitempty"`
	Domain    string        `json:"domain,omitempty"`
	Username  string        `json:"username,omitempty"`
	Password  string        `json:"-"`
	BaseDN    string        `json:"base_dn,omitempty"`
	LdapPort  int           `json:"ldap_port,omitempty"`
	Auth      Authorization `json:"authorization"`
	Config    string        `json:"config,omitempty"`
	Profile   string        `json:"profile,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
}

// Authorized reports whether the target passed the authorization gate.
func (t *Target) Authorized() bool { return t != nil && t.Auth.Granted }

// DisplayName returns a short human-readable label for the target.
func (t *Target) DisplayName() string {
	if t == nil {
		return "<nil>"
	}
	if t.Name != "" {
		return t.Name
	}
	if t.Domain != "" {
		return t.Domain
	}
	if t.Address != "" {
		return t.Address
	}
	if t.Config != "" {
		return t.Config
	}
	return "unknown target"
}
