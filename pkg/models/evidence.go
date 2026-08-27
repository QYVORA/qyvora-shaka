package models

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Evidence is one verifiable observation backing a finding or relationship.
// It is immutable once recorded within a session. Reports trace
// finding → evidence → observed object → collection source.
type Evidence struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`   // attribute|observation|configuration|service|relationship
	Source    string    `json:"source"` // collection source, e.g. "LDAP://DC01/CN=...,..."
	Target    string    `json:"target,omitempty"`
	Data      string    `json:"data,omitempty"`
	Hash      string    `json:"hash"`
	State     State     `json:"state"`
	Timestamp time.Time `json:"timestamp"`
}

// HashContent returns the lowercase hex SHA-256 digest of s.
func HashContent(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
