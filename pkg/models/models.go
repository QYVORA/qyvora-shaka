// Package models defines the normalized data model shared by every stage of
// the shaka assessment pipeline.
//
// Active Directory is a graph, not a list. The model therefore represents
// objects (domains, users, groups, computers, OUs, trusts) and the
// relationships between them, plus findings, evidence, risk, targets and
// sessions. Plain structs with JSON tags keep every value serializable for
// evidence, reporting, and machine-to-machine integration without coupling
// to any particular stage.
package models

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// State distinguishes how the framework knows a value: directly observed,
// inferred from evidence, validated, or unknown. Never report assumptions as
// facts.
type State string

const (
	StateObserved  State = "observed"
	StateValidated State = "validated"
	StateInferred  State = "inferred"
	StateUnknown   State = "unknown"
	StateNotSeen   State = "not_seen"
)

// NewID returns a random lowercase hex identifier with the given prefix,
// used for targets, sessions, evidence, and findings so identifiers are
// unique without coordination.
func NewID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return prefix + "-" + hex.EncodeToString([]byte(time.Now().Format("150405.000000000")))
	}
	return prefix + "-" + hex.EncodeToString(b)
}

// NoiseLevel classifies operational footprint for OPSEC awareness.
type NoiseLevel string

const (
	NoiseLevelPassive    NoiseLevel = "passive"     // Observation only, no detectable emissions
	NoiseLevelLow        NoiseLevel = "low"         // Blends with normal behavior
	NoiseLevelModerate   NoiseLevel = "moderate"    // Detectable but non-hostile patterns
	NoiseLevelAggressive NoiseLevel = "aggressive"  // Obviously adversarial activity
)
