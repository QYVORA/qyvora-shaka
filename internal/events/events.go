// Package events implements the shared QYVORA JSONL event envelope used by
// anansi, toha3ee, jabari and aksum. Every emitted line is one JSON object:
//
//	{"schema_version":"1.0","timestamp":"...","execution_id":"...",
//	 "framework":"shaka","level":"info","event":"directory.user.discovered","data":{}}
//
// Consumers key on event names, never on terminal output. See the QYVORA
// output spec for the frozen contract.
package events

import (
	"io"

	shared "github.com/QYVORA/qyvora-events"
)

// SchemaVersion is the event schema version every emitted event carries.
const SchemaVersion = shared.SchemaVersion

// Shared verbs use the ecosystem spelling exactly; shaka adds directory-
// and assessment-specific verbs with a "category.thing.state" shape so
// consumers can route on prefix without a lookup table.
const (
	ScanStarted       = "scan.started"
	ScanCompleted     = "scan.completed"
	StageStarted      = "stage.started"
	StageCompleted    = "stage.completed"
	FindingDiscovered = "finding.discovered"
	EvidenceCollected = "evidence.collected"
	Warning           = "warning"
	Error             = "error"
	ReportGenerated   = "report.generated"

	DomainDiscovered       = "domain.discovered"
	DomainControllerDiscov = "domain_controller.discovered"
	ComputerDiscovered     = "computer.discovered"
	UserDiscovered         = "user.discovered"
	GroupDiscovered        = "group.discovered"
	OUDiscovered           = "ou.discovered"
	GPODiscovered          = "gpo.discovered"
	TrustDiscovered        = "trust.discovered"
	ServiceDiscovered      = "service.discovered"
	RelationshipDiscovered = "relationship.discovered"
	AnalysisCompleted      = "analysis.completed"
	RiskCalculated         = "risk.calculated"
)

// Level values for the envelope's level field.
const (
	LevelInfo    = shared.LevelInfo
	LevelWarning = shared.LevelWarning
	LevelError   = shared.LevelError
)

type Event = shared.Event
type Stream = shared.Stream

// NewStream returns a stream bound to shaka.
func NewStream(w io.Writer) *Stream { return shared.NewStream(w, "shaka") }
