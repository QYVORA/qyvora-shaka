package models

// RiskLevel is the operation risk rating for an assessment operation. It
// governs blast radius and whether confirmation is required.
type RiskLevel string

const (
	// RiskS1 is read-only, reversible, low impact (e.g. an LDAP query).
	RiskS1 RiskLevel = "S1"
	// RiskS2 is read-mostly with limited impact.
	RiskS2 RiskLevel = "S2"
	// RiskS3 is higher impact and requires explicit confirmation.
	RiskS3 RiskLevel = "S3"
	// RiskS4 is the highest risk and disabled in safe/compliance profiles.
	RiskS4 RiskLevel = "S4"
)

// Rank returns the numeric rank of a risk level (S1=1 .. S4=4).
func (r RiskLevel) Rank() int {
	switch r {
	case RiskS1:
		return 1
	case RiskS2:
		return 2
	case RiskS3:
		return 3
	case RiskS4:
		return 4
	default:
		return 0
	}
}

// RequiresConfirmation reports whether an operation at this risk needs an
// explicit confirmation before running.
func (r RiskLevel) RequiresConfirmation() bool { return r == RiskS3 || r == RiskS4 }

// TargetRisk summarizes the overall risk of a finding or assessment.
type TargetRisk struct {
	Score int    `json:"score"` // 0..100
	Level string `json:"level"` // none|low|medium|high|critical
}
