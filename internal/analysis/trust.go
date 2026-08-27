package analysis

import (
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// TrustAnalyzer models and analyzes domain trust relationships.
type TrustAnalyzer struct{}

// Analyze classifies each trust's security significance and state.
func (a *TrustAnalyzer) Analyze(trusts []*models.Trust) []TrustAssessment {
	var out []TrustAssessment
	for _, t := range trusts {
		if t == nil {
			continue
		}
		out = append(out, TrustAssessment{
			Source:               t.SourceDomain,
			Target:               t.TargetDomain,
			Direction:            t.Direction,
			Type:                 t.Type,
			Transitive:           t.Transitive,
			SecuritySignificance: trustSignificance(t),
			State:                t.State,
		})
	}
	return out
}

// TrustAssessment is the analyzed security posture of one trust.
type TrustAssessment struct {
	Source               string       `json:"source"`
	Target               string       `json:"target"`
	Direction            string       `json:"direction"`
	Type                 string       `json:"type"`
	Transitive           bool         `json:"transitive"`
	SecuritySignificance string       `json:"security_significance"`
	State                models.State `json:"state"`
}

func trustSignificance(t *models.Trust) string {
	// Unfiltered external/forest trusts that are transitive are the most
	// security-relevant because a compromise can cross the boundary.
	if t.Type == "external" && !t.IsSIDFiltered {
		return "high"
	}
	if t.Type == "forest" && t.Transitive {
		return "high"
	}
	if t.Type == "parent_child" {
		return "medium"
	}
	return "low"
}
