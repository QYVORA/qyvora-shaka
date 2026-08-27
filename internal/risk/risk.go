// Package risk implements the risk engine. It separates severity, confidence,
// impact and exposure rather than emitting a fake-precision score, and every
// score is explainable: a finding's classification is derived from explicit,
// documented components rather than an opaque formula.
package risk

import (
	"context"

	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// MaxScore is the total attainable target risk score (0..100).
const MaxScore = 100

// Assessor computes per-finding context and overall target risk.
type Assessor struct{}

// Risk summarises the risk components of a single finding in a transparent
// way a report can reproduce.
type Risk struct {
	Severity   models.Severity   `json:"severity"`
	Confidence models.Confidence `json:"confidence"`
	Impact     int               `json:"impact"`   // 0..5
	Exposure   int               `json:"exposure"` // 0..5
	Score      int               `json:"score"`    // 0..100, derived from the above
	Level      string            `json:"level"`
	Rationale  string            `json:"rationale"`
}

// Level maps a 0..100 risk score to a severity label.
func Level(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 35:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

// ScoreFor computes the transparent risk of a single finding. Exposure is a
// per-finding heuristic: 3 (network-exposed) by default, lowered for purely
// local/account-scoped conditions.
func ScoreFor(f *models.Finding) Risk {
	if f == nil {
		return Risk{}
	}
	sev := f.Severity.Weights()           // 0..4
	conf := confidenceValue(f.Confidence) // 0..1
	exposure := 3
	if f.Category == "authentication" || f.Category == "kerberos" {
		exposure = 4
	}
	score := int(float64(sev) * conf * (float64(exposure) / 5.0) * 35)
	if score > MaxScore {
		score = MaxScore
	}
	rationale := "impact=" + string(f.Severity) +
		" confidence=" + string(f.Confidence) +
		" exposure=" + itoa(exposure) + "/5"
	return Risk{
		Severity: f.Severity, Confidence: f.Confidence,
		Impact: sev, Exposure: exposure,
		Score: score, Level: Level(score), Rationale: rationale,
	}
}

// Assess computes the target-level risk from a collection of findings.
// Findings that were ruled a false positive or resolved are excluded.
func (a *Assessor) Assess(ctx context.Context, findings []*models.Finding) (int, string) {
	var total float64
	var maxWeight float64
	excluded := 0
	for _, f := range findings {
		if f == nil {
			continue
		}
		if f.Status == models.StatusFalsePositive || f.Status == models.StatusResolved {
			excluded++
			continue
		}
		r := ScoreFor(f)
		total += float64(r.Score)
		maxWeight += float64(MaxScore)
	}
	if maxWeight == 0 {
		return 0, Level(0)
	}
	score := int(total / maxWeight * MaxScore)
	if score > MaxScore {
		score = MaxScore
	}
	return score, Level(score)
}

func confidenceValue(c models.Confidence) float64 {
	switch c {
	case models.ConfidenceConfirmed:
		return 1.0
	case models.ConfidenceHigh:
		return 0.85
	case models.ConfidenceMedium:
		return 0.6
	case models.ConfidenceLow:
		return 0.3
	default:
		return 0.5
	}
}

func itoa(v int) string {
	return string(rune('0' + v))
}
