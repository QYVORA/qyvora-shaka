package risk

import (
	"context"
	"testing"

	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

func TestLevelBoundaries(t *testing.T) {
	cases := []struct {
		score int
		level string
	}{
		{0, "none"}, {1, "low"}, {34, "low"}, {35, "medium"},
		{59, "medium"}, {60, "high"}, {79, "high"}, {80, "critical"}, {100, "critical"},
	}
	for _, c := range cases {
		if got := Level(c.score); got != c.level {
			t.Errorf("Level(%d) = %q, want %q", c.score, got, c.level)
		}
	}
}

func TestLevelPanicsNoneForHigh(t *testing.T) {
	if Level(0) == "high" {
		t.Fatal("zero effort must read as none, not high")
	}
}

func TestScoreForNil(t *testing.T) {
	if ScoreFor(nil).Score != 0 {
		t.Fatal("nil finding should yield zeroed risk")
	}
}

func TestScoreForSeverityOrdering(t *testing.T) {
	critical := ScoreFor(&models.Finding{Severity: models.SeverityCritical, Confidence: models.ConfidenceHigh, Category: "privilege"})
	low := ScoreFor(&models.Finding{Severity: models.SeverityLow, Confidence: models.ConfidenceHigh, Category: "privilege"})
	if critical.Score <= low.Score {
		t.Fatalf("critical finding should score higher than low, got %d vs %d", critical.Score, low.Score)
	}
	if critical.Rationale == "" {
		t.Fatal("rationale should explain the score")
	}
}

func TestAssessExcludesFalsePositive(t *testing.T) {
	a := &Assessor{}
	findings := []*models.Finding{
		{Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Category: "kerberos"},
		{Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Category: "kerberos", Status: models.StatusFalsePositive},
	}
	score, level := a.Assess(context.Background(), findings)
	// Two identical findings, one excluded: total = 1 finding worth; average = that finding's score capped.
	if level != "high" && level != "critical" {
		t.Errorf("unexpected level %q for a single high finding", level)
	}
	if score == 0 {
		t.Fatal("score must be nonzero with a real finding")
	}
}

func TestAssessNoFindings(t *testing.T) {
	a := &Assessor{}
	score, level := a.Assess(context.Background(), nil)
	if score != 0 || level != "none" {
		t.Fatalf("no findings should yield 0/none, got %d/%q", score, level)
	}
}
