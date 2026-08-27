package rules

import (
	"testing"

	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

func TestEvalSortsAndAssignsRuleID(t *testing.T) {
	e := New()
	e.Add(&Rule{ID: "B-2", Severity: models.SeverityLow, Detect: func(Context) []*models.Finding {
		return []*models.Finding{{Title: "b"}}
	}})
	e.Add(&Rule{ID: "A-1", Severity: models.SeverityHigh, Detect: func(Context) []*models.Finding {
		return []*models.Finding{{Title: "a"}}
	}})

	found := e.Eval(Context{})
	if len(found) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(found))
	}
	if found[0].RuleID != "A-1" {
		t.Errorf("high-severity rule should sort first, got %q", found[0].RuleID)
	}
	// Determinism: the second occurrence must equal the first.
	again := e.Eval(Context{})
	for i := range again {
		if again[i].Fingerprint() != found[i].Fingerprint() {
			t.Fatalf("Eval must be deterministic, mismatch at %d", i)
		}
	}
}

func TestRulesSortedAndNilDetectSkipped(t *testing.T) {
	e := New()
	e.Add(&Rule{ID: "Z", Detect: func(Context) []*models.Finding { return nil }})
	e.Add(&Rule{ID: "A", Detect: nil}) // should be skipped
	rs := e.Rules()
	if len(rs) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rs))
	}
	if rs[0].ID != "A" || rs[1].ID != "Z" {
		t.Errorf("rules not sorted by ID: %q %q", rs[0].ID, rs[1].ID)
	}
	if len(e.Eval(Context{})) != 0 {
		t.Fatal("nil Detect rules must be skipped and produce no findings")
	}
}
