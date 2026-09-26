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

// TestEvalAttachesFindingsEvidence verifies that findings are linked to the
// context evidence that supports their affected objects, deterministically.
func TestEvalAttachesFindingsEvidence(t *testing.T) {
	evAlice := &models.Evidence{ID: "ev-1", Kind: "attribute", Source: "LDAP://corp.local/CN=alice", Target: "alice", Data: "sam_account_name=alice", Hash: "h1"}
	evTrust := &models.Evidence{ID: "ev-2", Kind: "relationship", Source: "LDAP://corp.local/trustedDomain", Target: "other.local", Data: "corp.local->other.local(External/Inbound)", Hash: "h2"}

	e := New()
	e.Add(&Rule{ID: "U-1", Severity: models.SeverityMedium, Detect: func(Context) []*models.Finding {
		return []*models.Finding{{Title: "user finding", Objects: []string{"alice"}}}
	}})
	e.Add(&Rule{ID: "T-1", Severity: models.SeverityLow, Detect: func(Context) []*models.Finding {
		return []*models.Finding{{Title: "trust finding", Objects: []string{"corp.local", "other.local"}}}
	}})
	e.Add(&Rule{ID: "N-1", Severity: models.SeverityLow, Detect: func(Context) []*models.Finding {
		return []*models.Finding{{Title: "no-evidence finding", Objects: []string{"ghost"}}}
	}})

	ctx := Context{
		Evidence: map[string][]*models.Evidence{
			evAlice.Hash: {evAlice},
			evTrust.Hash: {evTrust},
		},
	}
	found := e.Eval(ctx)
	if len(found) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(found))
	}
	byTitle := map[string]*models.Finding{}
	for _, f := range found {
		byTitle[f.Title] = f
	}

	uf := byTitle["user finding"]
	if len(uf.Evidence) != 1 || uf.Evidence[0].Target != "alice" {
		t.Errorf("user finding should carry the alice evidence, got %+v", uf.Evidence)
	}
	tf := byTitle["trust finding"]
	if len(tf.Evidence) != 1 || tf.Evidence[0].Target != "other.local" {
		t.Errorf("trust finding should carry the trust evidence, got %+v", tf.Evidence)
	}
	nf := byTitle["no-evidence finding"]
	if len(nf.Evidence) != 0 {
		t.Errorf("unmatched finding should carry no evidence, got %+v", nf.Evidence)
	}
}

// TestAttachEvidenceDeterministic verifies that equal inputs yield equal
// evidence lists in stable order regardless of map traversal order.
func TestAttachEvidenceDeterministic(t *testing.T) {
	e := New()
	e.Add(&Rule{ID: "D-1", Detect: func(Context) []*models.Finding {
		return []*models.Finding{{Title: "x", Objects: []string{"target"}}}
	}})
	ctx := Context{Evidence: map[string][]*models.Evidence{
		"z": {{ID: "z", Kind: "attribute", Target: "target", Hash: "z"}},
		"a": {{ID: "a", Kind: "observation", Target: "target", Hash: "a"}},
	}}
	f1 := e.Eval(ctx)
	f2 := e.Eval(ctx)
	if len(f1[0].Evidence) != len(f2[0].Evidence) {
		t.Fatalf("evidence counts differ across evals")
	}
	for i := range f1[0].Evidence {
		if f1[0].Evidence[i].ID != f2[0].Evidence[i].ID {
			t.Fatalf("evidence order unstable: %q vs %q", f1[0].Evidence[i].ID, f2[0].Evidence[i].ID)
		}
	}
}
