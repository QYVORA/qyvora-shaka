package pipeline_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-shaka/internal/assess"
	"github.com/QYVORA/qyvora-shaka/internal/directory"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// runDemo runs the full pipeline against the in-memory demo directory and
// returns the finished session.
func runDemo(t *testing.T) *models.Session {
	t.Helper()
	sim := directory.Demo()
	svc, err := directory.New(context.Background(), directory.Options{Sim: sim})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	runner := assess.New(svc, nil, nil, nil)
	runner.Options = assess.Full()
	res, err := runner.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return res.Session
}

func TestDemoPipelineEnumeratesTrust(t *testing.T) {
	ses := runDemo(t)
	if len(ses.Trusts) != 1 {
		t.Fatalf("expected 1 trust, got %d", len(ses.Trusts))
	}
}

func TestDemoPipelineRecordsTrustEvidence(t *testing.T) {
	ses := runDemo(t)
	if len(ses.Evidence) == 0 {
		t.Fatal("expected evidence records to be wired into the session")
	}
	rel := false
	for _, ev := range ses.Evidence {
		if ev.Kind == "relationship" {
			rel = true
		}
	}
	if !rel {
		t.Fatal("expected a relationship evidence record for the trust")
	}
}

func TestDemoPipelineAddsEscalationEdges(t *testing.T) {
	ses := runDemo(t)
	adminOf := 0
	trusts := 0
	for _, e := range ses.Edges {
		switch e.Type {
		case models.RelAdminOf:
			adminOf++
		case models.RelTrusts:
			trusts++
		}
	}
	if adminOf < 1 {
		t.Fatalf("expected at least one is_admin_of escalation edge, got %d", adminOf)
	}
	if trusts < 1 {
		t.Fatalf("expected at least one trusts edge, got %d", trusts)
	}
}

func TestDemoPipelineFiresTrustFindings(t *testing.T) {
	ses := runDemo(t)
	found := false
	for _, f := range ses.Findings {
		if f.RuleID == "ADM-006" || f.RuleID == "AUTH-001" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a trust-related finding to fire from enumerated trusts")
	}
}

func TestDemoPipelineFiresDelegationAndPostureFindings(t *testing.T) {
	ses := runDemo(t)
	expected := map[string]bool{
		"ADM-008":  false, // constrained delegation
		"ADM-009":  false, // computer unconstrained delegation
		"ADM-010":  false, // RBCD
		"ADM-011":  false, // risky SPN class
		"ADM-012":  false, // credential material in description
		"ADM-013":  false, // SID history
		"ADM-014":  false, // nested privileged membership
		"AUTH-002": false, // LAPS not applied
		"AUTH-003": false, // privileged GPO link
		"AUTH-004": false, // weak password policy
	}
	for _, f := range ses.Findings {
		if _, ok := expected[f.RuleID]; ok {
			expected[f.RuleID] = true
		}
	}
	for rule, fired := range expected {
		if !fired {
			t.Errorf("expected rule %s to fire on the demo directory", rule)
		}
	}
}

func TestDemoPipelineIncludesGPOAndAppliesEdges(t *testing.T) {
	ses := runDemo(t)
	if len(ses.GPOs) != 2 {
		t.Fatalf("expected 2 GPOs enumerated, got %d", len(ses.GPOs))
	}
	applies := 0
	for _, e := range ses.Edges {
		if e.Type == models.RelAppliesTo {
			applies++
		}
	}
	if applies != 2 {
		t.Fatalf("expected 2 gPLink applies_to edges, got %d", applies)
	}
}

func TestDemoPipelinePasswordPolicyObserved(t *testing.T) {
	ses := runDemo(t)
	if len(ses.Domains) != 1 {
		t.Fatalf("expected 1 domain, got %d", len(ses.Domains))
	}
	pp := ses.Domains[0].PasswordPolicy
	if !pp.Observed {
		t.Fatal("expected the demo domain password policy to be observed")
	}
	if pp.MinLength != 8 {
		t.Errorf("expected min length 8, got %d", pp.MinLength)
	}
}

func TestDemoPipelineHighRiskEscalationPath(t *testing.T) {
	ses := runDemo(t)
	var paths []map[string]any
	if raw, ok := ses.Attributes["attack_paths"]; ok && raw != "" {
		if err := json.Unmarshal([]byte(raw), &paths); err != nil {
			t.Fatalf("unmarshal attack paths: %v", err)
		}
	}
	if len(paths) == 0 {
		t.Fatal("expected at least one attack path")
	}
	// The top path must reach a domain (sensitive) — a genuine privilege result.
	top := paths[0]
	if top["level"] != "high" {
		t.Errorf("highest-ranked path should be high risk, got %v", top["level"])
	}
	// The top path must cross a real escalation boundary (administrative
	// control), not mere membership containment.
	reason, _ := top["reason"].(string)
	if !strings.Contains(reason, "administrative control") {
		t.Errorf("highest-ranked path should cite administrative control, got %q", reason)
	}
}
