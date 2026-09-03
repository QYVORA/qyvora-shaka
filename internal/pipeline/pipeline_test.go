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
