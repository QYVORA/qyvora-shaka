package models

import "testing"

func TestFindingFingerprintStableAndOrderInsensitive(t *testing.T) {
	mk := func(objs []string, attrs map[string]string) *Finding {
		return &Finding{
			RuleID: "ADM-001", Category: "privilege", Title: "Privileged Membership",
			Objects: objs, Attributes: attrs,
		}
	}
	a := mk([]string{"x", "y"}, map[string]string{"sam": "a", "id": "1"})
	b := mk([]string{"y", "x"}, map[string]string{"id": "1", "sam": "a"})
	c := mk([]string{"x", "z"}, map[string]string{"sam": "a", "id": "1"})

	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("identical findings must share a fingerprint regardless of map/slice order")
	}
	if a.Fingerprint() == c.Fingerprint() {
		t.Fatal("different affected objects must produce different fingerprints")
	}
}

func TestSessionAddFindingDedupsByFingerprint(t *testing.T) {
	s := NewSession()
	add := func(objs []string, attrs map[string]string, conf Confidence) {
		s.AddFinding(&Finding{
			RuleID: "ADM-001", Category: "privilege", Title: "T", Objects: objs,
			Attributes: attrs, Confidence: conf, Evidence: []Evidence{{ID: "e1"}},
		})
	}
	add([]string{"x"}, map[string]string{"sam": "a"}, ConfidenceHigh)
	add([]string{"x"}, map[string]string{"sam": "a"}, ConfidenceConfirmed) // duplicate -> merge, raise confidence
	add([]string{"y"}, map[string]string{"sam": "b"}, ConfidenceMedium)    // distinct -> new

	if len(s.Findings) != 2 {
		t.Fatalf("expected 2 findings after dedup, got %d", len(s.Findings))
	}
	var merged *Finding
	for _, f := range s.Findings {
		if len(f.Objects) == 1 && f.Objects[0] == "x" {
			merged = f
		}
	}
	if merged == nil || merged.Confidence != ConfidenceConfirmed {
		t.Fatalf("duplicate should merge and raise confidence, got %v", merged)
	}
}

func TestSessionAddEvidenceDedupsByHash(t *testing.T) {
	s := NewSession()
	s.AddEvidence(&Evidence{Hash: "abc", ID: "ev1"})
	s.AddEvidence(&Evidence{Hash: "abc", ID: "ev2"})
	s.AddEvidence(&Evidence{Hash: "def", ID: "ev3"})
	if len(s.Evidence) != 2 {
		t.Fatalf("expected 2 evidence after hash dedup, got %d", len(s.Evidence))
	}
}

func TestDomainByName(t *testing.T) {
	s := NewSession()
	s.Domains = []*Domain{{Name: "corp.example.com", NetBIOS: "CORP"}}
	if d := s.DomainByName("corp.example.com"); d == nil {
		t.Fatal("expected full-name lookup to succeed")
	}
	if d := s.DomainByName("CORP"); d == nil {
		t.Fatal("expected NetBIOS lookup to succeed")
	}
	if d := s.DomainByName("nope.example.com"); d != nil {
		t.Fatal("expected nil for unknown domain")
	}
}

func TestSeverityWeightsAndConfidenceRank(t *testing.T) {
	if SeverityCritical.Weights() <= SeverityHigh.Weights() {
		t.Fatal("critical must weigh more than high")
	}
	if ConfidenceConfirmed.Rank() <= ConfidenceLow.Rank() {
		t.Fatal("confirmed must rank above low")
	}
}
