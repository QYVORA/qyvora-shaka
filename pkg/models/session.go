package models

import "time"

// Session ties one assessment run to a target and everything it learned:
// discovered objects, relationships, findings, evidence, and events.
type Session struct {
	ID       string    `json:"id"`
	TargetID string    `json:"target_id"`
	Profile  string    `json:"profile"`
	Start    time.Time `json:"start"`
	End      time.Time `json:"end,omitempty"`
	Stages   []string  `json:"stages,omitempty"`

	Domains   []*Domain             `json:"domains,omitempty"`
	DCS       []*DomainController   `json:"domain_controllers,omitempty"`
	Computers []*Computer           `json:"computers,omitempty"`
	Users     []*User               `json:"users,omitempty"`
	Groups    []*Group              `json:"groups,omitempty"`
	OUs       []*OrganizationalUnit `json:"ous,omitempty"`
	GPOs      []*GroupPolicy        `json:"gpos,omitempty"`
	Services  []*Service            `json:"services,omitempty"`
	Trusts    []*Trust              `json:"trusts,omitempty"`
	Nodes     []*Node               `json:"graph_nodes,omitempty"`
	Edges     []*Edge               `json:"graph_edges,omitempty"`

	Findings []*Finding  `json:"findings,omitempty"`
	Evidence []*Evidence `json:"evidence,omitempty"`

	RiskScore int      `json:"risk_score,omitempty"`
	RiskLevel string   `json:"risk_level,omitempty"`
	OutputDir string   `json:"output_dir,omitempty"`
	Errors    []string `json:"errors,omitempty"`
	// Attributes carries summarized analysis context (trust summary, attack
	// path blurb) for reporting convenience.
	Attributes map[string]string `json:"attributes,omitempty"`
}

// NewSession creates a session with a fresh identifier and the start time.
func NewSession() *Session {
	return &Session{
		ID:       NewID("sess"),
		Start:    time.Now().UTC(),
		Stages:   []string{},
		Findings: []*Finding{},
		Evidence: []*Evidence{},
		Errors:   []string{},
	}
}

// AddFinding records a finding, merging duplicates by fingerprint.
func (s *Session) AddFinding(f *Finding) {
	if f == nil {
		return
	}
	f.SessionID = s.ID
	fp := f.Fingerprint()
	for _, existing := range s.Findings {
		if existing.Fingerprint() == fp {
			mergeEvidence(existing, f)
			return
		}
	}
	s.Findings = append(s.Findings, f)
}

// AddEvidence records an evidence item, deduplicating by hash.
func (s *Session) AddEvidence(ev *Evidence) {
	if ev == nil {
		return
	}
	for _, existing := range s.Evidence {
		if existing.Hash != "" && existing.Hash == ev.Hash {
			return
		}
	}
	s.Evidence = append(s.Evidence, ev)
}

// Finish marks the session end time.
func (s *Session) Finish() { s.End = time.Now().UTC() }

// DomainByName returns the domain matching the given name (full or NetBIOS),
// or nil.
func (s *Session) DomainByName(name string) *Domain {
	for _, d := range s.Domains {
		if d != nil && (d.Name == name || d.NetBIOS == name) {
			return d
		}
	}
	return nil
}

func mergeEvidence(dst, src *Finding) {
	seen := make(map[string]bool, len(dst.Evidence))
	for _, ev := range dst.Evidence {
		seen[ev.ID] = true
	}
	for _, ev := range src.Evidence {
		if !seen[ev.ID] {
			dst.Evidence = append(dst.Evidence, ev)
			seen[ev.ID] = true
		}
	}
	if src.Confidence.Rank() > dst.Confidence.Rank() {
		dst.Confidence = src.Confidence
	}
}
