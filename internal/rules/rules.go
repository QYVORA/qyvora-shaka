// Package rules implements the deterministic, rule-based finding engine.
// Rules carry rich metadata (ID, name, description, category, severity,
// confidence, required evidence, affected object types, detection logic,
// remediation guidance, references) and are applied to a session's discovered
// objects. Rules are deterministic: they never depend on map iteration order,
// and results are explicitly sorted.
package rules

import (
	"sort"

	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// Rule is one detection definition.
type Rule struct {
	ID            string
	Name          string
	Description   string
	Category      string
	Severity      models.Severity
	Confidence    models.Confidence
	RequiredState models.State // minimum state of evidence required to fire
	ObjectTypes   []string
	Detect        func(ctx Context) []*models.Finding
	Remediation   string
	References    []string
}

// Context carries the session state a rule evaluates.
type Context struct {
	Users     []*models.User
	Groups    []*models.Group
	Computers []*models.Computer
	Domains   []*models.Domain
	Trusts    []*models.Trust
	OUs       []*models.OrganizationalUnit
	GPOs      []*models.GroupPolicy
	Evidence  map[string][]*models.Evidence
}

// Engine applies a set of rules to a context and collects findings.
type Engine struct {
	rules []*Rule
}

// New returns an empty engine.
func New() *Engine { return &Engine{} }

// Add registers a rule.
func (e *Engine) Add(r *Rule) { e.rules = append(e.rules, r) }

// AddMany registers several rules.
func (e *Engine) AddMany(rs ...*Rule) { e.rules = append(e.rules, rs...) }

// Rules returns the registered rules sorted by ID.
func (e *Engine) Rules() []*Rule {
	out := append([]*Rule(nil), e.rules...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Eval runs every rule against the context and returns findings sorted by
// severity (desc), then rule ID, then fingerprint. Rules are applied in
// sorted ID order so results are stable across runs.
func (e *Engine) Eval(ctx Context) []*models.Finding {
	var all []*models.Finding
	for _, r := range e.Rules() {
		if r.Detect == nil {
			continue
		}
		found := r.Detect(ctx)
		for _, f := range found {
			if f == nil {
				continue
			}
			f.RuleID = r.ID
			all = append(all, f)
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		si, sj := all[i].Severity.SortRank(), all[j].Severity.SortRank()
		if si != sj {
			return si > sj
		}
		if all[i].RuleID != all[j].RuleID {
			return all[i].RuleID < all[j].RuleID
		}
		return all[i].Fingerprint() < all[j].Fingerprint()
	})
	return all
}
