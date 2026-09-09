package pipeline

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/QYVORA/qyvora-shaka/internal/analysis"
	"github.com/QYVORA/qyvora-shaka/internal/core"
	"github.com/QYVORA/qyvora-shaka/internal/risk"
	"github.com/QYVORA/qyvora-shaka/internal/rules"
	"github.com/QYVORA/qyvora-shaka/internal/rules/builtin"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// DefaultEngine returns the full set of built-in detection rules.
func DefaultEngine() *rules.Engine {
	e := rules.New()
	e.AddMany(builtin.Builtin()...)
	return e
}

// evalRules runs the default rules engine against the session and converts
// findings to the session.
func evalRules(env *core.Env) []*models.Finding {
	engine := DefaultEngine()
	byHash := map[string][]*models.Evidence{}
	for _, ev := range env.Session.Evidence {
		if ev == nil {
			continue
		}
		byHash[ev.Hash] = append(byHash[ev.Hash], ev)
	}
	ctx := rules.Context{
		Users:     env.Session.Users,
		Groups:    env.Session.Groups,
		Computers: env.Session.Computers,
		Domains:   env.Session.Domains,
		Trusts:    env.Session.Trusts,
		OUs:       env.Session.OUs,
		GPOs:      env.Session.GPOs,
		Evidence:  byHash,
	}
	return engine.Eval(ctx)
}

// computeRisk scores the session's findings into an overall risk.
func computeRisk(findings []*models.Finding) (int, string) {
	var a risk.Assessor
	return a.Assess(context.Background(), findings)
}

// runIdentity executes the identity/privilege correlation pass.
func runIdentity(sess *models.Session) analysis.IdentityResult {
	var ia analysis.IdentityAnalyzer
	return ia.Analyze(sess.Users, sess.Groups, sess)
}

// runTrusts analyzes trust relationships into a summary string.
func runTrusts(sess *models.Session) string {
	var ta analysis.TrustAnalyzer
	assessments := ta.Analyze(sess.Trusts)
	parts := make([]string, 0, len(assessments))
	for _, a := range assessments {
		parts = append(parts, a.Source+"->"+a.Target+"("+a.SecuritySignificance+")")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// runPaths computes attack paths from the relationship graph and returns a
// serialized summary (JSON) for the session attributes.
func runPaths(env *core.Env, followUp bool) string {
	if env.Graph == nil {
		return "[]"
	}
	maxDepth := 12
	if followUp {
		maxDepth = 6
	}
	apa := &analysis.AttackPathAnalyzer{Graph: env.Graph}
	paths := apa.Analyze(maxDepth)
	if len(paths) == 0 {
		return "[]"
	}
	data, _ := json.Marshal(limitPaths(paths))
	return string(data)
}

func limitPaths(paths []analysis.AttackPath) []analysis.AttackPath {
	const max = 25
	if len(paths) <= max {
		return paths
	}
	return paths[:max]
}

// jsonify serializes a value to a compact JSON string for storage in session
// attributes.
func jsonify(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(data)
}
