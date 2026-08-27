// Package pipeline composes the assessment stages (discovery, enumeration,
// graph construction, analysis, findings, risk) into the full shaka
// workflow. Both the CLI one-shot path and the interactive console call this
// same pipeline so results never diverge. Each stage is a focused, testable
// unit honoring the DISCOVER → VERIFY → DEEPEN → CORRELATE → ANALYZE →
// REPORT principle.
package pipeline

import (
	"context"

	"github.com/QYVORA/qyvora-shaka/internal/core"
	"github.com/QYVORA/qyvora-shaka/internal/discovery"
	"github.com/QYVORA/qyvora-shaka/internal/enumeration"
	"github.com/QYVORA/qyvora-shaka/internal/events"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// Options tune how deeply a pipeline run goes.
type Options struct {
	// Limit caps how many objects of each kind are enumerated (0 = no cap).
	Limit int
	// GroupsOnly enumerates only users/groups (identity profile).
	GroupsOnly bool
	// IncludeTrusts runs the trust analysis stage.
	IncludeTrusts bool
	// FollowUp enables the deepening engine after discovery.
	FollowUp bool
	// MaxDepth bounds the deepening engine.
	MaxDepth int
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{Limit: 0, IncludeTrusts: true, FollowUp: true, MaxDepth: 4}
}

// Stage discovery ------------------------------------------------------------

// DiscoveryStage discovers domains and domain controllers.
type DiscoveryStage struct{}

// Name implements core.Stage.
func (s *DiscoveryStage) Name() string { return "discovery" }

// Run implements core.Stage.
func (s *DiscoveryStage) Run(ctx context.Context, env *core.Env) error {
	if env.Dir == nil {
		return nil
	}
	eng := discovery.Engine{Dir: env.Dir, Events: env.Events}
	res, err := eng.DiscoverRoot(ctx)
	if err != nil {
		return err
	}
	env.Session.Domains = res.Domains
	env.Session.DCS = res.DCS
	// Seed the graph with domain + DC nodes.
	seedGraph(env)
	return nil
}

// EnumerationStage enumerates directory objects.
type EnumerationStage struct{ Options }

// Name implements core.Stage.
func (s *EnumerationStage) Name() string { return "enumeration" }

// Run implements core.Stage.
func (s *EnumerationStage) Run(ctx context.Context, env *core.Env) error {
	if env.Dir == nil {
		return nil
	}
	base, err := env.Dir.RootBaseDN()
	if err != nil {
		return err
	}

	ue := enumeration.UserEnumerator{Dir: env.Dir, Events: env.Events}
	users, err := ue.Enumerate(ctx, base, s.Limit)
	if err != nil && len(users) == 0 {
		env.Log.Warnf("user enumeration: %v", err)
	} else {
		env.Session.Users = users
		seedUsers(env)
	}

	ge := enumeration.GroupEnumerator{Dir: env.Dir, Events: env.Events}
	groups, err := ge.Enumerate(ctx, base, s.Limit)
	if err != nil && len(groups) == 0 {
		env.Log.Warnf("group enumeration: %v", err)
	} else {
		env.Session.Groups = groups
		seedGroups(env)
	}

	if !s.GroupsOnly {
		ce := enumeration.ComputerEnumerator{Dir: env.Dir, Events: env.Events}
		comps, err := ce.Enumerate(ctx, base, s.Limit)
		if err != nil && len(comps) == 0 {
			env.Log.Warnf("computer enumeration: %v", err)
		} else {
			env.Session.Computers = comps
			seedComputers(env)
		}

		oe := enumeration.OUEnumerator{Dir: env.Dir, Events: env.Events}
		ous, err := oe.Enumerate(ctx, base, s.Limit)
		if err == nil {
			env.Session.OUs = ous
		}
		if s.IncludeTrusts {
			env.Session.Trusts = []*models.Trust{}
		}
	}
	return nil
}

// GraphStage finalizes the relationship graph and exports it to the session.
type GraphStage struct{}

// Name implements core.Stage.
func (s *GraphStage) Name() string { return "graph" }

// Run implements core.Stage.
func (s *GraphStage) Run(_ context.Context, env *core.Env) error {
	if env.Graph == nil {
		return nil
	}
	// Expand nested group memberships into member_of edges so the graph
	// captures how principals relate to privileged groups.
	env.Session.Nodes = env.Graph.Nodes()
	env.Session.Edges = env.Graph.Edges()
	return nil
}

// AnalysisStage runs identity, trust, kerberos and attack-path analysis.
type AnalysisStage struct{ FollowUp bool }

// Name implements core.Stage.
func (s *AnalysisStage) Name() string { return "analysis" }

// Run implements core.Stage.
func (s *AnalysisStage) Run(ctx context.Context, env *core.Env) error {
	// Identity / privilege correlation.
	env.Session.Attributes = map[string]string{}
	env.Session.Attributes["identity"] = jsonify(runIdentity(env.Session))
	env.Session.Attributes["trusts"] = runTrusts(env.Session)
	env.Session.Attributes["attack_paths"] = runPaths(env, s.FollowUp)

	if env.Events != nil {
		env.Events.Info(events.AnalysisCompleted, map[string]any{
			"users": len(env.Session.Users), "groups": len(env.Session.Groups),
		})
	}
	return nil
}

// FindingsStage runs the rules engine against the session.
type FindingsStage struct{}

// Name implements core.Stage.
func (s *FindingsStage) Name() string { return "findings" }

// Run implements core.Stage.
func (s *FindingsStage) Run(ctx context.Context, env *core.Env) error {
	res := evalRules(env)
	for _, f := range res {
		env.Session.AddFinding(f)
		if env.Events != nil {
			env.Events.Info(events.FindingDiscovered, map[string]any{
				"rule": f.RuleID, "severity": string(f.Severity), "title": f.Title,
			})
		}
	}
	return nil
}

// RiskStage computes the assessment risk.
type RiskStage struct{}

// Name implements core.Stage.
func (s *RiskStage) Name() string { return "risk" }

// Run implements core.Stage.
func (s *RiskStage) Run(ctx context.Context, env *core.Env) error {
	score, level := computeRisk(env.Session.Findings)
	env.Session.RiskScore = score
	env.Session.RiskLevel = level
	if env.Events != nil {
		env.Events.Info(events.RiskCalculated, map[string]any{"score": score, "level": level})
	}
	return nil
}
