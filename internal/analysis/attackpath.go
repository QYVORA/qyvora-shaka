package analysis

import (
	"sort"

	"github.com/QYVORA/qyvora-shaka/internal/graph"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// AttackPath is one explained path through the environment.
type AttackPath struct {
	Source        string   `json:"source"`
	Destination   string   `json:"destination"`
	Nodes         []string `json:"nodes"`
	Relationships []string `json:"relationships"`
	Length        int      `json:"length"`
	Risk          int      `json:"risk"`
	Level         string   `json:"level"`
	Reason        string   `json:"reason"`
}

// AttackPathAnalyzer uses the relationship graph to find meaningful paths
// from a starting principal to sensitive resources, ranked by security
// relevance. Every path is explainable: it carries the exact node sequence,
// relationship chain, risk and a plain-language reason.
type AttackPathAnalyzer struct {
	Graph *graph.Graph
}

// SensitiveNode reports whether a node represents a sensitive destination
// (domain, domain controller, or a privileged/sensitive resource).
func sensitive(n *models.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind {
	case models.NodeDomain, models.NodeDC:
		return true
	case models.NodeResource:
		return true
	default:
		return false
	}
}

// Analyze finds attack paths from each principal to sensitive destinations.
// Potential attackers are users/groups up to a bounded depth.
func (a *AttackPathAnalyzer) Analyze(maxDepth int) []AttackPath {
	principals := a.principals()
	var paths []AttackPath
	seen := map[string]bool{}
	for _, p := range principals {
		for _, path := range a.Graph.ShortestPaths(p, sensitive, maxDepth) {
			key := path.Source + ">" + join(path.Nodes)
			if seen[key] {
				continue
			}
			seen[key] = true
			risk := a.riskOf(path)
			paths = append(paths, AttackPath{
				Source: path.Source, Destination: path.Destination,
				Nodes:         path.Nodes,
				Relationships: path.Edges,
				Length:        path.Length,
				Risk:          risk, Level: levelOf(risk),
				Reason: "Path from " + path.Source + " to sensitive " + path.Destination +
					" via " + a.joinException(path) + " [" + join(path.Nodes) + "]",
			})
		}
	}
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Risk != paths[j].Risk {
			return paths[i].Risk > paths[j].Risk
		}
		if paths[i].Source != paths[j].Source {
			return paths[i].Source < paths[j].Source
		}
		return join(paths[i].Nodes) < join(paths[j].Nodes)
	})
	return paths
}

func (a *AttackPathAnalyzer) principals() []string {
	var out []string
	for _, n := range a.Graph.Nodes() {
		if n.Kind == models.NodeUser || n.Kind == models.NodeGroup {
			out = append(out, n.ID)
		}
	}
	sort.Strings(out)
	return out
}

// riskOf scores a path by length, destination type and the escalation edges it
// crosses: direct privilege edges (AdminOf, HasPrivilege) and cross-boundary
// trust edges are weighted far above mere membership containment, so paths
// that cross a real privilege boundary are surfaced first.
func (a *AttackPathAnalyzer) riskOf(p graph.Path) int {
	base := 20
	if n := a.Graph.Node(p.Destination); n != nil {
		switch n.Kind {
		case models.NodeDomain, models.NodeDC:
			base = 70
		case models.NodeResource:
			base = 55
		}
	}
	// Escalation edges add meaningful risk; containment edges do not.
	escalation := 0
	for i := 1; i < len(p.Nodes); i++ {
		switch a.hopEscalation(p.Nodes[i-1], p.Nodes[i]) {
		case models.RelAdminOf, models.RelHasPrivilege:
			escalation += 30
		case models.RelTrusts:
			escalation += 20
		case models.RelTrustedBy:
			escalation += 10
		}
	}
	risk := base + escalation - (p.Length * 8)
	if risk < 10 {
		risk = 10
	}
	if risk > 100 {
		risk = 100
	}
	return risk
}

// hopEscalation returns the strongest escalation relationship between two
// nodes, or "" when none exists. It scans the full edge set so it is correct
// even when multiple typed edges share the same from/to pair (e.g. a principal
// that is both a member and an administrator of a domain).
func (a *AttackPathAnalyzer) hopEscalation(from, to string) models.RelationshipType {
	best := models.RelationshipType("")
	for _, e := range a.Graph.Edges() {
		if e.From != from || e.To != to {
			continue
		}
		switch e.Type {
		case models.RelAdminOf:
			return models.RelAdminOf
		case models.RelHasPrivilege:
			if best != models.RelAdminOf {
				best = models.RelHasPrivilege
			}
		case models.RelTrusts:
			if best == "" {
				best = models.RelTrusts
			}
		case models.RelTrustedBy:
			if best == "" {
				best = models.RelTrustedBy
			}
		}
	}
	return best
}

// joinException names the strongest escalation mechanism along the path, or
// "membership containment" when the path only traverses containment edges. It
// gives each attack path a plain-language mechanism.
func (a *AttackPathAnalyzer) joinException(p graph.Path) string {
	best := "membership containment"
	for i := 1; i < len(p.Nodes); i++ {
		switch a.hopEscalation(p.Nodes[i-1], p.Nodes[i]) {
		case models.RelAdminOf:
			best = "administrative control"
		case models.RelHasPrivilege:
			if best != "administrative control" {
				best = "privileged access"
			}
		case models.RelTrusts:
			if best != "administrative control" && best != "privileged access" {
				best = "cross-domain trust"
			}
		}
	}
	return best
}

func levelOf(risk int) string {
	switch {
	case risk >= 60:
		return "high"
	case risk >= 35:
		return "medium"
	default:
		return "low"
	}
}

func join(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += " -> "
		}
		out += s
	}
	return out
}
