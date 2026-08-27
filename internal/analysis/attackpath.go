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
			risk := riskOf(path)
			paths = append(paths, AttackPath{
				Source: path.Source, Destination: path.Destination,
				Nodes:         path.Nodes,
				Relationships: path.Edges,
				Length:        path.Length,
				Risk:          risk, Level: levelOf(risk),
				Reason: "Path from " + path.Source + " to sensitive " + path.Destination +
					" via " + join(path.Nodes),
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

// riskOf scores a path by length and destination type: shorter paths to a
// domain/DC are most security-relevant.
func riskOf(p graph.Path) int {
	base := 20
	if p.Destination != "" {
		if n := p.Destination; n != "" {
			base = 55
		}
	}
	// Shorter path => higher risk; subtract per hop.
	risk := base - (p.Length * 6)
	if risk < 10 {
		risk = 10
	}
	if risk > 100 {
		risk = 100
	}
	return risk
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
