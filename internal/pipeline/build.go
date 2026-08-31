package pipeline

import (
	"github.com/QYVORA/qyvora-shaka/internal/core"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// seedGraph creates domain and domain-controller nodes and edges.
func seedGraph(env *core.Env) {
	for _, d := range env.Session.Domains {
		if d == nil {
			continue
		}
		id := nodeID("domain", d.ID)
		env.Graph.UpsertNode(&models.Node{ID: id, Kind: models.NodeDomain, Label: d.Name, Domain: d.Name})
	}
	for _, dc := range env.Session.DCS {
		if dc == nil {
			continue
		}
		id := nodeID("dc", dc.ID)
		env.Graph.UpsertNode(&models.Node{ID: id, Kind: models.NodeDC, Label: dc.Hostname, Domain: dc.Domain})
		dom := env.Session.DomainByName(dc.Domain)
		if dom != nil {
			env.Graph.AddEdge(&models.Edge{
				ID: nodeID("e", dc.ID+"-joins"), From: id, To: nodeID("domain", dom.ID),
				Type: models.RelJoins, Source: "discovery",
				Confidence: models.ConfidenceConfirmed,
			})
		}
	}
}

// seedUsers creates a node per user and membership edges to their domain.
func seedUsers(env *core.Env) {
	for _, u := range env.Session.Users {
		if u == nil {
			continue
		}
		id := nodeID("user", u.ID)
		env.Graph.UpsertNode(&models.Node{ID: id, Kind: models.NodeUser, Label: labelOf(u.Name, u.SAMAccount), Domain: u.Domain})
		if dom := env.Session.DomainByName(u.Domain); dom != nil {
			env.Graph.AddEdge(&models.Edge{
				ID: nodeID("e", u.ID+"-joins"), From: id, To: nodeID("domain", dom.ID),
				Type: models.RelJoins, Source: "enumeration",
				Confidence: models.ConfidenceConfirmed,
			})
		}
	}
}

// seedGroups creates a group node and member→principal edges derived from the
// group member attribute (actual directory evidence).
func seedGroups(env *core.Env) {
	byDN := map[string]*models.Node{}
	for _, n := range env.Graph.Nodes() {
		byDN[n.ID] = n
	}
	// Map child DNs to node IDs so member references can resolve.
	for _, g := range env.Session.Groups {
		if g == nil {
			continue
		}
		id := nodeID("group", g.ID)
		env.Graph.UpsertNode(&models.Node{ID: id, Kind: models.NodeGroup, Label: labelOf(g.Name, g.SAMAccount), Domain: g.Domain})
		if dom := env.Session.DomainByName(g.Domain); dom != nil {
			env.Graph.AddEdge(&models.Edge{
				ID: nodeID("e", g.ID+"-joins"), From: id, To: nodeID("domain", dom.ID),
				Type: models.RelJoins, Source: "enumeration",
				Confidence: models.ConfidenceConfirmed,
			})
		}
	}
	// Second pass: resolve member DNs to existing user/group nodes.
	resolve := func(dn string) string {
		if n := byDN[dn]; n != nil {
			return n.ID
		}
		// Try matching by distinguished name against known groups/users.
		for _, u := range env.Session.Users {
			if u != nil && u.DistName == dn {
				return nodeID("user", u.ID)
			}
		}
		for _, g := range env.Session.Groups {
			if g != nil && g.DistName == dn {
				return nodeID("group", g.ID)
			}
		}
		return ""
	}
	for _, g := range env.Session.Groups {
		if g == nil {
			continue
		}
		gid := nodeID("group", g.ID)
		for _, m := range g.Members {
			target := resolve(m)
			if target == "" {
				continue
			}
			env.Graph.AddEdge(&models.Edge{
				ID: nodeID("e", gid+"-has-"+target), From: gid, To: target,
				Type: models.RelMember, Source: "enumeration",
				Confidence: models.ConfidenceConfirmed,
			})
			env.Graph.AddEdge(&models.Edge{
				ID: nodeID("e2", target+"-in-"+gid), From: target, To: gid,
				Type: models.RelMemberOf, Source: "enumeration",
				Confidence: models.ConfidenceConfirmed,
			})
		}
	}
}

// seedComputers creates a node per computer and joins edges to the domain.
func seedComputers(env *core.Env) {
	for _, c := range env.Session.Computers {
		if c == nil {
			continue
		}
		id := nodeID("computer", c.ID)
		env.Graph.UpsertNode(&models.Node{ID: id, Kind: models.NodeComputer, Label: labelOf(c.Name, c.Name), Domain: c.Domain})
		if dom := env.Session.DomainByName(c.Domain); dom != nil {
			env.Graph.AddEdge(&models.Edge{
				ID: nodeID("e", c.ID+"-joins"), From: id, To: nodeID("domain", dom.ID),
				Type: models.RelJoins, Source: "enumeration",
				Confidence: models.ConfidenceConfirmed,
			})
		}
	}
}

func nodeID(kind, id string) string {
	return kind + ":" + id
}

func labelOf(name, fallback string) string {
	if name != "" {
		return name
	}
	return fallback
}
