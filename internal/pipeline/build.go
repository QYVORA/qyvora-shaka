package pipeline

import (
	"fmt"
	"strings"

	"github.com/QYVORA/qyvora-shaka/internal/core"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// recordObjectEvidence records a deterministic evidence item for an
// enumerated object so findings can cite the observation that supports them.
// Source is the LDAP DIT location; Target is the identifier findings use for
// the object (SAMAccount/netBIOS name, DN, or domain name).
func recordObjectEvidence(env *core.Env, kind, source, target, data string) {
	if env.Evidence == nil || env.Session == nil {
		return
	}
	if target == "" && data == "" {
		return
	}
	ev := env.Evidence.Add(&models.Evidence{
		Kind:   kind,
		Source: source,
		Target: target,
		Data:   data,
		State:  models.StateObserved,
	})
	if ev != nil {
		env.Session.AddEvidence(ev)
	}
}

// ldapSource renders the collection source for a directory object.
func ldapSource(domain, dn string) string {
	if dn == "" {
		return "LDAP://" + domain
	}
	return "LDAP://" + domain + "/" + dn
}

// seedGraph creates domain and domain-controller nodes and edges.
func seedGraph(env *core.Env) {
	for _, d := range env.Session.Domains {
		if d == nil {
			continue
		}
		id := nodeID("domain", d.ID)
		env.Graph.UpsertNode(&models.Node{ID: id, Kind: models.NodeDomain, Label: d.Name, Domain: d.Name})
		recordObjectEvidence(env, "configuration", ldapSource(d.Name, d.DistName), d.Name,
			fmt.Sprintf("name=%s netbios=%s base_dn=%s sid=%s", d.Name, d.NetBIOS, d.BaseDN, d.SID))
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
		recordObjectEvidence(env, "attribute", ldapSource(u.Domain, u.DistName), u.SAMAccount,
			fmt.Sprintf("sam_account_name=%s name=%s upn=%s domain=%s admin_count=%t",
				u.SAMAccount, u.Name, u.UPN, u.Domain, u.AdminCount))
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
		recordObjectEvidence(env, "attribute", ldapSource(g.Domain, g.DistName), g.SAMAccount,
			fmt.Sprintf("sam_account_name=%s name=%s domain=%s members=%d",
				g.SAMAccount, g.Name, g.Domain, len(g.Members)))
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
		recordObjectEvidence(env, "attribute", ldapSource(c.Domain, c.DistName), c.Name,
			fmt.Sprintf("name=%s dns_name=%s os=%s domain=%s laps_managed=%t unconstrained_delegation=%t",
				c.Name, c.DNSName, c.OperatingSystem, c.Domain, c.LAPSManaged, c.TrustedForDelegation))
	}
}

// seedTrusts creates domain↔domain trust edges so trust relationships carry
// real cross-domain escalation semantics and appear in attack paths.
func seedTrusts(env *core.Env) {
	for _, t := range env.Session.Trusts {
		if t == nil {
			continue
		}
		from := nodeID("domain", domainNodeID(env, t.SourceDomain))
		to := nodeID("domain", domainNodeID(env, t.TargetDomain))

		env.Graph.UpsertNode(&models.Node{ID: from, Kind: models.NodeDomain, Label: t.SourceDomain, Domain: t.SourceDomain})
		env.Graph.UpsertNode(&models.Node{ID: to, Kind: models.NodeDomain, Label: t.TargetDomain, Domain: t.TargetDomain})

		// "trusts" edge: source domain names the target as a trusted domain,
		// granting authentication flow across the boundary (real escalation).
		env.Graph.AddEdge(&models.Edge{
			ID: nodeID("e", t.ID+"-trusts"), From: from, To: to,
			Type: models.RelTrusts, Source: "enumeration",
			Confidence: models.ConfidenceHigh,
		})
		if t.Direction == "inbound" || t.Direction == "bidirectional" {
			env.Graph.AddEdge(&models.Edge{
				ID: nodeID("e", t.ID+"-trusted_by"), From: to, To: from,
				Type: models.RelTrustedBy, Source: "enumeration",
				Confidence: models.ConfidenceHigh,
			})
		}
	}
}

// domainNodeID returns a stable node id for a domain label, preferring an
// existing domain node id when present so trust edges join known domains.
func domainNodeID(env *core.Env, name string) string {
	if d := env.Session.DomainByName(name); d != nil {
		return d.ID
	}
	return "dom_" + normalizeLabel(name)
}

func normalizeLabel(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			out = append(out, c)
		case c >= 'A' && c <= 'Z':
			out = append(out, c+('a'-'A'))
		case c == '.' || c == '-':
			out = append(out, '_')
		}
	}
	return string(out)
}

// recordTrustEvidence records a stable, hashable evidence item for each trust
// and links it to the session so reporting can trace the relationship.
func recordTrustEvidence(env *core.Env, trusts []*models.Trust) {
	if env.Evidence == nil {
		return
	}
	for _, t := range trusts {
		if t == nil {
			continue
		}
		ev := env.Evidence.Add(&models.Evidence{
			Kind:   "relationship",
			Source: "LDAP://" + t.SourceDomain + "/trustedDomain/" + t.TargetDomain,
			Target: t.TargetDomain,
			Data:   t.SourceDomain + "->" + t.TargetDomain + "(" + t.Type + "/" + t.Direction + ")",
			State:  models.StateObserved,
		})
		if ev != nil {
			env.Session.AddEvidence(ev)
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

// seedOUs creates a node per organizational unit and joins it to the domain.
func seedOUs(env *core.Env) {
	for _, ou := range env.Session.OUs {
		if ou == nil {
			continue
		}
		id := nodeID("ou", ou.ID)
		env.Graph.UpsertNode(&models.Node{ID: id, Kind: models.NodeOU, Label: labelOf(ou.Name, ou.DistName), Domain: ou.Domain})
		if dom := env.Session.DomainByName(ou.Domain); dom != nil {
			env.Graph.AddEdge(&models.Edge{
				ID: nodeID("e", ou.ID+"-joins"), From: id, To: nodeID("domain", dom.ID),
				Type: models.RelJoins, Source: "enumeration",
				Confidence: models.ConfidenceConfirmed,
			})
		}
		recordObjectEvidence(env, "attribute", ldapSource(ou.Domain, ou.DistName), ou.DistName,
			fmt.Sprintf("dn=%s name=%s domain=%s", ou.DistName, ou.Name, ou.Domain))
	}
}

// seedGPOs creates a node per Group Policy Object and adds applies_to edges
// for every gPLink observed on an OU, so the graph carries the policy surface
// scoped to high-value containers.
func seedGPOs(env *core.Env) {
	byDN := map[string]string{}
	for _, g := range env.Session.GPOs {
		if g == nil {
			continue
		}
		id := nodeID("gpo", g.ID)
		env.Graph.UpsertNode(&models.Node{ID: id, Kind: models.NodeGPO, Label: labelOf(g.Name, g.ID), Domain: g.Domain})
		byDN[g.DistName] = id
		if dom := env.Session.DomainByName(g.Domain); dom != nil {
			env.Graph.AddEdge(&models.Edge{
				ID: nodeID("e", g.ID+"-joins"), From: id, To: nodeID("domain", dom.ID),
				Type: models.RelJoins, Source: "enumeration",
				Confidence: models.ConfidenceConfirmed,
			})
		}
		recordObjectEvidence(env, "configuration", ldapSource(g.Domain, g.DistName), g.ID,
			fmt.Sprintf("dn=%s name=%s domain=%s", g.DistName, g.Name, g.Domain))
	}
	for _, ou := range env.Session.OUs {
		if ou == nil {
			continue
		}
		ouID := nodeID("ou", ou.ID)
		for _, dn := range ou.LinkedGPOs {
			gpoID := byDN[dn]
			if gpoID == "" {
				continue
			}
			env.Graph.AddEdge(&models.Edge{
				ID: nodeID("e", ou.ID+"-applies-"+gpoID), From: gpoID, To: ouID,
				Type: models.RelAppliesTo, Source: "enumeration",
				Confidence: models.ConfidenceConfirmed,
			})
		}
	}
}

// seedEscalation adds real privilege-escalation edges to the graph. Unlike
// pure membership containment, these edges model the security semantics that
// BloodHound and ACL analysis expose:
//
//   - AdminOf:  privileged principals (adminCount, Domain Admins member,
//     backup operators, etc.) have direct administrative control over their
//     domain — a real escalation boundary crossing.
//
//   - Kerberoastable: accounts with registered SPNs are sensitive targets
//     (an attacker holding any domain credential can request a crackable
//     TGS). These users are treated as sensitive destinations for path
//     analysis.
//
// Every edge is grounded in observed directory attributes, never assumed.
func seedEscalation(env *core.Env) {
	privileged := map[string]bool{}
	for _, g := range env.Session.Groups {
		if g == nil {
			continue
		}
		if g.AdminCount || isPrivilegedGroupName(g.Name) {
			for _, m := range g.Members {
				privileged[m] = true
			}
		}
	}
	for _, u := range env.Session.Users {
		if u == nil {
			continue
		}
		id := nodeID("user", u.ID)
		dom := env.Session.DomainByName(u.Domain)
		if dom == nil {
			continue
		}
		domID := nodeID("domain", dom.ID)
		// adminOf domain: adminCount users and privileged-group members
		if u.AdminCount || privileged[u.DistName] {
			env.Graph.AddEdge(&models.Edge{
				ID: nodeID("e", u.ID+"-admin_of"), From: id, To: domID,
				Type: models.RelAdminOf, Source: "enumeration",
				Confidence: models.ConfidenceHigh,
			})
			// Group members inherit escalation: a user who IS a privileged group
			// member also holds adminOf the domain.
		}
		// Kerberoastable: SPN-bearing users are sensitive targets; mark with
		// a has_privilege edge to a resource-like node representing the
		// kerberoastable property, so attack paths that land on them are
		// semantically meaningful.
		if len(u.ServicePrincipalNames) > 0 {
			kerbID := nodeID("kerberoastable", u.ID)
			env.Graph.UpsertNode(&models.Node{
				ID: kerbID, Kind: models.NodeResource,
				Label: u.SAMAccount + " (kerberoastable)", Domain: u.Domain,
			})
			env.Graph.AddEdge(&models.Edge{
				ID: nodeID("e", u.ID+"-has_spn"), From: id, To: kerbID,
				Type: models.RelHasPrivilege, Source: "enumeration",
				Confidence: models.ConfidenceHigh,
			})
		}
	}
}

func isPrivilegedGroupName(name string) bool {
	switch strings.ToLower(name) {
	case "domain admins", "enterprise admins", "schema admins",
		"administrators", "account operators", "server operators",
		"print operators", "backup operators", "dnsadmins",
		"group policy creators owners", "cert publishers":
		return true
	}
	return false
}
