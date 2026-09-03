package analysis

import (
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-shaka/internal/graph"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// buildGraph constructs a small graph:
//
//	user-a --member_of--> Domain Admins --admin_of--> corp (domain)
//	user-b --member_of--> Employees  --joins----->> corp (domain)
//
// It verifies that the administrative-control path outranks the containment
// path and is labeled as such.
func TestAttackPathEscalationOutranksContainment(t *testing.T) {
	g := graph.New()
	g.UpsertNode(&models.Node{ID: "user:a", Kind: models.NodeUser, Label: "a"})
	g.UpsertNode(&models.Node{ID: "user:b", Kind: models.NodeUser, Label: "b"})
	g.UpsertNode(&models.Node{ID: "group:da", Kind: models.NodeGroup, Label: "Domain Admins"})
	g.UpsertNode(&models.Node{ID: "group:emp", Kind: models.NodeGroup, Label: "Employees"})
	g.UpsertNode(&models.Node{ID: "domain:corp", Kind: models.NodeDomain, Label: "corp"})

	// user-a is a member of Domain Admins and thus an admin of the domain.
	g.AddEdge(&models.Edge{ID: "e:mo1", From: "user:a", To: "group:da", Type: models.RelMemberOf, Source: "enumeration"})
	g.AddEdge(&models.Edge{ID: "e:da_group", From: "group:da", To: "domain:corp", Type: models.RelMemberOf, Source: "enumeration"})
	g.AddEdge(&models.Edge{ID: "e:da_admin", From: "user:a", To: "domain:corp", Type: models.RelAdminOf, Source: "enumeration"})

	// user-b is in Employees (containment only).
	g.AddEdge(&models.Edge{ID: "e:mo2", From: "user:b", To: "group:emp", Type: models.RelMemberOf, Source: "enumeration"})
	g.AddEdge(&models.Edge{ID: "e:emp_join", From: "group:emp", To: "domain:corp", Type: models.RelJoins, Source: "enumeration"})
	g.AddEdge(&models.Edge{ID: "e:b_join", From: "user:b", To: "domain:corp", Type: models.RelJoins, Source: "enumeration"})

	apa := &AttackPathAnalyzer{Graph: g}
	paths := apa.Analyze(8)

	// Collect the single strongest path per source.
	bySource := map[string]AttackPath{}
	for _, p := range paths {
		if cur, ok := bySource[p.Source]; !ok || p.Risk > cur.Risk {
			bySource[p.Source] = p
		}
	}

	aPath, ok := bySource["user:a"]
	if !ok {
		t.Fatal("expected a path from user:a")
	}
	bPath, ok := bySource["user:b"]
	if !ok {
		t.Fatal("expected a path from user:b")
	}
	if aPath.Risk <= bPath.Risk {
		t.Fatalf("admin path (%d) should outrank containment path (%d)", aPath.Risk, bPath.Risk)
	}
	if !strings.Contains(aPath.Reason, "administrative control") {
		t.Errorf("admin path reason should cite administrative control, got %q", aPath.Reason)
	}
}

func TestAttackPathKerberoastableTarget(t *testing.T) {
	g := graph.New()
	g.UpsertNode(&models.Node{ID: "user:svc", Kind: models.NodeUser, Label: "svc"})
	g.UpsertNode(&models.Node{ID: "kerb:svc", Kind: models.NodeResource, Label: "svc (kerberoastable)", Domain: "corp"})
	g.AddEdge(&models.Edge{ID: "e:spn", From: "user:svc", To: "kerb:svc", Type: models.RelHasPrivilege, Source: "enumeration"})

	apa := &AttackPathAnalyzer{Graph: g}
	paths := apa.Analyze(4)
	if len(paths) == 0 {
		t.Fatal("expected a path to the kerberoastable target")
	}
	if paths[0].Destination != "kerb:svc" {
		t.Errorf("path should target the kerberoastable resource, got %q", paths[0].Destination)
	}
	if !strings.Contains(paths[0].Reason, "privileged access") {
		t.Errorf("kerberoastable path reason should cite privileged access, got %q", paths[0].Reason)
	}
}
