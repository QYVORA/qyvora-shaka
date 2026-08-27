package graph

import (
	"testing"

	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

func TestUpsertNodeAndDedup(t *testing.T) {
	g := New()
	g.UpsertNode(&models.Node{ID: "u1", Kind: models.NodeUser, Label: "alice"})
	g.UpsertNode(&models.Node{ID: "u1", Kind: models.NodeUser, Label: "Alice"})
	if got := len(g.Nodes()); got != 1 {
		t.Fatalf("expected 1 node after dedup, got %d", got)
	}
	n := g.Node("u1")
	if n.Label != "Alice" {
		t.Errorf("upsert should update label, got %q", n.Label)
	}
}

func TestAddEdgeDedupAndConfidenceMerge(t *testing.T) {
	g := New()
	g.UpsertNode(&models.Node{ID: "u", Kind: models.NodeUser})
	g.UpsertNode(&models.Node{ID: "g", Kind: models.NodeGroup})
	first := g.AddEdge(&models.Edge{ID: "e1", From: "u", To: "g", Type: models.RelMemberOf, Confidence: models.ConfidenceMedium})
	second := g.AddEdge(&models.Edge{ID: "e2", From: "u", To: "g", Type: models.RelMemberOf, Confidence: models.ConfidenceHigh, EvidenceIDs: []string{"ev1"}})
	if second != first {
		t.Fatalf("duplicate edge should return existing id, got %q want %q", second, first)
	}
	if got := len(g.Edges()); got != 1 {
		t.Fatalf("expected 1 edge after dedup, got %d", got)
	}
	edge := g.Edge("u", "g")
	if edge.Confidence != models.ConfidenceHigh {
		t.Errorf("confidence should merge upward, got %v", edge.Confidence)
	}
	if len(edge.EvidenceIDs) != 1 {
		t.Errorf("evidence ids should merge, got %v", edge.EvidenceIDs)
	}
}

func TestShortestPathsDeterministic(t *testing.T) {
	ns := []*models.Node{
		{ID: "a", Kind: models.NodeUser},
		{ID: "b", Kind: models.NodeGroup},
		{ID: "c", Kind: models.NodeGroup},
		{ID: "d", Kind: models.NodeGroup},
	}
	edges := [][3]string{
		{"a", "b", string(models.RelMemberOf)},
		{"a", "c", string(models.RelMemberOf)},
		{"b", "d", string(models.RelMemberOf)},
		{"c", "d", string(models.RelMemberOf)},
	}
	g := New()
	for _, n := range ns {
		g.UpsertNode(n)
	}
	for _, e := range edges {
		g.AddEdge(&models.Edge{ID: "e_" + e[0] + e[1], From: e[0], To: e[1], Type: models.RelationshipType(e[2])})
	}
	// d is a group; add a separate "admin" node so we have a distinct sink.
	g.UpsertNode(&models.Node{ID: "admin", Kind: models.NodeGroup})
	g.AddEdge(&models.Edge{ID: "e_dadm", From: "d", To: "admin", Type: models.RelMemberOf})

	paths := g.ShortestPaths("a", func(n *models.Node) bool { return n.ID == "admin" }, 10)
	if len(paths) == 0 {
		t.Fatal("expected at least one path to admin")
	}
	for i := 0; i < len(paths)-1; i++ {
		if paths[i].Length > paths[i+1].Length || (paths[i].Length == paths[i+1].Length && paths[i].Destination > paths[i+1].Destination) {
			t.Fatalf("paths not deterministically sorted: %+v", paths)
		}
	}
	// Two length-3 paths exist: a->b->d->admin and a->c->d->admin.
	want := 2
	if len(paths) != want {
		t.Errorf("expected %d shortest paths, got %d", want, len(paths))
	}
}
