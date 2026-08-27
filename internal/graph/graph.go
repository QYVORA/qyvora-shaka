// Package graph implements the relationship graph: a first-class subsystem
// modeling Active Directory as connected objects. It supports node/edge
// creation, deduplication, relationship metadata, evidence references, source
// tracking, timestamps, and security-relevant path traversal. Edges are
// derived from actual evidence, never manufactured.
package graph

import (
	"sort"
	"sync"

	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// Graph is a directed graph of nodes and typed edges with deterministic
// traversal and deduplication.
type Graph struct {
	mu    sync.RWMutex
	nodes map[string]*models.Node
	edges map[string]*models.Edge
	adj   map[string][]string // from -> to ids
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{
		nodes: map[string]*models.Node{},
		edges: map[string]*models.Edge{},
		adj:   map[string][]string{},
	}
}

// UpsertNode adds a node or returns the existing one.
func (g *Graph) UpsertNode(n *models.Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if existing, ok := g.nodes[n.ID]; ok {
		// Keep the existing node; update label if the new one has one.
		if n.Label != "" {
			existing.Label = n.Label
		}
		return
	}
	g.nodes[n.ID] = n
}

// AddEdge adds a typed edge, deduplicating on (from,to,type). It returns the
// edge ID, or "" when an identical edge already exists.
func (g *Graph) AddEdge(e *models.Edge) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := e.From + "\x00" + e.To + "\x00" + string(e.Type)
	if existing, ok := g.edges[key]; ok {
		// Merge confidence upward and evidence references.
		if e.Confidence.Rank() > existing.Confidence.Rank() {
			existing.Confidence = e.Confidence
		}
		for _, id := range e.EvidenceIDs {
			if !contains(existing.EvidenceIDs, id) {
				existing.EvidenceIDs = append(existing.EvidenceIDs, id)
			}
		}
		return existing.ID
	}
	g.edges[key] = e
	g.adj[e.From] = append(g.adj[e.From], e.To)
	return e.ID
}

// Nodes returns all nodes in deterministic ID order.
func (g *Graph) Nodes() []*models.Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]*models.Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Edges returns all edges in deterministic key order.
func (g *Graph) Edges() []*models.Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]*models.Edge, 0, len(g.edges))
	for _, e := range g.edges {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		if out[i].To != out[j].To {
			return out[i].To < out[j].To
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// Node returns a node by ID, or nil.
func (g *Graph) Node(id string) *models.Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.nodes[id]
}

// Outgoing returns the neighbors reachable from id in sorted order.
func (g *Graph) Outgoing(id string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := append([]string(nil), g.adj[id]...)
	sort.Strings(out)
	return out
}

// Edge returns the first edge from a to b, or nil.
func (g *Graph) Edge(from, to string) *models.Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, e := range g.edges {
		if e.From == from && e.To == to {
			return e
		}
	}
	return nil
}

// Path is one ordered sequence of nodes from source to destination.
type Path struct {
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Nodes       []string `json:"nodes"`
	Edges       []string `json:"edges"`
	Length      int      `json:"length"`
}

// ShortestPaths returns all distinct shortest paths (by node count) from
// source to destinations matching predicate, up to maxDepth. Results are
// deterministic: visited order is guaranteed by sorted adjacency.
func (g *Graph) ShortestPaths(source string, dest func(*models.Node) bool, maxDepth int) []Path {
	if maxDepth <= 0 || maxDepth > 32 {
		maxDepth = 12
	}
	var out []Path
	best := -1
	var dfs func(node string, nodes, edges []string, depth int)
	dfs = func(node string, nodes, edges []string, depth int) {
		if best >= 0 && depth > best {
			return
		}
		n := g.Node(node)
		if n == nil {
			return
		}
		if dest(n) {
			if best < 0 || depth < best {
				best = depth
				out = out[:0]
			}
			if depth == best {
				p := Path{
					Source: source, Destination: node,
					Nodes:  append([]string(nil), nodes...),
					Edges:  append([]string(nil), edges...),
					Length: depth,
				}
				out = append(out, p)
			}
			return
		}
		if depth >= maxDepth {
			return
		}
		for _, nb := range g.Outgoing(node) {
			edge := g.Edge(node, nb)
			edgeID := ""
			if edge != nil {
				edgeID = edge.ID
			}
			dfs(nb, append(append([]string(nil), nodes...), nb),
				append(append([]string(nil), edges...), edgeID), depth+1)
		}
	}
	dfs(source, []string{source}, nil, 0)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Length != out[j].Length {
			return out[i].Length < out[j].Length
		}
		if out[i].Destination != out[j].Destination {
			return out[i].Destination < out[j].Destination
		}
		return join(out[i].Nodes) < join(out[j].Nodes)
	})
	return out
}

func join(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += "\x00"
		}
		out += s
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
