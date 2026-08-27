# Correlation: the graph stage

CORRELATE is the third canonical stage. It turns discovered objects and
relationships into a reasoner over the environment: a directed, typed
relationship graph whose edges are derived from evidence — never from a guess.

## Where this lives

- `internal/graph` — the graph model, deduplication, and traversal.
- `internal/pipeline/build.go` — seeds the graph from session objects.
- `internal/pipeline` — the concrete graph stage.
- `internal/analysis/attackpath.go` — security-relevant path analysis on top.

## Nodes

A node is one object in the environment. Node kinds:
`domain`, `domain_controller`, `computer`, `user`, `group`, `ou`, `gpo`,
`service`, `resource`.

## Edges

Edges are directed, typed relationships:

| Type | Meaning |
|---|---|
| `member_of` | principal → group |
| `member` | group → principal |
| `joins` (`member_of_domain`) | computer/user → domain |
| `trusts` / `trusted_by` | domain → domain |
| `contains` | container → object (OU) |
| `has_privilege` / `has_permission` | principal → resource |
| `applies_to` | gpo → ou/computer |
| `runs_on` | service → computer |
| `is_admin_of` | principal → computer/domain |

Each edge carries a `Source` (collection source, e.g. `discovery`, `enumeration`),
a `Confidence`, and the `EvidenceIDs` backing it.

## How the graph is built

`internal/pipeline/build.go` seeds the graph in passes:

1. **Discovery** adds domain nodes and domain-controller nodes, joined to
   their domain (`RelJoins`).
2. **Enumeration** adds user, group and computer nodes (also joined to their
   domain), then a second pass resolves each group's `member` DNs to actual
   nodes and creates the `member` / `member_of` edge pair. A member reference
   that cannot be resolved is skipped — no fabricated membership.
3. **Trusts** add `trusts`/`trusted_by` edges from the trust analyzer.

## Deduplication and confidence

- Nodes are keyed by ID; inserting an existing node only updates its label.
- Edges are deduplicated on `(from, to, type)`. When an identical edge is
  added again, the stored edge merges confidence **upward** and appends any
  new evidence IDs.
- Results are deterministic: nodes sort by ID, edges by (from, to, type).

## Path analysis

`graph.ShortestPaths(source, dest, maxDepth)` returns all distinct shortest
paths (by node count) from a source to destinations matching a predicate, up
to a bounded maximum depth (defaulting to 12 when the caller passes no cap).
Traversal is over sorted adjacency, so results are deterministic.

`internal/analysis/attackpath.go` builds on this: from every principal
(user/group) node to **sensitive** destinations (domain, domain controller,
or resource nodes), it produces explainable paths — each carries its exact
node sequence, relationship chain, risk and a plain-language `Reason`. Paths
are ranked by risk and capped in the report.

## Trust correlation

Trust relationships are correlated in the analysis stage. The trust analyzer
(`internal/analysis/trust.go`) classifies each trust's direction, type,
transitivity and SID-filtering status into a security significance:
external and unfiltered or transitive forest trusts are rated highest
because a compromise can cross the domain boundary.

## The demo result

`shaka assess --sim` produces a 10-node / 13-edge graph deterministically:
a domain node, a domain controller, four users, three groups, and one
computer, connected by joins and membership edges derived from the demo
directory's attributes.

## Viewing the graph

```sh
shaka graph     # edge list from the latest session: from, type, to, confidence
```

See [Reporting](Reporting.md) for rendering the graph inside other report
formats.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `depth.max` | 6 | reserved default; not yet consumed by traversal (path analysis uses a caller-supplied cap) |

See [Configuration](Configuration.md).