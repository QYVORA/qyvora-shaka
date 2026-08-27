# Verify: the VERIFY / DEEPEN stages

The canonical pipeline is:

```
DISCOVER → VERIFY → DEEPEN → CORRELATE → ANALYZE → REPORT
```

This document describes the VERIFY and DEEPEN stages — how SHAKA confirms
what discovery and enumeration produced, and how it deepens the picture
with bounded follow-up work.

## Where this lives

- `internal/deepening` — the follow-up engine.
- `internal/enumeration` — focused enumerators (users, groups, computers,
  OUs, trusts), including nested group membership expansion.
- `internal/pipeline` / `internal/assess` — stage wiring that carries the
  `FollowUp` option into the analysis stage.

## The idea

Discovery and enumeration are broad strokes: they answer *what exists*.
VERIFY and DEEPEN answer *what it means*. When an object is discovered,
follow-up determines which deeper queries apply and schedules them —
verifying that observed attributes are real and expanding relationships that
matter for security, such as:

- nested group membership beneath a privileged group,
- delegation and authentication flags on service accounts,
- trust direction/type details that determine security significance.

Follow-up results feed the analysis stage, which turns them into security
paths and new findings.

## Bounding and safety

The follow-up engine (`internal/deepening`) prevents unbounded runaway work
through several mechanisms working together:

- **Operation-ID deduplication** — every work item carries an operation ID;
  a visited operation is never scheduled again.
- **Depth limits** — work beyond the configured maximum depth is not
  scheduled.
- **Cycle detection** — visited-object tracking across the run breaks cycles
  in nested structures.
- **Bounded concurrency** — a fixed worker pool limits fan-out instead of
  unbounded goroutines.

## How it is wired

- `shaka assess` enables follow-up (`base.FollowUp = true` in the CLI,
  plumbed via `pipeline.Options` into `AnalysisStage`).
- `DefaultOptions()` sets a bounded maximum depth (`MaxDepth: 4`) that caps
  follow-up and shortest-path expansion.
- The analysis stage (`AnalysisStage`) consumes follow-up results when
  computing identity, trust, Kerberos and attack-path outputs.
- Graph traversal (`internal/graph.ShortestPaths`) computes security-relevant
  paths with its own bounded maximum depth, returning distinct shortest
  paths deterministically.
- Follow-up work honors context cancellation, so SIGINT/SIGTERM aborts it
  cleanly at the next boundary.

## Relationship to the demo

The offline demo is small and fully connected; follow-up has nothing extra to
produce, so `shaka assess --sim` remains deterministic (10 nodes / 13 edges,
medium risk 53/100). On a live directory, follow-up is what turns a flat
object listing into the verified, deepened picture the analysis stages rely
on.

## Configuration

The follow-up engine reads its bounds from the pipeline `Options` (`MaxDepth`
and the worker count), and honors `-v/--verbose` logging. The
`depth.max` and `concurrency.followup` keys are defined as configuration
defaults but are not yet consumed by the follow-up wiring; treat them as
reserved until the live pipeline drives them. See
[Configuration](Configuration.md).
