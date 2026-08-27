# Architecture

This document describes how SHAKA is built and why. It targets contributors
and reviewers; operators should read the
[Getting started](Getting-Started.md) guide instead.

## Design goals

1. **Authorized-first.** An explicit authorization gate precedes every
   assessment. There is no configuration that enables unauthenticated broad
   scanning, and `--sim` targets are the only auto-authorized ones (offline,
   no network I/O).
2. **Single-target, not network-centric.** SHAKA assesses one specified
   directory/domain at a time plus, optionally, the trusts that domain
   declares. It never sweeps a subnet.
3. **Evidence-derived.** Every relationship edge and every finding is backed
   by hashed, deduplicated evidence. The graph is never fabricated from a
   guess.
4. **Modular and testable.** Every pipeline stage is a small Go interface;
   every enumerator is decoupled from the transport and unit-testable with
   synthetic fixtures (the offline simulator).
5. **Honest status reporting.** No stage claims success it did not perform,
   and no rule claims a result it could not observe.
6. **One runner for every surface.** Both the one-shot CLI and the
   interactive console funnel through the same `internal/assess.Runner`, so
   behavior never diverges.

## Package layout

```
cmd/shaka/             executable entry point; calls cli.Execute()
internal/cli/          cobra command tree, appState, authorization gate,
                       console REPL, rendering, version/updates
internal/core/         pipeline contracts: Stage, Env
internal/orchestration/ profile builder + pipeline runner
internal/config/       viper-based configuration (QYVORA_SHAKA_* namespace)
internal/target/       target manager (enforces the authorization gate)
internal/validation/   target validation
internal/directory/    directory service abstraction + offline simulator +
                       Demo() fixtures + normalize helpers
internal/discovery/    discovery engine (domains, DCs, base DN)
internal/enumeration/  focused enumerators (users, groups, computers, OUs, trusts)
internal/ldap/         LDAP client / BER encoding (live connections)
internal/transport/    transport abstraction (entries the LDAP/directory layer returns)
internal/graph/        relationship graph + correlation (nodes, edges, dedup, paths)
internal/deepening/    deepening / VERIFY follow-up engine
internal/analysis/     identity, trust, Kerberos and attack-path analysis
internal/rules/        rule interface + registry; internal/rules/builtin/ built-ins
internal/evidence/     evidence store (SHA-256 hashing, dedup)
internal/risk/         severity/confidence/exposure scoring
internal/assess/       Runner / Options (Full(), stage toggles)
internal/pipeline/     concrete stages: discovery, enumeration, graph, analysis,
                       findings, risk (build.go seeds the graph)
internal/reporting/    renderers: terminal, json, markdown, html, yaml
internal/output/       output formatting (Printer)
internal/session/      session persistence (JSON under ./sessions; session.dir)
internal/logger/       leveled logging
internal/events/       JSONL event stream (shared QYVORA envelope)
internal/safety/       architectural safety metadata
internal/exitcode/     exit code contract (0/1/2/130)
internal/selfupdate/   verified self-update
internal/capabilities/ machine-readable tool catalog
internal/banner/       brand banner (ASCII art)
internal/version/      build identity
pkg/models/            shared data model (Target, Session, Finding, Graph, …)
```

### The core contract

`internal/core` defines the two contracts everything plugs into:

```go
type Stage interface {
    Name() string
    Run(ctx context.Context, env *Env) error
}

type Env struct {
    Target   *models.Target
    Session  *models.Session
    Graph    *graph.Graph
    Dir      directory.Service
    Evidence *evidence.Store
    Log      *logger.Logger
    Config   *viper.Viper
    Events   *events.Stream
}
```

A stage reads from and writes to `Env`. Stages never construct low-level LDAP
operations directly — they go through `Env.Dir` (the directory service
abstraction), which is how tests substitute the offline simulator.

## The pipeline

The canonical pipeline is:

```
DISCOVER → VERIFY → DEEPEN → CORRELATE → ANALYZE → REPORT
```

It is implemented by the concrete stages in `internal/pipeline`, wired by
`internal/assess.Runner` (via `internal/orchestration`) and shared by the CLI
and the console:

| Canonical | Concrete stage | Package |
|---|---|---|
| DISCOVER | discovery | `internal/discovery` |
| VERIFY | deepening / follow-up | `internal/deepening` |
| DEEPEN | enumeration (+ follow-up expansion) | `internal/enumeration` |
| CORRELATE | graph | `internal/graph` |
| ANALYZE | analysis (identity, trust, Kerberos, attack paths) + rules | `internal/analysis`, `internal/rules` |
| REPORT | findings, risk, reporting | `internal/pipeline`, `internal/risk`, `internal/reporting` |

- `internal/assess.Runner` builds a pipeline from `assess.Options`; every
  stage defaults to true (full pipeline) and each can be toggled. `assess.Full()`
  enables all six stages.
- Each stage is timed and recorded on the session.
- A stage error fails the session with a non-zero exit code and a recorded
  error; partial results already collected are still persisted.
- Context cancellation (SIGINT/SIGTERM) aborts cleanly at the next stage
  boundary; the process exits with code 130.

### Profiles

Profiles are configurations of *which* stages run and how deep the assessment
goes. Each is a clearly defined scope, never "do less because we got bored".
The current set (`internal/config` & `internal/orchestration` agree):

| Profile | Use |
|---|---|
| `quick` | Fast posture read |
| `standard` | Default full assessment |
| `deep` | Research-grade, maximum depth |
| `directory` | Directory-object focused |
| `authentication` | Authentication and Kerberos posture |
| `trust` | Trust relationships focused |
| `identity` | Users, groups and privilege focused |
| `compliance` | Audit-oriented output |
| `research` | Full fidelity, raw context |

The profile is validated; a typo is an error rather than a silent change in
what an assessment does.

## Directories and transports

`internal/directory` defines the assessment-facing service boundary:

```go
type Service interface {
    Ping(ctx context.Context) error
    RootBaseDN() (string, error)
    Search(ctx context.Context, baseDN, filter string, attrs []string) ([]*transport.Entry, error)
    Describe() string
    Kind() Kind
    Close()
}
```

- `directory.New(...)` with a live endpoint dials through `internal/ldap`
  (LDAP/LDAPS, optional bind, paging, timeouts) and serves LDAP entries.
- `directory.New(...)` with `Options.Sim: directory.Demo()` returns the
  offline simulator service, which answers subtree searches in memory with no
  network I/O.
- `internal/transport` supplies the `transport.Entry` type (an LDAP-style
  entry with attributes) that the directory layer normalizes into `pkg/models`
  objects via `internal/directory`'s normalize helpers.

## Graph and correlation

`internal/graph` models Active Directory as a directed graph. Node kinds:
domain, domain_controller, computer, user, group, ou, gpo, service, resource.
Edge types include `member_of`, `member`, `joins` (member_of_domain),
`trusts`/`trusted_by`, `contains`, `has_privilege`, `applies_to`, `runs_on`
and `is_admin_of`.

- `internal/pipeline/build.go` seeds the graph: domain and DC nodes from
  discovery, then user/group/computer nodes and membership edges from
  enumeration. Group member DNs resolve to actual nodes; edges are only made
  where directory evidence exists.
- The graph deduplicates nodes and edges, merges confidence upward, and
  attaches evidence IDs to edges.
- `graph.ShortestPaths` computes deterministic shortest paths to sensitive
  destinations, bounded by a maximum-depth argument (defaulting to 12). See
  [Correlation](Correlation.md).

## Rules and the analysis stage

`internal/rules` is a deterministic rule engine. Rules carry ID, name,
description, category, severity, confidence, affected object types, detection
logic, remediation and references. `internal/rules/builtin` registers the
built-in set (ADM-001 … ADM-006, AUTH-001). Rules never depend on map
iteration order; `rules.Engine.Eval` sorts findings by severity (desc), then
rule ID, then fingerprint, so results are stable across runs.

`internal/analysis` adds the correlation passes: identity/privilege
(`identity.go`), trust significance (`trust.go`), Kerberos/authentication
(`kerberos.go`), and attack paths (`attackpath.go`). Findings are recorded on
the session with `AddFinding` (fingerprint-deduplicated); evidence with
`AddEvidence` (hash-deduplicated). See [Rules](Rules.md).

## Risk

`internal/risk` separates severity, confidence, impact and exposure rather
than emitting a fake-precision score. Each finding's risk is explainable
(`risk.Risk` carries the rationale); `risk.Assessor.Assess` combines findings
into a 0..100 target score with a `none|low|medium|high|critical` level. The
offline demo (`shaka assess --sim`) deterministically yields medium 53/100.

## Reporting

`internal/reporting` renders a `Session` to terminal, JSON, Markdown, HTML or
YAML. Renderers are functions of the session only — no directory access —
which keeps them trivially testable and allows offline report generation from
saved sessions. See [Reporting](Reporting.md).

## Configuration

`internal/config` loads with precedence:

1. built-in defaults
2. config file (`-c/--config`, else the discovery list)
3. environment variables (`QYVORA_SHAKA_*`)

`QYVORA_SHAKA` is set as the viper environment prefix, so `report.dir` becomes
`QYVORA_SHAKA_REPORT_DIR`, `ldap.timeout_seconds` →
`QYVORA_SHAKA_LDAP_TIMEOUT_SECONDS`, and so on. `QYVORA_AUTHORIZED=true` is
honored directly by the authorization gate. See [Configuration](Configuration.md).

## Authorized-only flow

The authorization gate (`internal/cli/authorization.go`) enforces:

- interactive confirmation on `assess`/`target` when stdin is a TTY,
- `-y/--authorized` (or the `authorized` config key) for non-interactive runs,
- `QYVORA_AUTHORIZED=true` for automation,
- refusal with an explicit error and exit code 1 otherwise.

`--sim` targets are auto-authorized: the offline demo performs no network I/O
and is inherently safe. The target manager (`internal/target`) refuses to make
an unauthorized target current, so the gate cannot be bypassed. There is no
path that silently proceeds without authorization. See
[Security Model](Security-Model.md).