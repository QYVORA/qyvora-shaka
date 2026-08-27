# SHAKA — Authorized Active Directory / Windows Security Assessment Framework

**Authorized Microsoft Active Directory / Windows security assessment**
**framework**

SHAKA is a terminal-first Go framework for authorized Active Directory
security assessment: discover an environment, enumerate directory objects,
verify and deepen what was found, correlate relationships into a graph,
analyze authentication and trust configuration, and produce evidence-driven
reports.

The CLI and binary are `shaka` (Go module
`github.com/QYVORA/qyvora-shaka`). It is part of the QYVORA open-source
ecosystem.

> Every assessment requires explicit target authorization. SHAKA is scoped,
> reversible, logged, and intended for use only on systems you are authorized
> to assess. See [SECURITY.md](SECURITY.md) and
> [Security Model](docs/Security-Model.md).

---

## What it is

A single interface for assessing one authorized Active Directory domain:

- **Discovery** — identify the domain, its base DN, and its domain
  controllers over LDAP.
- **Enumeration** — enumerate users, groups, computers, organizational units
  and trusts.
- **Verification and deepening** — run follow-up queries that confirm and
  deepen findings, bounded by depth and deduplicated.
- **Correlation** — build a relationship graph (membership, joins, trusts)
  whose edges are derived from evidence, never manufactured.
- **Analysis** — evaluate a deterministic rule engine (ADM-xxx / AUTH-xxx
  findings) plus identity, trust and Kerberos assessment.
- **Reporting** — terminal, JSON, Markdown, HTML and YAML reports rendered
  from the saved session.

When the environment is unavailable or you want an offline walk-through, the
built-in offline simulator (`--sim`, `directory.Demo()`) models the
`corp.example.com` domain deterministically.

## What it is NOT

- **Not a mass scanner.** The scope of an assessment is a single specified
  directory/domain, plus optionally the trusts that domain declares. SHAKA
  never sweeps a subnet or auto-discovers an environment.
- **Not an unauthorized-access tool.** Every run passes an authorization
  gate; there is no configuration or command path that proceeds silently
  without authorization.
- **Not an exploitation framework.** The foundation release performs
  read-only discovery, enumeration and analysis. It does not change state on
  the directory it assesses.

See [Security Model](docs/Security-Model.md) for the trust boundaries.

## Pipeline

```
DISCOVER → VERIFY → DEEPEN → CORRELATE → ANALYZE → REPORT
```

| Stage | What happens |
|---|---|
| DISCOVER | domains, domain controllers, base DN; seeds the graph |
| VERIFY | follow-up queries confirm what discovery/enumeration produced |
| DEEPEN | nested memberships and deeper object detail are expanded |
| CORRELATE | the relationship graph is completed (nodes, edges, trusts) |
| ANALYZE | rule engine, identity, trust, Kerberos and attack-path analysis |
| REPORT | findings, evidence and risk are recorded and rendered |

## Status

**Foundation.** The core pipeline, offline simulator, rule engine,
evidence and risk systems, reporting, CLI and interactive console, safety
model, and verified self-update are implemented and tested. See
[Roadmap](docs/Roadmap.md) for what is planned (deeper live LDAP features,
Kerberos/SMB protocol analysis, more rules, ecosystem integration).

## Features

- **`DISCOVER → VERIFY → DEEPEN → CORRELATE → ANALYZE → REPORT` pipeline**
  orchestrated by configurable profiles (`quick`, `standard`, `deep`,
  `directory`, `authentication`, `trust`, `identity`, `compliance`,
  `research`).
- **Live and offline targets** — a live directory over LDAP/LDAPS, or the
  built-in offline demo simulator (`--sim`), auto-authorized.
- **Directory service abstraction** — `internal/directory` wraps LDAP
  (connection, bind, search, paging, normalization) so the pipeline is
  transport-agnostic; `internal/ldap` provides the low-level LDAP/BER client.
- **Relationship graph** — `internal/graph` models Active Directory as typed
  nodes and edges, with deduplication, confidence merging and deterministic
  shortest-path analysis for security-relevant paths.
- **Rule engine** — deterministic detection rules backed by hashed,
  deduplicated evidence (ADM-001 … ADM-006, AUTH-001).
- **Risk scoring** — transparent severity × confidence × exposure scoring per
  finding and per target.
- **Reporting** — terminal, JSON, Markdown, HTML and YAML from the saved
  session; `shaka report` re-renders at any time.
- **JSONL event stream** — `--events` emits a machine-readable
  run/stage/finding feed (stdout, stderr, or file) for automation.
- **Authorization gate** — explicit per-target confirmation, non-interactive
  mode, and refusal in any ambiguous context.
- **Interactive console** — running bare `shaka` drops into a
  Metasploit-style REPL where every one-shot command is available.
- **Machine-readable capabilities** — `shaka capabilities` / `shaka tools`
  exposes an AI-ready tool catalog with risk and authorization metadata.

## Install

Requires Go (the `go.mod` pins the toolchain) to build from source.

```sh
make build                # builds bin/shaka
# or
go build -o bin/shaka ./cmd/shaka
```

Install into your system so `shaka` appears on `PATH` with an icon and
desktop entry (see [Installation](docs/Installation.md)):

```sh
sudo make install         # system-wide (Linux/Unix), or:
make install-user         # per-user, no root
```

## Updating

```sh
shaka updates                # check; `shaka update` works as an alias
shaka updates --install      # download, verify, install the latest release
```

Updates check the official QYVORA GitHub releases, verify the artifact's
SHA-256 against the published `SHA256SUMS`, and swap the binary in
atomically. Downgrades are refused; any failure leaves the installed binary
untouched. No Go toolchain or Git is required.

## Quick start

```sh
# Interactive console (Metasploit-style REPL)
shaka

# Offline demo assessment (no live directory, auto-authorized)
shaka assess --sim

# Live assessment of an authorized directory (interactive confirmation)
shaka assess --endpoint dc01:389

# Non-interactive (automation) — explicit authorization
shaka assess --endpoint dc01:389 --user svc-audit -y --json
```

`shaka assess --sim` runs the full pipeline against the offline demo and
yields 10 graph nodes / 13 edges, a `medium` risk score of 53/100, and the
expected findings (2x `ADM-001` privileged group membership, `ADM-003`
Kerberos pre-authentication not required) — a deterministic walk-through of
the whole pipeline.

Inside the console you get the banner, a prompt, and every one-shot command:

```text
shaka> assess
shaka> findings
shaka> graph
shaka> report
shaka> help
shaka> exit
```

## Documentation

| Document | Purpose |
|---|---|
| [Architecture](docs/Architecture.md) | Package layout and pipeline design |
| [Installation](docs/Installation.md) | Building from source |
| [Getting started](docs/Getting-Started.md) | First assessment |
| [CLI reference](docs/CLI.md) | Every command and flag |
| [Targets](docs/Targets.md) | Directory endpoints, sim mode, authorization |
| [Configuration](docs/Configuration.md) | Config file, environment, profiles |
| [Rules](docs/Rules.md) | Rule engine and the ADM-xxx / AUTH-xxx set |
| [Verify](docs/Verify.md) | The VERIFY/DEEPEN stages (deepening) |
| [Correlation](docs/Correlation.md) | The graph / CORRELATE stage |
| [Evidence](docs/Evidence.md) | Evidence collection, hashing, dedup |
| [Reporting](docs/Reporting.md) | Report formats and session persistence |
| [Security model](docs/Security-Model.md) | Trust boundaries and safety controls |
| [Development](docs/Development.md) | Building and contributing code |
| [Roadmap](docs/Roadmap.md) | Planned work |

## Project layout

```
cmd/shaka/             executable entry point; calls cli.Execute()
internal/cli/          cobra command tree, appState, authorization gate,
                       console REPL, rendering, version/updates
internal/core/         pipeline stage contracts (Stage, Env)
internal/orchestration/ pipeline + profiles
internal/config/       viper-based config (QYVORA_SHAKA_* environment namespace)
internal/target/       target manager
internal/validation/   target validation
internal/directory/    directory service abstraction + offline simulator +
                       Demo() fixtures + normalize helpers
internal/discovery/    discovery engine
internal/enumeration/  focused enumerators (users, groups, computers, OUs, trusts)
internal/ldap/         LDAP client / BER (live connections)
internal/transport/    transport abstraction
internal/graph/        relationship graph + correlation (shortest paths)
internal/deepening/    deepening / VERIFY follow-up engine
internal/analysis/     identity, trust, Kerberos and attack-path analysis
internal/rules/        rule engine; internal/rules/builtin/ built-in rules
internal/evidence/     evidence store (hashing, dedup)
internal/risk/         severity/confidence/exposure scoring
internal/assess/       Runner/Options (Full(), stage toggles) reused by CLI + console
internal/pipeline/     stage wiring (build.go seeds the graph), rules/risk wiring
internal/reporting/    report renderers: terminal, json, markdown, html, yaml
internal/output/       output formatting
internal/session/      session persistence (JSON under ./sessions; session.dir)
internal/logger/       logging
internal/events/       JSONL event stream
internal/safety/       architectural safety metadata
internal/exitcode/     exit codes (0/1/2/130)
internal/selfupdate/   verified self-update (SHA-256, atomic swap)
internal/capabilities/ machine-readable capability/tool catalog
internal/banner/       brand banner (ASCII art)
internal/version/      build identity
pkg/models/            shared data model (finding.go, session.go, graph.go, …)
```

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report security issues per
[SECURITY.md](SECURITY.md). Community and governance details are in
[GOVERNANCE.md](GOVERNANCE.md).