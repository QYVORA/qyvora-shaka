# Roadmap

An honest status of what is done, what is next, and what is explicitly out of
scope. Nothing here promises a date or a feature that is not being built.

## Done (foundation)

- [x] Modular Go project layout (`cmd/`, `internal/`, `pkg/`)
- [x] Data model (`pkg/models`): targets, sessions, findings, evidence,
      graph, severity/confidence, risk
- [x] Directory service abstraction + offline simulator (`directory.Demo()`)
- [x] Pipeline: DISCOVER → VERIFY → DEEPEN → CORRELATE → ANALYZE → REPORT
      (discovery → enumeration → graph → analysis → findings → risk)
- [x] Profiles (`quick`, `standard`, `deep`, `directory`, `authentication`,
      `trust`, `identity`, `compliance`, `research`)
- [x] Rule engine + built-in `ADM-001 … ADM-006` and `AUTH-001`
- [x] Evidence store with SHA-256 hashing and deduplication
- [x] Risk scoring (severity × confidence × exposure, 0..100)
- [x] Reporting: terminal, JSON, Markdown, HTML, YAML
- [x] Relationship graph with dedup, confidence merging and shortest paths
- [x] Full CLI: `assess`, `discover`, `enumerate`, `analyze`, `findings`,
      `evidence`, `graph`, `report`, `target`, `capabilities`, `tools`,
      `updates`, `completion`, `version` — plus the interactive console
- [x] Authorization gate, dry-run, non-interactive mode, `--sim` auto-auth
- [x] Config file + `QYVORA_SHAKA_*` environment namespace + defaults
- [x] Safety metadata (`internal/safety`) and exit-code contract
- [x] Verified self-update (SHA-256, atomic swap, no downgrades)
- [x] Unit tests covering filters, normalizers, enumerators, rules, risk,
      graph, evidence, models, and reporting (offline, deterministic)

## Planned

### Deeper live LDAP coverage

- [ ] Expanded discovery of the forest topology and configuration partition
- [ ] Richer object normalization (GPOs, service principal names, RODC/GC
      detection, functional levels)
- [ ] Paged-search robustness and larger-directory performance work

### Kerberos / SMB protocol analysis

- [ ] Protocol-level Kerberos assessment (AS-REP / TGT inspection against
      the authorized target, gated and reversible)
- [ ] SMB/session-based hardening checks on authorized hosts
- [ ] These remain gated by the safety model; nothing ships without explicit
      authorization and reversibility guarantees

### Rule expansion

- [ ] Additional ADM rules across authentication, delegation, and trust
- [ ] Per-profile rule subsetting (profiles currently do not filter the rule
      set)
- [ ] Reference and remediation guidance per rule

### Ecosystem integration

- [ ] Tighten the machine-readable capability catalog consumption contract
      for the QYVORA AI orchestrator
- [ ] Session/report diffing between assessment runs
- [ ] Additional report export paths (PDF/CSV), templates

## Deferred / explicit non-goals

- [ ] Broad subnet or mass scanning — **out of scope by design**
- [ ] Unauthorized-access automation, credential dumping, brute forcing —
      **out of scope**
- [ ] Write operations against the assessed directory — **out of scope in the
      foundation release**

## Guiding principle

> Every capability is gated, scoped, reversible where it could have impact,
> and clearly documented. Features are shipped only when they are honest
> about what they do.