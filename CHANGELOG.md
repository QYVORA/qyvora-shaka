# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **Unified version system** — `internal/version` identity now also carries
  official QYVORA contact details (website, support, location), surfaced by
  `shaka version` in terminal and machine formats.
- **Contact details** — the `version` command, README, and `SECURITY.md`
  surface official QYVORA contact: https://qyvora.netlify.app ·
  qyvorasec@gmail.com · Tamale, Ghana.
- **ANSI hygiene** — terminal colors are disabled when stdout is piped or
  redirected or `NO_COLOR` is set; the console `clear` command only emits
  control sequences to an interactive terminal.
- Fatal config/event errors no longer call `os.Exit(1)` directly; they surface
  through `Execute`'s exit-code contract.

### Added


- Foundation release of SHAKA, the authorized Active Directory / Windows
  security assessment framework.
  - `assess` pipeline: DISCOVER → VERIFY → DEEPEN → CORRELATE → ANALYZE →
    REPORT, implemented as discovery → enumeration → graph → analysis →
    findings → risk
  - Offline demo simulator (`directory.Demo()`) modeling `corp.example.com`
    (domain, DC, users, groups, computer, OUs, external trust); `--sim`
    targets are auto-authorized
  - Directory service abstraction with a live LDAP/LDAPS service and the
    in-memory simulator; low-level LDAP/BER client
  - Relationship graph with typed nodes/edges, deduplication, confidence
    merging, and deterministic shortest-path/attack-path analysis
  - Deepening / VERIFY follow-up engine with depth limits, dedup, and cycle
    protection
  - Rule engine with built-in rules `ADM-001 … ADM-006` and `AUTH-001`
  - Evidence store with SHA-256 hashing and deduplication
  - Risk scoring (severity × confidence × exposure, 0..100)
  - Reporting: terminal, JSON, Markdown, HTML, YAML, rendered from saved
    sessions
  - Session persistence as JSON under `./sessions/`
  - JSONL event stream (`--events`) using the shared QYVORA envelope
  - CLI: `assess`, `discover`, `enumerate`, `analyze`, `findings`,
    `evidence`, `graph`, `report`, `target`, `capabilities`, `tools`,
    `updates`, `completion`, `version` — plus the interactive console
  - Console parity: every one-shot command available in the REPL, assessments
    running against the offline demo by default
  - Authorization gate with interactive and non-interactive modes
  - Config file, `QYVORA_SHAKA_*` environment namespace, and defaults;
    profiles `quick`, `standard`, `deep`, `directory`, `authentication`,
    `trust`, `identity`, `compliance`, `research`
  - Verified self-update (SHA-256 checksums, atomic swap, no downgrades, no
    Go toolchain required)
  - Exit-code contract (0 / 1 / 2 / 130)
  - Unit tests (offline, deterministic, no live directory required)
  - Documentation and community files (README, docs/, CONTRIBUTING,
    SECURITY, NOTICE, SUPPORT, GOVERNANCE, CODE_OF_CONDUCT)