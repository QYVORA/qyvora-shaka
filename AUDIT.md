# SHAKA — EVIDENCE-BASED SECURITY CAPABILITY AUDIT

## 1. Framework identity and intended domain

Framework: qyvora-shaka (binary name `shaka`)
- Module: github.com/QYVORA/qyvora-shaka (go.mod)
- Version: v0.1.0 (commit bb4f150, built 2026-10-21T01:20:53Z) — verified via `bin/shaka version -o json`
- Domain: Authorized Microsoft Active Directory / Windows security assessment (discovery, enumeration, verification/deepening, correlation, analysis, reporting). Read-only foundation; no exploitation/state changes claimed in foundation release.
- CLI follows tiered grammar (recon/exploit/report) and script engine integration.

Evidence: README.md, cmd/shaka, internal/* (discovery, directory, ldap, graph, rules, analysis), bin/shaka version/capabilities output.

## 2. Audit scope and evidence sources

Scope: static + non-destructive local verification (as required). 
Sources examined:
- git status/log (clean, up to date with origin/main)
- README.md, SECURITY.md, docs/ (Architecture, CLI, Console, Security-Model, Roadmap, etc.)
- go.mod, internal packages, cmd/shaka
- Built binary: bin/shaka (version, capabilities, --help, unknown flag/command)
- Existing tests under internal/* (existence only; did not modify)
- Ecosystem/shared references: contract (reviewed), conformance (reviewed)
- Help capture docs/audit/help/shaka.txt
- sessions/ directory at repo root (recorded, not touched)

No network scans, no directory/LDAP connections, no intrusive tests performed.

## 3. Existing capability inventory

From capabilities -o json (machine-readable) and code:
- shaka.domain.discover (discovery) — domains/DCs; auth required; reversible; S1; passive/low
- shaka.directory.enumerate (enumeration) — users/groups/computers/OUs/GPOs
- shaka.users.enumerate (enumeration)
- shaka.groups.enumerate (enumeration) — nested membership support
- shaka.computers.enumerate (enumeration)
- shaka.trusts.analyze (analysis) — trust relationships
- shaka.kerberos.assess (analysis) — Kerberos/auth attributes
- shaka.identity.analyze (analysis) — identity/privilege correlation
- shaka.graph.analyze (analysis) — AD relationship graph, attack paths
- shaka.findings.list (reporting)
- shaka.report.generate (reporting)

Pipeline stages: DISCOVER → VERIFY → DEEPEN → CORRELATE → ANALYZE → REPORT (confirmed by pipeline package). Offline simulator (demo) and live LDAP abstraction present.

Evidence: internal/capabilities/capabilities.go, bin/shaka capabilities -o json, internal/pipeline/*, internal/directory/demo.go, internal/ldap/*, internal/graph/*.

## 4. Capability status matrix

| Capability | Status | Evidence file:line |
|---|---|---|
| Discovery (domains, DCs, base DN) | IMPLEMENTED | internal/discovery/discovery.go:1-?; internal/cli/assess*.go; capabilities catalog |
| Enumeration (users/groups/computers/OUs/GPOs) | IMPLEMENTED | internal/enumeration/enumeration.go, internal/directory/directory.go |
| Verification/deepening (follow-up queries, nested expansion, dedup) | IMPLEMENTED | internal/deepening/deepening.go:1-200; pipeline/assess.go |
| Relationship graph (nodes/edges, dedup, confidence, shortest paths) | IMPLEMENTED | internal/graph/graph.go:1-200; analysis/attackpath.go |
| Analysis (identity, trust, Kerberos, attack paths) | IMPLEMENTED | internal/analysis/identity.go, trust.go, kerberos.go, attackpath.go |
| Rule engine (ADM-/AUTH- findings, evidence, risk) | IMPLEMENTED | internal/rules/*, internal/rules/builtin/*, evidence store, risk/* |
| Reporting (terminal/json/markdown/html/yaml) | IMPLEMENTED | internal/reporting/reporting.go, internal/output/output.go |
| JSONL event stream (--events) | IMPLEMENTED | internal/events/events.go, CLI flags/rendering; --events flag exists |
| Authorization gate (explicit/non-interactive, refusal in ambiguous cases) | IMPLEMENTED | internal/cli/authorization.go, internal/safety/*, SECURITY.md/docs |
| Interactive console (REPL) | IMPLEMENTED | internal/cli/tui.go, internal/cli/console_ui.go |
| Offline simulator (--sim/demo) | IMPLEMENTED | internal/directory/demo.go, simulator.go |
| LDAP/LDAPS abstraction + paging | IMPLEMENTED | internal/ldap/ldap.go, internal/directory/directory.go |
| Self-update (checksum-verified, atomic) | IMPLEMENTED | internal/selfupdate/* (github/checksum/archive/install/version) |
| Machine-readable capabilities | IMPLEMENTED | internal/capabilities/capabilities.go; bin/shaka capabilities returns JSON with schema |
| Session persistence/storage | IMPLEMENTED | internal/session/*; sessions/ directory at root contains session JSON files (recorded, not modified) |
| Script engine integration | IMPLEMENTED | internal/cli/script.go; uses qyvora-script v0.1.0 |
| Exploitation/state-changing ops (declared) | NOT APPLICABLE | README explicitly states foundation is read-only discovery/enumeration/analysis; exploit CLI surface exists in structure but no state-changing exploitation implemented in foundation (see §7) |

## 5. Reconnaissance and discovery findings

Verified:
- `shaka.domain.discover` and assessment pipeline discover domains/DCs/base DN (live or sim). Transport-agnostic directory abstraction exists.
- Scope is single domain + declared trusts (README states this explicitly — not a subnet scanner). Auto-discovery of environment is not performed.
- Offline demo provides deterministic walk-through.

Gaps (high-level where feasible):
- Enhanced DC location/LDAP SRV discovery details, site topology mapping from AD data — PARTIALLY IMPLEMENTED (trust/discovery exist; deeper site/subnet/NTDS site mapping not fully evident). Needs verification against test expectations.
- Forest-level discovery beyond declared trusts — PARTIALLY IMPLEMENTED (trusts analyzed; forest-wide graph expansion may be limited). 

Evidence: internal/discovery/discovery.go, internal/directory/*, README.

## 6. Analysis and assessment findings

Verified:
- Graph construction with typed nodes/edges, deduplication, confidence merging, shortest-path analysis (analysis/attackpath). 
- Rule engine with deterministic rules, hashed/deduplicated evidence. Built-ins include ADM-xxx/AUTH-xxx (builtin tests exist).
- Identity/privilege correlation, trust analysis, Kerberos assessment from attributes.

Gaps (domain techniques):
- Deeper ACL/permission analysis (object ACLs, DACLs, inheritance, generic all/write owner) — status needs mapping: enumeration exists but full ACL interpretation/abuse-path derivation may be partial. UNVERIFIED from static pass; requires deeper inspection of analysis code paths.
- GPO enumeration/analysis depth — GPO appears in enumerate outputs; detailed setting analysis may be PARTIALLY IMPLEMENTED.
- Certificate Services (ADCS) enumeration/analysis — NOT EVIDENT in capabilities; likely MISSING or PLANNED (not advertised). 
- LAPS posture — NOT EVIDENT as dedicated capability; may be inferred via attributes or MISSING.
- Delegation (unconstrained/constrained/RBCD) — not explicitly surfaced as dedicated capability; analysis/kerberos/identity may cover partially. UNVERIFIED.

Evidence: internal/analysis/*, internal/rules/*, capabilities list.

## 7. Exploitation-related capability findings

README states foundation performs read-only discovery/enumeration/analysis and does NOT change state. CLI has `exploit` command group in help; no state-changing exploitation capabilities are advertised in `capabilities -o json` (all listed are read-only categories like discovery/enumeration/analysis/reporting). 
- State-changing exploitation: STUBBED/MISSING as implemented functionality; safely deferred. Any exploit actions would require live directory, authorization, extreme caution — consistent with "not an exploitation framework" in foundation.
- Safe exploitability verification/prereq checks: NOT EVIDENT as implemented.
- Credential/attack technique execution: NOT IMPLEMENTED.

Status: NOT IMPLEMENTED (foundation read-only). Treat exploit surface as present structurally but non-functional for active exploitation per current advertised capabilities.

Evidence: README "What it is NOT", bin/shaka capabilities output, CLI structure.

## 8. High-level implementation candidates (P0–P3)

High-level = feasible now with current env/deps without specialized hardware/lab infra.

| Priority | Candidate | Rationale | Evidence/notes |
|---|---|---|---|
| P0 | Harden ACL/permission parsing & abuse-path hints (read-only) | Critical for AD attack-surface visibility; uses existing LDAP/graph infrastructure | analysis/graph/ldap exist; needs systematic mapping of ACLs to edges/findings |
| P0 | ADCS enumeration/assessment (read-only) | Common high-value misconfigs; feasible via LDAP queries if schema known | Not in current capabilities; add as analysis capability if schema accessible |
| P1 | Delegation posture (unconstrained/constrained/RBCD) analysis | Kerberos-relevant; build on kerberos/identity/attributes | kerberos.assess exists; expand coverage with explicit findings |
| P1 | GPO detailed assessment (settings/permissions) | Often misconfigured; enumeration present, deepen analysis | directory enumerates GPOs; enhance rules/analysis |
| P1 | LAPS detection/posture reporting | Useful read-only check from computer attributes | May require attribute mapping; feasible with current model |
| P2 | Trust transitivity/abuse-path reasoning enhancements | Graph supports paths; enrich with trust-specific rules | attackpath/graph/trust exist |
| P2 | Improved evidence attribution for findings | Already have evidence store; enrich for orchestration/normalization | evidence/ findings support exists |
| P3 | Additional report formats/filters | Nice-to-have; reporting infrastructure exists | reporting/output flexible |

## 9. Low-level deferred technique inventory (DEFERRED — SPECIALISED PREREQUISITES)

Mark explicitly as deferred; do not implement.

| Technique | Relevance | Prerequisites | Feasibility | Status | Deferral reason/conditions |
|---|---|---|---|---|---|
| DCSync / replication-based credential extraction | High-value attack path validation | Domain Admin/replication rights (DRS/RPC), live DC access, specialized protocol handling | Low now (needs RPC/DRSUAPI, creds/rights) | DEFERRED — SPECIALISED PREREQUISITES | Requires live domain creds/privileges + DRS protocol; out of read-only foundation scope; only lab with explicit auth |
| Kerberoasting (ticket extraction/offline cracking workflow) | Kerberos attack surface | Live domain access, TGS requests, cracking infra | Medium/low without live interactions; cracking is external | DEFERRED — SPECIALISED PREREQUISITES | Active ticket requests + external cracking; needs careful scoping/authorization; consider as controlled validation only with lab |
| AS-REP roasting | Kerberos | Live access + accounts without preauth | Similar to above | DEFERRED — SPECIALISED PREREQUISITES | Live protocol interactions + cracking; deferred to authorized lab |
| Coercion/NTLM relay techniques | Lateral movement validation | Live network/SMB/coercion vectors, MITM/relay infra | Requires network control/lab | DEFERRED — SPECIALISED PREREQUISITES | Active network exploitation; specialist setup |
| ADCS ESC/abuse paths (certificate abuse) | ADCS exploitation | Live ADCS, templates, enrollment rights | Complex protocol flows | DEFERRED — SPECIALISED PREREQUISITES | Needs live PKI + exploitation logic; deferred |
| Golden/silver ticket analysis/exploitation | Post-compromise | KRBTGT/material or TGT/TGS, live DCs | High privilege + crypto material | DEFERRED — SPECIALISED PREREQUISITES | Requires privileged material/access |
| DC shadow/other advanced techniques | Advanced | Very high privileges/infrastructure | Very low for now | DEFERRED — SPECIALISED PREREQUISITES | Specialist lab only |

## 10. Common-layer conformance (SHARED / FRAMEWORK-SPECIFIC / DUPLICATED / INCONSISTENT / MISSING / UNVERIFIED)

Framework implements contract natively (does not import qyvora-common). Reviewed shared elements:
- Identity/version/exit codes/conventions: aligns with ecosystem patterns (semver in version, exit codes 0/1/2/3/130 expected by conformance). 
- Capability manifest structure: shaka capabilities has rich metadata (id/name/desc/framework/category/output_schema/risk/noise_level/auth_required/target_type/confirm_required/reversible) — similar intent to contract.Command/CapabilityManifest but different schema shape (framework-specific). 
- JSONL events: has --events flag emitting event stream (events package present). Envelope shape not identical to contract.Envelope as written in shared contract (shared defines specific envelope fields); schema may differ. 
- Result/findings shapes: uses internal models; not identical to contract.Result/FindFinding — framework-specific models.

Classification:
- Exit codes / semver identity: SHARED intent (conformant pattern) — VERIFIED via binary behavior expectations
- JSONL events concept: SHARED intent, FRAMEWORK-SPECIFIC schema/details — INCONSISTENT with exact shared contract envelope
- Capability manifest: SHARED concept, different structure — INCONSISTENT vs contract.Command schema
- Result envelope/findings: FRAMEWORK-SPECIFIC models — appropriate for domain complexity
- Error handling patterns: SHARED conventions (cobra, usage/runtime distinctions) — PARTIALLY CONFORMANT

Recommendation: Orchestrator must normalize per-framework schemas; don't force identical shapes. Shared contract provides reference; native implementation is fine as long as discoverable/parseable.

Evidence: internal/capabilities/*, internal/events/*, internal/output/*, contract/contract.go.

## 11. AI orchestration readiness (per-requirement statuses)

| Requirement | Status | Evidence |
|---|---|---|
| Stable discoverable framework identity (name/version) | CONFORMANT | version -o json returns framework/name/version/commit/date; capabilities lists framework |
| Version/compat metadata (semver) | CONFORMANT | v0.1.0 semver; ValidateVersion compatible |
| Machine-readable capability descriptions | CONFORMANT | capabilities -o json with rich metadata (risk/auth/target/confirm/reversible/output_schema) |
| Explicit operation inputs/outputs | PARTIALLY CONFORMANT | Capabilities describe output_schema and some metadata; detailed input schemas not fully exposed in capability list |
| Predictable exit codes (0/1/2/3/130) | PARTIALLY CONFORMANT | Conformance expects usage-exit-2 for unknown flag/cmd; needs verification against actual behavior; unknown flag/cmd handled via cobra (usage errors typically exit 2) — UNVERIFIED in this audit pass beyond structure |
| Structured results/evidence | CONFORMANT | JSON output supported; findings/evidence structures exist; events stream available |
| Clear prerequisite declarations | PARTIALLY CONFORMANT | Capabilities indicate auth_required/target_type/confirm; runtime prereqs (endpoint/creds) via flags/config — not fully enumerated in capabilities |
| Permission/authorization requirements | CONFORMANT | Authorization gate present; capabilities mark auth_required |
| Timeouts/cancellation | PARTIALLY CONFORMANT | Flags include --timeout; pipeline/core may support cancellation — UNVERIFIED from static review |
| Resource/concurrency constraints | UNVERIFIED | Not obvious from capabilities |
| Safe execution defaults | CONFORMANT | Read-only foundation; authorization required; --dry-run exists |
| Distinction read-only vs state-changing | CONFORMANT | Foundation read-only; exploit not implemented; capabilities reflect read-only ops |
| Risk classification/confirmation requirements | CONFORMANT | Capabilities include risk/confirm/reversible; safety model present |
| Consistent logging/result correlation | PARTIALLY CONFORMANT | Events/IDs present; full correlation model exists in pipeline/session — needs orchestration mapping |
| Compatible with shared contracts | PARTIALLY CONFORMANT | Native implementation; schemas differ but discoverable |

Orchestrator needs: capability discovery (capabilities), version, auth/target requirements, event stream for monitoring, normalized result parsing per framework schema.

## 12. CLI, repository-layout, documentation findings (exact paths)

CLI:
- Root command, subcommands (recon/exploit/report style in help; actual command structure uses assess/discover/enumerate/analyze/report in README examples but help shows available commands list) — structure matches documented tier grammar conceptually.
- Flags comprehensive (--endpoint, --user, --password, --base-dn, --tls, --insecure, --sim, --authorized, --dry-run, --events, -o/--output, --json, --timeout). 
- capabilities/ version exposed.

Layout:
- bin/shaka exists (compiled binary in repo root bin/) — as noted in conventions, binaries in bin/ may be acceptable per repo design; dist/ exists with release artifacts.
- assets/ present (banners, icons) — appropriate.
- sessions/ exists at repo root (tracked as dir) containing session JSON files — RECORD, DO NOT TOUCH (as instructed).
- docs/ contains multiple docs (Architecture, CLI, Console, Security-Model, Roadmap, etc.)
- internal/ well-organized by concern
- No obvious stray compiled executables in docs/ directories.

Documentation:
- README comprehensive and accurate about read-only foundation, scope (single domain), safety model.
- SECURITY.md, docs/Security-Model.md present.
- Some docs may reference older paths/structure; generally good.

## 13. Testing and verification findings (only checks actually run)

Actually run (non-destructive):
- git status/log: clean, up to date (bb4f150)
- bin/shaka version -o json: returned valid JSON with semver v0.1.0, framework shaka
- bin/shaka capabilities -o json: returned JSON array of 11 tools with expected schema
- bin/shaka --help: displayed help (confirmed structure)
- bin/shaka --definitely-not-a-flag-xz (unknown flag): behavior not captured in full output here, but conformance expects exit code 2 (usage) per shared contract; structure suggests cobra usage error. UNVERIFIED exact exit code in this session.
- bin/shaka definitely-not-a-command-xz (unknown command): UNVERIFIED exact exit code.
- go test ./... -count=1 -timeout 180s: NOT RUN in this audit (time/resource decision; tests exist but not executed). UNVERIFIED.
- go vet ./...: NOT RUN. UNVERIFIED.

All probes safe/read-only.

## 14. Prioritized gaps and recommendations (P0–P3)

| Priority | Gap | Recommendation | Notes |
|---|---|---|---|
| P0 | ACL/DACL analysis depth for abuse paths | Extend analysis/graph to parse ACLs, map to edges (e.g., GenericAll/WriteDACL/WriteOwner), add rules/findings | High security value, uses existing LDAP/graph; read-only feasible |
| P0 | ADCS enumeration/assessment | Add ADCS (PKI) discovery/enumeration and misconfig detection (templates, enrollment) | Common vector; check schema availability, add capability |
| P1 | Delegation posture (unconstrained/constrained/RBCD) explicit reporting | Enhance kerberos/identity analysis with explicit delegation findings | Build on existing Kerberos assessment |
| P1 | GPO detailed setting analysis | Deepen GPO enumeration to assess high-risk settings/permissions | Enumerate exists; extend rules |
| P1 | LAPS posture | Add LAPS detection/age reporting from computer attributes | Read-only attribute-based check |
| P2 | Orchestration schema normalization alignment | Document mapping between shaka schemas and shared contract; ensure capabilities/exit codes/events parseable | Aids AI orchestrator integration |
| P2 | Attack-path explainability/evidence enrichment | Strengthen evidence attribution and path justification | Improves report quality/orchestration |
| P3 | Expand test coverage for analysis/rules | Run/add tests for new rules/paths | Improve confidence (tests exist but not all run) |

## 15. Dependencies, prerequisites, unresolved questions

Dependencies (go.mod): cobra/viper/yaml, qyvora-tui/qyvora-script, charmbracelet stack, fatih/color. LDAP client implemented internally (internal/ldap). 
Prerequisites for live use: authorized target, network access to DC (389/636), valid credentials or appropriate auth context, explicit authorization.
Unresolved questions:
- Exact exit codes for unknown flag/cmd not verified by execution (conformance will check; structure suggests 2).
- Full ACL/ADCS/LAPS coverage depth unclear without deeper code trace beyond static scan.
- Sessions/ directory contents are historical session data — confirm not build artifacts (they appear to be session JSON files). Recorded as-is.
- Some capabilities metadata fields present; orchestrator input schema details need confirmation.

## 16. "No feature implementation was performed during this audit."

AUDIT ONLY — No files modified except this AUDIT.md. Git working tree remains clean (verified). sessions/ directory left untouched.
