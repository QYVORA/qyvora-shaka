# Security Model

This document describes SHAKA's trust boundaries, safety controls, and
operational guidance. It is required reading for contributors and for anyone
operating SHAKA against live directories.

## Authorized use only

SHAKA is a tool for **authorized Microsoft Active Directory / Windows
security assessment**. It is not a scanner, and it is not intended to reach
directories you neither own nor have explicit written permission to test.
Operating it otherwise may violate law and policy in your jurisdiction.

## The authorization gate

Every assessment of a live target passes an authorization gate before any
directory interaction:

1. The target is identified (directory endpoint + base DN).
2. The operator confirms authorization:
   - `-y/--authorized` flag, the `authorized` config key, or
     `QYVORA_AUTHORIZED=true`, or
   - an interactive confirmation prompt when stdin is a terminal.
3. Authorization is recorded on the target and carried into the session
   (scope, method, granted by).

In a non-interactive context, a live (non-sim) assessment **without** these is
refused with exit code 1 — there is no silent path.

The offline `--sim` target is **auto-authorized** by design: the simulator
performs no network I/O and touches nothing outside the process.

## Scope boundaries

- **One target.** The scope of an assessment is a single specified
  directory/domain, reached over a single endpoint.
- **Declared trusts only.** Optionally, the trusts *that target declares* may
  be analyzed. SHAKA never discovers a second domain by sweeping.
- **No subnet scanning.** There is no operation that enumerates a subnet or
  auto-discovers an environment.
- The scope string is recorded with every authorization so an operator can
  audit exactly what was authorized.

## Trust boundaries

```
 Operator ── shaka (local process) ── LDAP/LDAPS ── directory service (read-only)
                │
                └── sessions/ (JSON, 0600)   reports/   event stream
```

- **SHAKA runs locally.** The assessed directory is reached only through the
  directory service abstraction over LDAP; `--sim` never leaves the process.
- **The directory is untrusted input.** Responses are decoded and normalized
  defensively (`internal/directory`); malformed entries are handled without
  crashing the process.
- **Evidence is captured locally** with SHA-256 hashing and persisted only in
  the local session/report files.
- **Passwords are never serialized.** `Target.Password` is excluded from JSON
  (`json:"-"`).

## Safety controls

| Control | Detail |
|---|---|
| Authorization gate | every live run must pass (see above) |
| Single-target scope | one directory/domain (+ declared trusts) |
| No subnet scanning | no mass or automatic discovery |
| Read-only by default | all foundation operations are reversible, no state change |
| Safety metadata | `internal/safety` models each operation's risk (S1–S4), target type, confirm flag and reversibility |
| Timeouts | directory operations bounded by `ldap.timeout_seconds` / `--timeout` |
| Cancellation | SIGINT/SIGTERM cancels the pipeline cleanly (exit 130) |
| Deterministic parsing | filters and normalizers fail closed, never panic |
| Evidence hashing | evidence is SHA-256 hashed at capture |
| Restricted permissions | sessions written mode 0600, events file mode 0600 |
| Bounded depth | follow-up stops at `Options.MaxDepth` and path traversal at a caller-supplied cap, so analysis can never expand without limit |

## Logging and reversibility

- Operations are logged (stages, discovered objects, findings, risk) and
  recorded on the session with timestamps, so an operator can reconstruct
  exactly what happened.
- Every foundation operation is **reversible**: it changes no state on the
  assessed directory. Reports, sessions and evidence are local artifacts.
- `--dry-run` resolves and prints the assessment plan without executing it.

## What SHAKA does not do

- It does **not** scan subnets, CIDRs, or ranges, and cannot be pointed at a
  "network" — only at a specified directory endpoint.
- It does **not** provide unauthorized-access automation, brute forcing, or
  credential dumping.
- It does **not** modify the directory (no writes, no password changes, no
  policy mutation) in the foundation release.
- It does **not** embed an LLM; the AI orchestrator is a separate layer that
  consumes SHAKA's machine-readable capability metadata.

## Non-interactive safety

For automation, authorization must be explicit: `-y/--authorized` or
`QYVORA_AUTHORIZED=true`. A non-TTY invocation that skips this is refused with
exit code 1 before any connection is made. Set `authorized: true` in a config
file only in environments you fully control.

## Logging and privacy

- Session and report files may contain account names, group names, and
  directory metadata. Treat them as sensitive artifacts; do not run SHAKA
  against directories containing data you are not authorized to collect.
- Evidence and event output is written locally with restrictive permissions.

## Reporting security issues

See [SECURITY.md](../SECURITY.md). Do **not** open a public issue for
vulnerabilities.