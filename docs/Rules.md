# Rules

SHAKA's findings stage evaluates a deterministic rule engine
(`internal/rules`) against the session's discovered objects. Rules are small,
independent, evidence-backed, and unit-tested.

## Rule structure

A rule carries rich metadata and one detection function:

```go
type Rule struct {
    ID            string
    Name          string
    Description   string
    Category      string
    Severity      models.Severity
    Confidence    models.Confidence
    RequiredState models.State
    ObjectTypes   []string
    Detect        func(ctx Context) []*models.Finding
    Remediation   string
    References    []string
}
```

`rules.Context` provides the session state a rule evaluates: users, groups,
computers, domains, trusts, organizational units, and evidence. Rules are
applied in sorted ID order, and the engine sorts results by severity
(descending), then rule ID, then fingerprint — so a run is stable across
machine, time, and map iteration. Rules are deterministic by construction.

## Built-in rules

The built-in set (`internal/rules/builtin`) is `ADM-001 … ADM-006` plus
`AUTH-001`:

| ID | Rule | Category | Severity | Confidence |
|---|---|---|---|---|
| `ADM-001` | Privileged Group Membership Discovered | privilege | high | high |
| `ADM-002` | Account Password Never Expires | authentication | medium (high for privileged accounts) | high |
| `ADM-003` | Kerberos Pre-Authentication Not Required | kerberos | high | high |
| `ADM-004` | Unconstrained Delegation | kerberos | high | medium |
| `ADM-005` | Weak or Legacy Authentication Encryption | authentication | medium | medium |
| `ADM-006` | External or Forest Trust Present | trust | medium | medium |
| `AUTH-001` | Domain Trust Relationship | trust | informational | medium |

Notes:

- **ADM-001** flags users marked privileged (`adminCount`). The demo directory
  produces two such findings (Administrator and svc-backup).
- **ADM-003** flags accounts where Kerberos pre-authentication is not
  required (`DONT_REQUIRE_PREAUTH`), exposing them to AS-REP roasting. In the
  demo directory this fires for `kpreauth`.
- **ADM-006** flags external/forest trusts; **AUTH-001** records any trust as
  informational context. Both are fed by the trust analyzer.
- A rule's `Confidence` is honest: where evidence cannot confirm a claim, the
  rule says so (e.g. `ADM-004` and `ADM-005` are medium confidence).

## Finding anatomy

Every rule produces zero or more `models.Finding`:

```go
type Finding struct {
    ID             string
    TargetID       string
    SessionID      string
    RuleID         string
    Title          string
    Category       string
    Description    string
    Impact         string
    Recommendation string
    Severity       models.Severity
    Confidence     models.Confidence
    Status         FindingStatus   // detected | confirmed | false-positive | resolved | informational
    State          State
    Objects        []string        // affected object identifiers
    Evidence       []Evidence
    Attributes     map[string]string
    References     []string
    Timestamp      time.Time
}
```

Each finding carries a **fingerprint**: the SHA-256 of rule ID, category,
title, sorted affected objects and sorted attributes. Two findings with the
same fingerprint describe the same underlying issue; `Session.AddFinding`
merges them (including their evidence) instead of duplicating.

## The demo result

`shaka assess --sim` exercises the rule engine against the offline demo
directory and deterministically yields three findings:

- 2x `ADM-001` Privileged Group Membership Discovered
- 1x `ADM-003` Kerberos Pre-Authentication Not Required

## Rules and profiles

The full built-in rule set runs in every profile; profiles select pipeline
depth and scope, not a subset of rules.

## Writing a rule

1. Add a detection function under `internal/rules/builtin/`.
2. Register it in `builtin.Builtin()`.
3. Assign a stable ID in the ADM/AUTH namespace.
4. Add table-driven tests in `internal/rules/`.
5. Document it in this file.

The minimum bar: deterministic detection, honest confidence, evidence recorded
for each finding, a doc comment on the rule, and tests with synthetic (or demo
simulator) fixtures. See [Development](Development.md).