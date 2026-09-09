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
computers, domains, trusts, organizational units, group policy objects, and
evidence. Rules are applied in sorted ID order, and the engine sorts results
by severity (descending), then rule ID, then fingerprint — so a run is stable
across machine, time, and map iteration. Rules are deterministic by
construction.

## Built-in rules

The built-in set (`internal/rules/builtin`) is `ADM-001 … ADM-014` plus
`AUTH-001 … AUTH-004`:

| ID | Rule | Category | Severity | Confidence |
|---|---|---|---|---|
| `ADM-001` | Privileged Group Membership Discovered | privilege | high | high |
| `ADM-002` | Account Password Never Expires | authentication | medium (high for privileged accounts) | high |
| `ADM-003` | Kerberos Pre-Authentication Not Required | kerberos | high | high |
| `ADM-004` | Unconstrained Delegation | kerberos | high | medium |
| `ADM-005` | Weak or Legacy Authentication Encryption | authentication | medium | medium |
| `ADM-006` | External or Forest Trust Present | trust | medium | medium |
| `ADM-007` | Kerberoastable Account (SPN Set) | kerberos | medium (high for privileged) | high |
| `ADM-008` | Constrained Delegation Configured | kerberos | medium (high for privileged) | high |
| `ADM-009` | Computer Account Unconstrained Delegation | kerberos | high | high |
| `ADM-010` | Computer Allows Resource-Based Constrained Delegation | kerberos | medium | high |
| `ADM-011` | Risky Service Principal Name Class | kerberos | medium (high for privileged) | medium |
| `ADM-012` | Credential Material in Description | secrets | medium (high for privileged) | high |
| `ADM-013` | Account Has SID History | trust | medium (high for privileged) | high |
| `ADM-014` | Privileged Group Membership via Nesting | privilege | high | high |
| `AUTH-001` | Domain Trust Relationship | trust | informational | medium |
| `AUTH-002` | Local Administrator Password Not Managed (LAPS) | configuration | medium | high |
| `AUTH-003` | Group Policy Linked to Privileged Container | policy | medium | high |
| `AUTH-004` | Weak Domain Password Policy | authentication | medium (high when very weak) | high |

Notes:

- **ADM-001** flags users marked privileged (`adminCount`). The demo directory
  produces two such findings (Administrator and svc-backup).
- **ADM-003** flags accounts where Kerberos pre-authentication is not
  required (`DONT_REQUIRE_PREAUTH`), exposing them to AS-REP roasting. In the
  demo directory this fires for `kpreauth`.
- **ADM-006** flags external/forest trusts; **AUTH-001** records any trust as
  informational context. Both are fed by the trust analyzer.
- **ADM-008 … ADM-010** model the delegation spectrum on users and computers:
  constrained delegation (`msDS-AllowedToDelegateTo`), unconstrained
  delegation (`TRUSTED_FOR_DELEGATION`), and resource-based constrained
  delegation (`msDS-AllowedToActOnBehalfOfOtherIdentity`). These attributes
  are distinct and are never conflated.
- **ADM-014** resolves nested group membership from the enumerated group
  objects, so a user who reaches a privileged group indirectly is surfaced
  even when `adminCount` is not set.
- **AUTH-002** fires for non-domain-controller computers without an
  `ms-Mcs-AdmPwdExpirationTime` attribute; domain controllers are excluded
  because LAPS does not apply to them.
- **AUTH-003** flags GPO links (from `gPLink`) on privileged containers.
- **AUTH-004** evaluates the domain password policy read from the domain
  object; it only fires when the policy was actually observed.
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
directory and deterministically yields 18 findings across 15 rules:

- 2x `ADM-001` Privileged Group Membership Discovered
- 1x `ADM-003` Kerberos Pre-Authentication Not Required
- 1x each `ADM-006`, `ADM-007`, `ADM-008`, `ADM-010`, `ADM-012`, `ADM-013`,
  `ADM-014`, `AUTH-001`, `AUTH-002`, `AUTH-003`, `AUTH-004`
- 2x `ADM-009` Computer Account Unconstrained Delegation (DC01 and FILESRV)
- 2x `ADM-011` Risky Service Principal Name Class (svc-web HTTP, FILESRV MSSQLSvc)

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