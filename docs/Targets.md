# Targets

A **target** is the single, explicitly authorized directory/domain an
assessment operates on. SHAKA never infers a target, never seeds one from a
subnet, and refuses to assess a target that has not passed the authorization
gate.

## Target types

| Type | Description |
|---|---|
| `domain` | a directory/domain reached over LDAP (live assessment) |
| `config` | an offline directory snapshot for static review (reserved) |

## Directory endpoints

Live targets are specified with the shared directory connection flags:

```sh
shaka assess --endpoint dc01:389
shaka assess --endpoint dc01:636 --tls
shaka assess --endpoint dc01:389 --user "corp\svc-audit" --password "…"
shaka assess --endpoint dc01:389 --base-dn "DC=corp,DC=example,DC=com"
```

- `--endpoint host[:port]` — if the port is omitted, `ldap.port` (default 389)
  is used.
- `--base-dn` — when empty, the base DN is derived automatically from the
  root DSE (`defaultNamingContext`, falling back to
  `rootDomainNamingContext`).
- `--user`/`--password` — LDAP bind credentials; an empty username means
  anonymous.
- `--tls` — LDAPS (TLS); `--insecure` skips TLS certificate verification for
  test environments.
- `--timeout` — overrides the default directory operation timeout
  (`ldap.timeout_seconds`, default 15s).

The directory service abstraction (`internal/directory`) wraps these into a
`directory.Service`; the pipeline never talks to LDAP directly.

## Sim mode (`--sim`)

The offline demo replaces the live directory with `directory.Demo()`, an
in-memory simulator modeling `corp.example.com`:

- 1 domain, 1 domain controller (DC01, userAccountControl 532480)
- 4 users (Administrator, svc-backup, jdoe, kpreauth — UAC 4194816, meaning
  Kerberos pre-authentication is not required)
- 3 groups (Domain Admins, Backup Operators, Employees)
- 1 computer, 2 organizational units, 1 external trust

`--sim` targets are **auto-authorized**: the simulator performs no network
I/O, so there is nothing to authorize. `shaka assess --sim` produces the
deterministic demo result (10 nodes / 13 edges, medium risk 53/100).

## Authorization gate

A live target must pass the authorization gate before any assessment work:

1. `-y/--authorized` flag, or the `authorized` config key, or
   `QYVORA_AUTHORIZED=true` — granted immediately.
2. Otherwise, if stdin is a TTY, an interactive confirmation prompt shows the
   target and scope; answering `y` grants authorization.
3. Otherwise the run is **refused** with exit code 1:

```
target authorization required; re-run with --authorized to confirm scope non-interactively
```

Authorization is recorded on the target model (`Authorization` — granted,
scope, method, granted by) and carried into the session. The target manager
(`internal/target`) refuses to make an unauthorized target current, so the
gate cannot be bypassed.

> Scope: authorization covers **this one target** plus, optionally, the
> trusts that target declares. It never authorizes a subnet or a second
> domain; see [Security Model](Security-Model.md).

## Managing targets

The in-process target manager (`internal/target`) records targets for the
duration of the process. Sessions persist their target ID; the manager itself
is per-invocation.

### `target set`

Selects and authorizes the current target:

```sh
shaka target set --sim                          # auto-authorized demo target
shaka target set --endpoint dc01:389            # interactive authorization
shaka target set --endpoint dc01:389 -y         # non-interactive
shaka target set --endpoint dc01:389 --name corp01   # friendly name
```

`target set` performs the same authorization checks as `assess`. The current
target becomes the default for commands that do not specify connection flags.

### `target list`

Lists known targets with `target`, `type`, and `authorized` columns.

### `target show`

Shows the current target in the active output format (full target model in
`--json`).

## Notes

- Connection flags on a command override the current selected target;
  otherwise the current target is used.
- Console `target` commands print a hint that target selection is done via
  `shaka target set --sim` or with `--endpoint`/`--base-dn`.
- Credentials passwords are never serialized into sessions
  (`json:"-"` on `Target.Password`).