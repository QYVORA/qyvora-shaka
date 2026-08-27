# Getting Started

## Build

```sh
make build
export PATH="$PWD/bin:$PATH"
shaka version
```

Alternatively build directly:

```sh
go build -o bin/shaka ./cmd/shaka
```

See [Installation](Installation.md) for installing `shaka` onto your system
with an icon and desktop entry.

## Interactive console

Running `shaka` with no subcommand drops you into the interactive,
Metasploit-style console:

```sh
shaka
```

You get the ASCII wordmark banner, the version line, and a `shaka>` prompt.
Every one-shot command is available as a console command. Console assessments
run against the built-in offline demo directory by default, so the whole flow
works without a live directory:

```text
shaka> assess
shaka> findings
shaka> graph
shaka> report
shaka> capabilities
shaka> help
shaka> exit
```

Console extras: `help`/`?`, `version`/`ver`, `history`, and the aliases for
every command (`scan`, `enum`, `finds`, `ev`, `path`, `caps`/`tools`,
`update`). Type `exit`/`quit`/`bye` to leave.

## Offline demo assessment

The offline demo is the fastest way to exercise the full pipeline:

```sh
shaka assess --sim
```

`directory.Demo()` simulates `corp.example.com`: one domain, one domain
controller (DC01), four users (Administrator, svc-backup, jdoe and kpreauth —
whose userAccountControl of 4194816 means Kerberos pre-authentication is not
required), three groups (Domain Admins, Backup Operators, Employees), one
computer, two organizational units, and an external trust.

The run is deterministic and yields:

- session persisted under `./sessions/`
- graph: 10 nodes / 13 edges
- risk: `medium` (53/100)
- findings: 2x `ADM-001` (Privileged Group Membership Discovered) and
  `ADM-003` (Kerberos Pre-Authentication Not Required)

Because `--sim` is offline (no network I/O), it is **auto-authorized** — no
confirmation prompt is shown.

## First live assessment

### 1. Confirm you are authorized

Every live assessment begins with explicit target authorization. You confirm
scope with `-y/--authorized`, with `QYVORA_AUTHORIZED=true` in the
environment, or interactively when stdin is a terminal.

In an automation context, a live target without one of these is **refused**
with exit code 1.

### 2. Assess the directory

```sh
shaka assess --endpoint dc01:389
```

SHAKA will:

1. Confirm authorization (interactive prompt on a TTY).
2. Derive the base DN from the root DSE when no `--base-dn` is given.
3. Run DISCOVER → VERIFY → DEEPEN → CORRELATE → ANALYZE → REPORT.
4. Print a summary (discovered object counts, graph size, risk and findings)
   and save the session JSON under `./sessions/`.

For an authenticated bind and LDAPS:

```sh
shaka assess --endpoint dc01:636 --tls --user "corp\svc-audit" \
  --base-dn "DC=corp,DC=example,DC=com"
```

### 3. Non-interactive / automation

```sh
shaka assess --endpoint dc01:389 -y --json
shaka assess --endpoint dc01:389 -y -o reports/day1.html
```

The authorization gate is satisfied non-interactively by `-y/--authorized` or
`QYVORA_AUTHORIZED=true`. A realistic CI invocation:

```sh
QYVORA_AUTHORIZED=true shaka assess --endpoint dc01:389 --json --events stderr
```

> `authorized: true` in a config file is a strong statement. Use it only in
> environments you control; see [Security Model](Security-Model.md).

## Review the report

```sh
shaka findings                      # list findings from the latest session
shaka evidence                      # list collected evidence
shaka graph                         # render the relationship graph (edges)
shaka report                        # render the latest session, terminal
shaka report -f markdown            # as Markdown
shaka report -f json                # as JSON
shaka report -f html --out report.html   # to a file
```

Reports are rendered from the saved session and can be produced at any time,
in any format, offline. See [Reporting](Reporting.md).

## Exploring commands

One-shot commands mirror the console and let you run individual stages:

```sh
shaka discover                      # DISCOVER only
shaka enumerate users               # enumeration, users
shaka enumerate groups
shaka enumerate all
shaka analyze                       # run the rule engine + risk over the latest session
```

## Profiles

Choose a profile to control how deep the assessment goes. The profile is set
from configuration or the environment (there is no per-command profile flag):

```sh
QYVORA_SHAKA_PROFILE=quick shaka assess --endpoint dc01:389
QYVORA_SHAKA_PROFILE=deep shaka assess --endpoint dc01:389
export QYVORA_SHAKA_PROFILE=identity
shaka assess --endpoint dc01:389
```

or persistently in the config file:

```yaml
profile: deep
```

See [Configuration](Configuration.md) for the full list and precedence.