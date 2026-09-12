# CLI Reference

`shaka` — command reference for the authorized Active Directory security
assessment framework.

## Global flags

```
-y, --authorized          confirm authorization scope non-interactively
-c, --config string       config file (default ~/.config/qyvora/shaka/config.yaml)
    --dry-run             resolve and print the assessment plan without executing
    --events string       emit a JSONL event stream to stdout, stderr, or a file path
    --json                output in JSON format (shorthand for --output json)
-o, --output string       output format: terminal, json, markdown, html, yaml
-q, --quiet               suppress non-error output
    --timeout string      default timeout for directory operations (e.g. 30s)
-v, --verbose             verbose output

Directory connection flags (shared by assess/discover/enumerate/target):
    --endpoint string     directory endpoint host[:port], e.g. dc01:389
    --base-dn string      base distinguished name (derived from root DSE if empty)
    --user string         bind username (empty = anonymous)
    --password string     bind password
    --tls                 use LDAPS (TLS)
    --insecure            skip TLS certificate verification
    --sim                 run against the built-in offline demo directory
```

`-h/--help` and `--version` are provided by cobra; `--version` prints
`shaka <version>`.

## Command summary

```
shaka                             start the interactive console
shaka assess                      full pipeline (alias: scan)
shaka discover                    DISCOVER stage only (alias: find)
shaka enumerate <objects>         enumerate directory objects (alias: enum)
shaka analyze                     rule engine + risk over the latest session (alias: rules)
shaka findings                    list findings from the latest session (alias: finds)
shaka evidence                    list evidence from the latest session (alias: ev)
shaka graph                       render the relationship graph from the latest session (alias: path)
shaka report                      render the latest assessment report
shaka target set|list|show        manage targets (alias: tgt)
shaka capabilities                list machine-readable capabilities (alias: caps)
shaka tools                       list AI-ready tool capabilities (alias: capabilities, caps)
shaka updates                     check for and install updates (alias: update, selfupdate)
shaka version                     print version and build information
shaka completion <shell>          generate shell completion (bash|zsh|fish|powershell)
shaka help                        help
```

## Interactive console

Running `shaka` with no subcommand drops into a Metasploit-style console.
On a real terminal this is a readline console; with piped/redirected stdin it
runs the same commands as a plain line reader (no banner, no colors).
Every one-shot command above works as a console command, so you can sequence
a workflow without repeating the `shaka` prefix:

```
shaka> assess
shaka> findings
shaka> graph
shaka> report
shaka> capabilities
shaka> help
shaka> exit
```

Console extras: `help`/`?`, `version`/`ver`, `history`, and `exit`/`quit`/
`q`/`bye`. Console assessment commands run against the built-in offline demo
directory by default, so the interactive flow always works without a live
directory. When stdin is not a terminal (pipes, scripts, CI), the console
degrades to line-by-line reading so command sequences can be fed
non-interactively.

The console and the one-shot CLI share the same underlying
`internal/assess.Runner`, so results never diverge.

## `assess` (alias `scan`)

Runs the full assessment pipeline and renders the result (summary table in
terminal format, or the full report in json/markdown/html/yaml).

```sh
shaka assess --sim
shaka assess --endpoint dc01:389
shaka assess --endpoint dc01:389 --tls --user corp\svc-audit -y
```

Flags:

- `--identity` — identity-focused assessment: enumerate users and groups only.
- `--limit int` — cap the number of objects enumerated per kind (0 = unlimited).
- the directory connection flags above.
- the global output flags (`-y`, `--json`, `-o`, `--dry-run`, `--timeout`,
  `--events`, …).

`--sim` targets are auto-authorized (offline demo). Live targets require the
authorization gate (see [Security Model](Security-Model.md) and
[Targets](Targets.md)).

## `discover` (alias `find`)

Runs only the discovery stage: domains, domain controllers, and the derived
base DN.

```sh
shaka discover --endpoint dc01:389
shaka discover --sim
```

## `enumerate` (alias `enum`)

Runs discovery + enumeration for the selected object set.

```sh
shaka enumerate [users|groups|computers|ous|trusts|all]
```

Flags:

- `--object string` — `users`, `groups`, `computers`, `ous`, `trusts`, or
  `all` (default `all`).
- `--limit int` — cap objects enumerated (0 = unlimited).
- the directory connection flags.

For `users`/`groups` the run is identity-focused (shorthand for
`--identity`).

## `analyze` (alias `rules`)

Runs the rule engine and risk assessment over the latest session.

```sh
shaka analyze
```

Reading and reporting are the same as for a full assessment.

## `findings` (alias `finds`)

Lists findings from the latest session as a table
(`severity`, `rule`, `title`, `confidence`, `target`).

## `evidence` (alias `ev`)

Lists evidence collected in the latest session as a table
(`id`, `type`, `hash`, `source`). Empty until findings with evidence exist.

## `graph` (alias `path`)

Renders the relationship graph from the latest session as an edge list
(`from`, `type`, `to`, `confidence`).

## `report`

Renders an assessment report from the latest session.

```sh
shaka report                    # latest session, active output format
shaka report -f markdown        # specific format
shaka report -f html --out report.html   # write to a file
```

Flags:

- `-f, --format string` — `terminal`, `markdown`, `html`, `json`, `yaml`.
- `--out string` — write the report to a file (default stdout).

## `target` (alias `tgt`)

Manages assessment targets.

```sh
shaka target set    # select and authorize the current target
shaka target list   # list known targets
shaka target show   # show the current target
```

`target set` accepts the directory connection flags plus `--name string` (a
friendly target name). With `--sim` the target is auto-authorized; with
`--endpoint` the authorization gate applies. See [Targets](Targets.md).

## `capabilities` (alias `caps`)

Lists shaka's machine-readable capabilities as a table
(`id`, `name`, `category`, `risk`, `auth`, `confirm`). Add `--json` (or
`-o json`) for the machine-readable catalog.

## `tools` (alias `capabilities`, `caps`)

The same catalog presented as AI-ready tool definitions. Same output as
`capabilities`.

## `updates` (alias `update`, `selfupdate`)

```sh
shaka updates                 # check for a newer release
shaka updates --install       # download, verify, install the latest release
```

See [Installation](Installation.md) for the update flow.

## `version`

Prints `shaka <version>` with fields for `framework`, `commit`, `built`, `by`
and `go`. Add `--json` for machine-readable build identity.

## `completion`

```sh
shaka completion bash
shaka completion zsh
shaka completion fish
shaka completion powershell
```

Writes the shell completion script to stdout.

## Environment variables

The environment namespace is `QYVORA_SHAKA_*`. Every config key maps to an
environment variable of the same name, uppercased with dots replaced by
underscores: `profile` → `QYVORA_SHAKA_PROFILE`, `report.dir` →
`QYVORA_SHAKA_REPORT_DIR`, `ldap.timeout_seconds` →
`QYVORA_SHAKA_LDAP_TIMEOUT_SECONDS`, and so on. `QYVORA_AUTHORIZED=true` is
honored directly by the authorization gate. Precedence: environment > config
file > defaults. See [Configuration](Configuration.md).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | runtime error (assessment, analysis, I/O, internal error) |
| 2 | usage error (unknown flag/command, invalid value, invalid config, missing or unauthorized target) |
| 130 | interrupted (128 + SIGINT) |

Authorization is required non-interactively: a live (non-sim) assessment
without `-y/--authorized` or `QYVORA_AUTHORIZED=true` is refused with exit
code 1.