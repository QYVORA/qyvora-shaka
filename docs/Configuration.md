# Configuration

SHAKA configuration is loaded by `internal/config` (viper) from a YAML config
file, the `QYVORA_SHAKA_*` environment namespace, and built-in defaults.

## Precedence

```
environment (QYVORA_SHAKA_*) > config file > built-in defaults
```

An explicit `-c/--config` path bypasses discovery. A missing config file is
not an error; a malformed one is. Invalid configured values are rejected
rather than silently accepted — for example, an unknown profile prevents the
run.

## Config file discovery

When no `-c/--config` is given, `config.yaml` is searched in:

1. the current directory
2. `$HOME/.qyvora-shaka/`
3. `$HOME/.config/qyvora/shaka/`
4. `/etc/qyvora-shaka/`

The canonical default locations are `~/.config/qyvora/shaka/config.yaml` and
`~/.qyvora-shaka/config.yaml`. See `configs/config.yaml.example` for a
reference file.

## Example

```yaml
profile: standard
output: terminal
verbose: false
quiet: false
json: false
authorized: false

log:
  level: info

report:
  dir: reports
  format: terminal   # terminal | json | markdown | html

ldap:
  port: 389
  timeout_seconds: 15
  page_size: 500

depth:
  max: 6
workers: 8
concurrency:
  discovery: 8
  followup: 8

session:
  dir: ""
```

## Keys

| Key | Default | Meaning |
|---|---|---|
| `profile` | `standard` | assessment profile (see below) |
| `output` | `terminal` | default output format (`terminal`, `json`, `markdown`, `html`, `yaml`) |
| `verbose` | `false` | equivalent of `--verbose` |
| `quiet` | `false` | equivalent of `--quiet` |
| `json` | `false` | equivalent of `--json` |
| `authorized` | `false` | treat runs as pre-authorized (strong statement) |
| `report.dir` | `reports` | directory reports are written to |
| `report.format` | `terminal` | default report format |
| `log.level` | `info` | `debug`, `info`, `warn`, `error` |
| `ldap.port` | `389` | default port when `--endpoint` omits `:port` |
| `ldap.timeout_seconds` | `15` | default timeout for directory operations |
| `ldap.page_size` | `500` | LDAP paged-search page size |
| `depth.max` | `6` | reserved default for graph/follow-up depth |
| `workers` | `8` | reserved default worker count |
| `concurrency.discovery` | `8` | reserved default discovery concurrency |
| `concurrency.followup` | `8` | reserved default follow-up (deepening) concurrency |
| `session.dir` | `./sessions` | session persistence directory (empty = `./sessions`) |

> Note on reserved keys: `report.dir`, `report.format`, `ldap.port`,
> `ldap.page_size`, `depth.max`, `workers`, `concurrency.discovery` and
> `concurrency.followup` are defined as configuration defaults but are not
> yet consumed by the live pipeline (bind/connect/paging intrinsics drive
> those paths). Set them as placeholders, but know they do not change
> behavior until the live directory pipeline reads them. Keys not listed are
> ignored.

## Environment variables

Every key maps to an environment variable: uppercase, with dots replaced by
underscores, prefixed with `QYVORA_SHAKA_`. So `profile` →
`QYVORA_SHAKA_PROFILE`, `report.dir` → `QYVORA_SHAKA_REPORT_DIR`, and
`ldap.timeout_seconds` → `QYVORA_SHAKA_LDAP_TIMEOUT_SECONDS`.

The authorization gate additionally honors `QYVORA_AUTHORIZED=true` directly
(no namespace prefix):

```sh
QYVORA_AUTHORIZED=true shaka assess --endpoint dc01:389 --json
```

## CLI flags

Flags take precedence over environment and config file for the values they
set (`-o/--output`, `--json`, `-v/--verbose`, `-q/--quiet`,
`-y/--authorized`, `--timeout`, `--events`). The profile itself is set from
configuration or the `QYVORA_SHAKA_PROFILE` environment variable only.

## Profiles

The `profile` key (or `QYVORA_SHAKA_PROFILE`) selects how deep an assessment
goes. Each is a clearly defined scope. The full set:

| Profile | Use |
|---|---|
| `quick` | Fast posture read |
| `standard` | Default full assessment |
| `deep` | Research-grade, maximum depth |
| `directory` | Directory-object focused |
| `authentication` | Authentication and Kerberos posture |
| `trust` | Trust relationships focused |
| `identity` | Users, groups and privilege focused |
| `compliance` | Audit-oriented output |
| `research` | Full fidelity, raw context |

An unknown profile is an error — a typo cannot silently change what an
assessment does.

## Session persistence

Sessions are stored as JSON files under `session.dir` (default `./sessions/`)
as `<id>.session.json`, written mode 0600. `analyze`, `findings`, `evidence`,
`graph` and `report` read the latest saved session from this store.