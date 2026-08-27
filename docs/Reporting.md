# Reporting

SHAKA renders every assessment session as a report. Reports are pure
functions of the saved session, which means they can be produced offline, in
any format, at any time.

## Session files

Each assessment produces a session JSON under `session.dir` (default
`./sessions/`):

```
./sessions/<id>.session.json
```

The session contains the target, profile, stages, discovered objects, graph
nodes and edges, findings, evidence, risk score, timestamps and any recorded
errors. It is the single source of truth for reports. Files are written mode
0600.

Commands that operate on the latest session — `analyze`, `findings`,
`evidence`, `graph`, `report` — read from this store.

## Formats

| Format | Flag | Use |
|---|---|---|
| terminal | `-o terminal` | human summary on stdout |
| json | `-o json` / `--json` | machine-readable |
| markdown | `-o markdown` / `report -f markdown` | docs/sharing |
| html | `-o html` / `report -f html` | self-contained page |
| yaml | `-o yaml` | structured, human-readable |

> `-o/--output` selects the output format globally and for `assess`;
> `shaka report -f/--format` selects the report format when re-rendering a
> saved session. Both accept the same values.

## Rendering

```sh
shaka report                  # latest session, active output format (terminal by default)
shaka report -f markdown      # specific format
shaka report -f html --out report.html   # write to a file
shaka report -f json > report.json
```

The `assess` result itself honors the global `-o`/`--json` flags, so a full
run can emit a JSON report directly:

```sh
shaka assess --sim --json
QYVORA_AUTHORIZED=true shaka assess --endpoint dc01:389 -o markdown
```

## Report contents

- Session and target identifiers, profile, start/finish timestamps.
- Discovered object counts (domains, domain controllers, users, groups,
  computers, OUs, trusts).
- Relationship graph size (nodes, edges).
- Risk: level and 0..100 score.
- Findings: severity, rule ID, title, confidence, fingerprint.
- Evidence item counts and linkage.

Reports are rendered by `internal/reporting` from the session alone — no
directory access — which keeps them deterministic and safe to regenerate.

## Output directory

`report.dir` (default `reports`) is the default directory reports are written
to, and the default format for `shaka report` is `report.format` (default
`terminal`). See [Configuration](Configuration.md).

## Event stream (`--events`)

`--events stdout|stderr|<file>` emits a JSONL event feed alongside the run —
one self-describing JSON object per line:

```json
{"schema_version":"1.0","timestamp":"…","execution_id":"…",
 "framework":"shaka","level":"info","event":"stage.started","data":{"stage":"discovery"}}
```

Events cover the run lifecycle (`scan.started`, `scan.completed`), stage
boundaries (`stage.started` / `stage.completed`), objects discovered
(`domain.discovered`, `user.discovered`, …), findings (`finding.discovered`),
evidence (`evidence.collected`), risk (`risk.calculated`) and
`report.generated`, plus `warning` and `error`. Consumers key on event names,
never on terminal output. A file target is appended with mode 0600.