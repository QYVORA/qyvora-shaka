# Development

Guidance for contributors. See also [Architecture](Architecture.md),
[Rules](Rules.md), [Verify](Verify.md), [Correlation](Correlation.md), and
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Setup

```sh
go test ./...
go vet ./...
gofmt -l cmd internal pkg   # should print nothing
```

Convenience wrappers (the `make check` target runs fmt + vet + test):

```sh
make build
make check
```

Tests require **no live directory** — directory access is behind
`directory.Service`, which tests substitute with the offline simulator
(`directory.Demo()`).

## Layout conventions

- `internal/` — private implementation. Never import from outside the module.
- `pkg/` — shared models package (`pkg/models`).
- `cmd/shaka/` — thin entry point; all wiring lives in `internal/cli`.

## How the pieces fit

- `internal/cli` builds the cobra command tree and the console; both funnel
  through `internal/assess.Runner`.
- `internal/pipeline` defines the concrete stages (discovery, enumeration,
  graph, analysis, findings, risk); `internal/orchestration` runs them.
- Stages touch the directory **only** through `Env.Dir`
  (`directory.Service`) — never LDAP directly — so tests can substitute the
  simulator.
- Enumerators normalize entries via `internal/directory`'s normalize helpers
  and attach evidence as they go.

## Adding a pipeline stage

1. Define a struct implementing `core.Stage` (`Name()`, `Run(ctx, *core.Env)`).
2. Wire it into the pipeline in `internal/assess` (stage toggles in
   `Options`) or `internal/pipeline`.
3. Add a CLI command in `internal/cli` if it should be invocable standalone.
4. Add unit tests using the simulator.
5. Document it in `docs/`.

## Adding a rule

See [Rules](Rules.md). Minimum bar:

- table-driven tests with synthetic (demo) fixtures,
- deterministic detection (no map-iteration dependence),
- honest confidence (do not claim high confidence on ambiguous input),
- evidence recorded for each finding,
- a doc comment on the rule detection function,
- an entry in `docs/Rules.md`.

## Code style

- `gofmt` output; `go vet` clean; `go test ./...` green before opening a PR.
- Contexts flow from `main` down; stages and follow-up handlers honor
  cancellation.
- Errors wrap with context (`fmt.Errorf("…: %w", err)`).
- No dead code, no unused imports, no `panic` in library paths.
- Findings and evidence deduplicate (fingerprint / hash); never append
  unchecked into a session.
- Do not add comments unless they explain *why*; the codebase uses doc
  comments on exported identifiers.

## Commit messages

Follow conventional commits:

```
feat: add account-operator privileges to identity analysis
fix: resolve group member DNs without panicking on empty member
test: cover ADM-003 pre-auth detection in the demo directory
docs: document the VERIFY stage
```

## Testing

- `go test ./...` — the full suite; run it with `-race` for concurrent
  paths (graph, evidence store, follow-up engine).
- New rules need fixtures: use `directory.Demo()` and the simulator's search
  engine for deterministic behavior.
- Report renderers are pure functions of a session — golden-test them with a
  hand-built session.