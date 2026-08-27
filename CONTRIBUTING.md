# Contributing

Thanks for contributing to SHAKA.

## Code of conduct

By participating you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Project scope

SHAKA is an **authorized Active Directory / Windows security assessment**
framework. It is deliberately **not** a mass scanner and **not** an
unauthorized-access or exploitation framework. Contributions that push
against those boundaries will be declined even if technically impressive.

Design goals: see [Architecture](docs/Architecture.md) and
[Security Model](docs/Security-Model.md).

## Development setup

```sh
go test ./...      # requires no live directory
make vet
make fmt
```

Run everything with one command:

```sh
make check      # fmt + vet + test
```

See [Development](docs/Development.md) for layout and style conventions.

## How to contribute

1. **Discuss first.** Open an issue for non-trivial features or API changes
   before writing code.
2. **Branch** from `main`: `feat/<topic>`, `fix/<topic>`, `docs/<topic>`.
3. **Implement**, following package conventions.
4. **Test.** New rules and enumerators need table-driven tests with synthetic
   or demo-simulator fixtures. Run `go test ./...` locally.
5. **Check.** `go vet ./...`, `gofmt`, no dead code.
6. **Open a PR** against `main` and reference the issue it closes.

## What to include in a PR

- A short description of the change and its motivation.
- Tests for new behavior.
- Documentation updates in `docs/` when behavior or interfaces change.
- A CHANGELOG entry under `[Unreleased]`.

## Reporting bugs

Open an issue with the bug template. Include the command you ran, the
version (`shaka version`), the OS, and any error output. Do **not** include
credentials, personal data, or evidence artifacts in public issues. Note that
sensitive directory details belong in a private report, not a public issue.

## Security issues

Do **not** open public issues for security vulnerabilities. Follow
[SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE). See [NOTICE](NOTICE).