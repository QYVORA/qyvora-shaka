# Support

## Documentation

Start with the `docs/` directory and the README. The
[Getting Started](docs/Getting-Started.md) guide covers the first assessment
and the [CLI reference](docs/CLI.md) covers every command and flag.

## Getting help

- Open an issue for bugs and feature requests (see
  [CONTRIBUTING.md](CONTRIBUTING.md)).
- Start with the project on GitHub: the repository is hosted under
  `github.com/QYVORA/qyvora-shaka`. For issues on other QYVORA projects, use
  their respective repositories.
- Report security vulnerabilities privately per [SECURITY.md](SECURITY.md) —
  never in a public issue.

## Operating responsibility

SHAKA is an **authorized-use** tool. Ensure you have explicit permission
before assessing any directory, and review the
[Security Model](docs/Security-Model.md) before deploying it in an
organization. Confirm scope non-interactively with `-y/--authorized` or
`QYVORA_AUTHORIZED=true`; `--sim` (offline demo) needs no authorization.