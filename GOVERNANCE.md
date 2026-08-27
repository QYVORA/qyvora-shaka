# Governance

## Maintainers

The project is maintained by QYVORA. Maintainer contact for security issues
is provided in `SECURITY.md`.

## Decision process

- **Small fixes and docs:** reviewed and merged by a maintainer.
- **New features and API changes:** discussed in an issue first, then
  implemented in a PR.
- **Security-sensitive changes:** reviewed by a maintainer and referenced
  against the [Security Model](docs/Security-Model.md).

## Releases

- Semantic versioning per [CHANGELOG.md](CHANGELOG.md).
- Releases are tagged from `main` after CI passes.
- `main` must remain buildable and green.

## Scope of authority

Maintainers may decline contributions that conflict with the project's
purpose (authorized assessment, single-target scope, no mass scanning, no
unauthorized-access or exploitation tooling) even if technically sound. This
is a deliberate boundary, not an error.

## Community

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Code
of conduct reports are handled by the maintainers documented there.