# Security Policy

## Authorized use only

SHAKA is an **authorized use** assessment framework. It must only be operated
against directories you own or are explicitly authorized to test. Unauthorized
use may violate law and policy in your jurisdiction and is out of the project's
scope by design. See the [Security Model](docs/Security-Model.md).

## Reporting a vulnerability

Please report security vulnerabilities **privately** — do not open a public
issue for them.

- **Contact:** create a private advisory in this repository (GitHub Security
  → Report a vulnerability), or contact the maintainers per the address in
  `GOVERNANCE.md`.
- **What to include:**
  - affected version / commit,
  - description of the issue and its impact,
  - steps to reproduce,
  - any suggested mitigation.

## Supported versions

The latest release and the `main` branch are supported. Security fixes land
in the next release and are backported only to the latest release branch.

## Our commitment

- We will acknowledge your report within 3 business days.
- We will provide a status update within 10 business days.
- We will coordinate public disclosure after a fix is released, and credit
  reporters who opt in.

## Scope

In scope: vulnerabilities in SHAKA itself — LDAP client handling, directory
parsing and normalization, rule/logic errors, evidence/session handling,
authorization logic, the console, and the CLI.

Out of scope: vulnerabilities in the assessed directory or Windows
environment; these are findings for an assessment, not framework
vulnerabilities. Out of scope as well: issues whose only content is
supporting unauthorized use of the framework.