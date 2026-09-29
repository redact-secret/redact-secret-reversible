# Governance

Redact Secret Vault is part of the [redact-secret](https://github.com/redact-secret) project. It follows a maintainer-led model: maintainers decide, in public, and record durable decisions in the repository.

## Roles

| Role | Who | Responsibilities |
| --- | --- | --- |
| Maintainer | [@milocosmopolitan](https://github.com/milocosmopolitan) | Reviews and merges pull requests; triages issues; owns the threat model, decision records, and release process; handles vulnerability reports ([SECURITY.md](SECURITY.md)) and code-of-conduct reports ([CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)); holds administrative access to the GitHub organization and the npm and PyPI packages. |
| Contributor | Anyone | Reports issues, proposes changes through pull requests, and reviews others' changes, following [CONTRIBUTING.md](CONTRIBUTING.md). |

A contributor becomes a maintainer by invitation from an existing maintainer after sustained, high-quality contributions and reviews. New maintainers are listed in this file.

## Decisions

- Day-to-day changes are decided in pull requests. Every change to `main` goes through a pull request with green CI.
- Durable choices (package boundaries, security properties, token and storage semantics, supported runtimes) are recorded as decision records in [`docs/decisions/`](docs/decisions/README.md), with status, consequences, rejected alternatives, and open questions. Security-sensitive changes update the [threat model](docs/specs/threat-model.md) first ([CONVENTIONS.md](CONVENTIONS.md#security-sensitive-changes)).
- Disagreements are discussed in the relevant issue or pull request; the maintainers make the final call and record the reason there.

## Releases

Only maintainers push release tags. A tag triggers [`release.yml`](.github/workflows/release.yml), which re-runs the tests and publishes with npm provenance and PyPI trusted publishing; no long-lived publish token is stored. See [RELEASING.md](RELEASING.md).

## Continuity

The project currently has a single maintainer, so its bus factor is 1. To keep the project able to create and close issues, accept changes, and release if the maintainer becomes unavailable, the goal is at least two people with administrative access to each of: the `redact-secret` GitHub organization, the `@redact-secret` npm scope, and the `redact-secret-vault` PyPI project. This file will list the second maintainer once added.
