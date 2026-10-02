# Documentation

New here? Start with the [repository README](../README.md), then the README of the package you use.

## Guides

- [Troubleshooting](guides/troubleshooting.md): every error code and denial reason, with its cause and fix.
- [Examples](../examples/README.md): programs that run as they are, including a local PostgreSQL setup.
- [Worker mode](guides/worker-mode.md): run the vault in a dedicated Worker.
- [PII findings](guides/pii.md): turn PII detection on and choose what is retained.
- [Persistent server](guides/persistent-server.md): capture in one process, restore in another, over PostgreSQL (alpha).

## Reference

- [`@redact-secret/vault`](reference/vault.md): runtime support, guarantees, API, error codes.
- [`@redact-secret/vault-server`](reference/vault-server.md): evaluation order, concurrency, audit, API.
- [`redact-secret-vault` (Python)](reference/vault-py.md): bridge process, PII, tests.
- [`@redact-secret/store-postgres`](reference/store-postgres.md): profiles, schema, grants, transactions, recovery.
- [`@redact-secret/store-sqlite`](reference/store-sqlite.md): the `sqlite-local-wal` profile, startup checks, transactions, restore detection and its blind spot, backup and recovery.
- [`@redact-secret/key-provider-aws-kms`](reference/key-provider-aws-kms.md): keys, IAM, rotation, cache, failures.
- [`@redact-secret/vault-conformance`](reference/vault-conformance.md): harness factories, case groups, fault injection.

## Project

- [Release status](status.md): published versions, registry state, and qualified runtimes.
- [Concepts and boundaries](concepts.md): repository boundaries, typed placeholders, security direction.

## Everything else

- [Architecture](../ARCHITECTURE.md): trust boundaries and components.
- [Conventions](../CONVENTIONS.md): documentation, implementation, and review rules.
- [Contributing](../CONTRIBUTING.md): reporting bugs, submitting changes, and the test policy.
- [Security policy](../SECURITY.md): private vulnerability reporting, response process, and release verification.
- [Code of conduct](../CODE_OF_CONDUCT.md), [governance](../GOVERNANCE.md), and [roadmap](../ROADMAP.md).
- [Assurance case](specs/assurance-case.md): why the security requirements are met.
- [Decisions](decisions/README.md): accepted boundaries and open design questions, including the [server authority interface](decisions/define-server-authority-interface.md) and [its in-memory implementation](decisions/implement-vault-server-in-memory.md), the earlier [persistent store contract](decisions/define-persistent-store-contract.md) (partly superseded), and the [ciphertext-only store decision](decisions/supersede-persistent-store-contract.md) that replaces it (implemented and published as alpha).
- [Persistent vault specification](specs/persistent-vault.md): record format, store and key-provider contracts, restore and failure semantics, recovery and erasure limits.
- [Persistent vault operations](specs/persistent-operations.md): expiry and cleanup, the four deletion-related operations, and the backup-recovery and failover runbooks.
- [SQLite store qualification record](research/qualification-store-sqlite-0.1.0-alpha.1.md): partial; what ran, what did not (power loss), and what remains.
- [Persistence qualification record](research/qualification-persistence-0.1.0-alpha.1.md): tested matrix, evidence index, unqualified profiles, and remaining limitations, with the [PostgreSQL qualification report](../packages/store-postgres/qualification/report/report.md) and the [design review](research/persistent-vault-design-review.md).
- [JavaScript and Python conformance and runtime matrix](research/js-python-conformance-and-runtime-matrix.md): every cell that was run for each runtime, the core pin, the equivalent-outcome evidence from the shared corpora, and the candid differences between the two servers.
- [Persistent record test vectors](../conformance/persistent/v1/README.md): deterministic wire vectors every implementation must reproduce.
- [Persistent backend research](research/persistent-backend-capabilities.md) (DynamoDB, Redis, SQLite; research only, no adapter) the [Python persistence parity plan](plans/python-persistence-parity.md), and the [Python qualification record](research/qualification-python-persistence-0.1.0b3.md) (Python persistent modules ship in `redact-secret-vault` `0.1.0b4` behind extras, not supported).
- [Threat model](specs/threat-model.md): assets, attackers, boundary, and residual risk per mode.
- [Browser in-memory security](specs/in-memory-security.md): guarantees, limits, and deployment alternatives.
- [Qualification record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-0.1.0-alpha.1.md) (archived): tested runtime/core matrix and evidence for 0.1.0-alpha.1.
- [Core beta.10 qualification record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-core-0.1.0-beta.10.md) (archived): PII-off and PII-on matrix for 0.1.0-alpha.2, including the registry verification of the published package.
- [Changelog](../CHANGELOG.md): release notes, including the 0.1.0-alpha.2 breaking changes and migration.
- [Worker-mode qualification record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-worker-mode.md) (archived): tested evidence for the optional dedicated-Worker mode, including its hostile-main-thread and CSP negative-control evidence.
- [Conformance corpus](../conformance/README.md): language-neutral adversarial cases.
- [Security policy](../SECURITY.md) and [releasing](../RELEASING.md).
- Earlier research records and plans (core integration, Python server integration, executed verification, security research, pre-implementation plan, issue roadmap, alpha.1 orchestrator prompt) were retired in `a47d6d9`; they remain readable in the [archived `docs/`](https://github.com/redact-secret/redact-secret-vault/tree/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs) tree.
