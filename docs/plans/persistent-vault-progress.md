# Persistent vault workstream — progress record

Durable working record for epic [#4](https://github.com/redact-secret/redact-secret-vault/issues/4). It exists so the work can resume after an interruption. It states what was verified, not what is planned to be true. Remove it (or archive it) when #112 closes.

## Baseline verified 2026-10-01

Read from `origin/main` at `35ffa32`, the registries, and the issue bodies; nothing below is copied from the task prompt.

| Item | State |
| --- | --- |
| `@redact-secret/vault` | `0.1.0-beta.3` on `main` and npm; `latest` and `beta` both point at it; peers `@redact-secret/core@0.1.0-beta.12` exactly |
| `@redact-secret/vault-server` | `0.1.0-beta.3`, same tags; depends on `@redact-secret/vault@0.1.0-beta.3` exactly |
| `redact-secret-vault` (PyPI) | `0.1.0a3`, `0.1.0b1`, `0.1.0b2`, `0.1.0b3` published |
| `@redact-secret/core` | `latest` and `beta` are `0.1.0-beta.12` |
| `@redact-secret/vault-contracts`, `vault-crypto`, `store-memory`, `store-postgres`, `key-provider-local`, `key-provider-aws-kms` | None exists on npm (404) |
| Open PRs | [#99](https://github.com/redact-secret/redact-secret-vault/pull/99), a stale `release/beta.2` PR superseded by the merged #98. Not touched by this workstream |
| Persistence code | At the baseline: none; `vault-server` wraps a private in-memory vault plus a metadata shadow (`packages/vault-server/src/server-vault.ts`). On the branch since: `packages/vault-contracts`, `vault-crypto`, `vault-conformance`, `store-memory`, `store-postgres`, `key-provider-aws-kms` (each `0.1.0-alpha.1`), `packages/vault-server/src/persistent/`, and `packages/vault/src/capture-plan.ts` (`vault` and `vault-server` at `0.1.0-beta.4`). All unpublished. `createServerVault` is unchanged |
| Persistent ADR | `docs/decisions/define-persistent-store-contract.md`, accepted for the contract only (#19, closed). It has a plaintext-returning `Store.consume`, per-entry atomicity, a `KeyProvider` that seals payloads, plaintext replay on retry, and `Store.purge` promising key destruction |
| `main` protection | Required checks: `boundaries`, `browser`, `node 20/22/24` on ubuntu and macos, `sast`. Admins enforced. No required reviews |
| Release | At the baseline: `release.yml` publishes `vault`, then `vault-server`, then PyPI, by trusted publishing, and knows no other package. On the branch since: it publishes `vault-contracts`, `vault`, the five other persistence packages through `scripts/publish-workspace.mjs`, then `vault-server`. That path has not run |

Documentation drift found: `ARCHITECTURE.md` still says alpha and "persistence is not implemented" in its status paragraph; `README.md` says Python `0.1.0b2` is on PyPI where `0.1.0b3` is. Fixed under #112.

## Verification environments

| Environment | State on 2026-10-01 |
| --- | --- |
| Node.js | 22.16.0 locally; CI covers 20, 22, 24 on Linux and macOS |
| PostgreSQL | No local server binaries. Docker Desktop answers after a restart on 2026-10-01; containers are the local environment, and GitHub Actions the CI one |
| AWS | The `redact-secret` CLI profile resolves to an IAM user that can list KMS keys. Creating test keys is authorized by the maintainer; create and use permissions are confirmed when #113 runs |
| npm publish | Trusted publishing can be configured only for a package that already exists (see `RELEASING.md`, "Provenance"). The first publish of each new package is therefore a manual maintainer step |

## External blockers

1. **First publish of new npm packages.** Still open. Needs the maintainer's npm account, for each of the six new packages, in dependency order (`RELEASING.md`, "Persistence packages"). Until `@redact-secret/vault-contracts` exists on npm with a trusted publisher, the `publish` job of `release.yml` stops at its first publish step and publishes nothing, `@redact-secret/vault` and `@redact-secret/vault-server` included.
2. **Release.** Still open. Each release needs the maintainer's confirmation before its tag is pushed. No tag has been pushed for `0.1.0-beta.4`.
3. **Implementation review.** In progress on 2026-10-01; its outcome goes into the qualification record.

## Deliverables and order

1. #104, #105, #107 — superseding ADR, `docs/specs/persistent-vault.md`, independent design review.
2. #106, #108, #110 (harness) — contracts, crypto, local key provider, `store-memory`, conformance harnesses.
3. #109 — persistent server profile in `vault-server`.
4. #20, #111 — `store-postgres`, recovery and erasure operations.
5. #113, #114, #115 — AWS KMS provider, backend research, Python parity plan.
6. #110, #112 — independent review, qualification, release.

## Log

- 2026-10-01: baseline verified; branch `docs/104-persistent-vault-design` opened.
- 2026-10-01: specification and superseding decision written; two-pass independent design review recorded in `docs/research/persistent-vault-design-review.md` (no critical, one high, fixed). Design frozen for implementation.
- 2026-10-01: maintainer decisions — push, PR, and merge are authorized; releases need confirmation before a tag is pushed. Docker Desktop restarted (daemon answers). Creating AWS KMS test keys with the `redact-secret` profile is authorized.
- 2026-10-01: #114 research drafted in `docs/research/persistent-backend-capabilities.md` (separate PR; its section references must follow the final specification numbering).
- 2026-10-01: #104, #106, #107 implemented: `vault-contracts`, `vault-crypto` with the local key provider, and the record format v1 vectors in `conformance/persistent/v1`.
- 2026-10-01: #108, #110 implemented: `vault-conformance` (store and key-provider harnesses, fault injection, 19 mutation controls) and `store-memory`.
- 2026-10-01: #109 implemented: the capture plan in `@redact-secret/vault` and `@redact-secret/vault-server/persistent`, with tests in `packages/vault-server/test/persistent` and an on-demand table of 39 mutations.
- 2026-10-01: #20, #111 implemented: `store-postgres`, its qualification run on PostgreSQL 17.11 (295 passed, 0 failed, 13 skipped), and `docs/specs/persistent-operations.md`.
- 2026-10-01: #113 implemented: `key-provider-aws-kms`, with one real-service run in `us-east-1`. #114 research and #115 plan (`docs/plans/python-persistence-parity.md`) merged into the branch.
- 2026-10-01: #112: versions set to `0.1.0-beta.4` and `0.1.0-alpha.1`; `release.yml`, `scripts/publish-workspace.mjs`, `qualification/check-persistence-boundaries.mjs`, and `qualification/persistence-consumer.mjs` added. CI run 36910248437 at `3815f34` passed every job, including `persistence` on Node.js 20, 22, 24 and `postgres 17`.
- 2026-10-01: #112 documentation: README, ARCHITECTURE, CHANGELOG, RELEASING, threat model, assurance case, and `docs/research/qualification-persistence-0.1.0-alpha.1.md` reconciled with the tree and the registries. Verified locally on Node.js 22.16.0: `test:persistence`, `test:vault-server` (256 tests, 252 passed, 4 skipped), `check:persistence-boundaries`, and the server mutation table (39 of 39 caught). Nothing is published; the implementation review is still in progress.
