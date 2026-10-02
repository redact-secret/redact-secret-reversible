# Persistent vault workstream — progress record (archived)

**Status: archived 2026-10-02.** Durable working record for epic [#4](https://github.com/redact-secret/redact-secret-vault/issues/4), kept as history after the release recorded for [#112](https://github.com/redact-secret/redact-secret-vault/issues/112). Nothing below the "Final state" section is maintained: its tables describe the repository on 2026-10-01 and are wrong about the registry today. Current state: [docs/status.md](../status.md), [RELEASING.md](../../RELEASING.md), and the [qualification record](../research/qualification-persistence-0.1.0-alpha.1.md). Like the other archived records (see [docs/README.md](../README.md)), it should leave the tree once its last commit is on `main`, with links to it pinned to that commit.

## Final state (2026-10-02)

Released. Tag `v0.1.0-beta.4` at `b77d8cb`; `release.yml` run [36996502364](https://github.com/redact-secret/redact-secret-vault/actions/runs/36996502364) published `@redact-secret/vault` and `@redact-secret/vault-server` `0.1.0-beta.4` with provenance. The seven `0.1.0-alpha.1` packages (`vault-contracts`, `vault-crypto`, `vault-conformance`, `store-memory`, `store-postgres`, `store-sqlite`, `key-provider-aws-kms`) were published by hand by the maintainer, without provenance. `redact-secret-vault` stays at `0.1.0b3` on PyPI. Registry-tarball qualification of `@redact-secret/vault@0.1.0-beta.4` (Node.js addon and WASM, Chromium, Firefox, WebKit) had 0 failures; see [section 9 of the qualification record](../research/qualification-persistence-0.1.0-alpha.1.md#9-registry-verification). The "External blockers" below were cleared by that release. The `key-provider-local` name in the baseline table was never a package; the local key provider is part of `vault-crypto`.

Open items at archive time. The issues were all open when this was written:

| Item | State |
| --- | --- |
| [#128](https://github.com/redact-secret/redact-secret-vault/issues/128), [#129](https://github.com/redact-secret/redact-secret-vault/issues/129) (Python persistence qualification and documentation) | Gates G5 (bridge qualification not done), G6 (server leak tests over the PostgreSQL adapter not run), and G9 (matrix incomplete) are not passed in full. Python persistence stays **not supported** ([record](../research/qualification-python-persistence-0.1.0b3.md)) |
| [#130](https://github.com/redact-secret/redact-secret-vault/issues/130) (`store-sqlite`) | Published as alpha, not a supported profile. The power-loss simulation was **NOT RUN** ([record](../research/qualification-store-sqlite-0.1.0-alpha.1.md)) |
| [#131](https://github.com/redact-secret/redact-secret-vault/issues/131) (stores without a clock of their own) | On hold. The DynamoDB inputs were settled from primary sources in [research](../research/dynamodb-profile-inputs.md); no adapter exists |
| [#18](https://github.com/redact-secret/redact-secret-vault/issues/18) (JS/Python conformance and core ranges) and epic [#3](https://github.com/redact-secret/redact-secret-vault/issues/3) | Open |
| Epic [#4](https://github.com/redact-secret/redact-secret-vault/issues/4) | Open until the items above are decided |
| Python `botocore` DEBUG log leak | With the SDK's loggers at `DEBUG`, `botocore` wrote the plaintext data key and the key ARN to the log (section 4.2 of the [Python qualification record](../research/qualification-python-persistence-0.1.0b3.md)). The changelog says not to enable it. It applies to the Python modules, which are not published |
| Trusted publishers on the seven new packages | Configured by the maintainer, not verified by the agent that recorded this |
| `store-memory` and `store-sqlite` extra `0.0.0-stage` version on npm | Seen on the registry on 2026-10-02, not explained |
| Performance archive (RELEASING.md step 7) | `docs/research/perf/0.1.0-beta.4.json` and the `bench/baseline.json` bump are not part of this record's commits |

## Baseline verified 2026-10-01

Read from `origin/main` at `35ffa32`, the registries, and the issue bodies; nothing below is copied from the task prompt.

| Item | State |
| --- | --- |
| `@redact-secret/vault` | `0.1.0-beta.3` on `main` and npm; `latest` and `beta` both point at it; peers `@redact-secret/core@0.1.0-beta.12` exactly |
| `@redact-secret/vault-server` | `0.1.0-beta.3`, same tags; depends on `@redact-secret/vault@0.1.0-beta.3` exactly |
| `redact-secret-vault` (PyPI) | `0.1.0a3`, `0.1.0b1`, `0.1.0b2`, `0.1.0b3`, `0.1.0b4` published |
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
- 2026-10-01: #130 implemented on a branch: `store-sqlite`, with a partial qualification record (`docs/research/qualification-store-sqlite-0.1.0-alpha.1.md`). Power-loss simulation not run; CI job `sqlite` defined, not yet run.
- 2026-10-01: #112 documentation: README, ARCHITECTURE, CHANGELOG, RELEASING, threat model, assurance case, and `docs/research/qualification-persistence-0.1.0-alpha.1.md` reconciled with the tree and the registries. Verified locally on Node.js 22.16.0: `test:persistence`, `test:vault-server` (256 tests, 252 passed, 4 skipped), `check:persistence-boundaries`, and the server mutation table (39 of 39 caught). Nothing is published; the implementation review is still in progress.
- 2026-10-01: #118 merged (`5e088d3`). Issues #104 to #111, #20, #113, #114, #115 closed with evidence comments. Follow-ups filed: Python handoffs #119 to #129, SQLite adapter #130, clockless-store contract revision #131. Epic #4, release issue #112, and redact-secret/redact-secret#1002 updated.
- 2026-10-01: remaining work is the release under #112: maintainer confirmation, the manual first publish of the six new packages, then tag `v0.1.0-beta.4`.
- 2026-10-02: `v0.1.0-beta.4` tagged and published; the seven alpha packages had been published by hand; registry verification recorded; this record archived.
