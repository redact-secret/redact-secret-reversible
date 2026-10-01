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
| Persistence code | None. `vault-server` wraps a private in-memory vault plus a metadata shadow (`packages/vault-server/src/server-vault.ts`) |
| Persistent ADR | `docs/decisions/define-persistent-store-contract.md`, accepted for the contract only (#19, closed). It has a plaintext-returning `Store.consume`, per-entry atomicity, a `KeyProvider` that seals payloads, plaintext replay on retry, and `Store.purge` promising key destruction |
| `main` protection | Required checks: `boundaries`, `browser`, `node 20/22/24` on ubuntu and macos, `sast`. Admins enforced. No required reviews |
| Release | `release.yml` publishes `vault`, then `vault-server`, then PyPI, by trusted publishing. It knows no other package |

Documentation drift found: `ARCHITECTURE.md` still says alpha and "persistence is not implemented" in its status paragraph; `README.md` says Python `0.1.0b2` is on PyPI where `0.1.0b3` is. Fixed under #112.

## Verification environments

| Environment | State on 2026-10-01 |
| --- | --- |
| Node.js | 22.16.0 locally; CI covers 20, 22, 24 on Linux and macOS |
| PostgreSQL | No local server binaries. Docker Desktop answers after a restart on 2026-10-01; containers are the local environment, and GitHub Actions the CI one |
| AWS | The `redact-secret` CLI profile resolves to an IAM user that can list KMS keys. Creating test keys is authorized by the maintainer; create and use permissions are confirmed when #113 runs |
| npm publish | Trusted publishing can be configured only for a package that already exists (see `RELEASING.md`, "Provenance"). The first publish of each new package is therefore a manual maintainer step |

## External blockers

1. **First publish of new npm packages.** Needs the maintainer's npm account. Until then the release workflow cannot publish them with provenance.
2. **Release.** Each release needs the maintainer's confirmation before its tag is pushed.

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
