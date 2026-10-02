# Assurance case

**Status:** current for `@redact-secret/vault` and `@redact-secret/vault-server` `0.1.0-beta.3` (published), and for the persistent server profile (published 2026-10-02: `0.1.0-beta.4` and the `0.1.0-alpha.1` persistence packages) within the profiles its [qualification record](../research/qualification-persistence-0.1.0-alpha.1.md) names. The persistent argument is in [its own section](#persistent-profile); the independent implementation review it rests on is recorded in [section 5 of the qualification record](../research/qualification-persistence-0.1.0-alpha.1.md#5-independent-reviews).

This document argues why the packages' security requirements are met. It does not restate the evidence; it links to it.

## Claim

A value retained by the vault reappears as plaintext only in a sink and field path the application granted, within the entry's lifetime and use budget, and — with `@redact-secret/vault-server` — only for an authenticated principal of the same tenant with a stated purpose that the application's policy allows. No vault output (error, audit event, stats) discloses a retained value.

## Threat model and trust boundaries

Assets, attacker capabilities, and the trust boundary of every mode (browser main thread, Node.js process, dedicated Worker, single-process server authority, persistent server profile) are in the [threat model](threat-model.md). The boundary is the page or process: the vault does not claim to protect against code already inside it. Browser-specific limits are in [in-memory security](in-memory-security.md), and component boundaries in [ARCHITECTURE.md](../../ARCHITECTURE.md).

## Secure design principles

| Principle | How it is applied |
| --- | --- |
| Fail-safe defaults | Nothing is retained until `capture` is called. Unredacted findings are rejected by default (`unredacted: "reject"`). PII is retained only when its exact type is allowlisted. A policy that throws, times out, or returns a malformed decision denies (`policy-evaluation-error`), never allows. Initialization failures fail closed (`CORE_FAILURE`). |
| Complete mediation | Every token occurrence in every restore is checked against the grant (sink, exact path), expiry, revocation, use budget, and, on the server, principal, tenant, purpose, and policy, at the time of the restore. Nothing is cached from an earlier decision. |
| Separation of privilege | Restoration needs both an issued token and an application grant. A token alone, or a visible type label, grants nothing ([decision](../decisions/decouple-typed-placeholders-from-restoration.md)). |
| Least privilege | Grants name one sink and exact field paths. Entries have a TTL and a per-entry use budget; limits bound entries, bytes, findings, and fields (`DEFAULT_LIMITS` in `packages/vault/src/vault.ts`). |
| Least common mechanism | One vault per session or task; tokens from one vault are unknown to another. Worker mode keeps the mapping in the Worker's private scope. |
| Economy of mechanism | A small public API (`capture`, `restore`, `revoke`, `stats`, `dispose`); detection and policy are delegated to the core rather than reimplemented ([boundary decision](../decisions/separate-reversible-boundary.md)). |
| Open design | All code, decisions, and the threat model are public. Security relies on 128-bit tokens from the platform CSPRNG and on authorization checks, not on secrecy of the design. |
| Psychological acceptability | Failures are typed errors with fixed codes, so the safe handling (keep the redacted text) is easy to write; the README shows it. |

## Common weaknesses countered

| Weakness | Countermeasure | Evidence |
| --- | --- | --- |
| Information exposure through errors or logs (CWE-209, CWE-532) | Errors, audit events, and stats carry fixed codes and counts only; the vault performs no logging, storage, network, or console use. | Negative tests in `packages/vault/test/suite.js`; packed-artifact checks in `qualification/` |
| Insufficient randomness (CWE-330, CWE-338) | Tokens carry 128 bits from `crypto.getRandomValues` (TypeScript) or `secrets` (Python); capture fails if no CSPRNG exists. | `packages/vault/src/token.ts`, `packages/vault-py/src/redact_secret_vault/token.py` |
| Authorization bypass through a user-controlled key (CWE-639) | A token is a lookup key, never authority; forged, altered, cross-vault, cross-tenant, expired, revoked, and over-budget tokens are denied. | [Conformance corpus](../../conformance/README.md); `packages/vault-server/test/` |
| Prototype pollution and unexpected input (CWE-1321, CWE-20) | Worker messages are validated against exact key allowlists, rejecting `__proto__`, `constructor`, and `prototype`; public functions reject invalid arguments with `INVALID_ARGUMENT`. | `packages/vault/src/worker-protocol.ts`; Worker hostile-page tests |
| Resource exhaustion (CWE-400) | Hard limits on input size, findings, entries, retained bytes, fields, and uses. | `DEFAULT_LIMITS`; limit tests |
| Race conditions (CWE-362) | `vault-server` serializes restore and revoke per instance; a queued revoke denies a later restore. All-or-nothing restore leaves no partial state. | `packages/vault-server/test/` |
| Injection through replacement patterns | Restoration does not interpret `$` patterns in model output. | `packages/vault/test/suite.js` |

## Persistent profile

### Claim

With the persistent profile, the claim above holds across server processes and restarts, with these additions: a store or a backup read without a wrapping key discloses no retained value, token, finding type, or grant; a stored record cannot be moved to another tenant, capture, entry, or session, or given another expiry or use budget, without failing authentication; a value is released at most once per use and never before the store has definitely committed the restore; and a revocation that commits before a restore denies it.

The claim is made for the qualified profiles only: Node.js 22, PostgreSQL 17.11 as a single primary (`fsync` and `synchronous_commit` on) or a primary with one synchronous standby, two server processes, the local key provider.

### Argument and evidence

| Sub-claim | Why it holds | Evidence |
| --- | --- | --- |
| The store never holds plaintext or a key | The store contract has no parameter or result that carries a value, a token, or a data key; encryption happens in a separate layer the server calls | [Specification](persistent-vault.md) §2, §4; `qualification/check-persistence-boundaries.mjs` (a store imports only the contracts and calls no cipher); `packages/vault-server/test/persistent/capture.test.mjs`; the PostgreSQL [report](../../packages/store-postgres/qualification/report/report.md), suite H-log |
| Records are bound to their scope | AES-256-GCM with associated data the server rebuilds from trusted scope; one data key per capture and one derived key per entry | `packages/vault-crypto/test/tamper.test.mjs`, `vectors.test.mjs`; [wire vectors](../../conformance/persistent/v1/README.md); `packages/vault-server/test/persistent/malicious-store.test.mjs`; report suite A, `substitution/*` |
| A restore is atomic and ordered against revocation | One conditional transaction is the linearization point; it must conflict with a concurrent revocation of a capture it names (specification §5.2) | Store harness groups `commit`, `concurrency`, `interleave`, `model` against `store-memory` and PostgreSQL; `atomicity.test.mjs`; report suite A (`restore-vs-revoke`: 0 of 160 restores started after an acknowledged revoke succeeded) |
| Release is at most once; an unknown outcome denies | Fields are returned only on `committed`; a receipt deduplicates and never replays; the server never retries an ambiguous commit | `attempts.test.mjs`; report suite B; report suite A, `kill-9-after-commit` |
| Every lifecycle operation is authorized | Tenant and session come only from resolvers; `lifecyclePolicy` gates capture, revoke, deletion, and attempt resolution; anything but `{ allow: true }` denies | `capture.test.mjs`, `lifecycle.test.mjs`, `restore-authorization.test.mjs` |
| Diagnostics carry no value, token, key, ciphertext, or driver text | Fixed-message errors with no `cause`; audit events with fixed fields | `leak.test.mjs`; `packages/vault-crypto/test/provider-failure.test.mjs`; `packages/store-postgres/test/diagnostics.test.mjs` |
| Acknowledged state survives the failures the profile names | `synchronous_commit = on` per write transaction; a synchronous standby required per transaction when asked | Report suites C (restart, crash recovery) and D (promotion of the synchronous standby) |
| A recovered database cannot serve old captures once the runbook has run | Every capture is stamped with the namespace epoch; a server refuses a store whose epoch differs from its configuration | Report suites E and D; [operations specification](persistent-operations.md) §5, §6 |
| Base packages gain no driver, SDK, or crypto dependency | Dependency rules checked on packed artifacts | `qualification/check-boundaries.mjs`, `check-persistence-boundaries.mjs`, `persistence-consumer.mjs` |
| The tests would notice a removed check | Mutation controls | 19 single-defect store models that the harness must fail (`packages/vault-conformance/test/mutation-controls.test.mjs`); 39 checks removed one at a time from the built server, each caught (`packages/vault-server/test/persistent/mutation-controls.mjs`, run on demand) |
| The design was examined by someone who did not write it | Two-pass independent design review before implementation: no critical finding, one high finding fixed | [Design review](../research/persistent-vault-design-review.md). The implementation review is pending and is not evidence yet |

Run results, versions, and what was skipped are in the [qualification record](../research/qualification-persistence-0.1.0-alpha.1.md).

### Not claimed

- **Exactly-once delivery.** A commit whose response is lost spends the use and delivers nothing.
- **Erasure.** Revocation and ciphertext deletion do not remove copies in backups, replicas, WAL archives, or logs, and no key is retired by this library.
- **Freshness against a database writer or an unnoticed rollback.** A party that can write the database can reset a use counter or a revocation; this was demonstrated. Two database restore methods are not detected by the PostgreSQL store.
- **Durability beyond the two named topologies.** An asynchronous replica was shown to be an unsafe failover target. Connection poolers, managed PostgreSQL services, other PostgreSQL versions, and TLS were not tested.
- **Safety of an injected adapter.** A `Store`, `KeyProvider`, or `RecordCrypto` runs in the trusted process; passing the harness does not contain a hostile one.
- **Protection once a wrapping key and a store copy are both held** by the same party.
- **A production key-management profile for the local key provider**, and anything about AWS KMS beyond one real-service run with single-Region symmetric keys.
- **Browser, Worker, or edge persistence; streaming; DynamoDB, Redis, or SQLite.** None is implemented. Python persistent modules exist in the source tree, not on PyPI and not supported; see the [qualification record](../research/qualification-python-persistence-0.1.0b3.md).
- **Performance.** Nothing was measured for these packages.
- **Hidden metadata.** Tenant and capture identifiers, times, counters, and sizes are visible to a reader of the store.

## Supporting processes

- Static analysis (OpenGrep with project rules) and Biome lint gate every pull request; see [CONTRIBUTING.md](../../CONTRIBUTING.md).
- Releases are built in CI and published with npm provenance and PyPI attestations; see [SECURITY.md](../../SECURITY.md#verifying-releases).
- Residual risks accepted for each mode are listed in the [threat model](threat-model.md#residual-risks-accepted-for-alpha1), and for the persistent profile [separately](threat-model.md#residual-risks-for-the-persistent-profile-current-published-alpha).
- The release workflow gates publishing on the persistence tests, the packed-artifact boundary checks, and `store-postgres` against a real PostgreSQL server; see [RELEASING.md](../../RELEASING.md#persistence-packages). None of the persistence packages has been published, so their provenance is not yet evidence.
