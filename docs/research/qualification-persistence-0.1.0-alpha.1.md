# Qualification record: persistent vault packages, 0.1.0-alpha.1

**Status:** record of what was run for the persistence packages on `main`, unpublished. It is the document the [persistent vault specification](../specs/persistent-vault.md) means by "a profile is supported only when its qualification record says so". Tracking issue: [#112](https://github.com/redact-secret/redact-secret-vault/issues/112), under epic [#4](https://github.com/redact-secret/redact-secret-vault/issues/4).

A row below is evidence for exactly the versions, backend, topology, and key provider it names. Anything not named is not qualified. A skipped test is not a pass.

## 1. Scope and date

Recorded 2026-10-01. Every identifier, key, token, and password used in these runs was synthetic.

In scope: the persistent profile of `@redact-secret/vault-server` (`@redact-secret/vault-server/persistent`) with `@redact-secret/vault-crypto`, the local key provider, `@redact-secret/store-postgres` on the two PostgreSQL profiles of section 2.3, and the optional `@redact-secret/key-provider-aws-kms`.

Not in scope: performance (nothing was measured for these packages), and every profile listed in [section 6](#6-unsupported-and-unqualified-profiles).

**Registry state (2026-10-01).** Nothing in this record has been published. `npm view` returns 404 for `@redact-secret/vault-contracts`, `vault-crypto`, `vault-conformance`, `store-memory`, `store-postgres`, and `key-provider-aws-kms`. `@redact-secret/vault` and `@redact-secret/vault-server` are at `0.1.0-beta.3` on npm (`latest` and `beta`); `0.1.0-beta.4` exists only in the manifests on `main`. Every run below used the working tree or tarballs packed from it, never a registry install of these versions. This paragraph is updated by the release-record commit.

## 2. Tested matrix

### 2.1 Package and dependency versions

| Component | Version |
| --- | --- |
| `@redact-secret/core` (exact peer) | `0.1.0-beta.12` |
| `@redact-secret/vault` | `0.1.0-beta.4` |
| `@redact-secret/vault-server` | `0.1.0-beta.4` |
| `@redact-secret/vault-contracts`, `vault-crypto`, `vault-conformance`, `store-memory`, `store-postgres`, `key-provider-aws-kms` | `0.1.0-alpha.1` each |
| `pg` (peer of `store-postgres`, `^8.11.0`) | `8.23.1` tested |
| `@aws-sdk/client-kms` (peer of `key-provider-aws-kms`, `^3`) | `3.1144.0` tested |

### 2.2 Runtimes

| What ran | Where | Node.js | Result |
| --- | --- | --- | --- |
| `npm run build` | Local, macOS arm64 | 22.16.0 | Exit 0 |
| `npm run test:persistence` | Local, macOS arm64 | 22.16.0 | `vault-contracts` 6 of 6; `vault-crypto` 104 of 104; `vault-conformance` 72 of 72; `store-memory` 132 of 132; `key-provider-aws-kms` 122 tests, 99 passed, 23 skipped (the real-KMS suite, not configured in this run). 0 failed |
| `npm run test:vault-server` (in-memory and persistent suites) | Local, macOS arm64 | 22.16.0 | 256 tests, 252 passed, 0 failed, 4 skipped (section 2.5) |
| `npm run check:persistence-boundaries` | Local, macOS arm64 | 22.16.0 | Passed for all seven packed packages |
| `ci` job `persistence node {20,22,24} ({ubuntu,macos}-latest)`: `npm run test:persistence` | GitHub Actions run [36910248437](https://github.com/redact-secret/redact-secret-vault/actions/runs/36910248437) at `3815f34` (PR [#118](https://github.com/redact-secret/redact-secret-vault/pull/118)) | 20, 22, 24 | All six jobs passed. The Node.js 22 Linux job's counts equal the local ones above |
| `ci` job `vault-server node {20,22,24} ({ubuntu,macos}-latest)`: `npm run test:vault-server` | Same run | 20, 22, 24 | All six jobs passed |
| `ci` job `boundaries`: lint, typecheck, `check:boundaries`, `check:persistence-boundaries`, `check:links` | Same run | 22 | Passed |
| `ci` job `postgres 17`: `npm run test:postgres`, then `npm run qualify:persistence` | Same run, Linux x86_64 | 22.23.3 | 281 tests, 270 passed, 0 failed, 11 skipped (the store-clock cases of section 2.5). Clean-consumer check passed over `store-memory` and the PostgreSQL service |
| `npm run qualify -w @redact-secret/store-postgres` (every suite, Docker topologies) | Local, macOS arm64, Docker 28.3.3 | 22.16.0 | 295 passed, 0 failed, 13 skipped ([report](../../packages/store-postgres/qualification/report/report.md)) |
| Real AWS KMS suite | Local, as the [package README](../reference/key-provider-aws-kms.md#what-was-qualified) states | 22.16.0 | 23 passed, none skipped. Not re-run for this record |

The same CI run's `node`, `browser`, `worker`, and `python` jobs passed; they cover the existing in-memory packages, not persistence. The `sast` run [36910248429](https://github.com/redact-secret/redact-secret-vault/actions/runs/36910248429) and the CodeQL run [36910248388](https://github.com/redact-secret/redact-secret-vault/actions/runs/36910248388) on the same commit passed.

What this means per runtime:

- **Node.js 22:** everything above.
- **Node.js 20 and 24:** contracts, crypto and the local key provider, the conformance harness, `store-memory`, the KMS provider against its fake, and the persistent server profile over `store-memory`, on Linux and macOS in CI. `store-postgres` and real AWS KMS were **not** run on Node.js 20 or 24.

### 2.3 Backend and topology

| Profile | Backend | Settings | Evidence |
| --- | --- | --- | --- |
| Single primary | PostgreSQL 17.11 (`postgres:17`, image digest `sha256:d74eeac9a635390a49bc21bd49fccd973de707e2a53a76ac49b552b8712ec46f`), one container | `fsync = on`, `full_page_writes = on`, `synchronous_commit = on` | Report suites conformance, A, B, C, F, G, H; and the CI `postgres 17` job (same image digest, single-node suites only) |
| Primary with one synchronous standby | PostgreSQL 17.11, two containers, standby from `pg_basebackup` | The above, `synchronous_standby_names = FIRST 1 (sync)`, store created with `requireSynchronousStandby: true` | Report suite D, first half. Local run only; CI does not run it |

Server topology in both: two independent server processes over one database (report suite A), each with its own `pg` pool, connected over loopback TCP without TLS, as a serving role that is not a superuser and holds only `grantStatements`.

### 2.4 Key providers

| Provider | What was run |
| --- | --- |
| Local key provider (`@redact-secret/vault-crypto/local-key-provider`) with injected synthetic material | Its own tests and the shared key-provider cases (`packages/vault-crypto/test/`); the persistent server tests; every PostgreSQL scenario |
| AWS KMS (`@redact-secret/key-provider-aws-kms`) | Its fake-backed suite in CI on Node.js 20, 22, 24. One real-service run on 2026-10-01 in `us-east-1` with `@aws-sdk/client-kms` 3.1144.0 on Node.js 22.16.0, against two single-Region symmetric customer managed keys created for the run: 23 tests passed. The KMS provider was **not** run together with `store-postgres`; its end-to-end cases go through `createRecordCrypto` only |

### 2.5 Skipped cases

| Where | Count | Reason |
| --- | --- | --- |
| `test:vault-server` | 3 | Compatibility checks for a core without a PII surface (beta.9); the installed core is `0.1.0-beta.12` |
| `test:vault-server` | 1 | `attempts.test.mjs`: a same-attempt retry of an entry that attempt exhausted. The server answers `budget`; the test was written against an earlier reading of specification §7.3 and is still marked skipped (section 7) |
| `test:persistence` | 23 | The real-KMS suite reports itself skipped unless `RSV_KMS_TEST_KEY_ARN` and `RSV_KMS_TEST_OLD_KEY_ARN` are set |
| Store conformance against PostgreSQL with the database clock | 11 | Cases that need the store clock at an exact value. The same cases pass in the controlled-clock configuration of the same suite |
| PostgreSQL report, suite `outside` | 2 | See section 7 |

## 3. Evidence index

Each row names the test file, scenario, or report section that is the evidence, or says "not demonstrated". Paths are relative to the repository root. "Report" is the [PostgreSQL qualification report](../../packages/store-postgres/qualification/report/report.md); "operations" is the [operations specification](../specs/persistent-operations.md).

### [#106](https://github.com/redact-secret/redact-secret-vault/issues/106) Versioned AEAD records

| Acceptance item | Evidence |
| --- | --- |
| Exact envelope, algorithm allowlist, versions, bounded sizes, canonical AAD | Specification §3; `packages/vault-crypto/test/codec.test.mjs`; `conformance/persistent/v1/vectors.json` |
| Authenticated scope, session, times, `maxUses`; encrypted value, grants, type, policy revision | `packages/vault-crypto/test/tamper.test.mjs`, `roundtrip.test.mjs`; report suite A, `substitution/*` |
| Key granularity, nonce uniqueness, re-wrap | One data key per capture with HKDF entry keys (a recorded deviation from the issue's per-entry preference, [decision](../decisions/supersede-persistent-store-contract.md)); `roundtrip.test.mjs`. Per-key usage limits: one message per entry key by construction, not a counted limit |
| Platform WebCrypto; no browser claim | `qualification/check-persistence-boundaries.mjs` (no `node:` import, no cipher outside `vault-crypto`). Browser: not run, not claimed |
| Errors expose no provider error, cause, or input | `packages/vault-crypto/test/provider-failure.test.mjs`; `packages/vault-server/test/persistent/leak.test.mjs` |
| Data keys and staged plaintext never reach the store or logs; buffer clearing | `packages/vault-server/test/persistent/capture.test.mjs` (first case), `plaintext-lifetime.test.mjs`. Clearing is best effort; runtime copies are not reachable |
| Known-answer and cross-language vectors, bit flips, swaps, algorithm confusion | `packages/vault-crypto/test/vectors.test.mjs`; [`conformance/persistent/v1`](../../conformance/persistent/v1/README.md), whose README records `verify_vectors.py` passing 58 checks on Python 3.13.15 with `cryptography` 50.0.2. The Python check is not in CI and was not re-run for this record |
| Re-wrap cannot reset consumption or revocation | Store conformance group `rekey` (report, conformance suite) |
| Payload re-encryption under a new data key | Not in version 1 (specification §6.2). Not demonstrated |

### [#107](https://github.com/redact-secret/redact-secret-vault/issues/107) Key-provider lifecycle and local provider

| Acceptance item | Evidence |
| --- | --- |
| Consumer-owned provider; no default key, environment discovery, passphrase default, or fallback | `packages/vault-crypto/test/local-key-provider.test.mjs`; `check-persistence-boundaries.mjs` forbids `process.env` in every packed file |
| Local provider with injected material; a test-only deterministic provider | `local-key-provider.test.mjs`; `packages/vault-conformance/test/key-provider.test.mjs` (`createInsecureTestKeyProvider` refuses to construct without the acknowledgement) |
| Active, decrypt-only, retired; unknown or retired key fails closed; timeouts and cancellation | `key-provider-conformance.test.mjs`, `provider-failure.test.mjs` in `packages/vault-crypto/test/` |
| Bounded cache, default off | The local provider has no cache. KMS: `packages/key-provider-aws-kms/test/cache.test.mjs` |
| Opaque token lookup, stable across restart | `vectors.test.mjs` (`entryId`); report suite A, `restart-both-processes` |
| Erasure responsibility | Stated in specification §9 and operations §3. No erasure was demonstrated, by design |
| Production qualification of the local provider | **Not demonstrated.** It was exercised only with synthetic material generated in the test process. How a deployment's secret manager delivers and protects the material was not tested |

### [#108](https://github.com/redact-secret/redact-secret-vault/issues/108) `store-memory` and the store harness

| Acceptance item | Evidence |
| --- | --- |
| Every store operation of the contract | `packages/store-memory/test/conformance.test.mjs` (the full suite, no case skipped) |
| No plaintext, decryption, principal, policy, or KMS import | `check-persistence-boundaries.mjs` (a store may import only `vault-contracts` and calls no cipher) |
| Fault points, lost responses, stale revisions, clock skew | `createFaultyStore`: `packages/vault-conformance/test/faulty-store.test.mjs`; phase hooks in `packages/store-memory/test/store-memory.test.mjs` |
| Reusable harness with one transaction oracle | `packages/vault-conformance/test/harness.test.mjs`, `mutation-controls.test.mjs` |
| Restart loses all memory state | `store-memory.test.mjs`, "restart loses all memory state" |

### [#109](https://github.com/redact-secret/redact-secret-vault/issues/109) Persistent server mode

| Acceptance item | Evidence |
| --- | --- |
| Capture reuses one implementation; no plaintext export | `packages/vault/test/capture-plan.test.mjs`; `qualification/check-boundaries.mjs` (the plan is `node`-only and not re-exported) |
| Tenant and session come from resolvers; a restore cannot assert a session | `capture.test.mjs`, `restore-authorization.test.mjs` in `packages/vault-server/test/persistent/` |
| `block` aborts; `warn`/`allow` explicit; PII allowlist | `capture.test.mjs`; `pii.test.mjs` (real core, PII on) |
| Atomic create before tokens are returned; no partial mapping on failure | `capture.test.mjs` (formatter, crypto, key, and store failures; fence after an ambiguous create); report suite B, `server/ambiguous-create-is-fenced` |
| Fresh identity, grants, policy per occurrence, staged output, atomic commit, then return | `restore-authorization.test.mjs`, `atomicity.test.mjs`, `attempts.test.mjs` |
| Revoke, delete, close distinct; restart and two-process access | `lifecycle.test.mjs`; `atomicity.test.mjs` (two instances over one store); report suite A (two OS processes) |
| Capability validation before side effects; sanitized diagnostics | `factory.test.mjs`, `leak.test.mjs` |
| No database or KMS dependency in `vault`, `vault-server`, `vault-contracts` | `check-persistence-boundaries.mjs`; `qualification/persistence-consumer.mjs`, consumer A |

### [#110](https://github.com/redact-secret/redact-secret-vault/issues/110) Adversarial conformance

| Required evidence | Evidence |
| --- | --- |
| Substitution across tenant, namespace, session, capture, entry; expiry, `maxUses`, AAD tampering; unknown schema or key | `malicious-store.test.mjs`; `packages/vault-crypto/test/tamper.test.mjs`; report suite A, `substitution/*` |
| 100 concurrent consumes, repeated tokens, multi-entry rollback, revoke races | `atomicity.test.mjs`; report suite A (`100-concurrent-single-use`, `multi-entry-race-no-partial`, `restore-vs-revoke`, `create-vs-fence`) |
| Disconnect, timeout, cancellation before and after commit; response loss; attempt mismatch; restarted caller | `attempts.test.mjs`; report suite B; report suite A, `kill-9-after-commit` |
| KMS outage, rotation, cache eviction, authentication failure | Against the fake: `provider.test.mjs`, `cache.test.mjs`. Real KMS: a disabled key with and without the cache, a context mismatch, a real timeout and abort (package README). A real KMS outage and real throttling: **not demonstrated** |
| Malicious adapter return values | `malicious-store.test.mjs` (19 cases) |
| Replayed backup, reset usage counter, fail-closed recovery | Report suites E and D; report suite A, `limit/used-reset-by-database-writer`, which is a demonstrated **limit**, not a control |
| Missing external revocation ledger | Not offered in version 1 (specification §9.3). Not demonstrated |
| PII off and on, `block`/`warn`/`allow` | `capture.test.mjs`, `pii.test.mjs`, `packages/vault/test/capture-plan.test.mjs` |
| Real-core Unicode and range parity for the persistent profile | **Not demonstrated directly.** The in-memory vault runs the same capture plan and passes the conformance corpus 1.3.0 in the `node` CI jobs; the persistent profile was not run against that corpus |
| Leakage through messages, causes, stacks, audit, console, driver debug | `leak.test.mjs`; `packages/store-postgres/test/diagnostics.test.mjs`; report suites H and H-log |
| Mutation tests | Section 4 |
| Packed packages in clean consumer projects; real backend; two processes | `qualification/persistence-consumer.mjs` (CI `postgres 17` job); report suites `packed` and A |
| A shared language-neutral corpus of lifecycle schedules | **Partly.** The wire vectors are language-neutral. The lifecycle schedules are the JavaScript harness in `@redact-secret/vault-conformance`; no second language runs them |

### [#20](https://github.com/redact-secret/redact-secret-vault/issues/20) PostgreSQL store

| Acceptance item | Evidence |
| --- | --- |
| Schema and migrations; no plaintext or tokens | `packages/store-postgres/README.md` (schema); report suite F; report H-log |
| Atomic create and conditional restore | Report, conformance suite (205 passed, 11 skipped across both clock configurations) |
| Lock order, bounded conflicts, no release from an aborted transaction, no commit retry | Report suite B and `probes`; the `interleave` cases of the conformance suite in both clock configurations |
| Authoritative routing and the durability profile | Report suites C and D; `sync/standby-refuses-to-serve` |
| Bounded cleanup separate from expiry and revocation | Report suite G |
| Two processes, restart, promoted replica, substitution, tenant isolation | Report suites A, C, D |
| Backup restore enters quarantine and cannot resurrect consumed or revoked tokens | Report suite E. Two of four restore methods are **not detected** by the adapter (section 7); for those the control is the configured epoch and the runbook |
| Packed package tests; least privilege; migration and rollback | Report suites `packed` and F. No migration between schema versions exists, so none was tested |

### [#111](https://github.com/redact-secret/redact-secret-vault/issues/111) Recovery, expiry, erasure operations

| Acceptance item | Evidence |
| --- | --- |
| Deny at expiry and revoke independent of cleanup; retention | Operations §2; report suite G |
| Revoke, ciphertext deletion, key retirement, verified erasure kept apart | Operations §3; `lifecycle.test.mjs` (`keyRetired: false`) |
| A wrapped key in a backup stays usable | Report suite E (a server holding the same material decrypted recovered captures) |
| Key retirement against a backup; an erasure statement | **Not demonstrated** (operations §3) |
| Recovery enters quarantine; invalidate and capture again | Operations §5; report suites E and D |
| Reconciliation against an external ledger | Not offered in version 1. Not demonstrated |
| Metadata exposure; read, write, rollback compromise | Operations §4; report suite A `limit/used-reset-by-database-writer` |
| Clock skew, disaster recovery, migrations | Conformance suite with a controlled clock; report suite C. Cross-site topologies: **not demonstrated** |
| Authenticated maintenance interface, audit events | `lifecycle.test.mjs`; report suite A `tenant-isolation`. Store-level recovery calls emit no audit event (operations §10) |
| Executable restore-from-backup negative control | `packages/store-postgres/qualification/scenarios/backup.scenario.mjs` |

### [#113](https://github.com/redact-secret/redact-secret-vault/issues/113) AWS KMS key provider

| Acceptance item | Evidence |
| --- | --- |
| Envelope data keys, exact key identity, context binding | `provider.test.mjs`, `conformance.test.mjs` in `packages/key-provider-aws-kms/test/`; the real-KMS run |
| IAM example | Written in the package README. **Not exercised:** the run created no policy and its principal had broader permissions |
| Nothing sensitive in the encryption context | `conformance.test.mjs` checks every command the fake received: digest-only context |
| Fail closed without the SDK cause; Region, key, account confusion | `provider.test.mjs`; real run: a wrong-account ARN and a nonexistent key id |
| Bounded opt-in cache; retirement | `cache.test.mjs`; real run: a disabled key with and without the cache |
| Real KMS integration | One run, as section 2.4 states |
| AWS SDK only in this package | `dependency-isolation.test.mjs`; `check-persistence-boundaries.mjs` |

### [#112](https://github.com/redact-secret/redact-secret-vault/issues/112) Boundaries and support claims

| Acceptance item | Evidence |
| --- | --- |
| Root and browser `vault` imports resolve no driver, SDK, persistence, or provider code; base packages stay driver-free | `qualification/check-boundaries.mjs`, `qualification/check-persistence-boundaries.mjs`, `qualification/persistence-consumer.mjs` consumer A (module graph observed with `node:module` hooks) |
| Consumer-supplied clients and who closes them | [`store-postgres` README](../reference/store-postgres.md#connection-ownership), [`key-provider-aws-kms` README](../reference/key-provider-aws-kms.md#what-the-application-owns), [`vault-server` README](../../packages/vault-server/README.md#persistent-profile) |
| Threat model and capability matrix name the qualified topology and versions | [Threat model](../specs/threat-model.md#persistent-mappings--implemented-on-main-qualified-for-two-postgresql-profiles); this record |
| Deny-by-default example | [Root README](../guides/persistent-server.md#quick-start) |
| Documentation reconciled with the registries | Section 1; verified with `npm view <package> dist-tags` and the PyPI JSON API on 2026-10-01 |
| Release workflow covers the new packages | `.github/workflows/release.yml`, `scripts/publish-workspace.mjs`, [RELEASING.md](../../RELEASING.md#persistence-packages). The publish path itself has **not been exercised**: no release has run |

## 4. Mutation controls

A mutation control removes one check and requires the tests to fail. It shows the tests detect that defect; it does not show the absence of other defects.

| Control | What it does | Result |
| --- | --- | --- |
| Store harness mutants: `packages/vault-conformance/test/mutation-controls.test.mjs` | 19 variants of the reference model, each with one defect (revocation ignored at commit, partial batch, no receipt uniqueness, budget off by one, expiry on the caller's clock, epoch ignored, and others). The harness must fail a named deterministic case for each. Mutant 12 is the §5.2 write skew and is shown to be visible only through the two-connection `interleave` schedule | Part of `npm run test:persistence`; passed locally and in CI |
| Server mutation table: `packages/vault-server/test/persistent/mutation-controls.mjs` | Removes 39 checks one at a time from a copy of the built `persistent/server.js` and runs the persistent test files against each copy. Run on demand, not in CI | Run for this record on Node.js 22.16.0: the unmutated baseline passed 189 tests in 11 files, and 39 of 39 mutations were caught |
| Crypto and AWS KMS mutation checks | Reported during development of those packages | **Not recorded in the repository.** No script or test in the tree reproduces them, and they were not re-run for this record. They are not evidence here |
| PostgreSQL lock-removal control | Reported during development: with the capture-row `FOR SHARE` lock removed from the built adapter, the two-connection revoke-versus-commit schedule fails in both clock configurations | **Not recorded in the repository** as a script or report section, and not re-run for this record. What the tree does show is the positive half: the `interleave` cases pass against PostgreSQL in both clock configurations, and harness mutant 12 fails them against the model |

## 5. Independent reviews

### Design review

Two passes by a reviewer that did not write the design, before any implementation: [persistent vault design review](persistent-vault-design-review.md). No critical finding; one high finding (a restore commit that did not conflict with a concurrent revocation), fixed by the conflict rule of specification §5.2; thirty findings in the first pass and ten low findings in the second, with their dispositions. It was a reading review. Its "Not assessed" list (backend isolation and durability, a key service's context binding, the vectors, PII activation in the capture plan) is what sections 2 to 4 above address by execution.

### Implementation review

A reviewer that wrote none of the code read the implementation and the claims on 2026-10-01, with instructions to break them, and ran its own probes against the built packages and a PostgreSQL 17 server. It could not make `restore` return a value for another tenant, an unnamed capture, another session, an ungranted sink or path, a revoked or expired capture, or past a budget; it found no partial consumption, no second release, and no plaintext, token, or key reaching a store. It found **no critical and no high defect**. It confirmed seven defects by reproduction; all are fixed, each with a regression test:

| # | Severity | Finding | Change | Test |
| --- | --- | --- | --- | --- |
| A1 | Medium, hard to exploit | `revoke` and `deleteCaptureCiphertext` read `request.captureId` again after the session check and the lifecycle policy had approved the first value. A getter, or a request object changed while the call was pending, could redirect the operation to another capture of the same tenant. No value was exposed | The identifier is read once and that value is used throughout | `review-regressions.test.mjs` |
| A2 | Low | A throwing `policyRevision` callback left a capture's encoded value unwiped and produced no audit event | The revision is read before any value is encoded, through the audited failure path; at restore it is a `policy-evaluation-error` denial | same |
| A3 | Low | `resolveAttempt` had no bound on distinct tokens before deriving identifiers | The restore bound applies before any derivation | same |
| A4 | Low | `store-postgres` judged expiry with the clock read at transaction start, so a commit that waited for a row lock could succeed after the capture expired | The clock is read again once every lock is held | `store-postgres/test/expiry-after-lock.test.mjs` (real database) |
| A5 | Low | An `async` audit hook that rejected became an unhandled rejection | The rejection is absorbed, in both server profiles | `review-regressions.test.mjs` |
| A6 | Low | `purpose` and `requestId` are echoed on audit events and could carry an issued token | Both are refused when they contain a token marker; `requestId` is bounded | same |
| A7 | Note | `store-memory` checked the receipt horizon before the quarantine and receipt checks, against the order of specification §5.5 | Reordered | harness |

Suspicions it could not reproduce, and what was done: the adapter now treats a `COMMIT` that PostgreSQL answers with a `ROLLBACK` tag as not applied; the server wipes its temporary copy of the digest key. Left as stated limits: a restore has per-call deadlines for policy but no overall deadline, so a slow policy keeps decrypted values in memory for as long as it runs; a tenant identifier containing U+0000 is accepted by the contract and cannot be stored by PostgreSQL (every operation fails closed with `STORE_UNAVAILABLE`); a provider result that arrives in the instant a call is being abandoned may not be wiped.

Test gaps it demonstrated by mutating copies of the build, and their state:

- Removing the branch that reports a cancelled synchronous-replication wait as ambiguous, or the per-transaction standby checks, fails no test in CI. Those branches are exercised only by the Docker failover scenario of the qualification run. **Still true.**
- Removing a buffer wipe in the crypto layer, or the wipe on a denied capture, fails no test. Wipes on the restore path are tested (`plaintext-lifetime.test.mjs`); the others are not. **Still true.** The wipes are best effort in any case (specification §6.2).
- Removing the entry row lock showed up as a hung test, not a failure. The package's tests now run with a timeout.

The reviewer did not re-run the Docker topologies or the real AWS KMS tests, and only skimmed the conformance model.

## 6. Unsupported and unqualified profiles

None of these is supported. "Research only" means a document exists and no code does.

| Profile | State |
| --- | --- |
| Python persistence | Not implemented. [Plan only](../plans/python-persistence-parity.md) |
| Browser, dedicated Worker, and edge persistence | Out of scope of the specification (§1). `@redact-secret/vault` persists nothing |
| Streaming capture or restore | Not implemented |
| An asynchronous replica as a failover target | Tested as a negative control and shown unsafe (report suite D) |
| Read replicas, logical replication, multi-primary, quorum commit, more than one synchronous standby | Not tested |
| Connection poolers (PgBouncer, Pgpool-II, cloud proxies) | Not tested |
| Managed PostgreSQL services and forks | Not tested |
| PostgreSQL versions other than 17.11 | Not tested |
| TLS to the database | Not tested; the runs used loopback TCP without TLS |
| `store-postgres` on Node.js 20 or 24, or with a `pg` other than 8.23.1 | Not tested |
| DynamoDB, Redis, SQLite adapters | [Research only](persistent-backend-capabilities.md); no adapter exists |
| AWS KMS multi-Region keys, external or CloudHSM key stores, imported key material, cross-account use, grants, other Regions and partitions | Not tested |
| `@redact-secret/store-memory` as persistence | It is non-durable and single-process by design. A server refuses it without `allowNonDurableStore: true` |
| The local key provider as a production key-management profile | Not qualified (section 3, #107) |
| Any combination not run together, including AWS KMS with `store-postgres` | Not tested |

## 7. Remaining limitations and supported alternatives

| Limitation | Shown by | Alternative |
| --- | --- | --- |
| A party that can write the database can reset `used`, a revocation, or the epoch record. Authenticated encryption shows a record is authentic, not current | Report suite A, `limit/used-reset-by-database-writer` | Restrict the serving role to `grantStatements`; treat database write access as vault authority. Freshness against that party needs a lifecycle authority outside the database, which version 1 does not have |
| Two restore methods are not detected by the adapter: `pg_dump` restored into the same cluster, and a base backup or snapshot started as a plain copy. A server left on the old epoch then released a consumed value again and restored a revoked capture | Report suite E | Follow the [recovery runbook](../specs/persistent-operations.md#5-backup-recovery-runbook) after every recovery: stop servers, quarantine, raise the configured epoch, invalidate, capture again |
| Promoting an asynchronous replica loses acknowledged consumption and revocation | Report suite D, negative control | Treat it as a recovery (the same runbook). Use the synchronous-standby profile with `requireSynchronousStandby: true` when failover must keep captures |
| Release is at most once. A commit whose response is lost spends the use and delivers nothing | Report suites A and B | Resolve with `resolveAttempt`; capture the value again from its source |
| Deleting ciphertext is not erasure. A wrapped key in a backup stays usable while its wrapping key is | Report suite E; operations §3 | Narrowly scoped wrapping keys with an independent registry, bounded backup expiry, or a stated completion delay |
| With the AWS KMS cache enabled, disabling a key does not reach a cached data key until `maxAgeMs` (at most five minutes) | `cache.test.mjs`; the real-KMS run | Leave the cache off (the default) |
| KMS records each call in CloudTrail with the context digest; a reader sees call volume, timing, principal, and key | Package README | Restrict access to the trail |
| Values are decrypted before grants and policy are checked, and exist in process memory for the duration of the call | Specification §7.2; `plaintext-lifetime.test.mjs` shows the bytes are overwritten afterwards | None in version 1 |
| Throughput, latency, table growth, and behavior at the size ceilings were not measured | — | Measure in the target deployment |

The PostgreSQL report was generated from commit `7ad981b`, before later changes to the server and to the adapter (the receipt-horizon check at creation, and the changes listed under the implementation review). Its `outside` suite therefore records an earlier server behavior: a 24-hour lifetime with a 24-hour receipt grace was accepted and restores failed closed. The server now refuses that configuration at creation. The single-node suites were re-run on the final code, locally and in CI; the Docker topology scenarios (restart, failover, backup restore, server log) were not re-run after those changes, and the adapter changes since then do not touch the code paths those scenarios exercise except the commit acknowledgement and the expiry re-check.

## 8. How to reproduce

```sh
npm ci
npm run build
npm run test:persistence                 # contracts, crypto, harness, store-memory, KMS against its fake
npm run test:vault-server                # in-memory and persistent server suites
npm run check:persistence-boundaries     # packed-artifact dependency rules
node packages/vault-server/test/persistent/mutation-controls.mjs

# Single-node PostgreSQL suites and the clean-consumer check, against a disposable database:
RSV_PG_ADMIN_URL=postgres://postgres:synthetic-local-only@127.0.0.1:5432/rsv \
RSV_PG_APP_URL=postgres://rsv_app:synthetic-local-only@127.0.0.1:5432/rsv \
  npm run test:postgres
npm run qualify:persistence              # with the two variables set, also runs over PostgreSQL

# Every PostgreSQL suite, with the topologies started and removed by the script (Docker, postgres:17):
npm run qualify -w @redact-secret/store-postgres

# Wire vectors:
node conformance/persistent/v1/generate-vectors.mjs --check
uv run --with cryptography python conformance/persistent/v1/verify_vectors.py
```

The real-KMS suite needs two test keys and is described in the [package README](../reference/key-provider-aws-kms.md#tests).
