# Qualification record: Python persistence, `redact-secret-vault` (tree of 0.1.0b3)

**Status:** record of what was run for the Python persistence modules in this tree. It is the document the [plan](../plans/python-persistence-parity.md) (section 6) and the [decision record](../decisions/python-persistence-api-and-packaging.md) mean by "support is stated only by the qualification record". Tracking issue: [#128](https://github.com/redact-secret/redact-secret-vault/issues/128), under epic [#4](https://github.com/redact-secret/redact-secret-vault/issues/4), plan handoff 10.

**Python persistence is not supported.** At least one gate below is not passed in full (G5, G6, G9: see [section 2](#2-result-by-gate)), so every Python persistence statement outside this record keeps the wording "not supported" or "research". A row below is evidence for exactly the versions, backend, topology, operating system, and key provider it names. Anything not named is not qualified. A skipped test is not a pass, and a run that was not made is listed as **NOT RUN**.

## 1. Scope and date

Recorded 2026-10-01. Every identifier, key, token, and password used in these runs was synthetic. The one real service used is AWS KMS in `us-east-1` with two symmetric test keys created for the run, scheduled for deletion afterwards (section 4.2); no ARN, account identifier, or credential is written here.

In scope: the Python persistent modules of the distribution `redact-secret-vault` as built from this tree: `redact_secret_vault.persistent` (contracts, canonical encoding, digests, the reference `store_memory`, the persistent server profile), `redact_secret_vault.crypto` (record crypto and the local key provider), `redact_secret_vault.stores.postgres` (PostgreSQL over `psycopg` 3), and `redact_secret_vault.keys.aws_kms` (AWS KMS over `boto3`).

Not in scope: performance beyond the measurement in the [decision record](../decisions/python-persistence-api-and-packaging.md); backends other than PostgreSQL; the Node.js core bridge (section 4.5 and the [decision](../decisions/limit-python-persistence-claim-to-a-supplied-core-client.md)); browser or Worker modes; Rust and Go.

**Version of the artifact.** Every run below used the working tree or the wheel built from it. The wheel reports `0.1.0b3` because `pyproject.toml` has not been changed. It is not the published `0.1.0b3` on PyPI, which has none of these modules: `pip install redact-secret-vault==0.1.0b3` installs the in-memory server only. Nothing in this record has been published, and the release will carry another version number.

## 2. Result by gate

Gates are those of plan section 6. "Passed" is for the cells named in section 3 and nothing else.

| Gate | Requirement | Result | Where |
| --- | --- | --- | --- |
| G1 Vectors | Plan 5.3 in full | **Passed** for the cells of section 3 | [4.1](#41-g1-vectors) |
| G2 Interop | Plan 5.4: JavaScript and Python on one database, both directions; lifecycle across languages; negatives | **Passed** for PostgreSQL 17.11 and the local key provider. The AWS KMS provider interoperated against one real key in one region | [4.2](#42-g2-interoperation) |
| G3 Store conformance | The language-neutral schedule corpus against the Python reference store and the Python PostgreSQL adapter | **Passed**; every skipped case is listed with its reason | [4.3](#43-g3-store-conformance) |
| G4 Two-process | Plan 6.1 with real processes | **Passed** for one host and one database. Two hosts with separate clocks: **NOT RUN** (clock skew is simulated by the caller's `now`) | [4.4](#44-g4-two-process-cases) |
| G5 PII and capture parity | Plan 6.2 | **Capture parity passed** against the in-memory server and the JavaScript persistent server. **Bridge qualification not done**, by [decision](../decisions/limit-python-persistence-claim-to-a-supplied-core-client.md) | [4.5](#45-g5-pii-and-capture-parity) |
| G6 Diagnostics | Plan 6.4 over the persistent paths | **Partly passed.** Crypto layer, reference-store server, PostgreSQL adapter, and KMS provider: passed. The server over the PostgreSQL adapter: **not run** | [4.6](#46-g6-diagnostics) |
| G7 Mutation controls | Plan 6.5 | **Passed**: 31 of 31 mutants caught. Two were not caught by the first run; tests were added | [4.7](#47-g7-mutation-controls) |
| G8 Packed wheel | Plan 6.6 | **Passed** on macOS arm64 with CPython 3.11, 3.12, and 3.13, and on Linux aarch64 (glibc) with 3.12, for all five extra combinations. Linux with 3.11 and 3.13: the three combinations that need no database. Two first runs failed and were fixed (section 4.8) | [4.8](#48-g8-packed-wheel) |
| G9 Matrix | Plan 6.7 | **Not complete.** One operating system and architecture per row; CI jobs are defined and have not run | [4.9](#49-g9-matrix) |

## 3. Tested matrix

| Component | Version or setting |
| --- | --- |
| Host | macOS 26.5.2 (Darwin 25.5.0), arm64 (Apple silicon), Docker Desktop 28.3.3 |
| Python (macOS) | CPython 3.11.16, 3.12.14, 3.13.15 (the tree-based runs of 4.1 to 4.7 used 3.11.16 and 3.12.14; the packed-wheel runs of 4.8 add 3.13.15) |
| Linux | Debian 12 (`node:22-bookworm`) container, linux/arm64, glibc 2.36, Node.js 22.23.3, CPython 3.11.2, 3.12.14, 3.13.15; packed-wheel runs only (4.8) |
| `cryptography` | 50.0.2, bundled OpenSSL 4.0.3; `cffi` 2.1.1 |
| `psycopg` | 3.3.6, `binary` build (bundled libpq 18.0.6, implementation `binary`); `psycopg-pool` 3.3.3 for one test. The `postgres` extra itself names plain `psycopg`, which cannot be imported without a system `libpq` |
| `boto3`, `botocore` | 1.43.107 each |
| PostgreSQL | 17.11 (Debian 17.11-1.pgdg13+2, aarch64) in a Docker container, a single primary, `fsync = on`, default `synchronous_commit`. The same major as the CI service container (`postgres:17`) |
| PostgreSQL deployment profile | Single primary only. The profile with a synchronous standby and failover were **not run** for Python |
| Node.js | 22.16.0 |
| `@redact-secret/core` | `0.1.0-beta.12`, the exact pin of the bridge and of both server packages |
| JavaScript counterpart | `@redact-secret/vault-server` and `@redact-secret/vault` `0.1.0-beta.4`; `vault-contracts`, `vault-crypto`, `store-memory`, `store-postgres`, `key-provider-aws-kms` `0.1.0-alpha.1`; `pg` 8.23.1 (all built from this tree) |
| AWS KMS | `us-east-1`, two symmetric `SYMMETRIC_DEFAULT` keys (`ENCRYPT_DECRYPT`), `boto3` default credential chain through a named profile |

| Packed wheel runs of section 4.8 | CPython 3.11.16, 3.12.14, 3.13.15 on macOS; CPython 3.11.2, 3.12.14, 3.13.15 on Linux (Debian 12 container, aarch64, glibc 2.36, Node.js 22.23.3) |
| Linux | `node:22-bookworm` container (`linux/arm64`) on Docker Desktop, reaching the same PostgreSQL 17.11 over the Docker host name |

## 4. Gates

Commands are run from `packages/vault-py` unless a path says otherwise, against a database prepared with `node packages/store-postgres/scripts/create-app-role.mjs` and `node packages/vault-py/tests/pg_prepare.mjs` (the schema is applied by the JavaScript package, which owns it; the Python adapter creates no table). The serving role is `rsv_app`, not a superuser, with only the grants `grantStatements` lists. `RSV_REQUIRE_POSTGRES=1` makes a missing database a failure and not a skip.

### 4.1 G1 Vectors

`conformance/persistent/v1/vectors.json` through the Python code that ships in the wheel: `pytest tests/test_persistent_vectors.py tests/test_crypto_vectors.py`. Every positive vector is reproduced byte for byte, and every negative case is rejected with the mapped error code, no other exception type, and `__cause__` and `__context__` unset.

| Cell | Result |
| --- | --- |
| macOS arm64, CPython 3.11.16 | 111 passed |
| macOS arm64, CPython 3.12.14 | 111 passed |
| Packed wheel in a clean virtualenv outside the checkout (G8): macOS arm64 CPython 3.11.16, 3.12.14, 3.13.15; Linux aarch64 CPython 3.11.2, 3.12.14, 3.13.15 | The `crypto` cell of [4.8](#48-g8-packed-wheel) includes both vector test files: 379 passed, 2 skipped in each |

`python conformance/persistent/v1/verify_vectors.py` (the independent oracle, which shares no code with either implementation, kept as the [decision record](../decisions/python-persistence-api-and-packaging.md) says): 58 checks passed, 0 failed, on 3.11.16 and 3.12.14. The JavaScript side of the same file is covered by its own record.

### 4.2 G2 Interoperation

**Record format and server, through PostgreSQL.** `pytest tests/test_interop_postgres.py` (24 tests). Two persistent server processes over one database and one namespace: `@redact-secret/vault-server/persistent` over `@redact-secret/store-postgres` (Node.js 22.16.0, its own `pg` pool, its own core) and the Python persistent server over `redact_secret_vault.stores.postgres` (its own pool, its own `NodeCoreBridge`). They share the key material (the same wrapping key under the key identifier `synthetic-1`) and the digest key, generated per run, and nothing else. Neither creates a table. The synthetic values are detected by the real core on each side.

| Case | Both orders (JavaScript seals and Python opens; Python seals and JavaScript opens) | Result |
| --- | --- | --- |
| A three-value capture sealed by one language is restored by the other; the restored fields equal the original values; the sealer then finds the shared budget used | yes | passed |
| Four captures sealed by one language each open in the other | yes | passed |
| A capture revoked by the other language is denied `revoked` by both | yes | passed |
| A restore committed by one language is `attempt-already-committed` to the other for the same attempt and request (the request digests agree outside the vectors), `attempt-mismatch` for a changed request from either language, and `resolveAttempt` reports `committed` | yes | passed |
| A session-bound capture made by one language is denied `source` by the other under another session or none, and restored under the same session (the session tags agree) | yes | passed |
| An exhausted budget is denied `budget` to both | yes | passed |
| Negative: a different digest key on one side denies the session-bound restore `source`, and nothing is consumed | yes | passed |
| Negative: different key material on one side denies the restore `key-unavailable` or `integrity-failure`, and the single-use value is still there for the right key | yes | passed |

The mixed-language variants of the cases of plan 6.1 are in [4.4](#44-g4-two-process-cases). Result: **24 passed**, 0 failed, 0 skipped, in about 15 s.

**Key provider, against real AWS KMS.** `pytest tests/test_aws_kms_real.py` with `RSV_KMS_TEST_KEY_ARN` and `RSV_KMS_TEST_OLD_KEY_ARN` set to two symmetric keys of one account in `us-east-1`, the default credential chain through a named profile. The JavaScript side is the provider of `packages/key-provider-aws-kms` in a child process (`tests/aws_kms_js_peer.mjs`); the data key never leaves it, only its SHA-256 does. **9 passed**, 0 failed:

- a data key wrapped by the JavaScript provider is unwrapped by Python, and the reverse, with equal plaintext digests;
- a different context fails `KEY_INTEGRITY`, for a key made by either side and unwrapped by either side;
- a key wrapped by the old key and rewrapped to the active key by Python unwraps in JavaScript, and a JavaScript rewrap is unwrapped by Python;
- a disabled key fails `KEY_UNAVAILABLE` (visible to `Decrypt` after 61 s on this run, KMS being eventually consistent) and works again when enabled;
- no namespace, tenant, or capture identifier appears in clear in any request context of `GenerateDataKey`, `Decrypt`, or `ReEncrypt`; the context is the digest and a version;
- a call that cannot finish in the provider timeout (1 ms) is `KEY_TIMEOUT`, and the provider works again;
- the opt-in cache serves a real key without a second `Decrypt` and `close` overwrites it;
- **SDK logging at `DEBUG`:** with the SDK's loggers at `DEBUG`, 72 records from `botocore` and `urllib3` were written, and **the plaintext data key (hexadecimal or base64) and the key ARN were in them** (`botocore.parsers` logs the response body). No identifier was: the context carries only the digest. The provider itself wrote no record, and no error, stream, or warning of the provider carried a key, a blob, an ARN, or an identifier. An application must not enable `DEBUG` for `botocore`, `boto3`, or `urllib3`, or the root logger, in a process that uses this provider. *Follow-up, [#145](https://github.com/redact-secret/redact-secret-vault/issues/145) (after this run, not part of it):* the provider now refuses to construct and refuses each KMS call while `DEBUG` is enabled for a guarded SDK logger, unless `allow_sdk_debug_logging=True` is passed; it was verified on `boto3` 1.43.107 with a stubbed HTTP layer, not against the real service.

56 further tests of the provider run against a fake client shaped like `boto3` and need no credentials (they run in CI); they are not interoperation evidence. Throttling was not provoked against the real service. The two keys were scheduled for deletion (7-day window) after the run.

### 4.3 G3 Store conformance

The language-neutral corpus (`conformance/persistent/v1/schedules.json`, 119 cases: 104 at the store level, 15 at the server level) through the Python driver `tests/schedule_driver.py` and the Node.js orchestrator `conformance/persistent/v1/orchestrator.mjs`. A skipped case names its reason and is never counted as a pass.

| Adapter and configuration | Passed | Failed | Skipped |
| --- | --- | --- | --- |
| Python reference store `store_memory`, store level, controllable clock and holds | 104 | 0 | 0 |
| `store_memory`, store level, a clock the harness cannot move and no holds | 92 | 0 | 12 (7 need `testClock`, 5 need holds) |
| `store_memory`, server level (the persistent server, local key provider, `NodeCoreBridge`) | 15 | 0 | 0 |
| **PostgreSQL adapter**, store level, a controllable store clock (a test-owned row read by the same SQL, parallelism 100) | 104 | 0 | 0 |
| PostgreSQL adapter, store level, the database's own clock, holds on | 97 | 0 | 7 (`testClock`) |
| PostgreSQL adapter, store level, the database's own clock, no holds | 92 | 0 | 12 (7 `testClock`, 5 holds) |
| PostgreSQL adapter, store level, every bound lowered (`max_create_entries` 8, `max_create_bytes` 64 KiB, `max_restore_entries` 8, `max_restore_captures` 4, `max_envelope_bytes` 4096) | 103 | 0 | 1 (`create.throws-store-capability-for-more-bytes-than-maxcreatebytes...`: `maxCreateBytes` cannot be exceeded within `maxCreateEntries` envelopes of `maxEnvelopeBytes`) |
| **PostgreSQL adapter**, server level (the persistent server over this adapter, local key provider) | 15 | 0 | 0 |

The two-connection schedules (`interleave.*`, 5 cases) ran with the hold point `before-commit` implemented by a pooled-connection wrapper in the test tree: the real transaction has executed its statements and waits before `COMMIT`. The fault points ran through the real adapter and real connections (`unavailable`, `before-first-write`, `drop-connection`, and `after-commit-before-ack`, where the commit reaches the server and the connection then fails). Neither hook is in the wheel. The unit tests of the adapter add a TCP relay that is cut at the `COMMIT` message (the commit forwarded and the acknowledgement withheld: `STORE_AMBIGUOUS`, receipt present, counter moved, replay is `already-committed`; the commit not forwarded: `STORE_AMBIGUOUS`, nothing applied; a cut in the middle of a transaction: `STORE_UNAVAILABLE`, nothing applied), a backend terminated from outside while a commit is held, and a call cancelled while held (the connection is closed, `CancelledError` is not converted, nothing applied).

Rows outside the contract, written with the admin role into a capture, entry, receipt, or recovery row, are never returned: a `bigint` beyond `2^53 - 1` (`created_at`, `expires_at`, `epoch`), a negative time, a wrapped key over 4096 bytes or empty on a live capture, a key reference empty or over 512 bytes, a malformed session tag, an envelope empty or over the store's limit, a receipt digest of 31 bytes, each is `STORE_UNAVAILABLE` with the fixed message. A namespace recorded under another database identity reads as `quarantined`.

The schedules alone did not catch two mutants of the adapter (4.7); tests were added for them.

### 4.4 G4 Two-process cases

`pytest tests/test_stores_postgres_processes.py` (17 tests) and the mixed-language cases of `test_interop_postgres.py`. Each case uses real operating-system processes (the Python driver as a child process for the first file, one JavaScript and one Python server process for the second), each its own interpreter with its own connections, against one database; a test asserts that the process identifiers differ from each other and from the conductor's. Topology: one host, one PostgreSQL 17.11 single primary, local TCP, the caller's clock and the database's are the same machine's.

| Case (plan 6.1) | Python and Python | JavaScript and Python |
| --- | --- | --- |
| Revoke against restore: B's revoke committed before A's commit starts | passed | passed (2 orders) |
| Revoke against restore: B's revoke held open across A's commit attempt, then committed (A waits, then is denied; a held commit is never undone by a late revoke, which waits for it) | passed, and the reverse case | passed (2 orders) |
| Quarantine against create, and invalidation against create (held creation: the recovery operation waits and is ordered after it; after it, creation under the old epoch is rejected) | passed (both operations) | quarantine passed (2 orders) |
| Budget: 100 concurrent restores of one entry with `max_uses` 7 from two processes: exactly 7 commit, the rest `budget`, `used` equals 7 | passed | passed (2 orders; 50 requests from each language) |
| Whole-request atomicity: a restore of three entries where one is out of budget changes no counter and writes no receipt | passed | not run |
| Receipts: the same attempt and request from two processes at once: one `committed`, one `already-committed`; a changed request `attempt-mismatch`; an ambiguous commit resolved from the other process as `committed` and a new attempt denied | passed | covered by 4.2 (sequential) |
| Create against fence: a delayed creation after `revoke_capture(fence_absent=True)` is `fenced` | passed | not run |
| Restart: a process captures and exits, a new process restores; a capture made by an exited process and revoked by another is denied to a third | passed | not run |
| A process killed (SIGKILL) while its transaction waits before `COMMIT`: nothing applied, the locks gone | passed | not run |
| Clock skew: a caller whose `now` is an hour off is `clock-skew` on create and on commit, and its revoke still succeeds | passed (simulated by the caller's `now`; the database clock is this machine's) | not run |
| Fork: a store created before `os.fork()` is not used by the child (`STORE_CLOSED`, no connection opened) | passed | not applicable |

**NOT RUN:** two hosts with separate clocks and a real skew; a process killed after `COMMIT` reached the server but before the acknowledgement was read (the relay of 4.3 stands in for that); a deployment with a synchronous standby.

### 4.5 G5 PII and capture parity

**Against the Python in-memory server** (`pytest tests/test_persistent_server_parity.py`, run on the macOS cells): every capture step of `conformance/v1/corpus.json` (52 cases, version 1.3.0) in a PII-off and a PII-on lane against both servers, each over its own `NodeCoreBridge`: 91 passed, 14 skipped (10 need PII on, 2 need PII off, 2 are `requiresSharedRealm`). Agreement on outcome, token count and types, `unrestorable`, `passed_through` and its types, the redacted text up to token position, and the stored record of each token opened with the test key. Two specified differences are asserted, not skipped (limits count one capture, and a negative clock reading).

**Against the JavaScript persistent server** (`pytest tests/test_capture_parity_javascript.py`): the same corpus, the same two lanes, each capture step run on `@redact-secret/vault-server/persistent` (own process per case and lane, because the core's activation is realm-global; own real core; `store-memory`; opens its own records with the same public test key) and on the Python persistent server (`store_memory`, own `NodeCoreBridge`). Compared per capture: the outcome (the Python code against the JavaScript `vaultCode`, and the core code), the token count and types, `unrestorable`, `passed_through` and its types, the redacted text up to token position, and the stored `(value, type)` of each token in order. **92 passed, 14 skipped** (the same 14); in the PII-on lane 48 captures with a retained value were compared value for value in 49 cases. `block` aborted with nothing stored and no fence; `warn` and `allow` under `reject` stored nothing; a PII type outside `pii.retain` was never in a payload; `eligible` never added one. The first run of this comparison found 30 differences; every one was either the JavaScript wrapping of a vault failure in `VAULT_FAILURE` (section 6, item 9) or a corpus policy map that the JavaScript API takes as an object with `evaluate`, both fixed in the comparison, not in either server. The Python and JavaScript records are also each opened by the other (4.2).

Two workers whose bridges report different activation identities: with `expected_pii_activation` set, the second fails `PII_ACTIVATION_MISMATCH` before storing anything (`tests/test_persistent_server.py`).

**Bridge qualification: not done.** The [decision](../decisions/limit-python-persistence-claim-to-a-supplied-core-client.md) limits any claim to an application-supplied, separately qualified `CoreClient`. The gaps recorded in the [threat model](../specs/threat-model.md) (an adversarial protocol run, fuzzing of the frame parser, supported operating systems, plaintext in the child's heap, a core replaced on disk, unbounded queuing, a discarded standard error) stay open. In all runs above the bridge was a test fixture.

### 4.6 G6 Diagnostics

Sentinels are the fixture values, the issued tokens, the data and entry keys, the wrapping material, the digest key, wrapped keys, envelopes (raw, hexadecimal, base64), the database password, and a marker planted in the driver's or SDK's failure. Channels: the exception's message, `repr`, `args`, attributes and slots; `__cause__` and `__context__` (both `None`); `__notes__` (absent); `traceback.format_exception` and the locals of every frame of the package that a traceback reaches; `logging` with the root logger and the library loggers at `DEBUG`; `warnings` as errors; standard output and error; audit events; `repr` and `str` of contract objects; pickling.

| Component | Test | Result |
| --- | --- | --- |
| Crypto layer and local provider | `tests/test_crypto_leaks.py` (every negative vector, provider outage, throttling and timeout, cancellation; a failing assertion prints no secret; buffers zero on every path; contract objects print lengths and refuse pickling) | passed |
| Persistent server over the reference store | `tests/test_persistent_server_leaks.py` (every negative path, a store that raises foreign exceptions or returns out-of-contract values, key-provider outage, cancellation at every `await` of capture and restore) | passed |
| **PostgreSQL adapter** | `tests/test_stores_postgres.py::test_nothing_secret_reaches_...`: 15 or more sanitized errors from every named fault, a malformed row, a closed store, and an invalid argument; the password of the connection, the envelope and wrapped-key bytes, and the marker in the driver's failure appear in none of the channels. With `psycopg` and `asyncio` loggers at `DEBUG`: 191 records, all about connection state, none with a statement, a parameter, or a row value (they do name the host, port, user, and database of a connection: an application that treats those as sensitive must not enable `DEBUG` for `psycopg`) | passed |
| **AWS KMS provider** | fake client: 15 or more errors through every mapped failure, the SDK's text and request identifier in none of the channels, and no SDK log record at `DEBUG`; real service: [4.2](#42-g2-interoperation), where the SDK itself logs the data key | passed for the provider; the SDK finding is recorded |
| Contract objects the adapter returns | `StoredEntry` and `StoredCapture` print lengths, not bytes | passed |

**NOT RUN:** the server leak tests over the PostgreSQL adapter (they run over the reference store; the schedule cases over PostgreSQL ran the server but are not leak runs), and the plan's "every schedule case" sweep over PostgreSQL. This is why G6 is not marked passed in full.

### 4.7 G7 Mutation controls

`python tests/mutation_controls.py` applies each mutant (one exact textual change to one module) to a throwaway copy of the package, runs the tests that must catch it (and, for the adapter, the schedule cases through the Python driver against PostgreSQL), and records which failed. `tests/test_mutation_controls.py` checks without a database that every mutant still applies exactly once. The 31 mutants cover the 16 rows of plan 6.5, one or more per row; the store-level mutants that apply to `store_memory` have their own table of mutated stores in `tests/store_mutants.py`, run by `tests/test_store_memory.py` (not repeated here).

**The first run caught 29 of 31.** Two escaped: `epoch-not-compared-at-commit` and `commit-expiry-on-caller-clock`. The shared schedule corpus does not distinguish a commit that ignores the namespace epoch (the lower-epoch capture also reads as revoked, so only the reason differed) or one that judges expiry on the caller's `now` (the corpus sends the store's own time as `now`). Tests were added to `tests/test_stores_postgres.py` (`test_a_commit_that_carries_an_epoch_other_than_the_namespaces_is_quarantined`, `test_expiry_is_judged_on_the_store_clock_and_not_on_the_callers`); the mutants were then caught. The same gap is likely to exist in the JavaScript harness, which converts the same cases; it was not checked there.

**Final run: 31 of 31 caught** (after the two tests of the paragraph above), on macOS arm64, CPython 3.12.14, PostgreSQL 17.11. The first test or schedule case that failed for each mutant:

| Mutant | Plan 6.5 row | Failed (first) |
| --- | --- | --- |
| `commit-reads-capture-without-lock` | Commit does not conflict with a concurrent revoke (reads the capture without lock or condition) | `test_a_revoke_held_open_across_a_commit_attempt_then_committed_denies_the_restore` |
| `create-ignores-recovery-lock` | Create does not conflict with quarantine | `test_a_creation_that_passed_its_recovery_check_is_ordered_against_a_recovery_operation[quarantine]` |
| `generation-not-compared-at-commit` | generation, lifecycle_revision, or ciphertext_revision not compared at commit (generation) | `schedule:commit.rejects-stale-for-a-different-lifecyclerevision-ciphertextrevision-or-generation` |
| `lifecycle-revision-not-compared-at-commit` | generation, lifecycle_revision, or ciphertext_revision not compared at commit (lifecycle revision) | `schedule:commit.rejects-stale-for-a-different-lifecyclerevision-ciphertextrevision-or-generation` |
| `ciphertext-revision-not-compared-at-commit` | generation, lifecycle_revision, or ciphertext_revision not compared at commit (ciphertext revision) | `schedule:commit.rejects-stale-for-a-different-lifecyclerevision-ciphertextrevision-or-generation` |
| `budget-not-checked-at-commit` | Budget checked at preflight only | `test_a_hundred_concurrent_restores_from_two_processes_commit_exactly_max_uses` |
| `receipt-digest-not-compared` | Receipt lookup skipped, or digest not compared (digest) | `test_one_attempt_submitted_by_two_processes_commits_once_and_the_other_is_already_committed` |
| `receipt-lookup-skipped` | Receipt lookup skipped, or digest not compared (lookup) | `test_one_attempt_submitted_by_two_processes_commits_once_and_the_other_is_already_committed` |
| `epoch-not-compared-at-commit` | Epoch not compared, or lower-epoch capture not treated as revoked (commit) | `test_a_commit_that_carries_an_epoch_other_than_the_namespaces_is_quarantined` |
| `lower-epoch-capture-not-revoked` | Epoch not compared, or lower-epoch capture not treated as revoked (read) | `schedule:recovery.every-capture-of-an-earlier-epoch-is-treated-as-revoked-by-every-operation` |
| `commit-expiry-on-caller-clock` | Store clock replaced by caller now at commit | `test_expiry_is_judged_on_the_store_clock_and_not_on_the_callers` |
| `store-error-raised-inside-except` | Sanitized error raised inside the except block (store) | `test_nothing_secret_reaches_an_error_a_traceback_a_log_a_warning_or_a_stream` |
| `aad-omits-tenant` | AAD omits one field (tenant) | `test_aad[session-bound]` |
| `aad-omits-capture` | AAD omits one field (capture) | `test_aad[session-bound]` |
| `aad-omits-entry` | AAD omits one field (entry) | `test_aad[session-bound]` |
| `aad-omits-session` | AAD omits one field (session) | `test_aad[session-bound]` |
| `aad-omits-created-at` | AAD omits one field (created-at) | `test_aad[session-bound]` |
| `aad-omits-expires-at` | AAD omits one field (expires-at) | `test_aad[session-bound]` |
| `aad-omits-max-uses` | AAD omits one field (max-uses) | `test_aad[session-bound]` |
| `lone-surrogate-test-removed-well-formed` | Lone-surrogate test removed (is_well_formed) | `test_a_surrogate_code_point_is_never_well_formed` |
| `lone-surrogate-test-removed-identifier` | Lone-surrogate test removed (is_identifier) | `test_identifier_predicates` |
| `utf16-length-replaced-by-len` | UTF-16 length replaced by len() | `test_utf16_length_is_counted_in_code_units_not_code_points` |
| `digest-sorts-by-utf16` | Sort by the order of a UTF-16 encoding instead of UTF-8 bytes (request digest) | `test_request_digest[session,` |
| `payload-sorts-by-utf16` | Sort by the order of a UTF-16 encoding instead of UTF-8 bytes (payload sets) | `test_payload_encodes_and_decodes_back[supplementary` |
| `decoder-accepts-trailing-bytes` | Decoder accepts trailing bytes | `test_negative_payload[one` |
| `decoder-accepts-unsorted-grants` | Decoder accepts unsorted grants | `test_negative_payload[sinks` |
| `sanitized-error-raised-inside-except` | Sanitized error raised inside the except block (crypto and codec) | `test_negative_envelope[empty]` |
| `unknown-key-ref-falls-back-to-the-active-key` | Fallback to another key when keyRef is unknown | `test_negative_local_unwrap[key` |
| `a-nonce-is-reachable-from-the-public-api` | Fixed nonce reachable from the public API | `test_no_public_entry_point_takes_a_nonce` |
| `session-tag-not-checked-before-unwrap` | Session tag not checked before unwrap | `test_the_denials_of_step_four_come_in_the_specified_order` |
| `fields-returned-when-the-commit-result-is-unknown` | Fields returned before the commit result is known | `test_an_unclassified_failure_at_commit_is_ambiguous_with_the_attempt_and_is_never_retried` |

A mutant is a deliberate defect, so "caught" shows that the named test can see that defect. It does not show that no other defect exists; a general mutation tool over the persistent modules is not run (plan open question 10).

### 4.8 G8 Packed wheel

`python -m build` (hatchling 1.32.4) builds one sdist (256 KB) and one wheel (`redact_secret_vault-0.1.0b3-py3-none-any.whl`, 125 KB) from the tree.

- `python scripts/verify-python-dist.py`: passed (version, the bridge script in the wheel, no `Requires-Dist` outside the extras `aws-kms`, `crypto`, `postgres`, and none of the test tree in the wheel).
- `python scripts/check-python-isolation.py <wheel>`: **passed**. Base install: no third-party distribution beside `pip`, `pip check` passes, the base imports load none of the three dependency families, and each optional module raises `ImportError` naming its extra. All extras: each family is importable, and importing one optional module loads only its own family. **Finding from the first run:** with only the `postgres` extra (plain `psycopg`) the adapter does not import on a host without `libpq` (`ImportError: no pq wrapper available`), because `import psycopg` itself needs it. The script now adds `psycopg[binary]` to that virtualenv, and the module, the README, and the decision record say which variant was tested.
- `python scripts/qualify-python-wheel.py <wheel> --python <version> [--cells ...]` (new): for each extra combination, a virtualenv in a temporary directory outside the repository (`uv venv`), the wheel installed with the extras, `pip check`, a check that `redact_secret_vault` is imported from that virtualenv and that the wheel holds no test driver, fixture, or hook, and the tests of the cell run from a copy of `tests/` in a mirror of the repository's layout (the vectors by `RSV_PERSISTENT_VECTORS`, the schedule corpus by `RSV_SCHEDULES_DIR`). Never an editable install.

| Cell (extras) | macOS arm64, 3.11.16 | macOS arm64, 3.12.14 | macOS arm64, 3.13.15 | Linux aarch64, 3.12.14 | Linux aarch64, 3.11.2 and 3.13.15 |
| --- | --- | --- | --- | --- | --- |
| `base` (none) | 143 passed, 3 skipped | 143 passed, 3 skipped | 143 passed, 3 skipped | 143 passed, 3 skipped | 143 passed, 3 skipped |
| `crypto` | 379 passed, 2 skipped | 379 passed, 2 skipped | 379 passed, 2 skipped | 379 passed, 2 skipped | 379 passed, 2 skipped |
| `crypto,postgres` (+ `psycopg[binary]`, `psycopg-pool`) | 82 passed | 82 passed | 82 passed | 82 passed | NOT RUN |
| `crypto,aws-kms` | 167 passed | 167 passed | 167 passed | 167 passed | 167 passed |
| `crypto,postgres,aws-kms` (+ `psycopg[binary]`, `psycopg-pool`) | 219 passed | 219 passed | 219 passed | 219 passed | NOT RUN |

Each cell selects its tests (`scripts/qualify-python-wheel.py`, `CELLS`); the database cells run `test_stores_postgres.py`, `test_stores_postgres_processes.py`, and `test_interop_postgres.py` (82 tests) or the vectors, the isolation tests, the KMS provider tests, and the two-process and interoperation tests (219). Versions installed in each virtualenv are printed by the script: `cryptography` 50.0.2, `cffi` 2.1.1, `psycopg` and `psycopg-binary` 3.3.6, `psycopg-pool` 3.3.3, `boto3` and `botocore` 1.43.107.

**Two first runs failed, and what was done.** (1) The first run of `crypto,postgres` on 3.12 failed 3 tests: three static tests read the adapter's source from the checkout, which the mirror does not copy. They now read the installed module (`redact_secret_vault.stores.postgres.__file__`), which is what a wheel test should read. The cell was re-run and passed. (2) The first run on Linux of `crypto,postgres` and `all` failed 2 of the cross-language budget tests: some of the 100 concurrent restores ended `COMMIT_AMBIGUOUS` or `STORE_UNAVAILABLE` instead of `budget`, which is what those codes mean after waiting too long for a row lock or a connection (the 2 s lock wait, the 10 s store deadline, and a pool of 20, with the database reached across the Docker network). The case now runs with a 10 s lock wait, a 30 s statement timeout, a 60 s store deadline, and a pool of 40 in both workers (`CONTENDED` in `tests/test_interop_postgres.py`), and passed on macOS and in the re-run on Linux. This is a sensitivity of that case to load and latency, found on the Linux cell, not a failure of an invariant: no run ever showed a restore committed beyond `max_uses`. A deployment under that load must expect those codes and resolve the attempt.

### 4.9 G9 Matrix

| Axis | Run | Not run |
| --- | --- | --- |
| Python | CPython 3.11, 3.12, 3.13 (full database cells on 3.11, 3.12, 3.13 on macOS and 3.12 on Linux). The whole tree suite, with the database, on 3.11.16 and 3.12.14: 1053 passed, 55 skipped, 0 failed, each. CPython 3.10.21 (the `python` CI job's lowest cell): the in-memory suite only, 315 passed, 18 skipped, the persistent tests not collected | The persistent modules on 3.10 (they refuse to import), 3.14, free-threaded builds, PyPy |
| Operating system and architecture | macOS arm64; Linux aarch64 with glibc 2.36 in a container | Linux x86-64, musl, Windows, macOS in CI |
| `cryptography` | 50.0.2 with OpenSSL 4.0.3 | any other version |
| `psycopg` | 3.3.6, `binary` build, libpq 18.0.6; `psycopg-pool` 3.3.3 | the pure-Python and `c` variants, a system `libpq`, any other version |
| PostgreSQL | 17.11, a single primary | other versions, a synchronous standby, failover, a pooler, a managed service, TLS |
| Topology | Two to three processes on one host, one database | Two hosts with separate clocks |
| Node.js and core | 22.16.0 (macOS) and 22.23.3 (Linux container); `@redact-secret/core` `0.1.0-beta.12` | Node.js 20 and 24 for the bridge, any other core version |
| Counterpart for G2 | JavaScript persistent packages built from this tree (versions in section 3) | any published version (none is published) |
| AWS KMS | `us-east-1`, two `SYMMETRIC_DEFAULT` keys, one run | other regions, multi-Region keys, throttling |
| CI | `ci` jobs `python` (3.10, 3.12, 3.13), `python-wheel`, and `python-postgres` (3.11, 3.12 on a `postgres:17` service container) are defined in `.github/workflows/ci.yml` | **None has run on GitHub Actions**: nothing was pushed |

A claim names cells; a cell not in the "Run" column is not claimed.

## 5. What was not run, failed, or was skipped

| Item | State |
| --- | --- |
| Two hosts with separate clocks | **NOT RUN.** Clock skew was simulated by the caller's `now` against one database clock |
| PostgreSQL synchronous standby, failover, backup and recovery runbooks, `acknowledge_identity_change` | **NOT RUN** for Python. The adapter implements them (`acknowledge_identity_change`, `invalidate_recovered`); only `invalidate_recovered` and the namespace-identity check are exercised, by the schedule corpus and `test_a_namespace_recorded_by_another_database_identity_reads_as_quarantined` |
| A process killed after `COMMIT` reached the server, before the acknowledgement was read | **NOT RUN** as a process kill; the TCP relay of 4.3 withholds the acknowledgement instead |
| G6 server leak tests over the PostgreSQL adapter, and a sweep of every schedule case with logging at `DEBUG` | **NOT RUN** |
| Bridge qualification: adversarial protocol run, fuzzing, supported operating systems, Windows | **NOT DONE**, by decision |
| `verify_vectors.py` and the vectors on Linux x86-64, Windows | **NOT RUN** (the vectors ran on macOS arm64 and, inside the packed-wheel runs, on Linux aarch64) |
| AWS KMS throttling, other regions, multi-Region keys | **NOT RUN** |
| Performance of the adapter or the provider | **NOT RUN** (nothing was measured beyond the seal and open time in the decision record) |
| Mixed-language runs of whole-request atomicity, create against fence, restart, process kill, and clock skew | **NOT RUN** (run for two Python processes only) |
| A cross-language restore of a payload that carries a `policyRevision` | **NOT RUN** |
| Mutation controls for the JavaScript side of the shared corpus | **NOT RUN** (the two gaps found in 4.7 are likely to exist there; not checked) |
| GitHub Actions | **NO JOB HAS RUN.** `python-postgres`, `python-wheel`, and the extended `python` job are defined, not executed |
| Skips | The 14 corpus skips (10 + 2 lane, 2 `requiresSharedRealm`) in each parity run; the 12 or 7 schedule skips with their stated reasons (4.3); one lowered-bounds schedule case; the real-KMS tests skip with their reason when no key is configured |
| Failures found and fixed during this work | The two escaped mutants (4.7); three wheel-cell tests that read the checkout (4.8); two Linux budget runs (4.8); the isolation script on a host without `libpq` (4.8); 30 differences in the first JavaScript parity run (4.5, section 6) |

## 6. Differences between the JavaScript and Python servers (carried from #18)

[The reconciliation of #3 and #15 to #18](server-epic-reconciliation.md) listed eight differences between the JavaScript and Python servers that no current document stated, and left #18 open for them. They were written before the Python persistent profile existed. This section brings each one up to date against the code and the runs of this record. A "now" below is a statement about the **Python persistent profile**; the Python in-memory server `InMemoryVaultServer` is unchanged by this work and keeps the behavior the reconciliation describes. Whether any difference is intended, or a defect, is still the maintainer's decision: the table records what is true, it does not decide.

| # | Topic | JavaScript | Python in-memory server (unchanged) | Python persistent profile (this work) | Evidence |
| --- | --- | --- | --- | --- | --- |
| 1 | **Source of `policyRevision`** (#18) | Stamped at capture from the server option (`policyRevision`, a string or a function) and echoed on every decision tuple; the caller cannot supply it. Persistent profile: the same option, stored in the encrypted payload | A field of `RestoreRequest`, supplied by the caller on each restore and passed to the policy (`types.py`, `server.py`) | **Aligned with JavaScript.** The server option `policy_revision` (string or callable), stamped at capture into the payload, echoed in the decision input; no restore request field carries it. A callable that changes between the policy decision and the commit denies `stale-policy` | `server.py` (`policy_revision` in `create_persistent_server_vault`, `_revision`, the capture stamp, the decision input); `server.ts` (`policyRevision`); the payload vectors carry the field. **NOT RUN:** a cross-language restore whose payload carries a revision (the interop runs use no revision) |
| 2 | No policy configured | A construction error | Constructible; every restore then denies `policy` | **Aligned with JavaScript.** `policy` and `lifecycle_policy` are required callables; anything else is `INVALID_ARGUMENT` at creation | `server.py` (`_open` argument checks) |
| 3 | Concurrent calls on one instance | In-memory: queued first in, first out. Persistent: concurrent, ordered by the store | One operation at a time; a second call fails `BUSY`; not thread-safe | **Aligned with the JavaScript persistent profile.** Concurrent operations on one instance are allowed and ordered by the store; no `_busy` flag. 50 concurrent restores from one process, and 100 from two processes of two languages, committed exactly `max_uses` | [G4](#44-g4-two-process-cases), [G2](#42-g2-interoperation) |
| 4 | Persistent profile | `@redact-secret/vault-server/persistent` (alpha, published 2026-10-02) | None | **Exists in the tree, not on PyPI, not supported.** This record | [section 2](#2-result-by-gate) |
| 5 | Order of PII unavailability | Activation observed when the server is created, before any scan | Checked after the first scan of each call | **Aligned with JavaScript for the persistent profile.** `expected_pii_activation` is required (JavaScript: optional); the server scans the empty string when it is created and compares the identity the core reports, and compares again on every capture. A mismatch is `PII_ACTIVATION_MISMATCH` and nothing is stored | `test_persistent_server.py`; [G5](#45-g5-pii-and-capture-parity) |
| 6 | Core realm | One process-wide realm | One realm per `NodeCoreBridge` process | **Unchanged.** One realm per bridge, so the corpus cases marked `requiresSharedRealm` are skipped in Python (2 cases in each lane) | [G5](#45-g5-pii-and-capture-parity) |
| 7 | Revoked-token reporting | Vault level `unknown-token`; server `revoked` | Server level only, so two corpus expectations are overridden | **The persistent profile reports `revoked`, as the JavaScript persistent server does.** A capture revoked by one language is denied `revoked` by both. The shared corpus is not run through the persistent restore path | [G2](#42-g2-interoperation) (`test_a_capture_revoked_by_the_other_language_is_denied_revoked_by_both`) |
| 8 | Preflight-order evidence | Two dedicated tests (in-memory server) | None | **Present for the persistent profile** (`test_the_denials_of_step_four_come_in_the_specified_order`). Still none for the in-memory server | `test_persistent_server.py` |

Differences found while running the persistent profiles against each other, which no earlier document states:

| # | Topic | JavaScript persistent | Python persistent | Evidence |
| --- | --- | --- | --- | --- |
| 9 | Error code of a vault failure at capture | `VAULT_FAILURE` with the vault's own code beside it (`vaultCode`, and `coreCode`) | The vault's own code (`BLOCKED_FINDING`, `LIMIT_EXCEEDED`, `UNREDACTED_FINDINGS`, `TOKEN_LITERAL_IN_INPUT`, `INVALID_ARGUMENT`, `PII_UNAVAILABLE`), not wrapped | [decision record, item 10](../decisions/python-persistence-api-and-packaging.md); the parity test maps one to the other, and the first run of it failed on exactly this until it did |
| 10 | `expected_pii_activation` | Optional | Required | same |
| 11 | Capture limits and the clock | `max_entries`, `max_retained_bytes`, and `vault_ttl_ms` bound one capture, a negative clock reading is refused | The same | The capture parity run (92 passed, no difference in outcome on any capture step of the corpus) |
| 12 | Redacted text of a finding that is not retained | The core's formatter | `<SECRET_n>` | Plan 2.1. **Not observed** on the corpus: the comparison replaces tokens by position and found no difference. Not separately exercised |

What would still make #18 complete is the list in the reconciliation, items (a) to (e). This record supplies evidence for (c) and (d) for the persistent profile only.

## 7. What this record supports

This record is the only document that may state support for a Python persistence cell, and it states **none**: [section 2](#2-result-by-gate) shows gates that are not passed in full. What the record lets other documents say, and no more:

- The Python distribution's source tree contains persistent modules (`persistent`, `crypto`, `stores.postgres`, `keys.aws_kms`) behind the `crypto`, `postgres`, and `aws-kms` extras. They are not on PyPI, in the tree only. The published `0.1.0b3` does not contain them.
- Against the cells named in section 3, and only those, these runs passed: the shared vectors; mixed-language interoperation with the JavaScript persistent server on one PostgreSQL 17.11 database, in both directions, including lifecycle and negative cases; the schedule corpus through a Python driver against the Python reference store and the Python PostgreSQL adapter; the two-process cases with real operating-system processes on one host; capture parity with the in-memory server and with the JavaScript persistent server on the shared corpus; the diagnostics runs listed in 4.6; and the 31 named mutation controls.
- One data key wrapped by the JavaScript AWS KMS provider was unwrapped by the Python provider, and one wrapped by the Python provider was unwrapped by the JavaScript one, against real keys in `us-east-1`. One run, one region, one key spec.
- The core bridge is not qualified. A capture in these runs went through `NodeCoreBridge` as a test fixture. Any deployment claim is for an application-supplied, separately qualified `CoreClient` ([decision](../decisions/limit-python-persistence-claim-to-a-supplied-core-client.md)).
- Not run, so not stated: Windows and macOS CI, Linux x86-64, free-threaded or PyPy interpreters, Python 3.10 for the persistent modules (the modules refuse to import on it, and the tests are not collected), a PostgreSQL with a synchronous standby, failover, a connection pooler, managed PostgreSQL, two hosts, power loss, throttling by AWS KMS, any region or key type but the one named, and any CI job on GitHub Actions (the jobs are defined; none has run).
- At-rest statements are about the store. They say nothing about plaintext that lives in the Python process, in the bridge's Node.js heap, in logs of libraries the application enables (section 4.2 shows `botocore` at `DEBUG` writing the data key), or in memory the interpreter cannot clear (plan 3.6).
