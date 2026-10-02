# Qualification record: `@redact-secret/store-sqlite` 0.1.0-alpha.1

**Status: partial, and the profile is not supported.** This record covers [#130](https://github.com/redact-secret/redact-secret-vault/issues/130), the `sqlite-local-wal` profile of the [backend research](persistent-backend-capabilities.md) (section 8.1). Run on 2026-10-01 on one machine. The package was published as `0.1.0-alpha.1` on 2026-10-02 (dist-tag `alpha`), after this record's runs; the registry tarball was not run through these gates. **The power-loss simulation required by the issue was not run, and the Node.js 20 run, the better-sqlite3 runs on Node.js 20, 24, and 25, and every Linux run have not happened.** Nothing here is a support claim. A profile is supported only when a record says every gate was run and passed; this one says otherwise.

## 1. Gates of the issue

| Gate | Result | Evidence |
| --- | --- | --- |
| Shared Store conformance suite of `@redact-secret/vault-conformance`, zero unexplained skips | **Run, passed.** 108 cases on the host clock (97 passed, 11 skipped) and the same 108 with a controlled clock (108 passed). Every skip is the documented one: the store clock cannot be moved on the host-clock run, and a test checks mechanically that each skipped case passed in the controlled-clock run | `packages/store-sqlite/test/conformance.test.mjs` |
| Two-connection schedules of specification §5.2 | **Run, passed**, in both runs (five schedules each: a revocation between a restore's read and commit; a quarantine between a creation's check and commit; a quarantine and an invalidation between a restore's read and commit; a fence between a creation's check and commit). The second connection lives in a worker thread, because the driver is synchronous; the primary call is held at its last statement before `COMMIT` while the competing call runs | `test/conformance.test.mjs`, `test/helpers.mjs` |
| Two independent server processes on one file: concurrent restore, restore against revoke, duplicate attempts | **Run, passed** (9 tests; 25 trials of each race): capture in one process and restore in another; 100 concurrent restores of a single-use token split across two processes, exactly one value returned and one receipt; repeated tokens across fields; a three-entry restore racing a one-entry restore, never partial; restore racing revoke with restores started after the revocation was acknowledged, none succeeded; creation racing a fence of the same identifier; the same attempt from both processes, committed once; an attempt reused for a different request; a writer that cannot get the lock within its busy timeout | `test/two-process.test.mjs` |
| Power-loss simulation at the block device | **NOT RUN.** No device-level fault injection is available in this environment, and none was built | The `durability: "durable"` declaration of the store rests on SQLite's documentation of `synchronous=FULL` in WAL mode ([research S3](persistent-backend-capabilities.md#7-sqlite-evidence)) and on the process-kill tests below. It is not evidence about power loss |
| Process kill around commit | **Run, passed** (6 tests). `SIGKILL` inside the transaction before `COMMIT` and after `COMMIT`, for a creation, a restore, and a revocation: nothing applied before, applied whole after, the receipt resolves the attempt, `PRAGMA integrity_check` is `ok`. Five rounds of kills at random moments while 40 restores were in flight: every spent use has its receipt and every receipt its spent use | `test/process-kill.test.mjs`. This is application-crash evidence only. A killed process leaves the operating system's page cache intact, so it says nothing about what survives when the power goes |
| Backup by the SQLite backup API and by file copy, restored, with the recovery runbook: recovered captures must not serve | **Run, passed** (12 tests). Backup API, `VACUUM INTO`, and a file copy after a `TRUNCATE` checkpoint, each restored over the live file: quarantined by the tripwire in a new process, no commit or creation served, revocation still works; the runbook then invalidated every recovered capture (`revoked`, including one the backup held with a use left) and new captures worked. Through the persistent server (backup-API route): the old-epoch server refused to start, a recovered token was denied `revoked`, capturing again worked. `sqlite3_rsync`: **not run** | `test/backup-restore.test.mjs` |
| `restoreDetection` stated honestly | `"sqlite-counter-high-water-mark-and-marker-file"`: detects an older copy only where a process outlived the replacement or the marker file did not come back with it. **Shown not to detect** an older copy restored together with its marker file: a spent single-use value was released again | [Reference, restore detection](../reference/store-sqlite.md#restore-detection); the "NOT detected" test |
| Packed-artifact boundary check | **Run, passed**: `store-sqlite` has one dependency (`vault-contracts`, exact), no peer, imports only `vault-contracts`, `node:fs`, and `node:path` (no driver, not even dynamically), and calls no cipher; no base package names either driver | `qualification/check-persistence-boundaries.mjs` |
| Clean-consumer check | **Run, passed**: the packed store drove the persistent server flow (capture on one instance, restore on another, a second use denied `budget`, another tenant `unknown-token`, revoke, ciphertext deletion) over a SQLite file; a consumer that installed the store alone got `STORE_INVALID_ARGUMENT` when it passed no driver, and none was installed. The default run installs no driver anywhere; the flow ran over `better-sqlite3` only with `RSV_QUALIFY_BETTER_SQLITE3=1`, and over `node:sqlite` on Node.js 24.21.0. The base-package consumer installed no driver | `qualification/persistence-consumer.mjs` |

## 2. Tested matrix

| Component | Version |
| --- | --- |
| `@redact-secret/store-sqlite` | `0.1.0-alpha.1` |
| `better-sqlite3` (installed by the application; not a dependency or peer of the package; tested `12.11.1`, range `^12.11.1`) | `12.11.1`, from `qualification/sqlite-driver` |
| `node:sqlite` (built into Node.js) | Node.js 22.23.3 (SQLite 3.51.3), 24.21.0 (3.53.4), 25.9.0 (3.51.3). Measured minimums: 22.22.3, 24.15.0 ([decision record](../decisions/choose-sqlite-driver.md)) |
| SQLite, as `sqlite_version()` reports it through that driver | `3.53.2` |
| `@redact-secret/core`, `vault-server`, `vault-contracts`, `vault-crypto`, `vault-conformance` | As in the [persistence record](qualification-persistence-0.1.0-alpha.1.md#21-package-and-dependency-versions) |

| What ran | Where | Node.js | Result |
| --- | --- | --- | --- |
| `npm run test:sqlite` (`better-sqlite3`; `node:sqlite` skipped with its reason: SQLite 3.49.1) | Local, macOS 26.5.2 arm64 (Apple M4), a local volume (the temporary directory; file-system type not recorded) | 22.16.0 | 273 tests, 261 passed, 0 failed, 12 skipped: the 11 host-clock cases of section 1, and the one `node:sqlite` suite this Node.js cannot run |
| The same tests, `RSV_SQLITE_DRIVERS=node:sqlite`, binaries from the `node` package | Same machine | 22.23.3 (SQLite 3.51.3), 24.21.0 (3.53.4), 25.9.0 (3.51.3) | Each: 271 tests, 260 passed, 0 failed, 11 skipped (the host-clock cases). 22.22.2, 22.16.0, and 20.20.0 refuse or lack `node:sqlite`, and the harness skips with the reason |
| `npm run check:persistence-boundaries`, `npm run qualify:persistence` | Same | 22.16.0 | Passed (PostgreSQL consumer not run: no database configured). The default run installs no driver; with `RSV_QUALIFY_BETTER_SQLITE3=1` the flow ran over `better-sqlite3`, and on 24.21.0 over `node:sqlite` |
| Root `npm ci` | Same | 22.16.0 | Installs no `better-sqlite3` or `prebuild-install`: neither is in the root lockfile or `node_modules` |
| `npm run build`, `npm run lint`, `npm run check:boundaries`, `npm run check:links` | Same | 22.16.0 | Passed |
| `ci` job `sqlite node {20,22,24} ({ubuntu,macos}-latest)` | **Defined, not run.** No branch containing it has been pushed | 20, 22, 24 | Not run |

**Not run, for any gate:** Node.js 20; `better-sqlite3` on Node.js 24, 25, and 20; `node:sqlite` on any Node.js release not listed above; Linux; any file system but the local macOS volume; `journal_mode=DELETE` beyond a startup check and one create (the profile is accepted by the code, and no gate ran on it); SQLite releases 3.44.6 and 3.50.7 (the version rule is unit-tested as a function); `better-sqlite3` 13; Windows; a network file system (rejected by the research, not tried); a slow or lying storage device; checkpoint starvation and WAL growth under long readers; a database larger than a few hundred megabytes; a host clock set back.

## 3. Limits measured

`node packages/store-sqlite/qualification/measure-limits.mjs`, synthetic random bytes, one process, `sqlite-local-wal/synchronous=FULL` with `fullfsync` on, on the machine above. The figures describe that machine, that volume, and that run.

| One `createCapture` of | Entries | Median of 3 |
| --- | --- | --- |
| 1 MiB | 16 | 8 ms |
| 4 MiB | 64 | 35 ms |
| 16 MiB | 256 | 100 ms |
| 64 MiB | 1024 | 416 ms |
| 128 MiB | 1024 | 680 ms |

200 single-entry restores in a row, one connection: 4.2 ms each. One restore of 1024 entries: 12 ms. The default `maxCreateBytes` is **16 MiB**: a transaction that holds the one write lock for about a tenth of a second on this machine. The driver is synchronous, so another process's write waits in the busy handler, and its event loop with it, for that long. The figure is a default, not a recommendation for a particular deployment, and a deployment on other storage should measure its own.

## 4. Evidence index

| Claim | Test |
| --- | --- |
| Startup refuses an older SQLite, anything but WAL+FULL (or DELETE+EXTRA), an unbounded or zero busy timeout, a missing or unmigrated file, a memory or URI name, an unwritable marker; one canonical path | `test/startup.test.mjs` |
| Every mutation is `BEGIN IMMEDIATE`, every read a plain read transaction, none deferred; a rejection rolls back the counter too | `test/transactions.test.mjs` (statement log of all thirteen operations) |
| Failure before `COMMIT`: nothing applied. `COMMIT` failing with a clean rollback: `STORE_UNAVAILABLE`. `COMMIT` failing without a confirmed rollback: `STORE_AMBIGUOUS`, never retried, resolved through the receipt, connection closed so the lock is released | `test/transactions.test.mjs` |
| A writer that cannot get the lock fails after its busy timeout with nothing applied; a WAL reader is not blocked | `test/transactions.test.mjs`, `test/two-process.test.mjs` |
| Errors carry no path, driver text, input, or cause | `test/diagnostics.test.mjs` |
| No plaintext column in the schema | `test/startup.test.mjs` |

## 5. Remaining before this profile can be called qualified

1. A power-loss simulation at the block device, with its method and result recorded. Until then, the durability declaration is documentation-based.
2. The `sqlite` CI job run on Node.js 20, 22, and 24 on Linux and macOS, and its result recorded here.
3. `sqlite3_rsync` and the SQLite backports, if the profile is to name them.
4. A decision on whether `journal_mode=DELETE` with `synchronous=EXTRA` is offered: the code accepts it, and the gates above did not run on it.
5. The independent review that every persistence package still needs ([#112](https://github.com/redact-secret/redact-secret-vault/issues/112)), and first publication.
