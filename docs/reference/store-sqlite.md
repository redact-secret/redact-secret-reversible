# `@redact-secret/store-sqlite` reference

The profile, startup checks, schema, transactions, recovery, and limits of [`@redact-secret/store-sqlite`](../../packages/store-sqlite/README.md). Setup and options are in the package README. The research it implements is [section 8.1 of the backend research](../research/persistent-backend-capabilities.md); the evidence is in the [qualification record](../research/qualification-store-sqlite-0.1.0-alpha.1.md).

**Status: alpha, unpublished, and not a supported profile.** Four of the five run gates of [#130](https://github.com/redact-secret/redact-secret-vault/issues/130) were run on one machine; the power-loss simulation was **not run**. The store declares `durability: "durable"` for the verified configuration because the persistent server requires the declaration; that declaration rests on SQLite's documentation of `synchronous=FULL` and on process-kill tests, and on no power-loss evidence.

## Profile

| Profile name in `capabilities().profile` | Settings, verified at startup | Notes |
| --- | --- | --- |
| `sqlite-local-wal/synchronous=FULL` (default) | `journal_mode=WAL`, `synchronous=FULL` | Readers are not blocked by a writer. Needs shared memory, so every process must be on the same host |
| `sqlite-local-delete/synchronous=EXTRA` (`journalMode: "delete"`) | `journal_mode=DELETE`, `synchronous=EXTRA` | Slower; a writer blocks readers. Equal standing in the research. Ran only through the startup and one create test; the conformance suite, process tests, and kill tests ran on WAL |

Not offered, and refused or absent by design: any network file system in any journal mode; `synchronous=NORMAL` or `OFF`; `journal_mode=MEMORY` or `OFF`; multi-host access; in-memory and temporary databases.

`crossProcess: true` means processes of this host. It is not multi-host. `storeClock: true` means the host clock, read inside the transaction.

## The driver

`better-sqlite3`, as an optional peer dependency (`^12.11.1`) that only this package names. The reason is in the [decision record](../decisions/choose-sqlite-driver.md): Node.js 20 has no `node:sqlite`, and the `node:sqlite` of the Node.js 22.16.0 measured here bundles SQLite 3.49.1, which the version check refuses. `better-sqlite3` 12.11.1 bundles SQLite 3.53.2. The base packages (`vault`, `vault-server`, `vault-contracts`, `vault-crypto`, `vault-conformance`) name no driver; `npm run check:persistence-boundaries` checks that on the packed tarballs, and checks that this package's only peer is the optional `better-sqlite3`.

### The driver is synchronous

Every store call runs its transaction to completion in the calling thread. When another process holds the write lock, `BEGIN IMMEDIATE` waits inside SQLite, and that wait blocks this process's event loop for up to `busyTimeoutMs` (default 5000), after which the call fails `STORE_UNAVAILABLE` with nothing applied. With one process on the file the wait never happens. With several processes, every write can stall every request in the waiting process for as long as another process's transaction lasts. Measured transaction times are in the [record](../research/qualification-store-sqlite-0.1.0-alpha.1.md#3-limits-measured). Do not set `busyTimeoutMs` above the server's `storeTimeoutMs` (10 000): the server's timeout cannot fire while the thread is blocked.

## Startup verification

`createSqliteStore` opens a connection, sets the pragmas below, reads each back, and refuses (`STORE_CAPABILITY`) on any mismatch. `checkDeployment` runs the same checks and returns the failed check names. Nothing in the error names a path, a value, or a driver message.

| Check name | Requirement |
| --- | --- |
| `sqlite-version` | `sqlite_version()` of the connection is 3.51.3 or later, or 3.44.6 or later in the 3.44 line, or 3.50.7 or later in the 3.50 line (the backports of the WAL fix named in the research). 3.45 to 3.49, 3.50.0 to 3.50.6, and 3.51.0 to 3.51.2 are refused. The backports were not run here: the rule is tested as a function over version strings only |
| `journal-mode` | `wal` (or `delete` with `journalMode: "delete"`), read back after `PRAGMA journal_mode` |
| `synchronous` | `2` (FULL) for WAL, `3` (EXTRA) for DELETE |
| `busy-timeout` | Equals the configured finite value, 1 to 60 000 ms. Zero and unbounded values are refused before any connection is opened |
| `foreign-keys` | On. Entries reference their capture |
| `locking-mode` | `normal`. An exclusive lock would shut out every other process |
| `fullfsync` | On macOS only: `fullfsync` and `checkpoint_fullfsync` are on, so a sync reaches the device rather than its cache |
| `schema` | `rsv_meta` holds the version this adapter was built for. A missing file or an unmigrated one is refused, and the store never creates a file: `migrate` does |
| `pragma` | Any other failure while applying the settings |

Also refused, as `STORE_INVALID_ARGUMENT`: an in-memory (`:memory:`), temporary (empty), or URI (`file:`) name, a name containing a NUL, and a journal mode other than the two above. A marker file that cannot be written is refused as `STORE_CAPABILITY`, so a tripwire that is declared is a tripwire that works.

`synchronous` is a per-connection setting, and `journal_mode` is persistent in the file and can be changed by another process. So every transaction reads both again and fails `STORE_UNAVAILABLE` if either is not the verified value. A connection used by a process other than the one that opened it (after a `fork`) fails the same way.

**One canonical path.** The path is resolved to its real name before it is opened, so a symlink and its target are one database, and the marker file is derived from the real name. SQLite documents that two names for one file mean two journals and undefined behavior.

**What is not checked.** That the file system is local and honors sync. SQLite cannot test for it either, and says that passing tests on a network file system is not evidence. That is the operator's requirement.

## Transactions and outcomes

- **Every mutation is `BEGIN IMMEDIATE … COMMIT`.** The writer role is taken before anything is read, so the checks of a restore or a creation and its writes see one state and no other connection can commit between them. `BEGIN DEFERRED` is never used for a write: its read-to-write upgrade can fail after reads the transaction already depended on. A test records every statement text the adapter sends for each of the thirteen operations and fails on any other form.
- **Reads** run in one explicit `BEGIN … COMMIT`: under WAL one snapshot, under a rollback journal a shared lock for its duration. `readEntries` returns entries, captures, and the recovery state from the same snapshot.
- **The conflict rule (specification §5.2) is met by the one-writer rule, and is stricter than the specification.** Commits in one namespace serialize against each other because SQLite has no row locks. That is a throughput property. `stale` arises only from a changed generation or revision, never from lock contention: the contention case is below.

| Event | Outcome |
| --- | --- |
| `BEGIN IMMEDIATE` cannot get the write lock within `busyTimeoutMs` | `STORE_UNAVAILABLE`, nothing attempted |
| Any failure after `BEGIN` and before `COMMIT` is sent, including a cancelled call checked before the transaction | `ROLLBACK`, then `STORE_UNAVAILABLE` (or the contract's `STORE_INVALID_ARGUMENT` / `STORE_CAPABILITY` where the body raised one). Nothing applied |
| `COMMIT` fails, the transaction is still open, and `ROLLBACK` succeeds | `STORE_UNAVAILABLE`: definitely no effect |
| `COMMIT` fails and the transaction is gone, or `ROLLBACK` fails | `STORE_AMBIGUOUS`, never retried. The connection is closed if a transaction is still open on it, so a transaction nobody can finish does not hold the write lock against every other process. The application opens a new store, then resolves the attempt through its receipt |
| Process killed before `COMMIT` | Nothing applied (SQLite's crash recovery, shown by the kill tests) |
| Process killed after `COMMIT`, before the reply | Applied. The receipt resolves it |

A call is not cancellable once its transaction has begun: it is synchronous. `signal` is honored before the call starts only.

## Schema

`migrate({ filename })` creates schema version 1 in `STRICT` tables and sets the journal mode: `rsv_meta`, `rsv_namespace`, `rsv_capture`, `rsv_entry`, and `rsv_receipt`, with the same columns as the [PostgreSQL schema](store-postgres.md#schema-and-migrations) and two additions in `rsv_meta`: a random `database_id` and a `counter` that every write transaction increments (restore detection, below). It is idempotent, keeps `database_id`, `counter`, and every row, and is forward-only: a store refuses a schema version it was not built for, in either direction.

No column holds a plaintext value, token, key, grant, finding type, principal, or session identifier ([specification §3.7](../specs/persistent-vault.md) lists what stays visible). Every statement binds its values as parameters.

## Clock

The store reads the host clock inside each transaction (`unixepoch('subsec')`, through the SQLite VFS), and rejects `clock-skew` when a caller's `now` differs by more than `maxClockSkewMs`. Because every server process is on the same host, the store's clock and the default server clock are the same source. The skew check therefore only detects an injected `now` that disagrees with the host. Of the two cases of specification §7.5, "only the store's clock is set back" cannot happen. **A host clock set back extends every lifetime by that amount, and nothing in the system detects it.** Trustworthy time on the host is a requirement.

## Limits

- The contract ceilings are 1024 entries per create and per restore, 64 captures per restore, and an envelope of 1 MiB + 64 KiB. They fit within SQLite's limits (no statement binds more than 1024 parameters of its own).
- `maxCreateBytes` defaults to **16 MiB**. One capture is one transaction that holds the only write lock, so the figure bounds how long other writers wait. On the one machine measured, creating 16 MiB took about 0.1 s and 64 MiB about 0.4 s ([measurements](../research/qualification-store-sqlite-0.1.0-alpha.1.md#3-limits-measured)). A deployment should measure its own storage; it can lower the value and may raise it to 256 MiB.
- One writer at a time. Throughput is one commit stream per file, and each commit pays a WAL sync.

## Restore detection

`capabilities().restoreDetection` is `"sqlite-counter-high-water-mark-and-marker-file"` by default and `"sqlite-process-high-water-mark"` with `restoreMarker: false`. The honest statement is narrow: **a backup made by any documented route is a faithful copy, so nothing stored inside the file can tell it from the original.** The adapter keeps two witnesses outside the contents of the database file and compares them with a counter inside it.

- **The counter.** `rsv_meta.counter` rises by one in every committed write transaction. A rejected transaction is rolled back, counter included.
- **The process-local high-water mark.** Each process remembers the highest counter it has seen for a canonical path, as long as it lives. A store opened again, in the same process, on a file that was replaced by an older copy sees a counter below its mark.
- **The marker file.** After every write commit the store records `{ databaseId, counter }` in `<database>.rsv-marker` (or the path in `restoreMarker`), replacing it atomically and never lowering it. It is advisory and written after the commit, so a crash between the two leaves it behind the database, which cannot cause a false alarm.

When the database's counter is below a witness, or its `database_id` is not the one the witness saw, or the marker file exists and cannot be parsed, **the store reads every namespace as `quarantined`**: creations and commits are rejected, revocation still works. `invalidateRecovered` ends it: it sets the new epoch and makes the file's present counter the baseline of both witnesses, in the same operation that revokes every earlier capture. Other processes that had seen a higher counter stay quarantined until they are restarted, which is what the runbook's first step already requires.

| Situation | Noticed with no operator action |
| --- | --- |
| Older copy placed at the path; a **new process** starts; the marker file is **not** restored with it | **Yes**: shown for backups made by the backup API, `VACUUM INTO`, and a file copy after a `TRUNCATE` checkpoint |
| Older copy placed at the path; a **process that outlived the replacement** opens the file again; marker or none | **Yes**, by its high-water mark |
| A different database (another `database_id`) placed at the path, marker file kept | **Yes** |
| Older copy placed **together with the marker file from the same backup**, and no process outlived the replacement | **No.** Shown: the single-use value consumed after the backup was released again. The runbook is the only control |
| Marker file deleted, and no process outlived the replacement | **No**, by construction; not run |
| Marker file present but unparseable | **Yes**, read as a rollback signal: every namespace quarantined until `invalidateRecovered` |
| Copy of the main file alone while the database is live (an older database by itself, because the `-wal` file held commits) | Looks like any older copy; as above |
| Rows restored selectively into a live database | **Not tested** |
| A party that can write both the database and the marker file | **No.** This design does not claim to detect a malicious rollback |

Place the marker outside the backup set (`restoreMarker`, on a volume that is not restored with the database) or it adds nothing for a whole-directory restore. The tripwire is a guard against a skipped runbook, not a replacement for it.

## Backup and recovery

**Routes that are safe for a live database**, each restored and checked in the tests: the SQLite backup API (`db.backup()` in `better-sqlite3`), `VACUUM INTO`, and a file copy **after** `PRAGMA wal_checkpoint(TRUNCATE)` completed with no other connection active. `sqlite3_rsync` is named by the research and **was not run**. A copy of the main file alone while the database is in use is shown by a test to be an older database: committed transactions can still be in the `-wal` file, which must be copied with it. `VACUUM INTO` also purges deleted content from the copy, as the research notes.

Replacing the database file with a backup is a silent rollback. **Run the [recovery runbook](../specs/persistent-operations.md#5-backup-recovery-runbook)**: stop every server of the namespace first, open a store on the recovered file with a maintenance process, `quarantine` and `invalidateRecovered` with a higher epoch for each namespace (`SELECT namespace, epoch, state FROM rsv_namespace` lists them), start servers with the new epoch, and capture again from the sources. Shown at the store level for all three backup routes: after the runbook every recovered capture was `revoked`, including one the backup held with a use left, and new captures under the new epoch worked. Shown through the persistent server for the backup-API route: a server configured with the old epoch refused to start (`STORE_QUARANTINED`), a restore of a recovered token was denied `revoked`, and capturing again worked.

## Cleanup and erasure

Call `sweepExpired` on a timer, repeating while `more` is true. It is a bounded delete in its own `BEGIN IMMEDIATE` transaction. Deleted rows remain in free pages, the WAL, and every earlier backup until overwritten or vacuumed. Deletion here is not erasure ([specification §9](../specs/persistent-vault.md)). Keep read transactions short: under WAL a long reader keeps the checkpoint from resetting the WAL, which then grows. The default auto-checkpoint is left on; an optional periodic `PRAGMA wal_checkpoint(TRUNCATE)` from a maintenance process bounds the file. Durability under `FULL` does not depend on checkpoints.

## What the file and its neighbors expose

The database holds the metadata of [specification §3.7](../specs/persistent-vault.md): identifiers, counters, times, key references, wrapped keys, and ciphertext. The `-wal` and `-shm` files and any backup hold the same. The marker file holds a database identifier and a counter. Give the directory and files owner-only permissions; the adapter writes the marker with mode `0600` and does not change the database file's mode. No statement text is logged by the adapter, and its errors carry no path.

## Not covered

- Network file systems, in any journal mode. Multi-host access. Replication tools.
- `synchronous=NORMAL`/`OFF`, `journal_mode=MEMORY`/`OFF`, `locking_mode=EXCLUSIVE`.
- Power loss at the block device: **not simulated.** Behavior of a device that lies about sync is outside what SQLite or this adapter can detect.
- `sqlite3_rsync`, the SQLite backport releases 3.44.6 and 3.50.7 (the version rule is unit-tested; no such library was run), `better-sqlite3` 13.x, Windows, and any Node.js, platform, or file system the record does not list.
- A decision on the unverified point the research leaves open about `fullfsync`: the adapter turns it on for macOS and reads it back; what that costs, and whether the documentation's wording on it holds, was not measured against a device.

## Running the tests

```sh
npm run test:sqlite                         # builds, then runs the package's tests
node packages/store-sqlite/qualification/measure-limits.mjs   # the measurements in the record
```

No service is needed: the databases are temporary files. `RSVQ_TRIALS` sets the number of race trials in the two-process test (default 25). The tests use unmistakably synthetic values and generated key material, and print no restored value.
