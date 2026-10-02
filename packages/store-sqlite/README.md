# @redact-secret/store-sqlite

A SQLite store for the [persistent vault server](../../docs/guides/persistent-server.md): one database file on a local file system, opened by one or more server processes **on the same host**. It holds ciphertext, wrapped keys, counters, and receipts. It never decrypts, holds no key, and evaluates no policy.

**Alpha, and not yet a supported profile.** The shared conformance suite, two server processes on one file, process kills around commit, and backup and restore were run (see the [qualification record](../../docs/research/qualification-store-sqlite-0.1.0-alpha.1.md)). **A power-loss simulation was not run**, so nothing here claims the store survives power loss. The record states what was run, on what, and what was not.

## Use

The package imports no SQLite driver. You install one, load it, and pass it in. Two are supported:

| Driver | Install | Notes |
| --- | --- | --- |
| `better-sqlite3` `^12.11.1` | `npm install better-sqlite3` | A native addon, with an install script. Bundles SQLite 3.53.2 (12.11.1). Node.js 20, 22, 24 |
| `node:sqlite` | Nothing | Built into Node.js 22 and later, experimental. It bundles whatever SQLite that Node.js release carries, so it is usable only where that is 3.51.3 or later: measured **22.22.3 and later 22.x (22.22.2 has 3.51.2), 24.15.0 and later 24.x (24.14.1 has 3.51.2), and 25.9.0**. Node.js 20 has none. Other releases are not measured |

```js
import Database from "better-sqlite3"; // or: import * as sqlite from "node:sqlite";
import { betterSqlite3Driver, createSqliteStore, migrate, nodeSqliteDriver } from "@redact-secret/store-sqlite";

const driver = betterSqlite3Driver(Database); // or: nodeSqliteDriver(sqlite)

// Once, before any server starts. Creates the file and the tables, and puts the file in WAL mode.
await migrate({ driver, filename: "/var/lib/vault/vault.sqlite" });

// In every server process, on the same host:
const store = await createSqliteStore({ driver, filename: "/var/lib/vault/vault.sqlite" });
```

Without a usable `driver` the store throws `STORE_INVALID_ARGUMENT`. The startup checks below apply to both drivers alike.

`createSqliteStore` refuses to return a store unless:

- the SQLite the driver loaded is 3.51.3 or later, or carries the backported fix (3.44.6 or later in its line, 3.50.7 or later in its line), because of a WAL corruption bug documented at [sqlite.org/wal.html](https://www.sqlite.org/wal.html) that needs two connections to write at the same instant;
- `journal_mode=WAL` with `synchronous=FULL` (or, with `journalMode: "delete"`, `DELETE` with `EXTRA`) is in effect, read back after it was set, and checked again in every transaction;
- `busy_timeout` is set to a finite value;
- foreign keys are enforced, `locking_mode` is `NORMAL`, and on macOS `fullfsync` is on;
- the file exists and has this adapter's schema version;
- the restore marker file, if used, can be written.

The error is `STORE_CAPABILITY` and says nothing about which check failed. `checkDeployment({ driver, filename })` runs the same checks and returns the names of the ones that failed.

| Option | Default | Meaning |
| --- | --- | --- |
| `driver` | required | `betterSqlite3Driver(...)` or `nodeSqliteDriver(...)` |
| `filename` | required | The database file. In-memory, temporary, `file:` and empty names are refused. It is canonicalized, so a symlink and its target are one database |
| `journalMode` | `"wal"` | `"wal"` (with `synchronous=FULL`) or `"delete"` (with `synchronous=EXTRA`) |
| `busyTimeoutMs` | `5000` | How long a statement waits for another connection's write lock. 1 to 60 000. Keep it below the server's `storeTimeoutMs` (default 10 000) |
| `maxClockSkewMs` | `2000` | Largest accepted difference between the host clock and a caller's `now`. 0 to 60 000 |
| `restoreMarker` | beside the database | Path of the restore tripwire's marker file, or `false` to keep only the process-local high-water mark. See below |
| `maxCreateEntries`, `maxRestoreEntries`, `maxRestoreCaptures`, `maxEnvelopeBytes` | the contract ceilings | May only be lowered |
| `maxCreateBytes` | 16 MiB | Sum of envelopes in one capture. At most 256 MiB. One capture is one transaction that holds the only write lock; on the measured machine 16 MiB took about 0.1 s |

## The rules

- **One host, one local file system.** Not NFS, SMB, a shared volume mounted on several hosts, or any network file system, in any journal mode. SQLite documents that WAL does not work there and that locking can corrupt the file there. Passing tests on one is not evidence.
- **One path.** Every process names the database the same way. The store canonicalizes the path; do not also open it under another name.
- **No connection across `fork`.** Open the store in the process that uses it. A store used from another process throws `STORE_UNAVAILABLE`.
- **The driver is synchronous.** A write that has to wait for another process's write lock blocks this process's event loop for up to `busyTimeoutMs`, then fails `STORE_UNAVAILABLE` with nothing applied. This is a property of the profile, not a bug.
- **One writer at a time.** Throughput is one commit stream per file; each commit pays a sync. Measured figures are in the record, on one machine.
- **Backups only by the SQLite backup API, `VACUUM INTO`, or `sqlite3_rsync`.** Never copy the main file alone while the database is in use: committed transactions can still be in the `-wal` file.
- **Restoring a backup is a rollback.** Follow the [recovery runbook](../../docs/specs/persistent-operations.md#5-backup-recovery-runbook). The store's tripwire is a guard against a skipped step, not a replacement for it, and it does not cover every case. See [restore detection](../../docs/reference/store-sqlite.md#restore-detection).
- **Schedule cleanup.** Call `store.sweepExpired({ namespace, now, limit })` on a timer and repeat while it returns `more: true`. Deleted rows stay in free pages, the WAL, and earlier backups until overwritten or vacuumed: deletion here is not erasure.
- **Trust the host clock.** The store reads the host clock inside its transaction, and every server process of the host shares it. A host clock set back extends lifetimes by that amount and nothing in the system detects it.

## More

The [reference](../../docs/reference/store-sqlite.md) covers the profile, the schema, transactions and outcome mapping, restore detection and its blind spots, limits, the driver choice, and how to run the tests.

## License

MIT
