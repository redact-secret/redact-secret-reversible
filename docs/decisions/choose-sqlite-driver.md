---
decision_id: decision-choose-sqlite-driver
status: accepted
scope: package
title: Support two SQLite drivers in @redact-secret/store-sqlite, injected by the application
decided_at: 2026-10-01
---
# Support two SQLite drivers in `@redact-secret/store-sqlite`, injected by the application

> **Accepted 2026-10-01** for `@redact-secret/store-sqlite` `0.1.0-alpha.1` ([#130](https://github.com/redact-secret/redact-secret-vault/issues/130)). It chooses how the store gets a driver. It does not qualify the SQLite profile: the [qualification record](../research/qualification-store-sqlite-0.1.0-alpha.1.md) states what was run and what was not. It revises this record's first version, which chose `better-sqlite3` alone as an optional peer loaded by the store.

## Context

The [backend research](../research/persistent-backend-capabilities.md) (section 8.1) proposes the `sqlite-local-wal` profile and requires SQLite 3.51.3 or later, or a release carrying the backported fix, because of a WAL corruption bug that two connections writing or checkpointing at the same instant can trigger. The adapter checks `sqlite_version()` of the connection it is given, so the SQLite a driver brings is a requirement, not a detail. The repository supports Node.js 20, 22, and 24 (`engines`). The dependency rule of [the specification](../specs/persistent-vault.md) (section 2) allows a store package to own its driver and no other package to name one.

Two drivers exist for Node.js.

| | `node:sqlite` | `better-sqlite3` |
| --- | --- | --- |
| Present on Node.js 20 | No (`process.versions.sqlite` is undefined on 20.20.0) | Yes (12.11.1 `engines` lists 20, 22, 23, 24, 25, 26) |
| SQLite version | The one the Node.js build bundles (table below) | The one the package bundles. **Measured with 12.11.1: 3.53.2** |
| Stability | Prints an `ExperimentalWarning` | A long-lived package; a native addon |
| Installation | Nothing to install | A prebuilt binary downloaded at install, or a build from source, by an install script (`prebuild-install`, with a `node-gyp` fallback) |
| Who controls the SQLite version | The Node.js release the application runs | The package version the application pins |

`process.versions.sqlite`, measured by running each Node.js binary (installed from the `node` package, macOS arm64):

| Node.js | SQLite |
| --- | --- |
| 20.20.0 | none |
| 22.16.0 | 3.49.1 |
| 22.22.0 | 3.50.4 |
| 22.22.1, 22.22.2 | 3.51.2 |
| **22.22.3**, 22.23.0, 22.23.3 | 3.51.3 |
| 24.14.1 | 3.51.2 |
| **24.15.0** | 3.51.3 |
| 24.16.0 | 3.53.0 |
| 24.21.0 | 3.53.4 |
| 25.9.0 | 3.51.3 |

The first Node.js release with SQLite 3.51.3 or later is therefore **22.22.3** in the 22 line and **24.15.0** in the 24 line (the release before each was measured and is below). For 25 only 25.9.0 was measured; earlier 25.x releases are **not verified**. The Node.js changelog was not consulted: these are measurements of installed binaries.

## Decision

- **Both drivers are supported, behind one thin interface.** `SqliteDriver` is `{ name, open(path, { fileMustExist, busyTimeoutMs }) }`, returning a connection with `prepare`, `exec`, `close`, and `inTransaction` (the part of `better-sqlite3` and `node:sqlite` the adapter uses). `betterSqlite3Driver(Database)` and `nodeSqliteDriver(sqliteModule)` wrap the two.
- **The application injects the driver.** The store imports no driver, not even dynamically, and declares no peer dependency. The application installs and loads one and passes it as `driver` to `migrate`, `createSqliteStore`, and `checkDeployment`; without one the store throws `STORE_INVALID_ARGUMENT`. The packed-artifact check enforces it: the store imports only `vault-contracts`, `node:fs`, and `node:path`, and no other package may name either driver.
- **The version check is common.** The adapter reads `sqlite_version()` from the connection and accepts 3.51.3 or later, or the backports 3.44.6 and 3.50.7 or later in their own lines, whichever driver supplied it. A `node:sqlite` on a Node.js whose SQLite is older is refused at startup (`STORE_CAPABILITY`), as `better-sqlite3` would be if it bundled an old SQLite.
- **`node:sqlite` needs `isTransaction`.** The store must know whether a transaction is still open after a failed `COMMIT`. `nodeSqliteDriver` refuses a connection that does not report it.
- **`better-sqlite3` is installed only where it is tested.** It is not a dependency of any workspace and is absent from the root lockfile, so `npm ci` in every other job installs no native addon and runs no install script. It is installed by `npm run install:sqlite-driver` into `qualification/sqlite-driver`, a directory outside the workspaces with its own `package.json` (exact version) and `package-lock.json` (integrity). The `sqlite` job of `ci.yml` and the `sqlite` job of `release.yml` run that step, with `contents: read` only; the `publish` job does not.
- **The range stops at 12 for `better-sqlite3`.** 13.x declares `node >= 22`, which would exclude Node.js 20. It is widened only after a version that supports every Node.js in `engines` is tested.

## Consequences

- The application owns the driver, its install script, and its upgrades. A consumer that wants `better-sqlite3` reviews and allows its install script; one that uses `node:sqlite` installs nothing.
- `node:sqlite` is experimental in the Node.js releases that have it, and which Node.js minor an application runs decides whether the store may start. The startup check makes that a refusal, not a silent risk.
- The driver is synchronous in both cases. A write that waits for another process's write lock blocks the event loop of its own process for up to `busyTimeoutMs`. This is documented in the [reference](../reference/store-sqlite.md#the-driver-is-synchronous).
- The tests run the full suite per driver. The CI matrix lists only combinations that can run: Node.js 20 runs `better-sqlite3` alone, 22 and 24 run both, with `node:sqlite` skipped with its reason where the runner's minor release is below the minimums above.

## Questions left open

- Whether `better-sqlite3` 13 should be supported on Node.js 22 and later while Node.js 20 stays on 12.
- Node.js 25 releases before 25.9.0, and any release not in the table above.
- `better-sqlite3` on Node.js 20 and 24, and on Linux, was not run for this record; the `sqlite` CI job covers them once it has run.
- Whether `node:sqlite` should become the default once it is no longer experimental and every Node.js in `engines` ships a SQLite that passes the check. Not before.
