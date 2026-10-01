---
decision_id: decision-choose-sqlite-driver
status: accepted
scope: package
title: Choose the SQLite driver of @redact-secret/store-sqlite
decided_at: 2026-10-01
---
# Choose the SQLite driver of `@redact-secret/store-sqlite`

> **Accepted 2026-10-01** for `@redact-secret/store-sqlite` `0.1.0-alpha.1` ([#130](https://github.com/redact-secret/redact-secret-vault/issues/130)). It chooses a driver. It does not qualify the SQLite profile: the [qualification record](../research/qualification-store-sqlite-0.1.0-alpha.1.md) states what was run and what was not.

## Context

The [backend research](../research/persistent-backend-capabilities.md) (section 8.1) proposes the `sqlite-local-wal` profile and requires SQLite 3.51.3 or later, or a release carrying the backported fix, because of a WAL corruption bug that two connections writing or checkpointing at the same instant can trigger. The adapter checks `sqlite_version()` at startup, so the version of SQLite a driver brings is a requirement, not a detail. The repository supports Node.js 20, 22, and 24 (`engines`). The dependency rule of [the specification](../specs/persistent-vault.md) (section 2) allows one package to name a database driver, and no other.

Two drivers were considered.

| | `node:sqlite` | `better-sqlite3` |
| --- | --- | --- |
| Present on Node.js 20 | No (Node.js 20 has no `node:sqlite`; not run here) | Yes (12.11.1 `engines` lists Node.js 20, 22, 23, 24, 25, and 26) |
| SQLite version | The one the Node.js build bundles. **Measured on Node.js 22.16.0: 3.49.1**, below the required 3.51.3, so the store would refuse to start | The one the package bundles. **Measured with 12.11.1: 3.53.2** |
| Stability | Prints an `ExperimentalWarning` on 22.16.0 | A long-lived package; a native addon |
| Installation | Nothing to install | A prebuilt binary downloaded at install, or a build from source |
| Who controls the SQLite version | The Node.js release the application runs | The package version the application pins |

## Decision

- **`better-sqlite3`, declared as an optional peer dependency (`^12.11.1`) of `@redact-secret/store-sqlite` and named by no other package.** The store loads it with a dynamic `import()` when it opens a connection and reports `STORE_CAPABILITY` when it is absent. `npm` does not install an optional peer, so a consumer that installs the store without the driver gets that error and nothing else; the clean-consumer check shows it.
- **The range stops at 12.** `better-sqlite3` 13.x declares `node >= 22`, which would exclude Node.js 20. The range is widened only after a version of the major that supports every Node.js in `engines` is tested.
- **No `node:sqlite`.** On Node.js 20 it does not exist, and on the Node.js 22 measured here it bundles a SQLite that the adapter's own version check refuses. Which SQLite an application gets would depend on the Node.js minor it happens to run.
- **The version check stays.** The adapter reads `sqlite_version()` from the connection it opened and accepts 3.51.3 or later, or the backports 3.44.6 and 3.50.7 or later in their own lines. It does not trust the package version.
- **The adapter types the connection itself** (`Database`, `Statement` in `src/deployment.ts`) and carries an ambient declaration for the one `import()`. No emitted type names the driver, so a consumer needs no types for it.

## Consequences

- The package has a native-addon installation cost that `store-postgres` does not. The driver runs an install script (`prebuild-install`, falling back to `node-gyp`) when an application installs it; that script is the application's to review and allow, and this package adds none of its own. A platform without a prebuilt binary and without a C++ toolchain cannot install the driver, and so cannot use the store.
- The driver is synchronous. A write that waits for another process's write lock blocks the event loop of its own process for up to `busyTimeoutMs`. This follows from the driver, not from SQLite, and is documented in the [reference](../reference/store-sqlite.md#the-driver-is-synchronous). A driver that ran SQLite on another thread would remove it and would add a thread boundary to every transaction; that was not built.
- The tests include the driver as a development dependency. The clean-consumer check installs it into a project of its own.

## Questions left open

- Whether `node:sqlite` should replace the dependency once it is stable and every Node.js in `engines` ships a SQLite that passes the version check. Not before.
- Whether to support `better-sqlite3` 13 on Node.js 22 and later while the version range for Node.js 20 stays on 12.
- Node.js 20 and 24 and Linux were not run for this record; the repository's `sqlite` CI job covers them once it has run.
