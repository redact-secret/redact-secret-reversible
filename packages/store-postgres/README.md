# @redact-secret/store-postgres

**Status: alpha, unpublished.** A ciphertext-only `Store` on PostgreSQL for the persistent Redact Secret vault server. It implements the store contract of the [persistent vault specification](../../docs/specs/persistent-vault.md) (§4, §5) with the types and validators of [`@redact-secret/vault-contracts`](../vault-contracts/README.md).

It stores envelopes, wrapped keys, counters, and receipts as it is given them. It never decrypts, holds no data key, resolves no principal, and evaluates no policy. The specification is implemented on `main` as alpha, and nothing here is a support claim beyond the two profiles below, on the versions below, as recorded in the [qualification report](qualification/report/report.md).

## Qualified deployment profiles

| Profile | Required settings | What the qualification run showed |
| --- | --- | --- |
| **Single primary** | `fsync = on`; `synchronous_commit = on` (the adapter sets it for every write transaction); `full_page_writes = on` | An acknowledged consumption, revocation, receipt, and fence survive a clean restart and a `SIGKILL` of the server followed by crash recovery ([restart scenario](qualification/scenarios/restart.scenario.mjs)) |
| **Primary with one synchronous standby** | The above, and `synchronous_standby_names` naming one streaming standby (`FIRST 1 (name)`); create the store with `requireSynchronousStandby: true` | A commit acknowledged on the primary was on the standby after the primary was killed and the standby promoted. A commit is not acknowledged while the standby is down ([failover scenario](qualification/scenarios/failover.scenario.mjs)) |

`durability: "durable"` in the store's capabilities is a declaration about these two profiles only. A single primary is durable against a crash of the server process or host that keeps its storage. It is not durable against loss of that storage: recovering from a backup is a rollback, and the [recovery runbook](../../docs/specs/persistent-operations.md#5-backup-recovery-runbook) applies.

`synchronous_commit = on` is the qualified value for the standby profile. It makes `COMMIT` wait until the standby has flushed the commit record, and a promoted standby replays everything it has flushed before it accepts writes. `remote_apply` is accepted as an option and the store starts with it; it additionally waits for replay on the standby, which only matters to readers of a standby, and this adapter never reads one. It was not run through the failover scenario.

### Not qualified

Each of these is unsupported. The first was tested and shown to be unsafe; the rest were not tested.

- **An asynchronous replica as a failover target.** Tested as a negative control: the primary acknowledged a consumption and a revocation that the standby never received, the standby was promoted, and after a wrong `acknowledgeIdentityChange` the single-use value was released a second time and the revoked capture was restorable. Promoting such a replica is a rollback. Treat it with the recovery runbook, never with `acknowledgeIdentityChange`.
- **Read replicas for any store call.** Every operation runs on the primary, including reads. A store pointed at a standby refuses to start, and a transaction that lands on one fails `STORE_UNAVAILABLE`.
- **Logical replication, multi-primary, and any topology in which two nodes accept writes.**
- **More than one synchronous standby, quorum commit (`ANY n`), and cascading standbys.** The adapter only checks that `synchronous_standby_names` is not empty.
- **`synchronous_commit` weaker than `on`.** The adapter overrides a weaker session or database default in every write transaction, so this cannot be configured through it.
- **Connection poolers** (PgBouncer, Pgpool-II, cloud proxies), in any pooling mode. Not tested. The adapter depends on one connection for the whole transaction, on transaction-local settings, on server warnings reaching the client, and on reading `pg_is_in_recovery()` from the server it writes to.
- **Managed PostgreSQL services and forks** whose storage or failover differ from stock PostgreSQL. The restore tripwire reads `pg_control_system()` and the WAL file name; a service that hides or changes either is not covered.
- **PostgreSQL versions other than 17.11**, Node.js versions other than 22 (22.16.0 for the full qualification run; the repository's `postgres` CI job runs the single-node suites on the Node.js 22 of its Linux runner), and `pg` versions other than 8.23.1. The `engines` field lists Node.js 20 and 24 because the repository targets them; this package's tests have not been run on them.
- **TLS.** The qualification connected over loopback TCP without TLS. The adapter does not open connections, so TLS is a property of the pool the application passes.

## Use

```js
import pg from "pg";
import { createPostgresStore, grantStatements, migrate } from "@redact-secret/store-postgres";

// Once, as the role that owns the schema:
await migrate(ownerPool, "rsv");
for (const statement of grantStatements("rsv", "rsv_app")) await ownerPool.query(statement);

// In every server process, as the serving role:
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 20 });
pool.on("error", () => {}); // an idle connection that drops must not crash the process
const store = await createPostgresStore({ pool, schema: "rsv", requireSynchronousStandby: true });
```

`createPostgresStore` checks the deployment before it returns a store: the schema version, that the server is a primary, that `fsync` is `on`, and, when asked, that a synchronous standby is configured. It throws `STORE_CAPABILITY` when a check fails and `STORE_UNAVAILABLE` when it cannot connect.

| Option | Default | Meaning |
| --- | --- | --- |
| `pool` | required | A `pg.Pool`, or anything with `connect()` returning a client with `query` and `release`. See connection ownership below |
| `schema` | `"rsv"` | Schema holding the tables. A lowercase identifier of at most 63 characters |
| `synchronousCommit` | `"on"` | `"on"` or `"remote_apply"`, set for every write transaction. `"remote_apply"` requires a configured synchronous standby |
| `requireSynchronousStandby` | `false` | Refuse to start, and fail every later transaction `STORE_UNAVAILABLE`, unless `synchronous_standby_names` is set. The setting is read again in each transaction because a reload can change it |
| `maxClockSkewMs` | `2000` | Largest accepted difference between the database clock and a caller's `now`. 0 to 60 000 |
| `statementTimeoutMs` | `5000` | Deadline for each statement inside a transaction. 1 to 600 000 |
| `lockTimeoutMs` | `2000` | How long a statement waits for a row lock before the operation reports `stale`. 1 to 600 000 |
| `maxCreateEntries` | `1024` | May only be lowered |
| `maxCreateBytes` | 64 MiB | Sum of envelopes in one capture. At most 256 MiB |
| `maxRestoreEntries` | `1024` | May only be lowered |
| `maxRestoreCaptures` | `64` | May only be lowered |
| `maxEnvelopeBytes` | 1 MiB + 64 KiB | May only be lowered |

A capture is one transaction and its envelopes travel as one statement's parameters, so `maxCreateBytes` is also a bound on one statement's size and on the memory one call uses. Lower it to what your captures need.

Besides the contract's methods the store has:

- `acknowledgeIdentityChange({ namespace })`, for failover to a synchronous standby. See restore detection below.
- `close()`, which marks this adapter closed so that later calls throw `STORE_CLOSED`.

## Connection ownership

The application creates the pool, configures it, and closes it. The package imports no driver: `pg` is a peer dependency, and the pool is passed in. `store.close()` closes nothing else. It does not end the pool, and a server vault's `close()` does not close the store.

The adapter takes one client per operation, runs one transaction on it, and releases it. A client whose transaction could not be rolled back, or whose `COMMIT` failed, is released with the destroy flag so the pool discards it.

While the adapter holds a client it listens for that client's `error` event, when the client has `on` and `removeListener` as a `pg` client does. `pg` emits `error` on a checked-out client whose connection fails, and Node.js turns an unhandled `error` event into an uncaught exception. Before this was added, a backend terminated between two statements crashed the test process. The application still needs its own `pool.on("error", ...)` for idle clients, which the adapter never holds.

If the pool is exhausted and `connect()` rejects, the operation fails `STORE_UNAVAILABLE` and has no effect. Give the pool a `connectionTimeoutMillis`; without one, a call waits for a connection until the server's own store deadline passes.

A pool that parses `bigint` as `BigInt` or as a number works: the adapter accepts all three forms.

## Schema and migrations

`migrate(pool, schema)` creates schema version 1: five tables and four secondary indexes.

| Table | Rows | Columns |
| --- | --- | --- |
| `rsv_schema` | One | The schema version |
| `rsv_namespace` | One per namespace | Epoch, state (`serving` or `quarantined`), and the database identity recorded for restore detection |
| `rsv_capture` | One per capture, fence, or tombstone | Namespace, tenant, capture identifier, state, generation, key revision, epoch, session tag, creation and expiry time, key reference, wrapped key, tombstone retention |
| `rsv_entry` | One per retained value | Namespace, tenant, entry identifier, capture identifier, `max_uses`, `used`, revisions, envelope, expiry |
| `rsv_receipt` | One per committed restore attempt | Namespace, tenant, attempt identifier, request digest, commit time, expiry |

- Run it as the role that owns the schema, before any store is opened. The serving role cannot run it.
- It is idempotent, and it takes a transaction-level advisory lock, so two processes migrating at once both succeed. Re-running it changed no row in the qualification run.
- Migrations are forward-only. There is no down migration, and no migration statement drops, truncates, updates, or deletes. A store refuses a schema whose recorded version is not the one it was built for (`STORE_CAPABILITY`), in either direction, so an older adapter does not write to a newer schema. Rolling back a release means deploying the previous adapter against a schema it still accepts; version 1 is the only version, so there is nothing to roll back to yet.
- A future migration must not rewrite `used`, a revision, an epoch, or a capture state (specification §11).

## Least-privilege grants

`grantStatements(schema, role)` returns the grants the serving role needs and nothing more:

```sql
GRANT USAGE ON SCHEMA "rsv" TO "rsv_app";
GRANT SELECT ON "rsv".rsv_schema TO "rsv_app";
GRANT SELECT, INSERT, UPDATE ON "rsv".rsv_namespace TO "rsv_app";
GRANT SELECT, INSERT, UPDATE, DELETE ON "rsv".rsv_capture, "rsv".rsv_entry, "rsv".rsv_receipt TO "rsv_app";
```

The serving role should be an ordinary login role: not a superuser, not the owner of the tables, without `CREATEDB`, `CREATEROLE`, `REPLICATION`, or `BYPASSRLS`. The whole conformance suite and every single-node scenario ran as such a role. The [privilege test](test/least-privilege.test.mjs) shows that it cannot `TRUNCATE`, `DROP`, or `ALTER` any of the tables, create objects in the schema, change `rsv_schema`, delete a namespace record, read `pg_authid`, set `session_replication_role`, or run `ALTER SYSTEM`.

The adapter also calls `pg_is_in_recovery()`, `pg_control_system()`, `pg_current_wal_insert_lsn()`, `pg_walfile_name()`, `pg_advisory_xact_lock()`, `clock_timestamp()`, and `set_config()`. PostgreSQL grants `EXECUTE` on these to `PUBLIC` by default. An installation that revoked that must grant them to the serving role.

These grants bound what a compromised serving credential can do with DDL. They do not stop it from updating `used`, a capture's state, or a namespace record: those are the writes the adapter itself performs. Specification §10 states what a party that can write the store can do.

## Transactions, lock order, and isolation

Every operation is one transaction on one connection.

- **Writes** run at `READ COMMITTED` with explicit row locks. **Reads** (`readEntries`, `readCaptures`, `inspectAttempt`, `recoveryState`) run at `REPEATABLE READ READ ONLY`, which gives the statements of one read a single snapshot (specification §5.4).
- Each transaction first sets `statement_timeout`, `lock_timeout`, and `synchronous_commit` with `set_config(..., true)`, which is transaction-local. A weaker session default is overridden, and the session's own settings are back after the transaction. Both were checked on a pooled connection.
- Each transaction then reads the database clock, `pg_is_in_recovery()`, the system identifier, and the WAL insert timeline in one statement. A standby fails the transaction there.

`commitRestore` takes its locks in this order, which is the order of specification §5.2:

1. The namespace recovery record, `FOR SHARE`. `quarantine` and `invalidateRecovered` take it `FOR UPDATE`, so they wait for commits in flight and block new ones. Commits do not block each other on it.
2. The receipt, by inserting it. A second transaction for the same attempt waits on the first one's insert, then finds the receipt and answers `already-committed` or `attempt-mismatch`. If the first one rolls back, its claim disappears with it.
3. The named captures, `FOR SHARE`, in identifier order. `revokeCapture`, `replaceCaptureKey`, and `deleteCiphertext` take a capture `FOR UPDATE`, so a revocation waits for a commit that named the capture, and a revocation that committed first is seen.
4. The named entries, `FOR UPDATE`, in identifier order.
5. One `UPDATE` applies every use. Then `COMMIT`.

`createCapture` takes the recovery record `FOR SHARE` and inserts with `ON CONFLICT DO NOTHING`; an insert that created fewer rows than asked rolls the whole capture back.

**Why not `SERIALIZABLE`.** The conflict rule of §5.2 is met by the row locks above: for each pair of operations that must not interleave, one waits for the other. `SERIALIZABLE` would add serialization failures to retry and would not remove any lock the rule needs. More importantly, an isolation level orders concurrent transactions on one server. It says nothing about whether a commit survives a crash or reached another node. That is decided by `fsync`, `synchronous_commit`, and the replication topology, which is what the two profiles above fix and what the failover scenario and its negative control test. Both halves of that scenario ran the same transactions at the same isolation level; only the half with a synchronous standby kept its acknowledged commits.

## Retry rules

- **The adapter never retries a commit.** A `COMMIT` that fails, or that the adapter cannot confirm, is reported as `STORE_AMBIGUOUS` and not sent again. Through a TCP proxy that counted frontend messages, one write `COMMIT` was on the wire per ambiguous attempt, at the adapter and through the server.
- A lock timeout (`55P03`), a deadlock (`40P01`), or a serialization failure (`40001`) rolls the transaction back and is reported as `rejected: "stale"` by `createCapture`, `commitRestore`, and `replaceCaptureKey`. Nothing was applied. The server re-reads and re-evaluates policy before it tries again (specification §7.2).
- `revokeCapture` runs its transaction a second time after such a rollback, or after losing a race with a creation of the same identifier. The first run applied nothing. If the second also fails it throws `STORE_UNAVAILABLE`.
- Any other failure before `COMMIT` is sent is `STORE_UNAVAILABLE`: the transaction was rolled back, or its connection was destroyed, and PostgreSQL discards an uncommitted transaction either way.
- A failure of the `COMMIT` call itself is `STORE_AMBIGUOUS` for a write, whether or not the message reached the server; the adapter cannot tell. The caller resolves it with `inspectAttempt` (the server's `resolveAttempt`).
- A `COMMIT` that PostgreSQL completes with a warning is also `STORE_AMBIGUOUS`. This is what happens when a backend waiting for the synchronous standby is cancelled: the transaction is committed on the primary and may be missing on the standby. This needs a client with `on`, as a `pg` client has.
- An `AbortSignal` that is aborted before `COMMIT` is sent rolls the transaction back (`STORE_UNAVAILABLE`). The adapter does not cancel a `COMMIT` in flight.

Read-only operations that fail throw `STORE_UNAVAILABLE`.

## Authoritative routing

Every call must reach the primary. The adapter checks `pg_is_in_recovery()` when the store is created and again at the start of every transaction, because a pool can be repointed by DNS or a proxy after creation. It does not find the primary for the application: routing is the application's, and a connection string that can resolve to a standby will produce `STORE_UNAVAILABLE` until it resolves to the primary again.

A split brain, in which two nodes both believe they are primary, is outside what the adapter can detect. Fencing the old primary is the failover tooling's job.

## Clock

The store clock is the database's: `clock_timestamp()`, in integer milliseconds, read at the start of each transaction for the skew check. Expiry at commit is judged with a second reading, taken after every row lock is held, so time spent waiting for a lock cannot carry a restore past its capture's expiry. A caller's `now` that differs from it by more than `maxClockSkewMs` is rejected `clock-skew`.

The default bound is 2000 ms. A caller's `now` is taken before it waits for a pool connection and for row locks, so under heavy contention on one row a call can age past a small bound and be rejected `clock-skew` although the clocks agree. The conformance run uses 30 000 ms for its 100-way contention cases for that reason and checks the bound itself with a controlled clock. Choose the bound with your pool size and lock waits in mind; the lifetime extension a skewed database clock can cause is at most the bound (specification §7.5).

## Cleanup

`sweepExpired({ namespace, now, limit })` removes, per call, at most `limit` rows of each kind: entries past their capture's expiry, capture rows past expiry (or, for a tombstone, past its retention) that have no entries left, and receipts past their expiry. It reports `more: true` when a kind reached the limit.

- Cleanup is never authorization. Expiry and revocation are conditions of the commit and hold whether or not a sweep has run. With a sweeper running throughout, the same schedule of 110 commits produced the same successes and refusals as without one, and no live row was removed ([sweep test](test/sweep-concurrency.test.mjs)). What a sweep can change is which refusal an expired capture gets: `expired` before its rows are swept, `unknown` after.
- It uses `FOR UPDATE SKIP LOCKED`: rows another transaction holds are left for the next call, so cleanup yields to restores.
- Schedule: call it for each namespace on a timer, for example once a minute, and repeat while `more` is true. `limit` is 1 to 10 000. A capture lives at most 24 hours, so storage is bounded by the capture rate even when sweeps are late.
- The server sets a receipt's expiry to its capture's expiry plus the skew bound plus a grace period (one hour by default), and a tombstone's retention to 24 hours by default. The sweep honors both to the millisecond.
- A swept row is deleted from the table. Its bytes remain in the heap until vacuum reuses the space, and in WAL, replicas, and backups for as long as those are kept. Deletion here is not erasure (specification §9, [operations](../../docs/specs/persistent-operations.md#3-the-four-operations)).

## Restore detection and its blind spots

The contract asks a durable adapter to say what it does to notice a restored or rolled-back database. This adapter's `restoreDetection` is `postgres-system-identifier-and-timeline`: `initializeNamespace` and `invalidateRecovered` record the cluster's system identifier and the timeline it is writing WAL on, and every transaction compares the current values with the recorded ones. When they differ the namespace reads `quarantined`, whatever its stored state, and captures and commits are rejected.

The timeline is taken from the current WAL file name, not from `pg_control_checkpoint()`. The control file keeps the pre-promotion timeline until the first checkpoint after a promotion completes. In the qualification run that took minutes, during which a promoted standby would have read as `serving`.

| Event | System identifier | Timeline | Detected |
| --- | --- | --- | --- |
| Promotion of a streaming standby | same | changes | yes, on the first call |
| `pg_dump` restored into a new cluster | changes | same | yes |
| Base backup with point-in-time recovery | same | changes | yes |
| `pg_dump` restored into the same cluster (another database, or over the same one) | same | same | **no** |
| A base backup or file-system snapshot started as a plain copy, without recovery configuration | same | same | **no** |
| Restart or crash recovery of the same cluster | same | same | not a restore |

Other blind spots, stated and not tested:

- Timeline numbers are not unique across histories. A recovery that happens to produce the timeline number already recorded is not noticed.
- A party that can write the database, or restore it and edit it, can also set the recorded identity (specification §9.3).
- Rows restored selectively into a live database (one table, or some rows) change neither value.

The tripwire is a guard against a skipped runbook. It is not the control. The control is the recovery epoch the application keeps outside the database: a server configured with a raised epoch refuses a restored database in every case above, including the two the tripwire misses, and a server left on the old epoch against an undetected restore serves stale rows. The [backup scenario](qualification/scenarios/backup.scenario.mjs) asserts both.

`acknowledgeIdentityChange({ namespace })` records the database's present identity without changing the epoch, so captures stay usable. It exists for one case: failover to a synchronous standby that held every acknowledged commit. It accepts a new timeline of the same cluster only. It refuses a changed system identifier, it does not lift a quarantine set by `quarantine`, and it cannot tell a synchronous standby from a stale one. Establishing that is the operator's job, and the [failover runbook](../../docs/specs/persistent-operations.md#6-failover-runbook) says how. On a standby that missed acknowledged commits it brings consumed tokens back.

## Limits

| Quantity | Value |
| --- | --- |
| Entries in one capture | 1024 |
| Bytes in one capture | 64 MiB by default, at most 256 MiB |
| Envelope | 1 MiB + 64 KiB |
| Entries in one restore | 1024 |
| Captures named by one restore | 64 |
| Capture lifetime | at most 24 hours (the contract's validators) |
| Rows per kind in one sweep | 10 000 |

An input over a declared bound throws `STORE_CAPABILITY` before any statement runs. The adapter never splits a batch.

Not measured by the qualification: throughput, latency, behavior at the size ceilings above, and table bloat under a long-running workload.

## What is visible in the database, and in its logs

A party that reads the database or a backup sees what specification §3.7 lists: per capture, the namespace, tenant, capture identifier, session tag, times, epoch, state, generation, key reference, and wrapped key; per entry, the entry identifier, `max_uses`, uses consumed, revisions, and the envelope with its length; per receipt, the attempt identifier, request digest, and time. It sees no value, issued token, finding type, grant, or data key. Tenant identifiers are stored as given.

**Errors.** Every error the adapter throws is a `StoreError` with the fixed message of its code, no `cause`, and no other property. The [diagnostics test](test/diagnostics.test.mjs) makes PostgreSQL return a unique violation naming a key value, a check violation printing the failing row, and exceptions quoting an envelope and a wrapped key; it first confirms the driver's error carries those bytes, then that the `StoreError`, the server's error, and the audit events do not. Connection failures carry no host, port, user, or password. The adapter writes nothing to the console.

**The database's own log is outside the adapter's control.** The [server-log scenario](qualification/scenarios/server-log.scenario.mjs) read it under three configurations:

| Server configuration | In the server log |
| --- | --- |
| Defaults (`log_statement = none`, `log_parameter_max_length_on_error = 0`) | Nothing for successful calls. For a failing statement: the error, the statement text with placeholders, and its `DETAIL`. A constraint violation's `DETAIL` prints the failing row: identifiers, counters, and the first bytes of the envelope |
| `log_statement = all` | Every bound parameter: whole envelopes, wrapped keys, tenant, capture, entry, and attempt identifiers, request digests |
| `log_statement = all` with `log_parameter_max_length = 0` | Statement text only |

No configuration put a plaintext value, an issued token, or a key in the log, because none is ever sent to the database. What statement logging does is copy ciphertext and wrapped keys into log files, which usually have a different retention and a wider audience than the database. Operators should keep `log_statement` at `none` or `ddl`, set `log_parameter_max_length = 0` and `log_parameter_max_length_on_error = 0`, treat server logs as holding §3.7 metadata, and apply the same to `log_min_duration_statement`, `auto_explain`, and any audit extension that records parameters.

`pg_stat_activity.query` showed the statement text with its `$n` placeholders and no bound value. It is visible to the role itself and to members of `pg_read_all_stats`.

## Running the tests

```sh
# Single-node suites against a database you provide (a CI service container):
RSV_PG_ADMIN_URL=postgres://postgres:synthetic-local-only@127.0.0.1:5432/rsv \
RSV_PG_APP_URL=postgres://rsv_app:synthetic-local-only@127.0.0.1:5432/rsv \
npm test -w @redact-secret/store-postgres

# Everything, with the topologies started and removed by the script (needs Docker and the postgres:17 image):
npm run qualify -w @redact-secret/store-postgres
```

`RSV_PG_ADMIN_URL` is a role that may create the schema; the diagnostics and commit-failure tests also use it to terminate backends and add constraints, so it must be a superuser or hold the equivalent privileges. `RSV_PG_APP_URL` is an existing login role with no privileges of its own; the tests grant it `grantStatements` and a test-only clock table. Without both variables every test reports itself skipped. A run without a database proves nothing and does not look like a pass.

`npm run qualify` starts its own containers and Docker network, named `rsvq-*` on host ports 56001 to 56040, runs every suite, removes what it started, and writes `qualification/report/summary.json` and `qualification/report/report.md`. Suites that need containers are reported as skipped, with the reason, when Docker is unavailable, and the run is then `incomplete`. With both `RSV_PG_*` variables set it uses that database for the single-node suites. `--only=A,D` runs a subset.

## Versions tested

PostgreSQL 17.11 (the `postgres:17` image, Debian, aarch64), Node.js 22.16.0, `pg` 8.23.1, on macOS (Darwin, arm64) with Docker 28.3.3. The [report](qualification/report/report.md) records the image digest, the settings queried, the counts per scenario, and the wall-clock times of the run it came from.

## License

MIT
