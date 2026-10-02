# @redact-secret/store-postgres

A PostgreSQL store for the [persistent vault server](../../docs/guides/persistent-server.md). It holds ciphertext, wrapped keys, counters, and receipts. It never decrypts, holds no key, and evaluates no policy.

**Alpha.** Qualified only on PostgreSQL 17.11, Node.js 22, and `pg` 8.23.1, in two profiles:

| Profile | You must set |
| --- | --- |
| Single primary | `fsync = on`, `full_page_writes = on` |
| Primary with one synchronous standby | The above, `synchronous_standby_names` naming one standby, and `requireSynchronousStandby: true` |

**Not supported:** connection poolers (PgBouncer and the like), managed PostgreSQL services, read replicas, asynchronous replicas as a failover target, and any other version. An asynchronous failover was tested and released a single-use value twice. See [what is and is not qualified](../../docs/reference/store-postgres.md#qualified-deployment-profiles).

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

## The rules

- **You own the pool.** Create it, give it a `connectionTimeoutMillis` and an `error` listener, and close it. `store.close()` does not end it.
- **Migrate as the owner, serve as a plain role.** Run `migrate` once with the role that owns the schema. The serving role gets only `grantStatements`.
- **Every call must reach the primary.** A store pointed at a standby refuses to start.
- **Schedule cleanup.** Call `store.sweepExpired({ namespace, now, limit })` on a timer and repeat while it returns `more: true`. Cleanup is housekeeping; expiry is enforced without it.
- **After a restore from backup or a failover, follow the runbook.** See [recovery](../../docs/specs/persistent-operations.md#5-backup-recovery-runbook) and [failover](../../docs/specs/persistent-operations.md#6-failover-runbook). Do not call `acknowledgeIdentityChange` unless the failover runbook tells you to.
- **Keep statement logging off.** `log_statement = all` copies ciphertext and wrapped keys into the server log.

## More

The [reference](../../docs/reference/store-postgres.md) covers connection ownership, the schema, grants, transactions and lock order, retry rules, the clock, cleanup, restore detection and its blind spots, limits, what is visible in the database and its logs, and how to run the tests. The evidence is in the [qualification report](qualification/report/report.md).

## License

MIT
