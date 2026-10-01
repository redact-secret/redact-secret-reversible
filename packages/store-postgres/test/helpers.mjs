// Fixtures for tests against a real PostgreSQL server. Every identifier,
// byte, and password here is synthetic.
//
// RSV_PG_ADMIN_URL: a role that may create the schema and roles (migrations).
// RSV_PG_APP_URL:   the serving role, granted only what grantStatements lists.
// Without both, every test in this package reports itself skipped: a run
// without a database proves nothing and must not look like a pass.
import pg from "pg";

import { createPostgresStore, grantStatements, migrate } from "../dist/index.js";
// Not a package export: the store with a replaceable clock expression, for the
// time-dependent cases below.
import { openPostgresStore } from "../dist/store.js";

export const ADMIN_URL = process.env.RSV_PG_ADMIN_URL;
export const APP_URL = process.env.RSV_PG_APP_URL;
export const HAVE_DATABASE = typeof ADMIN_URL === "string" && typeof APP_URL === "string";
export const SKIP = HAVE_DATABASE ? false : "RSV_PG_ADMIN_URL and RSV_PG_APP_URL are not set";
export const SCHEMA = process.env.RSV_PG_SCHEMA ?? "rsv";

let prepared;
/** Migrates once per process and grants the serving role its privileges. */
export function prepare() {
  prepared ??= (async () => {
    const admin = new pg.Pool({ connectionString: ADMIN_URL, max: 1 });
    try {
      await migrate(admin, SCHEMA);
      const role = new URL(APP_URL).username;
      for (const statement of grantStatements(SCHEMA, role)) await admin.query(statement);
      // Test-only clock table, one row per test clock. Not part of the schema the package creates.
      await admin.query(`CREATE TABLE IF NOT EXISTS "${SCHEMA}".rsv_test_clock (id text PRIMARY KEY, now_ms bigint NOT NULL)`);
      await admin.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON "${SCHEMA}".rsv_test_clock TO "${role}"`);
    } finally {
      await admin.end();
    }
  })();
  return prepared;
}

export function appPool(max = 40) {
  return new pg.Pool({ connectionString: APP_URL, max });
}

export function randomNamespace(prefix = "t") {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * A pool whose clients pause immediately before `COMMIT` is sent, while the
 * transaction still holds its locks. That is the point §5.2's two-connection
 * schedules need: a competing transaction on another connection either waits
 * for this one, or commits first and must then be visible to it.
 */
export function pausingPool(pool) {
  let gate;
  return {
    armOnce(beforeCommit) {
      gate = beforeCommit;
    },
    async connect() {
      const client = await pool.connect();
      // Only a write transaction is paused: its COMMIT is the linearization
      // point, and it is holding its row locks when the pause begins.
      let writing = false;
      return {
        async query(text, values) {
          if (text.startsWith("BEGIN")) writing = text.includes("READ COMMITTED");
          if (text === "COMMIT" && writing && gate !== undefined) {
            const run = gate;
            gate = undefined;
            await run();
          }
          return client.query(text, values);
        },
        release: (destroy) => client.release(destroy),
      };
    },
  };
}

/** The factory the conformance harness calls once per case. */
export async function conformanceFactory() {
  await prepare();
  const pool = appPool();
  const pausing = pausingPool(pool);
  // On the database clock a caller's `now` ages while its call waits for a
  // connection or a row lock, so a hundred contending calls would trip a
  // two-second skew bound for reasons that have nothing to do with skew. The
  // bound itself is exercised exactly in the controlled-clock run.
  const options = { schema: SCHEMA, lockTimeoutMs: 10_000, maxClockSkewMs: 30_000 };
  const store = await createPostgresStore({ pool: pausing, ...options });
  const secondStore = await createPostgresStore({ pool, ...options });
  return {
    store,
    // The database clock is the store's clock and cannot be moved by a test.
    clock: null,
    secondStore,
    async interleave({ primary, concurrent }) {
      let competing;
      pausing.armOnce(async () => {
        // Start the competing call on the second connection and give it time
        // to either finish or block on this transaction's locks.
        competing = concurrent(secondStore);
        await Promise.race([competing.catch(() => undefined), new Promise((resolve) => setTimeout(resolve, 400))]);
      });
      const result = await primary();
      if (competing !== undefined) await competing;
      return result;
    },
    async dispose() {
      await pool.end();
    },
  };
}

/**
 * The same factory with the store clock read from a test-owned row, so the
 * cases that need an exact clock value run against real transactions too.
 * Everything else — locks, isolation, commits — is the real database.
 */
export async function controlledClockFactory() {
  await prepare();
  const pool = appPool();
  const id = randomNamespace("clock");
  let now = 1_800_000_000_000;
  await pool.query(`INSERT INTO "${SCHEMA}".rsv_test_clock (id, now_ms) VALUES ($1, $2)`, [id, now]);
  const write = () => pool.query(`UPDATE "${SCHEMA}".rsv_test_clock SET now_ms = $2 WHERE id = $1`, [id, now]);
  // The clock interface is synchronous; writes are chained and awaited before the next store call.
  let pending = Promise.resolve();
  const clock = {
    now: () => now,
    advance(ms) {
      now += ms;
      pending = pending.then(write);
    },
    set(ms) {
      now = ms;
      pending = pending.then(write);
    },
  };
  const settled = {
    async connect() {
      await pending;
      return pool.connect();
    },
  };
  const nowSql = `(SELECT now_ms FROM "${SCHEMA}".rsv_test_clock WHERE id = '${id}')`;
  const pausing = pausingPool(settled);
  const store = await openPostgresStore({ pool: pausing, schema: SCHEMA, lockTimeoutMs: 10_000 }, nowSql);
  const secondStore = await openPostgresStore({ pool: settled, schema: SCHEMA, lockTimeoutMs: 10_000 }, nowSql);
  return {
    store,
    clock,
    secondStore,
    async interleave({ primary, concurrent }) {
      let competing;
      pausing.armOnce(async () => {
        competing = concurrent(secondStore);
        await Promise.race([competing.catch(() => undefined), new Promise((resolve) => setTimeout(resolve, 400))]);
      });
      const result = await primary();
      if (competing !== undefined) await competing;
      return result;
    },
    async dispose() {
      await pending;
      await pool.query(`DELETE FROM "${SCHEMA}".rsv_test_clock WHERE id = $1`, [id]);
      await pool.end();
    },
  };
}
