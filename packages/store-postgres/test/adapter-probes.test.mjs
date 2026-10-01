// Probes of the adapter's own mechanics against a real PostgreSQL server:
// the receipt claim, revocation under contention, pool exhaustion, driver
// type parsers, a missing namespace record, `acknowledgeIdentityChange`,
// connection state after aborted transactions, and the scope of the
// per-transaction settings.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";

import pg from "pg";

import { createPostgresStore } from "../dist/index.js";
import { hookPool, isApply } from "../qualification/lib/fault.mjs";
import {
  assertSanitized,
  captureState,
  evidence,
  initializeNamespace,
  openPool,
  randomAttemptId,
  randomNamespace,
  rawCapture,
  rawCommit,
  receiptCount,
  rows,
} from "../qualification/lib/harness.mjs";
import { ADMIN_URL, APP_URL, pausingPool, prepare, SCHEMA, SKIP } from "./helpers.mjs";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function rejection(promise) {
  try {
    await promise;
  } catch (thrown) {
    return thrown;
  }
  assert.fail("expected the call to throw");
}

describe("adapter probes", { skip: SKIP }, () => {
  let admin;
  let pool;
  let second;
  let namespace;
  let store;
  const options = { schema: SCHEMA, lockTimeoutMs: 10_000, maxClockSkewMs: 30_000 };

  before(async () => {
    await prepare();
    admin = openPool(ADMIN_URL, 4);
    pool = openPool(APP_URL, 30);
    second = openPool(APP_URL, 30);
    namespace = randomNamespace("probe");
    await initializeNamespace(pool, namespace, 1);
    store = await createPostgresStore({ pool, ...options });
  });

  after(async () => {
    await pool?.end();
    await second?.end();
    await admin?.end();
  });

  test("the receipt is claimed first: 60 identical attempts over two pools commit once, and a failed claimant frees the attempt", async () => {
    const other = await createPostgresStore({ pool: second, ...options });
    const created = rawCapture({ namespace, maxUses: 100 });
    await store.createCapture(created);
    const commit = await rawCommit(store, created, { counts: [2] });
    const outcomes = await Promise.all(Array.from({ length: 60 }, (_unused, index) => (index % 2 === 0 ? store : other).commitRestore(commit)));
    const counts = {};
    for (const outcome of outcomes) counts[outcome.outcome] = (counts[outcome.outcome] ?? 0) + 1;
    assert.deepEqual(counts, { committed: 1, "already-committed": 59 });
    assert.deepEqual((await captureState(admin, namespace, created.capture.captureId)).used, [2], "used incremented once");
    assert.equal(await receiptCount(admin, namespace, commit.attempt.attemptId), 1);

    // A claimant that is rejected after claiming the receipt rolls the claim back: the attempt stays absent and usable.
    const tight = rawCapture({ namespace, maxUses: 1 });
    await store.createCapture(tight);
    const over = await rawCommit(store, tight, { counts: [2] });
    assert.deepEqual(await store.commitRestore(over), { outcome: "rejected", reason: "budget" });
    assert.equal(await receiptCount(admin, namespace, over.attempt.attemptId), 0);
    assert.equal((await store.inspectAttempt({ scope: tight.scope, attemptId: over.attempt.attemptId })).state, "absent");
    const fits = { ...over, uses: over.uses.map((use) => ({ ...use, count: 1 })) };
    assert.equal((await store.commitRestore(fits)).outcome, "committed");
    evidence("probe", "receipt-first-claim", { identicalAttempts: 60, outcomes: counts, usedIncrements: 1 });
  });

  test("revokeCapture waits for a commit that holds the capture, and reports STORE_UNAVAILABLE, not success, when it cannot get the lock", async () => {
    const pausing = pausingPool(pool);
    const holder = await createPostgresStore({ pool: pausing, ...options });
    const impatient = await createPostgresStore({ pool: second, ...options, lockTimeoutMs: 150 });
    const created = rawCapture({ namespace, maxUses: 5 });
    await store.createCapture(created);
    const commit = await rawCommit(store, created);
    let revocation;
    pausing.armOnce(async () => {
      // The commit holds its share lock on the capture. Two lock waits of 150 ms each then fail.
      revocation = await rejection(
        impatient.revokeCapture({ scope: created.scope, captureId: created.capture.captureId, now: Date.now(), retentionMs: 0, fenceAbsent: false }),
      );
    });
    assert.equal((await holder.commitRestore(commit)).outcome, "committed");
    assertSanitized(revocation, "STORE_UNAVAILABLE");
    const state = await captureState(admin, namespace, created.capture.captureId);
    assert.equal(state.capture.state, "live", "the failed revocation applied nothing");
    assert.equal(state.capture.generation, 1);
    // With time to wait, the revocation is ordered after the commit.
    const later = await impatient.revokeCapture({ scope: created.scope, captureId: created.capture.captureId, now: Date.now(), retentionMs: 0, fenceAbsent: false });
    assert.equal(later.outcome, "revoked");
    evidence("probe", "revoke-after-contention", { whileLocked: "STORE_UNAVAILABLE", applied: false, afterwards: "revoked" });
  });

  test("an exhausted pool is STORE_UNAVAILABLE and applies nothing", async () => {
    const small = openPool(APP_URL, 1, { connectionTimeoutMillis: 200 });
    try {
      const starved = await createPostgresStore({ pool: small, ...options });
      const created = rawCapture({ namespace });
      await store.createCapture(created);
      const commit = await rawCommit(store, created);
      const held = await small.connect();
      try {
        assertSanitized(await rejection(starved.commitRestore(commit)), "STORE_UNAVAILABLE", ["timeout exceeded when trying to connect"]);
        assertSanitized(await rejection(starved.recoveryState({ namespace })), "STORE_UNAVAILABLE");
      } finally {
        held.release();
      }
      assert.deepEqual((await captureState(admin, namespace, created.capture.captureId)).used, [0]);
      assert.equal((await starved.commitRestore(commit)).outcome, "committed", "the store works again once a connection is free");
      evidence("probe", "pool-exhausted", { error: "STORE_UNAVAILABLE", applied: false });
    } finally {
      await small.end();
    }
  });

  test("a pool whose driver parses bigint as BigInt, or as a number, still works", async () => {
    for (const [label, parser] of [
      ["BigInt", (value) => BigInt(value)],
      ["Number", (value) => Number(value)],
    ]) {
      const types = { getTypeParser: (oid, format) => (oid === 20 ? parser : pg.types.getTypeParser(oid, format)) };
      const typed = openPool(APP_URL, 4, { types });
      try {
        const typedStore = await createPostgresStore({ pool: typed, ...options });
        const created = rawCapture({ namespace, maxUses: 2 });
        assert.equal((await typedStore.createCapture(created)).outcome, "created", label);
        const read = await typedStore.readEntries({ scope: created.scope, entryIds: [created.entries[0].entryId] });
        assert.equal(read.recovery.state, "serving");
        assert.equal(read.captures[0].expiresAt, created.capture.expiresAt);
        assert.equal(typeof read.captures[0].expiresAt, "number");
        assert.equal((await typedStore.commitRestore(await rawCommit(typedStore, created))).outcome, "committed");
        assert.equal((await typedStore.recoveryState({ namespace })).epoch, 1);
      } finally {
        await typed.end();
      }
    }
    evidence("probe", "bigint-type-parsers", { parsers: ["default (string)", "BigInt", "Number"], works: true });
  });

  test("a missing namespace record fails closed, and cannot be recreated over existing rows", async () => {
    const lost = randomNamespace("lost");
    await initializeNamespace(pool, lost, 1);
    const created = rawCapture({ namespace: lost });
    await store.createCapture(created);
    const commit = await rawCommit(store, created);
    await admin.query(`DELETE FROM "${SCHEMA}".rsv_namespace WHERE namespace = $1`, [lost]);
    assert.deepEqual(await store.recoveryState({ namespace: lost }), { epoch: 0, state: "uninitialized" });
    assert.deepEqual(await store.commitRestore(commit), { outcome: "rejected", reason: "quarantined" });
    assert.deepEqual(await store.createCapture(rawCapture({ namespace: lost })), { outcome: "rejected", reason: "quarantined" });
    assert.deepEqual(await store.initializeNamespace({ namespace: lost, epoch: 1 }), { outcome: "rejected", reason: "not-empty" });
    assert.deepEqual(await store.quarantine({ namespace: lost }), { epoch: 0, state: "uninitialized" });
    assert.deepEqual(await store.invalidateRecovered({ namespace: lost, newEpoch: 5 }), { outcome: "rejected", reason: "uninitialized" });
    assert.deepEqual(await store.acknowledgeIdentityChange({ namespace: lost }), { epoch: 0, state: "uninitialized" });
    assert.deepEqual((await captureState(admin, lost, created.capture.captureId)).used, [0]);
    evidence("probe", "namespace-record-missing", { commit: "quarantined", create: "quarantined", reinitialize: "not-empty" });
  });

  test("acknowledgeIdentityChange never lifts an operator's quarantine, never changes the epoch, and is a no-op on an unchanged database", async () => {
    const ns = randomNamespace("ack");
    await initializeNamespace(pool, ns, 3);
    const read = async () => (await rows(admin, `SELECT epoch::int AS epoch, state, system_identifier, timeline_id::int AS timeline_id FROM "${SCHEMA}".rsv_namespace WHERE namespace = $1`, [ns]))[0];
    const initial = await read();
    assert.deepEqual(await store.acknowledgeIdentityChange({ namespace: ns }), { epoch: 3, state: "serving" });
    assert.deepEqual(await read(), initial, "nothing changes when the identity is the recorded one");
    await store.quarantine({ namespace: ns });
    assert.deepEqual(await store.acknowledgeIdentityChange({ namespace: ns }), { epoch: 3, state: "quarantined" });
    assert.equal((await read()).state, "quarantined", "an explicit quarantine is lifted only by invalidateRecovered");
    // A recorded identity that differs reads as quarantined whatever the stored state says.
    const drifted = randomNamespace("ack");
    await initializeNamespace(pool, drifted, 1);
    await admin.query(`UPDATE "${SCHEMA}".rsv_namespace SET timeline_id = timeline_id + 7 WHERE namespace = $1`, [drifted]);
    assert.deepEqual(await store.recoveryState({ namespace: drifted }), { epoch: 1, state: "quarantined" });
    assert.deepEqual(await store.createCapture(rawCapture({ namespace: drifted })), { outcome: "rejected", reason: "quarantined" });
    assert.deepEqual(await store.acknowledgeIdentityChange({ namespace: drifted }), { epoch: 1, state: "serving" });
    assert.deepEqual(await store.recoveryState({ namespace: drifted }), { epoch: 1, state: "serving" });
    // A different system identifier is another cluster: a restore, never a promotion. It cannot be acknowledged.
    const moved = randomNamespace("ack");
    await initializeNamespace(pool, moved, 1);
    const movedCapture = rawCapture({ namespace: moved });
    await store.createCapture(movedCapture);
    await admin.query(`UPDATE "${SCHEMA}".rsv_namespace SET system_identifier = '1' WHERE namespace = $1`, [moved]);
    assert.deepEqual(await store.recoveryState({ namespace: moved }), { epoch: 1, state: "quarantined" });
    assert.deepEqual(await store.acknowledgeIdentityChange({ namespace: moved }), { epoch: 1, state: "quarantined" }, "a changed system identifier was acknowledged");
    assert.deepEqual(await store.recoveryState({ namespace: moved }), { epoch: 1, state: "quarantined" });
    assert.equal((await store.invalidateRecovered({ namespace: moved, newEpoch: 2 })).outcome, "invalidated");
    assert.deepEqual(await store.recoveryState({ namespace: moved }), { epoch: 2, state: "serving" });
    assert.equal((await store.readCaptures({ scope: movedCapture.scope, captureIds: [movedCapture.capture.captureId] }))[0].state, "revoked");
    evidence("probe", "acknowledge-identity-change", { liftsExplicitQuarantine: false, changesEpoch: false, acceptsNewTimeline: true, acceptsNewSystemIdentifier: false });
  });

  test("a connection is returned to the pool clean after every kind of aborted transaction", async () => {
    const one = openPool(APP_URL, 1);
    try {
      const hooked = hookPool(one);
      const single = await createPostgresStore({ pool: hooked, ...options, lockTimeoutMs: 200, statementTimeoutMs: 400 });
      const session = async () => {
        const [row] = await rows(
          one,
          `SELECT pg_backend_pid() AS pid, current_setting('statement_timeout') AS statement_timeout, current_setting('lock_timeout') AS lock_timeout,
                  current_setting('synchronous_commit') AS synchronous_commit, current_setting('transaction_read_only') AS read_only,
                  current_setting('transaction_isolation') AS isolation, pg_current_xact_id_if_assigned()::text AS xid,
                  (SELECT count(*)::int FROM pg_locks l WHERE l.pid = pg_backend_pid() AND l.locktype IN ('tuple', 'transactionid', 'advisory')) AS locks`,
        );
        return row;
      };
      const baseline = await session();
      const created = rawCapture({ namespace, entries: 2, maxUses: 1 });
      await single.createCapture(created);
      const commit = await rawCommit(single, created);
      const lockEntry = async () => {
        const client = await admin.connect();
        await client.query("BEGIN");
        await client.query(`SELECT 1 FROM "${SCHEMA}".rsv_entry WHERE namespace = $1 AND entry_id = $2 FOR UPDATE`, [namespace, created.entries[0].entryId]);
        return async () => {
          await client.query("ROLLBACK");
          client.release();
        };
      };

      const aborted = [];
      // 1. A rejection decided by the adapter (rollback with a result).
      aborted.push((await single.commitRestore({ ...commit, epoch: 9 })).reason);
      assert.deepEqual(await session(), baseline);
      // 2. Lock timeout.
      let release = await lockEntry();
      aborted.push((await single.commitRestore(commit)).reason);
      await release();
      assert.deepEqual(await session(), baseline);
      // 3. Statement timeout.
      const slow = await createPostgresStore({ pool: hooked, ...options, lockTimeoutMs: 10_000, statementTimeoutMs: 200 });
      release = await lockEntry();
      aborted.push((await rejection(slow.commitRestore(commit))).code);
      await release();
      assert.deepEqual(await session(), baseline);
      // 4. A statement the client failed after the server ran it.
      hooked.set({
        after: ({ text }) => {
          if (isApply(text)) throw new Error("synthetic");
        },
      });
      aborted.push((await rejection(single.commitRestore(commit))).code);
      hooked.clear();
      assert.deepEqual(await session(), baseline);
      // 5. Cancellation.
      const controller = new AbortController();
      hooked.set({
        after: ({ text }) => {
          if (isApply(text)) controller.abort();
        },
      });
      aborted.push((await rejection(single.commitRestore(commit, { signal: controller.signal }))).code);
      hooked.clear();
      assert.deepEqual(await session(), baseline);
      // 6. A read-only transaction.
      await single.readEntries({ scope: created.scope, entryIds: [created.entries[0].entryId] });
      assert.deepEqual(await session(), baseline);

      assert.deepEqual(aborted, ["quarantined", "stale", "STORE_UNAVAILABLE", "STORE_UNAVAILABLE", "STORE_UNAVAILABLE"]);
      assert.deepEqual((await captureState(admin, namespace, created.capture.captureId)).used, [0, 0]);
      assert.equal((await single.commitRestore(commit)).outcome, "committed", "the same connection then commits");
      assert.equal((await session()).pid, baseline.pid, "one connection served every call");
      evidence("probe", "connection-state-after-abort", { abortKinds: aborted, sameBackend: true, sessionSettingsUnchanged: true });
    } finally {
      await one.end();
    }
  });

  test("the per-transaction settings override a weaker session default and do not outlive the transaction", async () => {
    // A session whose own default is the weakest commit durability and no timeouts.
    const weak = openPool(APP_URL, 1);
    weak.on("connect", (client) => {
      client.query("SET synchronous_commit = off").catch(() => undefined);
    });
    try {
      const hooked = hookPool(weak);
      const inside = [];
      hooked.set({
        before: async ({ text, client, state }) => {
          if (text === "COMMIT" && state.writing) {
            const result = await client.query(
              "SELECT current_setting('synchronous_commit') AS synchronous_commit, current_setting('statement_timeout') AS statement_timeout, current_setting('lock_timeout') AS lock_timeout, current_setting('transaction_isolation') AS isolation",
            );
            inside.push(result.rows[0]);
          }
        },
      });
      const strict = await createPostgresStore({ pool: hooked, ...options, statementTimeoutMs: 4321, lockTimeoutMs: 1234 });
      const created = rawCapture({ namespace });
      assert.equal((await strict.createCapture(created)).outcome, "created");
      assert.equal((await strict.commitRestore(await rawCommit(strict, created))).outcome, "committed");
      hooked.clear();
      assert.equal(inside.length, 2);
      for (const settings of inside) {
        assert.equal(settings.synchronous_commit, "on");
        assert.equal(settings.lock_timeout, "1234ms");
        assert.equal(settings.statement_timeout, "4321ms");
        assert.equal(settings.isolation, "read committed");
      }
      const [afterwards] = await rows(weak, "SELECT current_setting('synchronous_commit') AS synchronous_commit, current_setting('statement_timeout') AS statement_timeout, current_setting('lock_timeout') AS lock_timeout");
      assert.deepEqual(afterwards, { synchronous_commit: "off", statement_timeout: "0", lock_timeout: "0" }, "the session's own settings are back");
      evidence("probe", "set-config-scope", { sessionDefault: "synchronous_commit=off", insideTransaction: inside[0], afterTransaction: afterwards });
    } finally {
      await weak.end();
    }
  });

  test("a connection that fails while the adapter holds it, between two statements, does not become an uncaught exception", async () => {
    const hooked = hookPool(pool);
    const guarded = await createPostgresStore({ pool: hooked, ...options });
    const created = rawCapture({ namespace });
    await store.createCapture(created);
    const commit = await rawCommit(store, created);
    const uncaught = [];
    const listener = (thrown) => uncaught.push(thrown);
    process.on("uncaughtException", listener);
    try {
      hooked.set({
        before: async ({ text, client, state }) => {
          if (text === "COMMIT" && state.writing) {
            // No statement is in flight: the driver has nobody to reject, and emits `error` on the client.
            await admin.query("SELECT pg_terminate_backend($1)", [client.processID]);
            await sleep(200);
          }
        },
      });
      assertSanitized(await rejection(guarded.commitRestore(commit)), "STORE_AMBIGUOUS");
      hooked.clear();
      await sleep(200);
    } finally {
      process.removeListener("uncaughtException", listener);
    }
    assert.equal(uncaught.length, 0, "the connection error escaped as an uncaught exception");
    assert.deepEqual((await captureState(admin, namespace, created.capture.captureId)).used, [0]);
    assert.equal((await guarded.commitRestore(commit)).outcome, "committed");
    evidence("probe", "client-error-event-while-checked-out", { uncaughtExceptions: 0 });
  });

  test("attempt identifiers are scoped by tenant and namespace", async () => {
    const attemptId = randomAttemptId();
    const mine = rawCapture({ namespace, tenant: "tenant-synthetic-a" });
    const theirs = rawCapture({ namespace, tenant: "tenant-synthetic-b" });
    await store.createCapture(mine);
    await store.createCapture(theirs);
    assert.equal((await store.commitRestore(await rawCommit(store, mine, { attemptId }))).outcome, "committed");
    assert.equal((await store.commitRestore(await rawCommit(store, theirs, { attemptId }))).outcome, "committed", "the same attempt identifier under another tenant is another attempt");
    assert.equal(await receiptCount(admin, namespace, attemptId), 2);
  });
});
