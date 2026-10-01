// Scenario G: cleanup under concurrency, and what cleanup may never remove.
//
// The store clock is read from a test-owned row (as in the controlled-clock
// conformance run), so captures can be made to expire. Locks, isolation, and
// commits are the real database's.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, before, describe, test } from "node:test";

import { openPostgresStore } from "../dist/store.js";
import {
  captureState,
  captureText,
  evidence,
  openPool,
  openVault,
  randomAttemptId,
  randomNamespace,
  rawCapture,
  rawCommit,
  RELEASE,
  restoreRequest,
  rows,
  settle,
  syntheticKeys,
} from "../qualification/lib/harness.mjs";
import { ADMIN_URL, APP_URL, prepare, SCHEMA, SKIP } from "./helpers.mjs";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const CONTEXT = { tenant: "tenant-synthetic-a", principal: "user-synthetic-1" };

describe("G. cleanup under concurrency", { skip: SKIP }, () => {
  let admin;
  let pool;
  let sweeperPool;
  const clocks = [];

  /** A store clock this test can move: one row of the test-only clock table. */
  const controlledClock = async () => {
    const id = randomNamespace("clock");
    let now = 1_800_000_000_000;
    await pool.query(`INSERT INTO "${SCHEMA}".rsv_test_clock (id, now_ms) VALUES ($1, $2)`, [id, now]);
    clocks.push(id);
    return {
      now: () => now,
      async advance(ms) {
        now += ms;
        await pool.query(`UPDATE "${SCHEMA}".rsv_test_clock SET now_ms = $2 WHERE id = $1`, [id, now]);
      },
      sql: `(SELECT now_ms FROM "${SCHEMA}".rsv_test_clock WHERE id = '${id}')`,
    };
  };

  before(async () => {
    await prepare();
    admin = openPool(ADMIN_URL, 4);
    pool = openPool(APP_URL, 40);
    sweeperPool = openPool(APP_URL, 4);
  });

  after(async () => {
    for (const id of clocks) await pool.query(`DELETE FROM "${SCHEMA}".rsv_test_clock WHERE id = $1`, [id]).catch(() => undefined);
    await pool?.end();
    await sweeperPool?.end();
    await admin?.end();
  });

  /**
   * One run of a fixed schedule: 100 commits against 20 live three-use
   * entries, and 10 commits against expired captures, with or without a
   * sweeper running the whole time on another connection.
   */
  const schedule = async (withSweeper) => {
    const clock = await controlledClock();
    const namespace = randomNamespace("sweep");
    const store = await openPostgresStore({ pool, schema: SCHEMA, lockTimeoutMs: 10_000 }, clock.sql);
    const sweeper = await openPostgresStore({ pool: sweeperPool, schema: SCHEMA, lockTimeoutMs: 10_000 }, clock.sql);
    await store.initializeNamespace({ namespace, epoch: 1 });

    const expired = [];
    for (let i = 0; i < 30; i += 1) {
      const input = rawCapture({ namespace, entries: 2, now: clock.now(), ttlMs: MINUTE });
      assert.equal((await store.createCapture(input)).outcome, "created");
      expired.push(input);
    }
    await clock.advance(2 * MINUTE);
    const live = [];
    for (let i = 0; i < 20; i += 1) {
      const input = rawCapture({ namespace, entries: 1, maxUses: 3, now: clock.now(), ttlMs: HOUR });
      assert.equal((await store.createCapture(input)).outcome, "created");
      live.push(input);
    }

    const commit = async (created) => {
      const attemptId = randomAttemptId();
      const digest = new Uint8Array(randomBytes(32));
      for (let round = 0; round < 40; round += 1) {
        const result = await store.commitRestore(await rawCommit(store, created, { attemptId, digest, now: clock.now() }));
        if (!(result.outcome === "rejected" && result.reason === "stale")) return { ...result, attemptId };
      }
      return { outcome: "rejected", reason: "stale", attemptId };
    };

    let sweeping = withSweeper;
    const swept = { calls: 0, entries: 0, captures: 0, receipts: 0 };
    const sweepLoop = (async () => {
      while (sweeping) {
        const result = await sweeper.sweepExpired({ namespace, now: clock.now(), limit: 7 });
        assert.equal(result.outcome, "swept");
        swept.calls += 1;
        swept.entries += result.entries;
        swept.captures += result.captures;
        swept.receipts += result.receipts;
      }
    })();

    const [liveResults, expiredResults] = await Promise.all([
      Promise.all(live.flatMap((created) => Array.from({ length: 5 }, async () => ({ captureId: created.capture.captureId, ...(await commit(created)) })))),
      Promise.all(expired.slice(0, 10).map((created) => commit(created))),
    ]);
    sweeping = false;
    await sweepLoop;
    if (withSweeper) {
      for (;;) {
        const result = await sweeper.sweepExpired({ namespace, now: clock.now(), limit: 7 });
        swept.calls += 1;
        swept.entries += result.entries;
        swept.captures += result.captures;
        swept.receipts += result.receipts;
        if (!result.more) break;
      }
    }

    const perCapture = {};
    for (const result of liveResults) {
      const label = result.outcome === "rejected" ? result.reason : result.outcome;
      perCapture[result.captureId] ??= {};
      perCapture[result.captureId][label] = (perCapture[result.captureId][label] ?? 0) + 1;
    }
    const expiredReasons = {};
    for (const result of expiredResults) {
      const label = result.outcome === "rejected" ? result.reason : result.outcome;
      expiredReasons[label] = (expiredReasons[label] ?? 0) + 1;
    }
    const committedAttempts = liveResults.filter((result) => result.outcome === "committed").map((result) => result.attemptId);
    const [{ n: receipts }] = await rows(admin, `SELECT count(*)::int AS n FROM "${SCHEMA}".rsv_receipt WHERE namespace = $1 AND attempt_id = ANY($2::text[])`, [namespace, committedAttempts]);
    const liveStates = await Promise.all(live.map((created) => captureState(admin, namespace, created.capture.captureId)));
    const [{ n: expiredEntries }] = await rows(admin, `SELECT count(*)::int AS n FROM "${SCHEMA}".rsv_entry WHERE namespace = $1 AND expires_at <= $2`, [namespace, clock.now()]);
    return { perCapture, expiredReasons, receipts, committed: committedAttempts.length, liveStates, expiredEntries, swept };
  };

  test("a sweeper running throughout never removes a live row and never changes which restores succeed", async () => {
    const quiet = await schedule(false);
    const busy = await schedule(true);
    for (const run of [quiet, busy]) {
      // Every live entry: exactly its three uses committed, the other two attempts refused for budget.
      assert.equal(Object.keys(run.perCapture).length, 20);
      for (const counts of Object.values(run.perCapture)) assert.deepEqual(counts, { committed: 3, budget: 2 });
      assert.equal(run.committed, 60);
      assert.equal(run.receipts, 60, "every committed attempt kept its receipt");
      for (const state of run.liveStates) {
        assert.equal(state.capture?.state, "live", "a live capture row was removed");
        assert.deepEqual(state.used, [3], "a live entry row was removed or changed");
      }
      // No restore of an expired capture ever succeeds; cleanup only changes which refusal is reported.
      assert.equal(run.expiredReasons.committed, undefined);
      for (const reason of Object.keys(run.expiredReasons)) assert.ok(["expired", "unknown"].includes(reason), reason);
    }
    assert.deepEqual(quiet.expiredReasons, { expired: 10 });
    assert.equal(quiet.expiredEntries, 60, "without a sweep the expired rows stay, and are still refused");
    assert.equal(busy.expiredEntries, 0, "the sweeper removed every expired entry");
    assert.equal(busy.swept.entries, 60);
    assert.equal(busy.swept.captures, 30);
    assert.equal(busy.swept.receipts, 0);
    evidence("G", "sweep-vs-restores", {
      commitsPerRun: 110,
      liveEntries: 20,
      withoutSweeper: { committed: quiet.committed, budget: 40, expiredCaptureReasons: quiet.expiredReasons },
      withSweeper: { committed: busy.committed, budget: 40, expiredCaptureReasons: busy.expiredReasons, sweepCalls: busy.swept.calls, sweptEntries: busy.swept.entries, sweptCaptures: busy.swept.captures },
      liveRowsRemoved: 0,
    });
  });

  test("a receipt outlives its capture by the skew bound and the configured grace, and a tombstone by its retention", async () => {
    const clock = await controlledClock();
    const namespace = randomNamespace("retain");
    const store = await openPostgresStore({ pool, schema: SCHEMA, lockTimeoutMs: 10_000 }, clock.sql);
    await store.initializeNamespace({ namespace, epoch: 1 });
    const { vault } = await openVault({ namespace, keys: syntheticKeys(), store, vaultOptions: { now: () => clock.now(), limits: { entryTtlMs: 10 * MINUTE } } });
    const sweep = () => store.sweepExpired({ namespace, now: clock.now(), limit: 100 });
    const skew = store.capabilities().maxClockSkewMs;

    const first = captureText(1, 9000);
    const captured = await vault.capture(first.text, { context: CONTEXT, release: RELEASE });
    const request = restoreRequest({ context: CONTEXT, captures: [captured.captureId], tokens: captured.tokens.map((token) => token.token), attemptId: randomAttemptId() });
    assert.equal((await settle(vault.restore(request))).ok, true);
    const second = captureText(1, 9001);
    const revoked = await vault.capture(second.text, { context: CONTEXT, release: RELEASE });
    assert.equal((await vault.revoke({ context: CONTEXT, captureId: revoked.captureId })).outcome, "revoked");

    const [receipt] = await rows(admin, `SELECT expires_at::text AS expires_at FROM "${SCHEMA}".rsv_receipt WHERE namespace = $1 AND attempt_id = $2`, [namespace, request.attemptId]);
    const receiptExpiry = Number(receipt.expires_at);
    assert.equal(receiptExpiry, captured.expiresAt + skew + HOUR, "capture expiry + skew bound + the default one-hour grace");
    const tombstone = await captureState(admin, namespace, revoked.captureId);
    assert.equal(Number(tombstone.capture.retain_until), revoked.expiresAt + 24 * HOUR, "capture expiry + the default 24-hour tombstone retention");

    // Past the captures' expiry: expiry denies before any cleanup has run.
    await clock.advance(10 * MINUTE + 1000);
    const beforeSweep = await settle(vault.restore(request));
    assert.deepEqual([beforeSweep.code, beforeSweep.reason], ["RESTORE_DENIED", "expired"]);
    assert.deepEqual(await sweep(), { outcome: "swept", entries: 2, captures: 1, receipts: 0, more: false });
    assert.equal((await vault.resolveAttempt(request)).state, "committed", "the receipt is still there after its capture was swept");
    const afterSweep = await settle(vault.restore(request));
    assert.equal(afterSweep.code, "RESTORE_DENIED");
    assert.equal((await captureState(admin, namespace, revoked.captureId)).capture.state, "revoked", "the tombstone is kept");
    const reuse = rawCapture({ namespace, tenant: CONTEXT.tenant, now: clock.now() });
    reuse.capture.captureId = revoked.captureId;
    assert.deepEqual(await store.createCapture(reuse), { outcome: "rejected", reason: "fenced" });

    // One millisecond before the receipt's expiry it stays; after it, it goes.
    await clock.advance(receiptExpiry - clock.now());
    assert.equal((await sweep()).receipts, 0);
    await clock.advance(1);
    assert.equal((await sweep()).receipts, 1);
    assert.equal((await vault.resolveAttempt(request)).state, "absent");
    // The tombstone goes only after its retention.
    await clock.advance(revoked.expiresAt + 24 * HOUR - clock.now());
    assert.equal((await sweep()).captures, 0);
    await clock.advance(1);
    assert.equal((await sweep()).captures, 1);
    evidence("G", "retention", { receiptOutlivesCaptureByMs: skew + HOUR, graceMs: HOUR, skewBoundMs: skew, tombstoneRetentionMs: 24 * HOUR, deniedBeforeSweep: beforeSweep.reason, deniedAfterSweep: afterSweep.reason });
  });
});
