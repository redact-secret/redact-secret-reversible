// Scenario B: failures around the commit, at the adapter and through the server.
//
// Three kinds of injection, all against a real PostgreSQL server:
// - a pool wrapper that throws, or destroys the socket, around a statement;
// - `pg_terminate_backend` from an admin connection, timed with a row lock;
// - a TCP proxy that loses the client exactly at `COMMIT`, before or after
//   the message reaches the server.
// Every case checks what the database holds afterwards with SQL.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";

import { StoreError } from "@redact-secret/vault-contracts";

import { createPostgresStore } from "../dist/index.js";
import { driverError, DRIVER_MARKER, hookPool, isApply, isEntryLock, startCommitProxy } from "../qualification/lib/fault.mjs";
import {
  assertSanitized,
  captureState,
  captureText,
  evidence,
  initializeNamespace,
  openPool,
  openVault,
  randomAttemptId,
  randomNamespace,
  rawCapture,
  rawCommit,
  receiptCount,
  RELEASE,
  restoreRequest,
  rows,
  settle,
  syntheticKeys,
} from "../qualification/lib/harness.mjs";
import { ADMIN_URL, APP_URL, prepare, SCHEMA, SKIP } from "./helpers.mjs";

const FORBIDDEN = [DRIVER_MARKER, "synthetic-local-only", "db.invalid", "postgres://", "08006", "57P01", "57014", "ECONNRESET"];
const CONTEXT = { tenant: "tenant-synthetic-a", principal: "user-synthetic-1" };
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function rejection(promise) {
  try {
    await promise;
  } catch (thrown) {
    return thrown;
  }
  assert.fail("expected the call to throw");
}

describe("B. failure around commit", { skip: SKIP }, () => {
  let admin;
  let pool;
  let plain;
  let namespace;
  let keys;
  const options = { schema: SCHEMA, lockTimeoutMs: 10_000, maxClockSkewMs: 30_000 };

  /** A raw capture, its commit input, and a hooked store on its own wrapper. */
  const fixture = async ({ entries = 1, maxUses = 1, storeOptions = {} } = {}) => {
    const created = rawCapture({ namespace, entries, maxUses });
    assert.equal((await plain.createCapture(created)).outcome, "created");
    const hooked = hookPool(pool);
    const store = await createPostgresStore({ pool: hooked, ...options, ...storeOptions });
    const commit = await rawCommit(plain, created);
    return { created, hooked, store, commit };
  };

  const state = async (created, attemptId) => ({
    used: (await captureState(admin, namespace, created.capture.captureId)).used,
    receipts: await receiptCount(admin, namespace, attemptId),
  });

  /** Holds a row lock on one entry from an admin transaction until `release` is called. */
  const holdEntry = async (entryId) => {
    const client = await admin.connect();
    await client.query("BEGIN");
    await client.query(`SELECT 1 FROM "${SCHEMA}".rsv_entry WHERE namespace = $1 AND entry_id = $2 FOR UPDATE`, [namespace, entryId]);
    return async () => {
      await client.query("ROLLBACK");
      client.release();
    };
  };

  const waitingForLock = async (pid) => {
    for (let i = 0; i < 200; i += 1) {
      const [row] = await rows(admin, "SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1", [pid]);
      if (row?.wait_event_type === "Lock") return;
      await sleep(25);
    }
    assert.fail("the backend never waited for the lock");
  };

  before(async () => {
    await prepare();
    admin = openPool(ADMIN_URL, 6);
    pool = openPool(APP_URL, 10);
    namespace = randomNamespace("commit-failure");
    keys = syntheticKeys();
    await initializeNamespace(pool, namespace, 1);
    plain = await createPostgresStore({ pool, ...options });
  });

  after(async () => {
    await pool?.end();
    await admin?.end();
  });

  describe("at the adapter", () => {
    test("a statement fails before it is sent, before COMMIT: STORE_UNAVAILABLE, nothing applied, and the attempt can be retried", async () => {
      const { created, hooked, store, commit } = await fixture();
      hooked.set({
        before: ({ text }) => {
          if (isApply(text)) throw driverError();
        },
      });
      assertSanitized(await rejection(store.commitRestore(commit)), "STORE_UNAVAILABLE", FORBIDDEN);
      assert.deepEqual(await state(created, commit.attempt.attemptId), { used: [0], receipts: 0 });
      assert.equal((await plain.inspectAttempt({ scope: created.scope, attemptId: commit.attempt.attemptId })).state, "absent");
      assert.equal(hooked.statements.at(-1), "ROLLBACK");
      hooked.clear();
      assert.equal((await store.commitRestore(commit)).outcome, "committed");
      evidence("B", "adapter/fail-before-commit-unsent-statement", { error: "STORE_UNAVAILABLE", applied: false });
    });

    test("the applying UPDATE runs and the client then fails, before COMMIT: STORE_UNAVAILABLE, rolled back", async () => {
      const { created, hooked, store, commit } = await fixture({ entries: 3 });
      hooked.set({
        after: ({ text }) => {
          if (isApply(text)) throw driverError();
        },
      });
      assertSanitized(await rejection(store.commitRestore(commit)), "STORE_UNAVAILABLE", FORBIDDEN);
      assert.deepEqual(await state(created, commit.attempt.attemptId), { used: [0, 0, 0], receipts: 0 });
      evidence("B", "adapter/fail-after-apply-before-commit", { error: "STORE_UNAVAILABLE", applied: false, entries: 3 });
    });

    test("COMMIT is sent and succeeds, then the acknowledgement is lost: STORE_AMBIGUOUS, and inspectAttempt reports the truth", async () => {
      const { created, hooked, store, commit } = await fixture();
      let commits = 0;
      hooked.set({
        after: ({ text, state: transaction }) => {
          if (text === "COMMIT" && transaction.writing) {
            commits += 1;
            throw driverError();
          }
        },
      });
      assertSanitized(await rejection(store.commitRestore(commit)), "STORE_AMBIGUOUS", FORBIDDEN);
      await sleep(300);
      assert.equal(commits, 1, "the adapter did not send COMMIT again");
      assert.deepEqual(await state(created, commit.attempt.attemptId), { used: [1], receipts: 1 });
      hooked.clear();
      const inspected = await store.inspectAttempt({ scope: created.scope, attemptId: commit.attempt.attemptId });
      assert.equal(inspected.state, "committed");
      assert.equal((await store.commitRestore(commit)).outcome, "already-committed");
      assert.deepEqual((await state(created, commit.attempt.attemptId)).used, [1]);
      evidence("B", "adapter/lost-acknowledgement", { error: "STORE_AMBIGUOUS", applied: true, commitsSent: commits, inspectAttempt: inspected.state });
    });

    test("the COMMIT call fails without reaching the server: still STORE_AMBIGUOUS, and inspectAttempt reports absent", async () => {
      const { created, hooked, store, commit } = await fixture();
      hooked.set({
        before: ({ text, state: transaction }) => {
          if (text === "COMMIT" && transaction.writing) throw driverError();
        },
      });
      // The adapter cannot tell this from a lost acknowledgement, so it must not claim "no effect".
      assertSanitized(await rejection(store.commitRestore(commit)), "STORE_AMBIGUOUS", FORBIDDEN);
      hooked.clear();
      await sleep(200);
      assert.deepEqual(await state(created, commit.attempt.attemptId), { used: [0], receipts: 0 });
      assert.equal((await store.inspectAttempt({ scope: created.scope, attemptId: commit.attempt.attemptId })).state, "absent");
      evidence("B", "adapter/commit-call-fails-unsent", { error: "STORE_AMBIGUOUS", applied: false, inspectAttempt: "absent" });
    });

    test("the socket is destroyed in the middle of the transaction: STORE_UNAVAILABLE, nothing applied, and the pool recovers", async () => {
      const { created, hooked, store, commit } = await fixture({ entries: 2 });
      hooked.set({
        before: ({ text, client }) => {
          if (isApply(text)) client.connection.stream.destroy();
        },
      });
      assertSanitized(await rejection(store.commitRestore(commit)), "STORE_UNAVAILABLE", FORBIDDEN);
      hooked.clear();
      await sleep(200);
      assert.deepEqual(await state(created, commit.attempt.attemptId), { used: [0, 0], receipts: 0 });
      assert.equal((await store.commitRestore(commit)).outcome, "committed", "a later call gets a working connection");
      evidence("B", "adapter/socket-destroyed-mid-transaction", { error: "STORE_UNAVAILABLE", applied: false });
    });

    test("pg_terminate_backend while the transaction waits for a row lock, before commit: STORE_UNAVAILABLE, nothing applied", async () => {
      const { created, hooked, store, commit } = await fixture({ entries: 2 });
      let pid;
      hooked.set({
        before: ({ text, client }) => {
          if (isEntryLock(text)) pid = client.processID;
        },
      });
      const release = await holdEntry(created.entries[1].entryId);
      try {
        const committing = rejection(store.commitRestore(commit));
        while (pid === undefined) await sleep(10);
        await waitingForLock(pid);
        const [terminated] = await rows(admin, "SELECT pg_terminate_backend($1) AS ok", [pid]);
        assert.equal(terminated.ok, true);
        assertSanitized(await committing, "STORE_UNAVAILABLE", FORBIDDEN);
      } finally {
        await release();
      }
      assert.deepEqual(await state(created, commit.attempt.attemptId), { used: [0, 0], receipts: 0 });
      evidence("B", "adapter/pg-terminate-backend-before-commit", { error: "STORE_UNAVAILABLE", applied: false });
    });

    test("pg_terminate_backend after the last statement and before COMMIT is sent: STORE_AMBIGUOUS, and the truth is absent", async () => {
      const { created, hooked, store, commit } = await fixture();
      hooked.set({
        before: async ({ text, client, state: transaction }) => {
          if (text === "COMMIT" && transaction.writing) {
            await admin.query("SELECT pg_terminate_backend($1)", [client.processID]);
            await sleep(150);
          }
        },
      });
      assertSanitized(await rejection(store.commitRestore(commit)), "STORE_AMBIGUOUS", FORBIDDEN);
      hooked.clear();
      assert.deepEqual(await state(created, commit.attempt.attemptId), { used: [0], receipts: 0 });
      assert.equal((await store.inspectAttempt({ scope: created.scope, attemptId: commit.attempt.attemptId })).state, "absent");
      evidence("B", "adapter/pg-terminate-backend-at-commit", { error: "STORE_AMBIGUOUS", applied: false, inspectAttempt: "absent" });
    });

    test("statement timeout while blocked: STORE_UNAVAILABLE and no partial application", async () => {
      const { created, hooked, store, commit } = await fixture({ entries: 3, storeOptions: { statementTimeoutMs: 300, lockTimeoutMs: 10_000 } });
      const release = await holdEntry(created.entries[1].entryId);
      try {
        assertSanitized(await rejection(store.commitRestore(commit)), "STORE_UNAVAILABLE", FORBIDDEN);
      } finally {
        await release();
      }
      assert.deepEqual(await state(created, commit.attempt.attemptId), { used: [0, 0, 0], receipts: 0 });
      assert.ok(hooked.statements.includes("ROLLBACK"));
      assert.equal((await store.commitRestore(commit)).outcome, "committed");
      evidence("B", "adapter/statement-timeout", { error: "STORE_UNAVAILABLE", applied: false, statementTimeoutMs: 300 });
    });

    test("lock timeout: rejected `stale` and no partial application", async () => {
      const { created, store, commit } = await fixture({ entries: 3, storeOptions: { lockTimeoutMs: 300 } });
      const release = await holdEntry(created.entries[1].entryId);
      let result;
      try {
        result = await store.commitRestore(commit);
      } finally {
        await release();
      }
      assert.deepEqual(result, { outcome: "rejected", reason: "stale" });
      assert.deepEqual(await state(created, commit.attempt.attemptId), { used: [0, 0, 0], receipts: 0 });
      evidence("B", "adapter/lock-timeout", { outcome: "rejected:stale", applied: false, lockTimeoutMs: 300 });
    });

    test("cancellation through AbortSignal before commit: STORE_UNAVAILABLE and nothing applied", async () => {
      const { created, hooked, store, commit } = await fixture({ entries: 2 });
      const controller = new AbortController();
      hooked.set({
        after: ({ text }) => {
          // Every use has been applied inside the transaction; COMMIT has not been sent.
          if (isApply(text)) controller.abort();
        },
      });
      assertSanitized(await rejection(store.commitRestore(commit, { signal: controller.signal })), "STORE_UNAVAILABLE", FORBIDDEN);
      assert.equal(hooked.statements.at(-1), "ROLLBACK");
      assert.deepEqual(await state(created, commit.attempt.attemptId), { used: [0, 0], receipts: 0 });
      // Already aborted: no connection is taken at all.
      const count = hooked.statements.length;
      assertSanitized(await rejection(store.commitRestore(commit, { signal: controller.signal })), "STORE_UNAVAILABLE", FORBIDDEN);
      assert.equal(hooked.statements.length, count);
      // Aborted while waiting for a row lock.
      const waiting = new AbortController();
      const release = await holdEntry(created.entries[0].entryId);
      try {
        hooked.clear();
        const call = rejection(store.commitRestore(commit, { signal: waiting.signal }));
        await sleep(200);
        waiting.abort();
        await release();
        assertSanitized(await call, "STORE_UNAVAILABLE", FORBIDDEN);
      } finally {
        await release().catch(() => undefined);
      }
      assert.deepEqual(await state(created, commit.attempt.attemptId), { used: [0, 0], receipts: 0 });
      evidence("B", "adapter/abort-signal-before-commit", { error: "STORE_UNAVAILABLE", applied: false, cases: 3 });
    });

    describe("connection lost exactly around COMMIT, through a TCP proxy", () => {
      let proxy;
      let proxied;
      let store;

      before(async () => {
        const target = new URL(APP_URL);
        proxy = await startCommitProxy({ targetHost: target.hostname, targetPort: Number(target.port || 5432) });
        const through = new URL(APP_URL);
        through.hostname = "127.0.0.1";
        through.port = String(proxy.port);
        proxied = openPool(through.toString(), 4);
        store = await createPostgresStore({ pool: proxied, ...options });
      });

      after(async () => {
        await proxied?.end().catch(() => undefined);
        await proxy?.close();
      });

      test("COMMIT reaches the server and the response never reaches the client: STORE_AMBIGUOUS, committed, and exactly one COMMIT on the wire", async () => {
        const created = rawCapture({ namespace });
        assert.equal((await plain.createCapture(created)).outcome, "created");
        const commit = await rawCommit(plain, created);
        const sentBefore = proxy.stats.sent;
        proxy.arm("after-forward");
        assertSanitized(await rejection(store.commitRestore(commit)), "STORE_AMBIGUOUS", FORBIDDEN);
        await sleep(500);
        assert.deepEqual(proxy.stats.dropped.slice(-1), ["after-forward"]);
        assert.equal(proxy.stats.sent - sentBefore, 1, "the adapter never retried the commit");
        assert.deepEqual(await state(created, commit.attempt.attemptId), { used: [1], receipts: 1 });
        const inspected = await store.inspectAttempt({ scope: created.scope, attemptId: commit.attempt.attemptId });
        assert.equal(inspected.state, "committed");
        evidence("B", "adapter/proxy-drop-after-commit-forwarded", { error: "STORE_AMBIGUOUS", applied: true, commitsOnWire: 1, inspectAttempt: "committed" });
      });

      test("the connection is lost as COMMIT is written, before the server receives it: STORE_AMBIGUOUS, not committed, one COMMIT attempted", async () => {
        const created = rawCapture({ namespace });
        assert.equal((await plain.createCapture(created)).outcome, "created");
        const commit = await rawCommit(plain, created);
        const sentBefore = proxy.stats.sent;
        const forwardedBefore = proxy.stats.writeCommits;
        proxy.arm("before-forward");
        assertSanitized(await rejection(store.commitRestore(commit)), "STORE_AMBIGUOUS", FORBIDDEN);
        await sleep(500);
        assert.deepEqual(proxy.stats.dropped.slice(-1), ["before-forward"]);
        assert.equal(proxy.stats.sent - sentBefore, 1);
        assert.equal(proxy.stats.writeCommits - forwardedBefore, 0, "the server never received a COMMIT");
        assert.deepEqual(await state(created, commit.attempt.attemptId), { used: [0], receipts: 0 });
        assert.equal((await store.inspectAttempt({ scope: created.scope, attemptId: commit.attempt.attemptId })).state, "absent");
        // `absent` lets the caller submit the same attempt again; it commits once.
        assert.equal((await store.commitRestore(commit)).outcome, "committed");
        assert.equal((await store.commitRestore(commit)).outcome, "already-committed");
        evidence("B", "adapter/proxy-drop-before-commit-forwarded", { error: "STORE_AMBIGUOUS", applied: false, commitsOnWire: 0, inspectAttempt: "absent" });
      });
    });
  });

  describe("through the server", () => {
    const open = async (overrides = {}) => {
      const hooked = hookPool(overrides.pool ?? pool);
      const opened = await openVault({ pool: hooked, namespace, keys, storeOptions: { lockTimeoutMs: 10_000, maxClockSkewMs: 30_000, ...overrides.storeOptions }, vaultOptions: overrides.vaultOptions });
      return { hooked, ...opened };
    };
    let offset = 5000;
    const capture = async (vault, maxUses = 1) => {
      const { text, values } = captureText(1, offset++);
      const captured = await vault.capture(text, { context: CONTEXT, release: RELEASE, maxUses });
      return { captureId: captured.captureId, tokens: captured.tokens.map((token) => token.token), values };
    };
    const request = (captured) => restoreRequest({ context: CONTEXT, captures: [captured.captureId], tokens: captured.tokens, attemptId: randomAttemptId() });
    const used = async (captured) => (await captureState(admin, namespace, captured.captureId)).used;
    const leakFree = (audit, values) => {
      const text = JSON.stringify(audit);
      for (const forbidden of [...FORBIDDEN, ...values]) assert.ok(!text.includes(forbidden), "an audit event carried text it must not");
    };

    test("a failure before COMMIT is STORE_UNAVAILABLE with no fields, nothing is consumed, and the same attempt then succeeds", async () => {
      const { vault, hooked, audit } = await open();
      const captured = await capture(vault);
      const req = request(captured);
      hooked.set({
        after: ({ text }) => {
          if (isApply(text)) throw driverError();
        },
      });
      const failed = await settle(vault.restore(req));
      assert.deepEqual([failed.ok, failed.name, failed.code, failed.hasFields], [false, "VaultServerError", "STORE_UNAVAILABLE", false]);
      assert.deepEqual(await used(captured), [0]);
      assert.equal(await receiptCount(admin, namespace, req.attemptId), 0);
      hooked.clear();
      const retried = await settle(vault.restore(req));
      assert.equal(retried.ok, true);
      assert.ok(retried.value.fields.body.includes(captured.values[0]));
      leakFree(audit, captured.values);
      evidence("B", "server/fail-before-commit", { error: "STORE_UNAVAILABLE", consumed: 0, retrySameAttempt: "ok" });
    });

    test("a lost acknowledgement is COMMIT_AMBIGUOUS with the attempt identifier and no fields; resolveAttempt reports committed", async () => {
      const { vault, hooked, audit } = await open();
      const captured = await capture(vault);
      const req = request(captured);
      let commits = 0;
      hooked.set({
        after: ({ text, state: transaction }) => {
          if (text === "COMMIT" && transaction.writing) {
            commits += 1;
            throw driverError();
          }
        },
      });
      const failed = await settle(vault.restore(req));
      assert.deepEqual([failed.ok, failed.code, failed.attemptId, failed.hasFields], [false, "COMMIT_AMBIGUOUS", req.attemptId, false]);
      hooked.clear();
      await sleep(300);
      assert.equal(commits, 1, "neither the server nor the adapter retried the commit");
      assert.deepEqual(await used(captured), [1]);
      const resolved = await vault.resolveAttempt(req);
      assert.equal(resolved.state, "committed");
      assert.ok(!("fields" in resolved));
      const replay = await settle(vault.restore(req));
      assert.equal(replay.ok, false);
      assert.equal(replay.code, "RESTORE_DENIED");
      leakFree(audit, captured.values);
      evidence("B", "server/lost-acknowledgement", { error: "COMMIT_AMBIGUOUS", fields: false, commitsSent: commits, resolveAttempt: resolved.state, replay: replay.reason });
    });

    test("through the TCP proxy: COMMIT_AMBIGUOUS in both directions, one COMMIT on the wire, and resolveAttempt tells them apart", async () => {
      const target = new URL(APP_URL);
      const proxy = await startCommitProxy({ targetHost: target.hostname, targetPort: Number(target.port || 5432) });
      const through = new URL(APP_URL);
      through.hostname = "127.0.0.1";
      through.port = String(proxy.port);
      const proxied = openPool(through.toString(), 4);
      try {
        const { vault } = await open({ pool: proxied });
        // Committed, acknowledgement lost.
        const first = await capture(vault);
        const firstRequest = request(first);
        let sent = proxy.stats.sent;
        proxy.arm("after-forward");
        const lost = await settle(vault.restore(firstRequest));
        assert.deepEqual([lost.code, lost.attemptId, lost.hasFields], ["COMMIT_AMBIGUOUS", firstRequest.attemptId, false]);
        await sleep(500);
        assert.equal(proxy.stats.sent - sent, 1, "one COMMIT of a write transaction on the wire: no retry");
        assert.equal((await vault.resolveAttempt(firstRequest)).state, "committed");
        assert.deepEqual(await used(first), [1]);
        // Not committed.
        const second = await capture(vault);
        const secondRequest = request(second);
        sent = proxy.stats.sent;
        proxy.arm("before-forward");
        const dropped = await settle(vault.restore(secondRequest));
        assert.deepEqual([dropped.code, dropped.attemptId, dropped.hasFields], ["COMMIT_AMBIGUOUS", secondRequest.attemptId, false]);
        await sleep(500);
        assert.equal(proxy.stats.sent - sent, 1);
        assert.equal((await vault.resolveAttempt(secondRequest)).state, "absent");
        assert.deepEqual(await used(second), [0]);
        const again = await settle(vault.restore(secondRequest));
        assert.equal(again.ok, true, "after `absent`, the same attempt may be submitted again");
        assert.deepEqual(await used(second), [1]);
        evidence("B", "server/proxy-around-commit", { afterForward: { error: "COMMIT_AMBIGUOUS", resolveAttempt: "committed", commitsOnWire: 1 }, beforeForward: { error: "COMMIT_AMBIGUOUS", resolveAttempt: "absent", commitsAttempted: 1 } });
      } finally {
        await proxied.end().catch(() => undefined);
        await proxy.close();
      }
    });

    test("the server's store deadline passes while the commit waits for a lock: COMMIT_AMBIGUOUS, and the cancelled transaction applies nothing afterwards", async () => {
      const { vault, hooked } = await open({ vaultOptions: { storeTimeoutMs: 400 } });
      const captured = await capture(vault);
      const req = request(captured);
      const [{ entry_id: entryId }] = (await captureState(admin, namespace, captured.captureId)).entries;
      const release = await holdEntry(entryId);
      let failed;
      try {
        failed = await settle(vault.restore(req));
      } finally {
        await release();
      }
      assert.deepEqual([failed.code, failed.attemptId, failed.hasFields], ["COMMIT_AMBIGUOUS", req.attemptId, false]);
      // The lock is free now; the adapter's transaction proceeds, sees the abort, and rolls back.
      for (let i = 0; i < 100 && hooked.statements.at(-1) !== "ROLLBACK"; i += 1) await sleep(20);
      assert.equal(hooked.statements.at(-1), "ROLLBACK");
      assert.deepEqual(await used(captured), [0]);
      assert.equal((await vault.resolveAttempt(req)).state, "absent");
      evidence("B", "server/store-deadline-while-blocked", { error: "COMMIT_AMBIGUOUS", applied: false, resolveAttempt: "absent" });
    });

    test("an ambiguous capture creation leaves a revoked capture: the server fences the identifier it issued", async () => {
      const { vault, hooked } = await open();
      const count = async () => (await rows(admin, `SELECT count(*)::int AS n, count(*) FILTER (WHERE state = 'revoked' AND generation = 2)::int AS revoked FROM "${SCHEMA}".rsv_capture WHERE namespace = $1`, [namespace]))[0];
      const before_ = await count();
      let creating = false;
      let armed = true;
      hooked.set({
        after: ({ text }) => {
          if (text.includes("VALUES ($1, $2, $3, 'live'")) creating = true;
          if (text === "COMMIT" && creating && armed) {
            armed = false;
            throw driverError();
          }
        },
      });
      const { text } = captureText(1, offset++);
      const failed = await settle(vault.capture(text, { context: CONTEXT, release: RELEASE }));
      assert.deepEqual([failed.ok, failed.code], [false, "STORE_UNAVAILABLE"]);
      const after_ = await count();
      assert.equal(after_.n, before_.n + 1, "the creation had committed");
      assert.equal(after_.revoked, before_.revoked + 1, "and the server then revoked the identifier it had issued");
      evidence("B", "server/ambiguous-create-is-fenced", { error: "STORE_UNAVAILABLE", captureState: "revoked" });
    });
  });

  test("errors the adapter throws are StoreError instances only", async () => {
    const hooked = hookPool(pool);
    const store = await createPostgresStore({ pool: hooked, ...options });
    hooked.set({
      before: () => {
        throw driverError();
      },
    });
    const created = rawCapture({ namespace });
    for (const call of [
      () => store.createCapture(created),
      () => store.readEntries({ scope: created.scope, entryIds: [created.entries[0].entryId] }),
      () => store.readCaptures({ scope: created.scope, captureIds: [created.capture.captureId] }),
      () => store.revokeCapture({ scope: created.scope, captureId: created.capture.captureId, now: Date.now(), retentionMs: 0, fenceAbsent: false }),
      () => store.inspectAttempt({ scope: created.scope, attemptId: "att_synthetic" }),
      () => store.deleteCiphertext({ scope: created.scope, captureId: created.capture.captureId, now: Date.now() }),
      () => store.sweepExpired({ namespace, now: Date.now(), limit: 10 }),
      () => store.recoveryState({ namespace }),
      () => store.quarantine({ namespace: randomNamespace("absent") }),
      () => store.acknowledgeIdentityChange({ namespace: randomNamespace("absent") }),
    ]) {
      const thrown = await rejection(call());
      assert.ok(thrown instanceof StoreError);
      assertSanitized(thrown, "STORE_UNAVAILABLE", FORBIDDEN);
    }
  });
});
