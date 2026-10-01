// Two independent server processes on one SQLite file (issue #130's gate):
// concurrent restore, restore against revoke, duplicate attempts.
//
// Each process is a separate Node.js process (support/process-worker.mjs) with
// its own connection, store, key provider, and persistent server vault. They
// share only the file and the key material generated for this run. The parent
// reads stored state with SQL on a connection of its own.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";

import { deriveEntryId } from "@redact-secret/vault-crypto";

import {
  captureText,
  initialized,
  openStore,
  randomAttemptId,
  randomNamespace,
  RELEASE,
  rawCapture,
  restoreRequest,
  spawnWorker,
  syntheticKeys,
  wire,
} from "../support/fixtures.mjs";
import { Database, freshDatabase, sql } from "./helpers.mjs";

const TENANT_A = { tenant: "tenant-synthetic-a", principal: "user-synthetic-1" };
const TRIALS = Number(process.env.RSVQ_TRIALS ?? 25);

const tally = (outcomes) => {
  const counts = {};
  for (const outcome of outcomes) {
    const label = outcome.ok ? "ok" : `${outcome.code}:${outcome.reason ?? ""}`;
    counts[label] = (counts[label] ?? 0) + 1;
  }
  return counts;
};

describe("two independent server processes on one SQLite file", () => {
  let database;
  let namespace;
  let keys;
  let a;
  let b;
  let offset = 0;
  const workers = new Set();

  const worker = async (extra = {}) => {
    const started = await spawnWorker({ filename: database.filename, namespace, epoch: 1, ...keys, ...extra });
    workers.add(started);
    return started;
  };

  /** Captures `count` synthetic values in one process and returns what a restore needs. */
  const capture = async (process_, { count = 1, maxUses = 1, context = TENANT_A } = {}) => {
    const { text, values } = captureText(count, offset);
    offset += count;
    const outcome = await process_.call("capture", { text, context, maxUses, release: RELEASE });
    assert.equal(outcome.ok, true, `capture failed: ${outcome.code}`);
    const tokens = outcome.value.tokens.map((token) => token.token);
    assert.equal(tokens.length, count);
    for (const value of values) assert.ok(!outcome.value.text.includes(value), "captured text must not contain the value");
    return { captureId: outcome.value.captureId, tokens, values, context };
  };

  const request = (captured, options = {}) =>
    restoreRequest({ context: captured.context, captures: [captured.captureId], tokens: captured.tokens, attemptId: randomAttemptId(), ...options });

  const entries = (captureId) =>
    sql(database.filename, "SELECT entry_id, used FROM rsv_entry WHERE namespace = ? AND capture_id = ? ORDER BY entry_id", namespace, captureId);
  const used = (captureId) => entries(captureId).map((row) => row.used);
  const receiptCount = (attemptId) =>
    sql(database.filename, "SELECT count(*) AS n FROM rsv_receipt WHERE namespace = ? AND attempt_id = ?", namespace, attemptId)[0].n;

  before(async () => {
    database = await freshDatabase();
    namespace = randomNamespace("two-process");
    keys = syntheticKeys();
    const parent = await openStore(database.filename);
    await initialized(parent, namespace, 1);
    parent.close();
    a = await worker();
    b = await worker();
    assert.notEqual(a.pid, b.pid);
    assert.notEqual(a.pid, process.pid);
  });

  after(async () => {
    for (const started of workers) await started.kill("SIGKILL");
    database?.cleanup();
  });

  test("a capture made in process A is restored in process B", async () => {
    const captured = await capture(a, { count: 2 });
    const req = request(captured);
    const restored = await b.call("restore", { request: req });
    assert.equal(restored.ok, true, `${restored.code}:${restored.reason}`);
    assert.equal(restored.value.restored, 2);
    for (const value of captured.values) assert.ok(restored.value.fields.body.includes(value));
    assert.deepEqual(used(captured.captureId), [1, 1]);
    assert.equal(receiptCount(req.attemptId), 1);
  });

  test("100 concurrent restores of a single-use token, split across both processes: exactly one returns the value", async () => {
    const captured = await capture(a);
    const requests = Array.from({ length: 100 }, () => request(captured));
    const [fromA, fromB] = await Promise.all([a.call("burst", { requests: requests.slice(0, 50) }), b.call("burst", { requests: requests.slice(50) })]);
    const outcomes = [...fromA, ...fromB];
    const winners = outcomes.filter((outcome) => outcome.ok);
    assert.equal(winners.length, 1, JSON.stringify(tally(outcomes)));
    assert.ok(winners[0].value.fields.body.includes(captured.values[0]));
    for (const outcome of outcomes) {
      if (outcome.ok) continue;
      assert.ok(["RESTORE_DENIED", "RESTORE_CONFLICT"].includes(outcome.code), outcome.code);
      assert.equal(outcome.hasFields, false);
    }
    assert.deepEqual(used(captured.captureId), [1]);
    const n = requests.filter((req) => receiptCount(req.attemptId) === 1).length;
    assert.equal(n, 1, "exactly one receipt");
  });

  test("a token repeated across fields consumes one use per occurrence, in one commit", async () => {
    const captured = await capture(a, { maxUses: 5 });
    const [token] = captured.tokens;
    const fields = (body, subject) => ({ context: TENANT_A, sink: "sink-a", purpose: "qualification", captures: [captured.captureId], fields: { body, subject }, attemptId: randomAttemptId() });
    const three = await b.call("restore", { request: fields(`${token} and ${token}`, `re: ${token}`) });
    assert.equal(three.ok, true, `${three.code}:${three.reason}`);
    assert.equal(three.value.restored, 3);
    assert.deepEqual(used(captured.captureId), [3]);
    // 3 + 3 > 5: the whole request is denied and nothing is consumed.
    const over = await a.call("restore", { request: fields(`${token} ${token}`, token) });
    assert.deepEqual([over.ok, over.code, over.reason], [false, "RESTORE_DENIED", "budget"]);
    assert.deepEqual(used(captured.captureId), [3]);
    assert.equal((await a.call("restore", { request: fields(token, token) })).ok, true);
    assert.deepEqual(used(captured.captureId), [5]);
  });

  test("a three-entry restore racing a one-entry restore from the other process never applies partially", async () => {
    for (let trial = 0; trial < TRIALS; trial += 1) {
      const captured = await capture(a, { count: 3 });
      const ids = await Promise.all(captured.tokens.map((token) => deriveEntryId(namespace, TENANT_A.tenant, token)));
      const whole = request(captured);
      const part = request({ ...captured, tokens: [captured.tokens[2]] });
      const [wide, narrow] = await Promise.all([a.call("restore", { request: whole }), b.call("restore", { request: part })]);
      const byId = new Map(entries(captured.captureId).map((entry) => [entry.entry_id, entry.used]));
      const usedInOrder = ids.map((id) => byId.get(id));
      assert.notEqual(wide.ok && narrow.ok, true, "both cannot consume the shared single-use entry");
      if (wide.ok) assert.deepEqual(usedInOrder, [1, 1, 1]);
      else if (narrow.ok) assert.deepEqual(usedInOrder, [0, 0, 1], "the denied three-entry request left its other entries untouched");
      else assert.deepEqual(usedInOrder, [0, 0, 0]);
    }
  });

  test("restore racing revoke across processes is linearizable", async () => {
    const maxUses = 8;
    let afterRevoke = 0;
    for (let trial = 0; trial < TRIALS; trial += 1) {
      const captured = await capture(a, { maxUses });
      const fire = (process_, n) => Array.from({ length: n }, () => process_.call("restore", { request: request(captured) }));
      // Overlapping restores from both processes, a revocation from B, and
      // restores that begin only after the revocation was acknowledged.
      const overlapping = [...fire(a, 3), ...fire(b, 3)];
      // A different delay each trial moves the revocation across the restores' read, policy, and commit steps.
      await new Promise((resolve) => setTimeout(resolve, (trial * 7) % 40));
      const revoking = b.call("revoke", { context: TENANT_A, captureId: captured.captureId });
      overlapping.push(...fire(a, 2));
      const revoked = await revoking;
      assert.equal(revoked.ok, true);
      assert.equal(revoked.value.outcome, "revoked");
      const late = [...fire(a, 2), ...fire(b, 2)];
      const outcomes = await Promise.all([...overlapping, ...late]);
      const acknowledged = BigInt(revoked.endedAt);
      const ok = outcomes.filter((outcome) => outcome.ok);
      for (const outcome of outcomes) {
        if (BigInt(outcome.startedAt) > acknowledged) {
          afterRevoke += 1;
          assert.equal(outcome.ok, false, "a restore that began after the revocation was acknowledged succeeded");
        }
        if (!outcome.ok) assert.ok(["RESTORE_DENIED", "RESTORE_CONFLICT"].includes(outcome.code), outcome.code);
      }
      assert.ok(ok.length <= maxUses);
      const [state] = sql(database.filename, "SELECT state FROM rsv_capture WHERE namespace = ? AND capture_id = ?", namespace, captured.captureId);
      assert.equal(state.state, "revoked");
      assert.deepEqual(used(captured.captureId), [ok.length], "used equals the number of successful restores");
      const final = await a.call("restore", { request: request(captured) });
      assert.deepEqual([final.ok, final.code, final.reason], [false, "RESTORE_DENIED", "revoked"]);
    }
    assert.ok(afterRevoke >= TRIALS * 4, "every trial started restores after the acknowledgement");
  });

  test("a creation racing a fence of the same capture identifier across processes: one order or the other, always revoked", async () => {
    for (let trial = 0; trial < TRIALS; trial += 1) {
      const input = rawCapture({ namespace, tenant: TENANT_A.tenant, entries: 2 });
      const revoke = { scope: input.scope, captureId: input.capture.captureId, now: Date.now(), retentionMs: 60_000, fenceAbsent: true };
      const [created, fenced] = await Promise.all(
        trial % 2 === 0
          ? [a.call("store", { method: "createCapture", input: wire(input) }), b.call("store", { method: "revokeCapture", input: wire(revoke) })]
          : [b.call("store", { method: "createCapture", input: wire(input) }), a.call("store", { method: "revokeCapture", input: wire(revoke) })],
      );
      assert.equal(created.ok, true);
      assert.equal(fenced.ok, true);
      const order = `${created.value.outcome}${created.value.reason === undefined ? "" : `:${created.value.reason}`}/${fenced.value.outcome}`;
      // Creation first: a live capture that is then revoked. Fence first: the creation is fenced.
      assert.ok(["created/revoked", "rejected:fenced/fenced"].includes(order), order);
      const [state] = sql(database.filename, "SELECT state FROM rsv_capture WHERE namespace = ? AND capture_id = ?", namespace, input.capture.captureId);
      assert.equal(state.state, "revoked");
      assert.equal(entries(input.capture.captureId).length, order === "created/revoked" ? 2 : 0);
      const again = await a.call("store", { method: "createCapture", input: wire(input) });
      assert.deepEqual([again.value.outcome, again.value.reason], ["rejected", "fenced"]);
    }
  });

  test("the same attempt submitted by both processes commits once", async () => {
    for (let trial = 0; trial < TRIALS; trial += 1) {
      const captured = await capture(a, { maxUses: 2 });
      const req = request(captured);
      const outcomes = await Promise.all([a.call("restore", { request: req }), b.call("restore", { request: req })]);
      const lost = outcomes.filter((outcome) => !outcome.ok);
      assert.equal(outcomes.filter((outcome) => outcome.ok).length, 1, JSON.stringify(tally(outcomes)));
      assert.deepEqual([lost[0].code, lost[0].reason], ["RESTORE_DENIED", "attempt-already-committed"]);
      assert.equal(lost[0].hasFields, false);
      assert.deepEqual(used(captured.captureId), [1], "used incremented once");
      assert.equal(receiptCount(req.attemptId), 1);
    }
    // With a single-use entry the loser may be denied at preflight, where the exhausted budget is seen before the receipt is.
    for (let trial = 0; trial < TRIALS; trial += 1) {
      const captured = await capture(a, { maxUses: 1 });
      const req = request(captured);
      const outcomes = await Promise.all([a.call("restore", { request: req }), b.call("restore", { request: req })]);
      assert.equal(outcomes.filter((outcome) => outcome.ok).length, 1);
      const lost = outcomes.find((outcome) => !outcome.ok);
      assert.equal(lost.code, "RESTORE_DENIED");
      assert.ok(["attempt-already-committed", "budget"].includes(lost.reason), lost.reason);
      assert.deepEqual(used(captured.captureId), [1]);
      assert.equal(receiptCount(req.attemptId), 1);
    }
  });

  test("an attempt identifier reused for a different request is a mismatch and consumes nothing", async () => {
    const captured = await capture(a, { maxUses: 3 });
    const original = request(captured, { purpose: "purpose-one" });
    assert.equal((await a.call("restore", { request: original })).ok, true);
    const different = { ...original, purpose: "purpose-two" };
    const mismatch = await b.call("restore", { request: different });
    assert.deepEqual([mismatch.ok, mismatch.code, mismatch.reason], [false, "RESTORE_DENIED", "attempt-mismatch"]);
    assert.deepEqual(used(captured.captureId), [1]);
    assert.equal((await b.call("resolveAttempt", { request: different })).value.state, "attempt-mismatch");
    assert.equal((await b.call("resolveAttempt", { request: original })).value.state, "committed");
  });

  test("a waiting writer in one process gives up after its busy timeout: nothing applied, STORE_UNAVAILABLE", async () => {
    // This process holds the write lock; the worker's mutation must wait, then fail with a fixed code and no effect.
    const impatient = await worker({ busyTimeoutMs: 200 });
    const holder = await freshHolder(database.filename);
    try {
      const input = rawCapture({ namespace, tenant: TENANT_A.tenant, entries: 1 });
      const startedAt = Date.now();
      const outcome = await impatient.call("store", { method: "createCapture", input: wire(input) });
      const waited = Date.now() - startedAt;
      assert.equal(outcome.ok, false);
      assert.equal(outcome.code, "STORE_UNAVAILABLE");
      assert.ok(waited >= 150 && waited < 5000, `waited ${waited} ms`);
      assert.equal(entries(input.capture.captureId).length, 0);
      assert.equal(sql(database.filename, "SELECT count(*) AS n FROM rsv_capture WHERE capture_id = ?", input.capture.captureId)[0].n, 0);
    } finally {
      holder.release();
      await impatient.kill("SIGKILL");
    }
  });
});

/** A connection that holds the write lock until released. */
async function freshHolder(filename) {
  const db = new Database(filename);
  db.pragma("busy_timeout = 30000");
  db.exec("BEGIN IMMEDIATE");
  return {
    release() {
      db.exec("ROLLBACK");
      db.close();
    },
  };
}
