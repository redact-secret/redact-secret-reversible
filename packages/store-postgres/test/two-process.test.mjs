// Scenario A: two independent server processes on one PostgreSQL database.
//
// Each process is a separate Node.js process (qualification/lib/vault-worker.mjs)
// with its own pool, store, key provider, and persistent server vault. They
// share only the database and the key material generated for this run. The
// parent initializes the namespace once, drives both over IPC, and checks
// stored state with SQL as the admin role.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";

import { deriveEntryId } from "@redact-secret/vault-crypto";

import {
  captureState,
  captureText,
  evidence,
  initializeNamespace,
  openPool,
  randomAttemptId,
  randomNamespace,
  rawCapture,
  receiptCount,
  RELEASE,
  restoreRequest,
  rows,
  spawnWorker,
  syntheticKeys,
  tally,
  wire,
} from "../qualification/lib/harness.mjs";
import { ADMIN_URL, APP_URL, prepare, SCHEMA, SKIP } from "./helpers.mjs";

const TENANT_A = { tenant: "tenant-synthetic-a", principal: "user-synthetic-1" };
const TENANT_B = { tenant: "tenant-synthetic-b", principal: "user-synthetic-2" };
const TRIALS = Number(process.env.RSVQ_TRIALS ?? 40);

describe("A. two independent server processes", { skip: SKIP }, () => {
  let admin;
  let parent;
  let namespace;
  let keys;
  let a;
  let b;
  let offset = 0;
  const workers = new Set();

  const worker = async (extra = {}) => {
    const started = await spawnWorker({ url: APP_URL, schema: SCHEMA, namespace, epoch: 1, ...keys, ...extra });
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

  const used = async (captureId) => (await captureState(admin, namespace, captureId)).used;

  before(async () => {
    await prepare();
    admin = openPool(ADMIN_URL, 4);
    parent = openPool(APP_URL, 4);
    namespace = randomNamespace("two-process");
    keys = syntheticKeys();
    await initializeNamespace(parent, namespace, 1);
    a = await worker();
    b = await worker();
    assert.notEqual(a.pid, b.pid);
    assert.notEqual(a.pid, process.pid);
    evidence("A", "processes", { pids: 2, distinct: a.pid !== b.pid });
  });

  after(async () => {
    for (const started of workers) await started.kill("SIGKILL");
    await parent?.end();
    await admin?.end();
  });

  test("a capture made in process A is restored in process B", async () => {
    const captured = await capture(a, { count: 2 });
    const req = request(captured);
    const restored = await b.call("restore", { request: req });
    assert.equal(restored.ok, true, `${restored.code}:${restored.reason}`);
    assert.equal(restored.value.restored, 2);
    for (const value of captured.values) assert.ok(restored.value.fields.body.includes(value));
    assert.deepEqual(await used(captured.captureId), [1, 1]);
    assert.equal(await receiptCount(admin, namespace, req.attemptId), 1);
    evidence("A", "capture-in-A-restore-in-B", { restored: 2 });
  });

  test("100 concurrent restores of a single-use token, split across both processes: exactly one returns the value", async () => {
    const captured = await capture(a);
    const requests = Array.from({ length: 100 }, () => request(captured));
    const [fromA, fromB] = await Promise.all([
      a.call("burst", { requests: requests.slice(0, 50) }),
      b.call("burst", { requests: requests.slice(50) }),
    ]);
    const outcomes = [...fromA, ...fromB];
    const winners = outcomes.filter((outcome) => outcome.ok);
    assert.equal(winners.length, 1, JSON.stringify(tally(outcomes)));
    assert.ok(winners[0].value.fields.body.includes(captured.values[0]));
    for (const outcome of outcomes) {
      if (outcome.ok) continue;
      assert.ok(["RESTORE_DENIED", "RESTORE_CONFLICT"].includes(outcome.code), outcome.code);
      assert.equal(outcome.hasFields, false);
    }
    assert.deepEqual(await used(captured.captureId), [1]);
    const [{ n }] = await rows(admin, `SELECT count(*)::int AS n FROM "${SCHEMA}".rsv_receipt WHERE namespace = $1 AND attempt_id = ANY($2::text[])`, [
      namespace,
      requests.map((req) => req.attemptId),
    ]);
    assert.equal(n, 1, "exactly one receipt");
    evidence("A", "100-concurrent-single-use", { attempts: 100, successes: winners.length, outcomes: tally(outcomes) });
  });

  test("a token repeated across fields consumes one use per occurrence, in one commit", async () => {
    const captured = await capture(a, { maxUses: 5 });
    const [token] = captured.tokens;
    const fields = (body, subject) => ({ context: TENANT_A, sink: "sink-a", purpose: "qualification", captures: [captured.captureId], fields: { body, subject }, attemptId: randomAttemptId() });
    const three = await b.call("restore", { request: fields(`${token} and ${token}`, `re: ${token}`) });
    assert.equal(three.ok, true, `${three.code}:${three.reason}`);
    assert.equal(three.value.restored, 3);
    assert.deepEqual(await used(captured.captureId), [3]);
    // 3 + 3 > 5: the whole request is denied and nothing is consumed.
    const over = await a.call("restore", { request: fields(`${token} ${token}`, token) });
    assert.deepEqual([over.ok, over.code, over.reason], [false, "RESTORE_DENIED", "budget"]);
    assert.deepEqual(await used(captured.captureId), [3]);
    const two = await a.call("restore", { request: fields(token, token) });
    assert.equal(two.ok, true);
    assert.deepEqual(await used(captured.captureId), [5]);
    evidence("A", "multi-field-repeated-token", { maxUses: 5, committed: [3, 2], deniedOverBudget: 1 });
  });

  test("a multi-entry request with one over-budget entry consumes nothing", async () => {
    const captured = await capture(a, { count: 3 });
    const single = request({ ...captured, tokens: [captured.tokens[1]] });
    assert.equal((await b.call("restore", { request: single })).ok, true);
    const before_ = await captureState(admin, namespace, captured.captureId);
    assert.equal(before_.used.reduce((sum, value) => sum + value, 0), 1);
    const all = request(captured);
    const denied = await a.call("restore", { request: all });
    assert.deepEqual([denied.ok, denied.code, denied.reason], [false, "RESTORE_DENIED", "budget"]);
    const after_ = await captureState(admin, namespace, captured.captureId);
    assert.deepEqual(after_.entries, before_.entries, "no entry row changed");
    assert.equal(await receiptCount(admin, namespace, all.attemptId), 0);
    evidence("A", "multi-entry-over-budget", { entries: 3, consumedByDenied: 0 });
  });

  test("a three-entry restore racing a one-entry restore from the other process never applies partially", async () => {
    const states = {};
    for (let trial = 0; trial < TRIALS; trial += 1) {
      const captured = await capture(a, { count: 3 });
      const ids = await Promise.all(captured.tokens.map((token) => deriveEntryId(namespace, TENANT_A.tenant, token)));
      const whole = request(captured);
      const part = request({ ...captured, tokens: [captured.tokens[2]] });
      const [wide, narrow] = await Promise.all([a.call("restore", { request: whole }), b.call("restore", { request: part })]);
      const state = await captureState(admin, namespace, captured.captureId);
      const byId = new Map(state.entries.map((entry) => [entry.entry_id, entry.used]));
      const usedInOrder = ids.map((id) => byId.get(id));
      assert.notEqual(wide.ok && narrow.ok, true, "both cannot consume the shared single-use entry");
      if (wide.ok) assert.deepEqual(usedInOrder, [1, 1, 1]);
      else if (narrow.ok) assert.deepEqual(usedInOrder, [0, 0, 1], "the denied three-entry request left its other entries untouched");
      else assert.deepEqual(usedInOrder, [0, 0, 0]);
      const label = wide.ok ? "three-entry-won" : narrow.ok ? "one-entry-won" : "neither";
      states[label] = (states[label] ?? 0) + 1;
    }
    evidence("A", "multi-entry-race-no-partial", { trials: TRIALS, states });
  });

  test("restore racing revoke across processes is linearizable", async () => {
    const maxUses = 8;
    let successes = 0;
    let afterRevoke = 0;
    let conflicts = 0;
    const seen = {};
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
        const label = outcome.ok ? "ok" : `${outcome.code}:${outcome.reason ?? ""}`;
        seen[label] = (seen[label] ?? 0) + 1;
        if (BigInt(outcome.startedAt) > acknowledged) {
          afterRevoke += 1;
          assert.equal(outcome.ok, false, "a restore that began after the revocation was acknowledged succeeded");
        }
        if (!outcome.ok) {
          assert.ok(["RESTORE_DENIED", "RESTORE_CONFLICT"].includes(outcome.code), outcome.code);
          if (outcome.code === "RESTORE_CONFLICT") conflicts += 1;
        }
      }
      assert.ok(ok.length <= maxUses);
      const state = await captureState(admin, namespace, captured.captureId);
      assert.equal(state.capture.state, "revoked");
      assert.deepEqual(state.used, [ok.length], "used equals the number of successful restores");
      successes += ok.length;
      const final = await a.call("restore", { request: request(captured) });
      assert.deepEqual([final.ok, final.code, final.reason], [false, "RESTORE_DENIED", "revoked"]);
    }
    assert.ok(afterRevoke >= TRIALS * 4, "every trial started restores after the acknowledgement");
    evidence("A", "restore-vs-revoke", { trials: TRIALS, restoresPerTrial: 12, successes, startedAfterAcknowledgedRevoke: afterRevoke, succeededAfterAcknowledgedRevoke: 0, conflicts, outcomes: seen });
  });

  test("a creation racing a fence of the same capture identifier across processes: one order or the other, always revoked", async () => {
    const orders = {};
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
      orders[order] = (orders[order] ?? 0) + 1;
      // Creation first: a live capture that is then revoked. Fence first: the creation is fenced.
      assert.ok(["created/revoked", "rejected:fenced/fenced", "rejected:stale/fenced"].includes(order), order);
      const state = await captureState(admin, namespace, input.capture.captureId);
      assert.equal(state.capture.state, "revoked");
      assert.equal(state.entries.length, order === "created/revoked" ? 2 : 0);
      const again = await a.call("store", { method: "createCapture", input: wire(input) });
      assert.deepEqual([again.value.outcome, again.value.reason], ["rejected", "fenced"]);
    }
    evidence("A", "create-vs-fence", { trials: TRIALS, orders });
  });

  test("the same attempt submitted by both processes commits once", async () => {
    const multiUse = {};
    for (let trial = 0; trial < TRIALS; trial += 1) {
      const captured = await capture(a, { maxUses: 2 });
      const req = request(captured);
      const outcomes = await Promise.all([a.call("restore", { request: req }), b.call("restore", { request: req })]);
      const ok = outcomes.filter((outcome) => outcome.ok);
      const lost = outcomes.filter((outcome) => !outcome.ok);
      assert.equal(ok.length, 1, JSON.stringify(tally(outcomes)));
      assert.deepEqual([lost[0].code, lost[0].reason], ["RESTORE_DENIED", "attempt-already-committed"]);
      assert.equal(lost[0].hasFields, false);
      assert.deepEqual(await used(captured.captureId), [1], "used incremented once");
      assert.equal(await receiptCount(admin, namespace, req.attemptId), 1);
      Object.assign(multiUse, { ok: (multiUse.ok ?? 0) + 1, "attempt-already-committed": (multiUse["attempt-already-committed"] ?? 0) + 1 });
    }
    // With a single-use entry the loser may be denied at preflight, where the
    // exhausted budget is seen before the receipt is.
    const singleUse = {};
    for (let trial = 0; trial < TRIALS; trial += 1) {
      const captured = await capture(a, { maxUses: 1 });
      const req = request(captured);
      const outcomes = await Promise.all([a.call("restore", { request: req }), b.call("restore", { request: req })]);
      assert.equal(outcomes.filter((outcome) => outcome.ok).length, 1);
      const lost = outcomes.find((outcome) => !outcome.ok);
      assert.equal(lost.code, "RESTORE_DENIED");
      assert.ok(["attempt-already-committed", "budget"].includes(lost.reason), lost.reason);
      singleUse[lost.reason] = (singleUse[lost.reason] ?? 0) + 1;
      assert.deepEqual(await used(captured.captureId), [1]);
      assert.equal(await receiptCount(admin, namespace, req.attemptId), 1);
    }
    evidence("A", "duplicate-attempt", { trials: TRIALS * 2, multiUse, singleUseLoserReason: singleUse });
  });

  test("an attempt identifier reused for a different request is a mismatch and consumes nothing", async () => {
    const captured = await capture(a, { maxUses: 3 });
    const original = request(captured, { purpose: "purpose-one" });
    assert.equal((await a.call("restore", { request: original })).ok, true);
    const different = { ...original, purpose: "purpose-two" };
    const mismatch = await b.call("restore", { request: different });
    assert.deepEqual([mismatch.ok, mismatch.code, mismatch.reason], [false, "RESTORE_DENIED", "attempt-mismatch"]);
    assert.deepEqual(await used(captured.captureId), [1]);
    const resolvedDifferent = await b.call("resolveAttempt", { request: different });
    assert.equal(resolvedDifferent.value.state, "attempt-mismatch");
    const resolvedOriginal = await b.call("resolveAttempt", { request: original });
    assert.equal(resolvedOriginal.value.state, "committed");
    evidence("A", "attempt-mismatch", { consumedByMismatch: 0 });
  });

  test("kill -9 after the commit, before the reply: the use is spent, the receipt says committed, and the value is not available again", async () => {
    const captured = await capture(a, { maxUses: 1 });
    const doomed = await worker({ hook: "kill-after-restore-commit" });
    const req = request(captured);
    const acknowledged = new Promise((resolve) => doomed.onEvent((message) => message.event === "commit-acknowledged" && resolve()));
    const reply = doomed.call("restore", { request: req }).then(
      () => "replied",
      (thrown) => (thrown.workerExited ? "no-reply" : "error"),
    );
    await acknowledged;
    const exit = await doomed.kill("SIGKILL");
    assert.equal(exit.signal, "SIGKILL");
    assert.equal(await reply, "no-reply", "the caller never received the restored fields");

    assert.deepEqual(await used(captured.captureId), [1], "the budget is consumed");
    assert.equal(await receiptCount(admin, namespace, req.attemptId), 1);
    const resolved = await b.call("resolveAttempt", { request: req });
    assert.equal(resolved.ok, true);
    assert.equal(resolved.value.state, "committed");
    assert.deepEqual(Object.keys(resolved.value).sort(), ["committedAt", "state"], "a resolution never carries fields");
    // The same attempt again, and a new attempt: neither returns the value.
    const replay = await b.call("restore", { request: req });
    assert.equal(replay.ok, false);
    assert.equal(replay.code, "RESTORE_DENIED");
    assert.ok(["attempt-already-committed", "budget"].includes(replay.reason));
    const fresh = await a.call("restore", { request: request(captured) });
    assert.deepEqual([fresh.ok, fresh.code, fresh.reason], [false, "RESTORE_DENIED", "budget"]);
    assert.deepEqual(await used(captured.captureId), [1]);
    evidence("A", "kill-9-after-commit", { signal: exit.signal, used: 1, resolveAttempt: resolved.value.state, replay: replay.reason, freshAttempt: fresh.reason });
  });

  test("tenants are isolated across processes", async () => {
    const captured = await capture(a, { maxUses: 2, context: TENANT_A });
    const foreign = request({ ...captured, context: TENANT_B });
    const denied = await b.call("restore", { request: foreign });
    assert.deepEqual([denied.ok, denied.code, denied.reason], [false, "RESTORE_DENIED", "unknown-token"]);
    const revoked = await b.call("revoke", { context: TENANT_B, captureId: captured.captureId });
    assert.equal(revoked.value.outcome, "not-found");
    const deleted = await b.call("deleteCiphertext", { context: TENANT_B, captureId: captured.captureId });
    assert.equal(deleted.value.outcome, "not-found");
    const own = request(captured);
    assert.equal((await b.call("restore", { request: own })).ok, true, "the owning tenant is unaffected");
    const resolved = await b.call("resolveAttempt", { request: { ...own, context: TENANT_B } });
    assert.equal(resolved.value.state, "absent", "another tenant cannot see the attempt");
    const state = await captureState(admin, namespace, captured.captureId);
    assert.equal(state.capture.state, "live");
    assert.deepEqual(state.used, [1]);
    const [{ n }] = await rows(admin, `SELECT count(*)::int AS n FROM "${SCHEMA}".rsv_capture WHERE namespace = $1 AND tenant = $2 AND capture_id = $3`, [namespace, TENANT_B.tenant, captured.captureId]);
    assert.equal(n, 0);
    evidence("A", "tenant-isolation", { foreignRestore: denied.reason, foreignRevoke: "not-found" });
  });

  describe("encrypted-record substitution by direct SQL as a database superuser", () => {
    const denied = async (process_, captured, expected, extra = {}) => {
      const before_ = await captureState(admin, namespace, captured.captureId);
      const req = request(captured, extra);
      const outcome = await process_.call("restore", { request: req });
      assert.equal(outcome.ok, false, "a substituted record was restored");
      assert.equal(outcome.code, "RESTORE_DENIED");
      assert.ok(expected.includes(outcome.reason), `denied ${outcome.reason}, expected one of ${expected}`);
      const after_ = await captureState(admin, namespace, captured.captureId);
      assert.deepEqual(after_.used, before_.used, "nothing was consumed");
      assert.equal(await receiptCount(admin, namespace, req.attemptId), 0);
      return outcome.reason;
    };
    const entry = `"${SCHEMA}".rsv_entry`;
    const capt = `"${SCHEMA}".rsv_capture`;

    test("envelopes swapped between two entries of one capture", async () => {
      const captured = await capture(a, { count: 2 });
      const changed = await admin.query(
        `UPDATE ${entry} x SET envelope = y.envelope FROM ${entry} y
          WHERE x.namespace = $1 AND y.namespace = $1 AND x.capture_id = $2 AND y.capture_id = $2 AND x.entry_id <> y.entry_id`,
        [namespace, captured.captureId],
      );
      assert.equal(changed.rowCount, 2);
      const reason = await denied(b, captured, ["integrity-failure"]);
      evidence("A", "substitution/envelope-swap-within-capture", { reason, consumed: 0 });
    });

    test("an envelope, and then the whole record, moved from another tenant", async () => {
      const mine = await capture(a, { context: TENANT_A });
      const theirs = await capture(a, { context: TENANT_B });
      await admin.query(
        `UPDATE ${entry} x SET envelope = y.envelope FROM ${entry} y
          WHERE x.namespace = $1 AND y.namespace = $1 AND x.capture_id = $2 AND y.capture_id = $3`,
        [namespace, mine.captureId, theirs.captureId],
      );
      const envelopeOnly = await denied(b, mine, ["integrity-failure"]);
      // The other tenant's wrapped key as well: record and key are consistent with each other, and bound to the wrong tenant.
      await admin.query(
        `UPDATE ${capt} x SET wrapped_key = y.wrapped_key, key_ref = y.key_ref FROM ${capt} y
          WHERE x.namespace = $1 AND y.namespace = $1 AND x.capture_id = $2 AND y.capture_id = $3`,
        [namespace, mine.captureId, theirs.captureId],
      );
      const wholeRecord = await denied(b, mine, ["integrity-failure", "key-unavailable"]);
      assert.equal((await b.call("restore", { request: request(theirs) })).ok, true, "the untouched source record still restores for its own tenant");
      evidence("A", "substitution/cross-tenant", { envelopeOnly, wholeRecord, consumed: 0 });
    });

    test("expires_at extended", async () => {
      const captured = await capture(a);
      await admin.query(`UPDATE ${capt} SET expires_at = expires_at + 3600000 WHERE namespace = $1 AND capture_id = $2`, [namespace, captured.captureId]);
      await admin.query(`UPDATE ${entry} SET expires_at = expires_at + 3600000 WHERE namespace = $1 AND capture_id = $2`, [namespace, captured.captureId]);
      const reason = await denied(b, captured, ["integrity-failure"]);
      evidence("A", "substitution/expires-at", { reason, consumed: 0 });
    });

    test("max_uses raised on an exhausted entry", async () => {
      const captured = await capture(a, { maxUses: 1 });
      assert.equal((await a.call("restore", { request: request(captured) })).ok, true);
      await admin.query(`UPDATE ${entry} SET max_uses = 5 WHERE namespace = $1 AND capture_id = $2`, [namespace, captured.captureId]);
      const reason = await denied(b, captured, ["integrity-failure"]);
      assert.deepEqual(await used(captured.captureId), [1]);
      evidence("A", "substitution/max-uses", { reason, consumed: 0 });
    });

    test("session_tag removed from a session-bound capture, and a foreign tag installed", async () => {
      const bound = { ...TENANT_A, session: "session-synthetic-1" };
      const other = { ...TENANT_A, session: "session-synthetic-2" };
      const captured = await capture(a, { context: bound });
      const donor = await capture(a, { context: other });
      const control = await denied(b, { ...captured, context: other }, ["source"]);
      await admin.query(`UPDATE ${capt} SET session_tag = NULL WHERE namespace = $1 AND capture_id = $2`, [namespace, captured.captureId]);
      const unbound = await denied(b, { ...captured, context: other }, ["integrity-failure"]);
      const unboundNoSession = await denied(b, { ...captured, context: TENANT_A }, ["integrity-failure"]);
      await admin.query(
        `UPDATE ${capt} x SET session_tag = y.session_tag FROM ${capt} y WHERE x.namespace = $1 AND y.namespace = $1 AND x.capture_id = $2 AND y.capture_id = $3`,
        [namespace, captured.captureId, donor.captureId],
      );
      const foreignTag = await denied(b, { ...captured, context: other }, ["source", "integrity-failure"]);
      evidence("A", "substitution/session-tag", { wrongSessionBeforeTampering: control, tagRemoved: unbound, tagRemovedNoSession: unboundNoSession, foreignTag, consumed: 0 });
    });

    test("wrapped_key swapped between two captures", async () => {
      const first = await capture(a);
      const second = await capture(a);
      const changed = await admin.query(
        `UPDATE ${capt} x SET wrapped_key = y.wrapped_key FROM ${capt} y
          WHERE x.namespace = $1 AND y.namespace = $1 AND x.capture_id = ANY($2::text[]) AND y.capture_id = ANY($2::text[]) AND x.capture_id <> y.capture_id`,
        [namespace, [first.captureId, second.captureId]],
      );
      assert.equal(changed.rowCount, 2);
      const one = await denied(b, first, ["integrity-failure", "key-unavailable"]);
      const two = await denied(a, second, ["integrity-failure", "key-unavailable"]);
      evidence("A", "substitution/wrapped-key-swap", { reasons: [one, two], consumed: 0 });
    });

    test("documented limit: a database writer who resets `used` to 0 makes a consumed value restorable again", async () => {
      const captured = await capture(a, { maxUses: 1 });
      const first = await a.call("restore", { request: request(captured) });
      assert.equal(first.ok, true);
      const exhausted = await b.call("restore", { request: request(captured) });
      assert.deepEqual([exhausted.ok, exhausted.reason], [false, "budget"]);
      await admin.query(`UPDATE ${entry} SET used = 0 WHERE namespace = $1 AND capture_id = $2`, [namespace, captured.captureId]);
      const second = await b.call("restore", { request: request(captured) });
      // This is the limit, asserted so that it cannot be mistaken for a protection:
      // authenticated encryption shows a record is authentic, not that its counter is current.
      assert.equal(second.ok, true, "a budget reset by a database writer is not detected (specification §10)");
      assert.ok(second.value.fields.body.includes(captured.values[0]));
      evidence("A", "limit/used-reset-by-database-writer", { secondRestoreSucceeded: true, specification: "§9.3, §10" });
    });
  });

  test("after both processes restart, a capture is still restorable and its consumed uses stay consumed", async () => {
    const captured = await capture(a, { maxUses: 2 });
    assert.equal((await b.call("restore", { request: request(captured) })).ok, true);
    const stopped = await a.stop();
    assert.equal(stopped.code, 0);
    await b.kill("SIGKILL");
    const a2 = await worker();
    const b2 = await worker();
    assert.ok(![a.pid, b.pid].includes(a2.pid) && ![a.pid, b.pid].includes(b2.pid));
    const restored = await a2.call("restore", { request: request(captured) });
    assert.equal(restored.ok, true, `${restored.code}:${restored.reason}`);
    assert.ok(restored.value.fields.body.includes(captured.values[0]));
    const exhausted = await b2.call("restore", { request: request(captured) });
    assert.deepEqual([exhausted.ok, exhausted.reason], [false, "budget"]);
    assert.deepEqual(await used(captured.captureId), [2]);
    a = a2;
    b = b2;
    evidence("A", "restart-both-processes", { restoredAfterRestart: true, usedAfter: 2 });
  });
});
