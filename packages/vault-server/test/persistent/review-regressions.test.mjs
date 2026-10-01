// Regression tests for the implementation review of 2026-10-01
// (docs/research/qualification-persistence-0.1.0-alpha.1.md, "Implementation review").
import assert from "node:assert/strict";
import test from "node:test";

import { captureOne, createRig, ctx, denied, registerLeakHygiene, rejects, restoreRequest, SECRET_A, SECRET_B, sleep } from "./helpers.mjs";

const S1 = "session-synthetic-0001";
const S2 = "session-synthetic-0002";

// A1: revoke and delete act on the capture identifier the session check and
// the policy saw, however the request object behaves afterwards.
for (const operation of ["revoke", "deleteCaptureCiphertext"]) {
  test(`${operation}: a request whose captureId changes after authorization still acts on the authorized capture only`, async () => {
    const rig = await createRig();
    const mine = await captureOne(rig, { context: ctx({ session: S2 }) });
    const victim = await captureOne(rig, { context: ctx({ session: S1 }), text: `other ${SECRET_B} value` });

    // A getter that answers with the caller's own capture first, then the victim's.
    let reads = 0;
    const shifting = { context: ctx({ session: S2 }) };
    Object.defineProperty(shifting, "captureId", { enumerable: true, get: () => (reads++ === 0 ? mine.captureId : victim.captureId) });
    await rig.vault[operation](shifting);
    assert.equal(reads, 1, "the identifier is read once");
    assert.equal((await rig.captureRow(victim.captureId)).state, "live", "the other session's capture is untouched");
    assert.equal((await rig.captureRow(mine.captureId)).state, "revoked");

    // A plain object mutated while the call is pending.
    const rig2 = await createRig();
    const own = await captureOne(rig2, { context: ctx({ session: S2 }) });
    const other = await captureOne(rig2, { context: ctx({ session: S1 }), text: `other ${SECRET_B} value` });
    const request = { context: ctx({ session: S2 }), captureId: own.captureId };
    const pending = rig2.vault[operation](request);
    request.captureId = other.captureId;
    await pending;
    assert.equal((await rig2.captureRow(other.captureId)).state, "live");
    assert.equal(rig2.audits.filter((event) => event.operation !== "capture" && event.outcome === "committed" && event.captureId === other.captureId).length, 0);
  });
}

// A2: a throwing policyRevision callback is a recorded failure, not a silent one.
test("a policyRevision callback that throws fails capture and denies restore, each with an audit event", async () => {
  let fail = false;
  const rig = await createRig({
    vault: {
      policyRevision: () => {
        if (fail) throw new Error("synthetic revision failure");
        return "rev-synthetic-1";
      },
    },
  });
  const captured = await captureOne(rig);
  fail = true;
  const before = rig.audits.length;
  await rejects(rig.vault.capture(`secret ${SECRET_A} here`, { context: ctx(), release: [{ sink: "sink-a", paths: ["body"] }] }), "INVALID_ARGUMENT");
  assert.equal(rig.spy.count("createCapture"), 1, "nothing was stored by the failed capture");
  await denied(rig.vault.restore(restoreRequest(captured)), "policy-evaluation-error");
  assert.deepEqual(await rig.used(captured.tokens.map((issued) => issued.token)), [0]);
  assert.equal(rig.audits.length - before, 2);
});

// A3: resolveAttempt has the bound a restore has, before any derivation work.
test("resolveAttempt refuses a request with more distinct tokens than a restore could carry, without calling the store", async () => {
  const rig = await createRig({ memoryOptions: { maxRestoreEntries: 4 } });
  const tokens = Array.from({ length: 5 }, (_unused, index) => `<rsv_${"abcdefghijklmnopqrstuvwxyz".slice(0, 25)}${"abcdefg"[index]}>`);
  const request = { context: ctx(), sink: "sink-a", purpose: "purpose-synthetic", captures: ["cap_aaaaaaaaaaaaaaaaaaaaaaaaaa"], fields: { body: tokens.join(" ") }, attemptId: "attempt-synthetic-1" };
  await rejects(rig.vault.resolveAttempt(request), "INVALID_ARGUMENT");
  assert.equal(rig.spy.count("inspectAttempt"), 0);
});

// A5: an async audit hook that rejects changes nothing and leaves no unhandled rejection.
test("an async audit hook that rejects does not affect the operation or the process", async () => {
  const unhandled = [];
  const onUnhandled = (reason) => unhandled.push(reason);
  process.on("unhandledRejection", onUnhandled);
  try {
    const rig = await createRig({ vault: { onAudit: async () => Promise.reject(new Error("synthetic audit failure")) } });
    const captured = await captureOne(rig);
    const restored = await rig.vault.restore(restoreRequest(captured));
    assert.equal(restored.restored, 1);
    await sleep(20);
    assert.equal(unhandled.length, 0);
  } finally {
    process.off("unhandledRejection", onUnhandled);
  }
});

// A6: text echoed on audit events cannot carry an issued token.
test("purpose and requestId are refused when they contain a token marker or are oversized", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  const token = captured.tokens[0].token;
  await rejects(rig.vault.restore(restoreRequest(captured, { purpose: `support ${token}` })), "INVALID_ARGUMENT");
  await rejects(rig.vault.restore(restoreRequest(captured, { requestId: `req ${token}` })), "INVALID_ARGUMENT");
  await rejects(rig.vault.restore(restoreRequest(captured, { requestId: "r".repeat(257) })), "INVALID_ARGUMENT");
  await rejects(rig.vault.revoke({ context: ctx(), captureId: captured.captureId, requestId: token }), "INVALID_ARGUMENT");
  await rejects(rig.vault.capture("plain text", { context: ctx(), release: [{ sink: "sink-a", paths: ["body"] }], requestId: token }), "INVALID_ARGUMENT");
  for (const event of rig.audits) assert.equal(JSON.stringify(event).includes(token), false);
  assert.deepEqual(await rig.used([token]), [0]);
});

registerLeakHygiene({ minErrors: 1 });
