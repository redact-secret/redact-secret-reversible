// revoke, deleteCaptureCiphertext, and close
// (docs/specs/persistent-vault.md §5.6, §5.7, §8.2, §9).
import assert from "node:assert/strict";
import test from "node:test";

import {
  ABSENT_CAPTURE,
  captureOne,
  createRig,
  CTX_A,
  CTX_B,
  ctx,
  denied,
  foreignError,
  NAMESPACE,
  registerLeakHygiene,
  rejects,
  RELEASE,
  restoreRequest,
  SECRET_A,
  SECRET_B,
  TENANT,
} from "./helpers.mjs";

const ORIGINAL = `secret ${SECRET_A} here`;
const S1 = "session-synthetic-0001";
const S2 = "session-synthetic-0002";

const DENIALS = [
  () => ({ allow: false }),
  () => {
    throw foreignError();
  },
  () => Promise.reject(foreignError()),
  () => new Promise(() => {}),
  () => true,
  () => null,
  () => ({}),
  () => ({ allow: "true" }),
];

test("revoke: an absent capture is not-found and writes nothing; the identifier stays usable at store level", async () => {
  const rig = await createRig();
  const result = await rig.vault.revoke({ context: CTX_A, captureId: ABSENT_CAPTURE });
  assert.deepEqual(result, { outcome: "not-found", entries: 0 });
  assert.ok(Object.isFrozen(result));
  assert.equal(rig.spy.mutations(), 0, "no mutating store call, so no fence and no tombstone");
  assert.deepEqual(rig.memory.control.counts(), { namespaces: 1, captures: 0, entries: 0, receipts: 0 });
  assert.equal(await rig.captureRow(ABSENT_CAPTURE), undefined);
  // The lifecycle policy was asked, and was told nothing about a capture that does not exist.
  assert.deepEqual(rig.lifecycleCalls, [
    { operation: "revoke", principal: CTX_A.principal, tenant: TENANT, sessionId: null, captureId: ABSENT_CAPTURE, requestedAt: rig.clock.now() },
  ]);

  // Nothing fenced the identifier: the store still accepts a create under it.
  const created = await rig.memory.store.createCapture({
    scope: { namespace: NAMESPACE, tenant: TENANT },
    epoch: 1,
    now: rig.clock.now(),
    capture: {
      captureId: ABSENT_CAPTURE,
      sessionTag: null,
      createdAt: rig.clock.now(),
      expiresAt: rig.clock.now() + 60_000,
      lookupVersion: 1,
      keyRef: "local:synthetic-2026-10",
      wrappedKey: Uint8Array.from({ length: 61 }, (_unused, index) => index),
    },
    entries: [{ entryId: "ab".repeat(32), maxUses: 1, envelope: Uint8Array.from({ length: 40 }, (_unused, index) => index) }],
  });
  assert.deepEqual(created, { outcome: "created" });
});

test("revoke: another tenant's capture is not-found, and stays live for its owner", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  assert.deepEqual(await rig.vault.revoke({ context: CTX_B, captureId: captured.captureId }), { outcome: "not-found", entries: 0 });
  assert.deepEqual(await rig.vault.deleteCaptureCiphertext({ context: CTX_B, captureId: captured.captureId }), {
    outcome: "not-found",
    entries: 0,
    keyRetired: false,
  });
  assert.equal(rig.spy.mutations(), 1, "only the capture itself was ever written");
  assert.equal((await rig.captureRow(captured.captureId)).state, "live");
  assert.equal((await rig.vault.restore(restoreRequest(captured))).fields.body, ORIGINAL);
});

test("revoke: denies future restores, keeps the ciphertext, and is idempotent", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { text: `a ${SECRET_A} b ${SECRET_B}`, maxUses: 3 });
  await rig.vault.restore(restoreRequest(captured));
  const first = await rig.vault.revoke({ context: CTX_A, captureId: captured.captureId, requestId: "request-synthetic-0001" });
  assert.deepEqual(first, { outcome: "revoked", entries: 2 });
  assert.deepEqual(rig.audits.at(-1), {
    operation: "revoke",
    outcome: "committed",
    at: rig.clock.now(),
    principalId: CTX_A.principal.id,
    tenant: TENANT,
    entries: 2,
    captureId: captured.captureId,
    requestId: "request-synthetic-0001",
  });
  const { input } = rig.spy.last("revokeCapture");
  assert.equal(input.fenceAbsent, false, "a public revoke never writes a fence");
  assert.equal(input.retentionMs, 24 * 60 * 60 * 1000);
  assert.deepEqual(input.scope, { namespace: NAMESPACE, tenant: TENANT });

  assert.deepEqual(await rig.vault.revoke({ context: CTX_A, captureId: captured.captureId }), { outcome: "already-revoked", entries: 2 });
  assert.deepEqual(await (await rig.open()).revoke({ context: CTX_A, captureId: captured.captureId }), { outcome: "already-revoked", entries: 2 });
  await denied(rig.vault.restore(restoreRequest(captured)), "revoked");
  // Revocation is not deletion: the rows are still there, with what was consumed.
  assert.deepEqual(rig.memory.control.counts(), { namespaces: 1, captures: 1, entries: 2, receipts: 1 });
  assert.deepEqual(await rig.used(captured.tokens.map(({ token }) => token)), [1, 1]);
  assert.equal(rig.lifecycleCalls.filter((call) => call.operation === "revoke").every((call) => call.sessionBound === false), true);
});

test("revoke: works in a quarantined namespace", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  await rig.memory.store.quarantine({ namespace: NAMESPACE });
  assert.deepEqual(await rig.vault.revoke({ context: CTX_A, captureId: captured.captureId }), { outcome: "revoked", entries: 1 });
  assert.equal((await rig.captureRow(captured.captureId)).state, "revoked");
});

test("revoke and delete: a session-bound capture is managed only from its own session", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { context: ctx({ session: S1 }) });
  const noResolver = await rig.open({ resolveSession: undefined });
  const before = rig.spy.mutations();
  for (const operation of ["revoke", "deleteCaptureCiphertext"]) {
    await rejects(rig.vault[operation]({ context: ctx({ session: S2 }), captureId: captured.captureId }), "LIFECYCLE_DENIED");
    await rejects(rig.vault[operation]({ context: CTX_A, captureId: captured.captureId }), "LIFECYCLE_DENIED");
    await rejects(noResolver[operation]({ context: ctx({ session: S1 }), captureId: captured.captureId }), "LIFECYCLE_DENIED");
    assert.equal(rig.audits.at(-1).outcome, "denied");
    assert.equal(rig.audits.at(-1).code, "LIFECYCLE_DENIED");
  }
  assert.equal(rig.spy.mutations(), before, "no store mutation");
  assert.equal((await rig.captureRow(captured.captureId)).state, "live");
  assert.equal((await rig.vault.restore(restoreRequest(captured, { context: ctx({ session: S1 }) }))).fields.body, ORIGINAL);

  // Its own session may revoke it, and the policy is told the capture is session-bound.
  rig.lifecycleCalls.length = 0;
  assert.equal((await rig.vault.revoke({ context: ctx({ session: S1 }), captureId: captured.captureId })).outcome, "revoked");
  assert.deepEqual(rig.lifecycleCalls, [
    {
      operation: "revoke",
      principal: CTX_A.principal,
      tenant: TENANT,
      sessionId: S1,
      captureId: captured.captureId,
      sessionBound: true,
      requestedAt: rig.clock.now(),
    },
  ]);
  // A tombstone keeps its session tag: still not manageable from elsewhere.
  await rejects(rig.vault.deleteCaptureCiphertext({ context: ctx({ session: S2 }), captureId: captured.captureId }), "LIFECYCLE_DENIED");
  assert.equal((await rig.vault.deleteCaptureCiphertext({ context: ctx({ session: S1 }), captureId: captured.captureId })).outcome, "deleted");
});

test("revoke and delete: a lifecyclePolicy deny, throw, timeout, or malformed return is LIFECYCLE_DENIED before any store mutation", async () => {
  const rig = await createRig({ vault: { policyTimeoutMs: 25 } });
  const captured = await captureOne(rig);
  const before = rig.spy.mutations();
  rig.lifecycleCalls.length = 0;
  for (const operation of ["revoke", "deleteCaptureCiphertext"]) {
    for (const behaviour of DENIALS) {
      rig.lifecycle = behaviour;
      await rejects(rig.vault[operation]({ context: CTX_A, captureId: captured.captureId }), "LIFECYCLE_DENIED");
      await rejects(rig.vault[operation]({ context: CTX_A, captureId: ABSENT_CAPTURE }), "LIFECYCLE_DENIED");
    }
  }
  assert.equal(rig.lifecycleCalls.length, DENIALS.length * 4, "asked once per call");
  assert.deepEqual([...new Set(rig.lifecycleCalls.map((call) => call.operation))], ["revoke", "delete-ciphertext"]);
  assert.equal(rig.spy.mutations(), before);
  assert.equal(rig.spy.count("revokeCapture") + rig.spy.count("deleteCiphertext"), 0);
  assert.equal((await rig.captureRow(captured.captureId)).state, "live");
  rig.lifecycle = () => ({ allow: true });
  assert.equal((await rig.vault.restore(restoreRequest(captured))).fields.body, ORIGINAL);
});

test("revoke and delete: an unresolved principal is LIFECYCLE_DENIED with no store call; a malformed request is INVALID_ARGUMENT", async () => {
  const rig = await createRig({ vault: { resolverTimeoutMs: 25 } });
  const captured = await captureOne(rig);
  rig.spy.reset();
  for (const operation of ["revoke", "deleteCaptureCiphertext"]) {
    for (const context of [undefined, {}, { principal: { id: "principal-synthetic-0001" } }, { principal: new Promise(() => {}) }, { ...CTX_A, session: 7 }]) {
      await rejects(rig.vault[operation]({ context, captureId: captured.captureId }), "LIFECYCLE_DENIED");
    }
    await rejects(rig.vault[operation](null), "INVALID_ARGUMENT");
    await rejects(rig.vault[operation]("request"), "INVALID_ARGUMENT");
    await rejects(rig.vault[operation]({ context: CTX_A }), "INVALID_ARGUMENT");
    await rejects(rig.vault[operation]({ context: CTX_A, captureId: "cap_short" }), "INVALID_ARGUMENT");
    await rejects(rig.vault[operation]({ context: CTX_A, captureId: captured.captureId.toUpperCase() }), "INVALID_ARGUMENT");
    await rejects(rig.vault[operation]({ context: CTX_A, captureId: captured.captureId, requestId: 7 }), "INVALID_ARGUMENT");
  }
  assert.equal(rig.spy.calls.length, 0);
  assert.equal(rig.lifecycleCalls.filter((call) => call.operation !== "capture").length, 0);
});

test("deleteCaptureCiphertext: revokes, removes the ciphertext, retires no key, and is idempotent", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { text: `a ${SECRET_A} b ${SECRET_B}`, maxUses: 2 });
  const kept = await captureOne(rig);
  rig.spy.reset();
  const deleted = await rig.vault.deleteCaptureCiphertext({ context: CTX_A, captureId: captured.captureId });
  assert.deepEqual(deleted, { outcome: "deleted", entries: 2, keyRetired: false });
  assert.ok(Object.isFrozen(deleted));
  assert.deepEqual(rig.spy.calls.map((call) => call.operation), ["readCaptures", "revokeCapture", "deleteCiphertext"]);
  assert.equal(rig.spy.last("revokeCapture").input.fenceAbsent, false);
  assert.deepEqual(rig.audits.at(-1), {
    operation: "delete-ciphertext",
    outcome: "committed",
    at: rig.clock.now(),
    principalId: CTX_A.principal.id,
    tenant: TENANT,
    entries: 2,
    captureId: captured.captureId,
  });

  // The entries and the stored key are gone; a tombstone remains.
  const row = await rig.captureRow(captured.captureId);
  assert.equal(row.state, "revoked");
  assert.equal(row.keyRef, "");
  assert.equal(row.wrappedKey.byteLength, 0);
  assert.equal((await rig.rows(captured.tokens.map(({ token }) => token))).entries.length, 0);
  assert.deepEqual(rig.memory.control.counts(), { namespaces: 1, captures: 2, entries: 1, receipts: 0 });
  // §8.3: after its ciphertext is deleted, a revoked capture's token is unknown.
  await denied(rig.vault.restore(restoreRequest(captured)), "unknown-token");
  await denied((await rig.open()).restore(restoreRequest(captured)), "unknown-token");
  assert.equal(rig.keys.stats.unwrap, 0);

  // Idempotent.
  for (let i = 0; i < 2; i += 1) {
    assert.deepEqual(await rig.vault.deleteCaptureCiphertext({ context: CTX_A, captureId: captured.captureId }), {
      outcome: "deleted",
      entries: 0,
      keyRetired: false,
    });
  }
  assert.deepEqual(await rig.vault.revoke({ context: CTX_A, captureId: captured.captureId }), { outcome: "already-revoked", entries: 0 });
  // There is no tenant-wide delete: the other capture of the tenant is untouched.
  assert.equal((await rig.vault.restore(restoreRequest(kept))).fields.body, ORIGINAL);
});

test("deleteCaptureCiphertext: an absent capture is not-found with keyRetired false and no mutation; an already revoked one is deleted", async () => {
  const rig = await createRig();
  assert.deepEqual(await rig.vault.deleteCaptureCiphertext({ context: CTX_A, captureId: ABSENT_CAPTURE }), {
    outcome: "not-found",
    entries: 0,
    keyRetired: false,
  });
  assert.equal(rig.spy.mutations(), 0);
  assert.equal(await rig.captureRow(ABSENT_CAPTURE), undefined);

  const captured = await captureOne(rig);
  await rig.vault.revoke({ context: CTX_A, captureId: captured.captureId });
  await denied(rig.vault.restore(restoreRequest(captured)), "revoked");
  assert.deepEqual(await rig.vault.deleteCaptureCiphertext({ context: CTX_A, captureId: captured.captureId }), {
    outcome: "deleted",
    entries: 1,
    keyRetired: false,
  });
  await denied(rig.vault.restore(restoreRequest(captured)), "unknown-token");
});

test("revoke and delete: store failures and malformed answers fail closed", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  const request = { context: CTX_A, captureId: captured.captureId };

  for (const operation of ["revoke", "deleteCaptureCiphertext"]) {
    rig.failNext("readCaptures", { kind: "unavailable" });
    await rejects(rig.vault[operation](request), "STORE_UNAVAILABLE");
    rig.failNext("readCaptures", { kind: "foreign-error", when: "before" });
    await rejects(rig.vault[operation](request), "STORE_UNAVAILABLE");
    for (const shape of ["null", "wrong-types", "foreign-entry"]) {
      rig.failNext("readCaptures", { kind: "malformed", shape });
      await rejects(rig.vault[operation](request), "INVARIANT_VIOLATION");
    }
    for (const result of [[null], ["capture"], [{ captureId: ABSENT_CAPTURE, sessionTag: null }], [{ captureId: captured.captureId, sessionTag: "zz" }]]) {
      rig.failNext("readCaptures", { kind: "result", result, delegate: false });
      await rejects(rig.vault[operation](request), "INVARIANT_VIOLATION");
    }
  }
  assert.equal(rig.spy.count("revokeCapture"), 0, "none of those reached a mutation");
  assert.equal(rig.lifecycleCalls.filter((call) => call.operation !== "capture").length, 0);

  // A revocation whose outcome is unknown is reported as a failure the caller retries; it is idempotent.
  rig.failNext("revokeCapture", { kind: "ambiguous", applied: true });
  await rejects(rig.vault.revoke(request), "STORE_UNAVAILABLE");
  assert.deepEqual(await rig.vault.revoke(request), { outcome: "already-revoked", entries: 1 });
  for (const fault of [
    { kind: "malformed", shape: "null" },
    { kind: "malformed", shape: "wrong-types" },
    { kind: "result", result: { outcome: "revoked", entries: -1 }, delegate: false },
    { kind: "result", result: { outcome: "revoked", entries: "1" }, delegate: false },
    { kind: "result", result: { outcome: "fenced" }, delegate: false },
  ]) {
    rig.failNext("revokeCapture", fault);
    await rejects(rig.vault.revoke(request), "INVARIANT_VIOLATION");
  }

  rig.failNext("deleteCiphertext", { kind: "unavailable" });
  await rejects(rig.vault.deleteCaptureCiphertext(request), "STORE_UNAVAILABLE");
  rig.failNext("deleteCiphertext", { kind: "foreign-error", when: "before" });
  await rejects(rig.vault.deleteCaptureCiphertext(request), "STORE_UNAVAILABLE");
  for (const [result, code] of [
    [{ outcome: "rejected", reason: "live" }, "INVARIANT_VIOLATION"],
    [{ outcome: "rejected", reason: "clock-skew" }, "CLOCK_SKEW"],
    [{ outcome: "deleted", entries: -1 }, "INVARIANT_VIOLATION"],
    [{ outcome: "deleted" }, "INVARIANT_VIOLATION"],
    [null, "INVARIANT_VIOLATION"],
  ]) {
    rig.failNext("deleteCiphertext", { kind: "result", result, delegate: false });
    await rejects(rig.vault.deleteCaptureCiphertext(request), code);
  }
  assert.deepEqual(await rig.vault.deleteCaptureCiphertext(request), { outcome: "deleted", entries: 1, keyRetired: false });
});

test("close: every method is CLOSED afterwards, no store call is made, and the store still holds the data", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { maxUses: 2 });
  const attempt = restoreRequest(captured, { attemptId: "attempt-synthetic-0001" });
  await rig.vault.restore(attempt);
  const counts = rig.memory.control.counts();
  rig.spy.reset();

  assert.equal(await rig.vault.close(), undefined);
  assert.equal(await rig.vault.close(), undefined, "close is idempotent");
  assert.equal(rig.spy.calls.length, 0, "close touches no store");

  await rejects(rig.vault.capture(ORIGINAL, { context: CTX_A, release: RELEASE }), "CLOSED");
  await rejects(rig.vault.restore(restoreRequest(captured)), "CLOSED");
  await rejects(rig.vault.restore(null), "CLOSED");
  await rejects(rig.vault.revoke({ context: CTX_A, captureId: captured.captureId }), "CLOSED");
  await rejects(rig.vault.deleteCaptureCiphertext({ context: CTX_A, captureId: captured.captureId }), "CLOSED");
  await rejects(rig.vault.resolveAttempt(attempt), "CLOSED");
  assert.equal(rig.spy.calls.length, 0);
  assert.equal(rig.lifecycleCalls.filter((call) => call.operation !== "capture").length, 0);
  assert.equal(rig.vault.namespace, NAMESPACE);

  // close revoked nothing and deleted nothing.
  assert.deepEqual(rig.memory.control.counts(), counts);
  assert.equal((await rig.captureRow(captured.captureId)).state, "live");
  const second = await rig.open();
  assert.equal((await second.restore(restoreRequest(captured))).fields.body, ORIGINAL);
  assert.equal((await second.resolveAttempt(attempt)).state, "committed");
});

registerLeakHygiene({ minErrors: 100 });
