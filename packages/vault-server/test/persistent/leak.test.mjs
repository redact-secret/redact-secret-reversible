// Leak hygiene (docs/specs/persistent-vault.md §4.1, §8.2; issue #110):
// nothing a store, a key provider, a crypto layer, or a callback throws, and
// nothing the server holds, reaches an error, an audit event, or the console.
//
// Every other file of this directory applies the same checks to every error
// it expects (helpers.mjs `rejects`) and ends with the same final scan. This
// file drives the faults that carry foreign text, and first proves the
// detector itself is not vacuous.
import assert from "node:assert/strict";
import test from "node:test";

import { KeyProviderError, RecordCryptoError, StoreError } from "@redact-secret/vault-contracts";

import {
  assertAuditClean,
  assertErrorClean,
  captureOne,
  createRig,
  CTX_A,
  ctx,
  failureOf,
  foreignError,
  hex,
  KEY_MATERIAL,
  leakStats,
  noteSecret,
  observedTokens,
  PURPOSE,
  registerLeakHygiene,
  RELEASE,
  restoreRequest,
  SECRET_A,
  SECRET_B,
  SINK,
  SYNTHETIC_SECRET_MARKER,
  TENANT,
  VaultServerError,
} from "./helpers.mjs";

const TWO = `first ${SECRET_A} second ${SECRET_B} end`;

test("detector: the leak check fails for each kind of thing that must not leak, through each surface", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  const envelope = rig.spy.last("createCapture").input.entries[0].envelope;
  const wrappedKey = rig.spy.last("createCapture").input.capture.wrappedKey;
  const forbidden = [
    SECRET_A,
    captured.tokens[0].token,
    captured.captureId,
    hex(KEY_MATERIAL),
    Buffer.from(KEY_MATERIAL).toString("base64"),
    hex(envelope),
    Buffer.from(envelope).toString("base64"),
    hex(wrappedKey),
    SYNTHETIC_SECRET_MARKER,
  ];
  const clean = new VaultServerError("STORE_UNAVAILABLE");
  assertErrorClean(clean);
  for (const value of forbidden) {
    const viaProperty = new VaultServerError("STORE_UNAVAILABLE");
    viaProperty.reason = `detail ${value}`;
    assert.throws(() => assertErrorClean(viaProperty), /leaks a/);

    const viaHidden = new VaultServerError("STORE_UNAVAILABLE");
    Object.defineProperty(viaHidden, "attemptId", { value: { nested: [value] }, enumerable: false });
    assert.throws(() => assertErrorClean(viaHidden), /leaks a/);

    const viaStack = new VaultServerError("STORE_UNAVAILABLE");
    viaStack.stack = `${viaStack.stack}\n    at ${value}`;
    assert.throws(() => assertErrorClean(viaStack), /leaks a/);

    assert.throws(
      () => assertAuditClean(Object.freeze({ operation: "restore", outcome: "denied", at: 1, purpose: `p ${value}` })),
      /leaks a/,
    );
  }
  // A data key seen by the provider spy is covered as well.
  assert.ok(leakStats().sensitive > forbidden.length);

  const withCause = new VaultServerError("STORE_UNAVAILABLE");
  withCause.cause = new Error("synthetic");
  assert.throws(() => assertErrorClean(withCause), /cause/);
  const withExtra = new VaultServerError("STORE_UNAVAILABLE");
  withExtra.detail = "synthetic";
  assert.throws(() => assertErrorClean(withExtra), /undocumented property/);
  const withMessage = new VaultServerError("STORE_UNAVAILABLE");
  withMessage.message = "synthetic driver said no";
  assert.throws(() => assertErrorClean(withMessage), /fixed message/);
  assert.throws(() => assertErrorClean(new Error("plain")), /expected a VaultServerError/);

  assert.throws(() => assertAuditClean(Object.freeze({ operation: "restore", outcome: "denied", at: 1, token: "synthetic" })), /undocumented field/);
  assert.throws(() => assertAuditClean(Object.freeze({ operation: "restore", outcome: "denied", at: 1, entries: { n: 1 } })), /must be a string or a number/);
  assert.throws(() => assertAuditClean({ operation: "restore", outcome: "denied", at: 1 }), /frozen/);
  // A capture identifier is allowed in an audit event's captureId field, and nowhere else.
  assertAuditClean(Object.freeze({ operation: "revoke", outcome: "committed", at: 1, captureId: captured.captureId }));
  assert.throws(
    () => assertAuditClean(Object.freeze({ operation: "revoke", outcome: "committed", at: 1, requestId: captured.captureId })),
    /leaks a capture identifier/,
  );
});

/** Every public operation, once, against whatever the rig currently does. Each failure is checked and recorded. */
async function exercise(rig, captured) {
  const failures = [];
  const note = async (promise) => {
    const failure = await failureOf(promise);
    if (failure !== undefined) failures.push(failure.code);
  };
  await note(rig.vault.capture(TWO, { context: CTX_A, release: RELEASE }));
  // The token of a failed capture, which only the entry-identifier spy saw, must not leak either.
  noteSecret("issued token", observedTokens.at(-1)?.token);
  await note(rig.vault.restore(restoreRequest(captured, { attemptId: "attempt-synthetic-leak" })));
  await note(rig.vault.resolveAttempt(restoreRequest(captured, { attemptId: "attempt-synthetic-leak" })));
  await note(rig.vault.revoke({ context: CTX_A, captureId: captured.captureId }));
  await note(rig.vault.deleteCaptureCiphertext({ context: CTX_A, captureId: captured.captureId }));
  return failures;
}

const STORE_FAULTS = [
  { kind: "foreign-error", when: "before" },
  { kind: "foreign-error", when: "after" },
  { kind: "ambiguous", applied: true },
  { kind: "ambiguous", applied: false },
  { kind: "unavailable" },
  { kind: "malformed", shape: "null" },
  { kind: "malformed", shape: "wrong-types" },
];
const SERVER_OPERATIONS = ["createCapture", "readEntries", "readCaptures", "commitRestore", "revokeCapture", "inspectAttempt", "deleteCiphertext"];

test("store faults: every operation the server calls, failing in every way, yields only fixed, clean errors", async () => {
  let failures = 0;
  for (const operation of SERVER_OPERATIONS) {
    for (const fault of STORE_FAULTS) {
      const rig = await createRig();
      const captured = await captureOne(rig, { maxUses: 4 });
      rig.faults.add({ operation, fault });
      const codes = await exercise(rig, captured);
      assert.ok(codes.length >= 1, `${operation}/${fault.kind}: the fault was reached`);
      failures += codes.length;
    }
  }
  assert.ok(failures >= SERVER_OPERATIONS.length * STORE_FAULTS.length);
});

test("store faults: a StoreError whose text was replaced with foreign text does not pass through", async () => {
  for (const code of ["STORE_UNAVAILABLE", "STORE_AMBIGUOUS", "STORE_INVALID_ARGUMENT", "STORE_CAPABILITY", "STORE_CLOSED"]) {
    for (const operation of SERVER_OPERATIONS) {
      const rig = await createRig();
      const captured = await captureOne(rig, { maxUses: 4 });
      rig.spy.before[operation] = () => {
        const error = new StoreError(code);
        error.message = `${SYNTHETIC_SECRET_MARKER} ${SECRET_A}`;
        error.detail = SECRET_A;
        error.cause = foreignError();
        throw error;
      };
      assert.ok((await exercise(rig, captured)).length >= 1);
    }
  }
});

test("key provider and crypto faults: foreign and tampered errors never pass through", async () => {
  const tampered = (ErrorClass, code) => {
    const error = new ErrorClass(code);
    error.message = `${SYNTHETIC_SECRET_MARKER} ${SECRET_A}`;
    error.cause = foreignError();
    return error;
  };
  const throwers = [
    () => {
      throw foreignError();
    },
    () => Promise.reject(foreignError()),
    () => {
      throw tampered(KeyProviderError, "KEY_UNAVAILABLE");
    },
    () => {
      throw tampered(KeyProviderError, "KEY_INTEGRITY");
    },
    () => {
      throw SECRET_A;
    },
    () => {
      throw null;
    },
  ];
  for (const thrower of throwers) {
    const rig = await createRig();
    const captured = await captureOne(rig, { maxUses: 4 });
    rig.keys.fail.generate = thrower;
    rig.keys.fail.unwrap = thrower;
    assert.deepEqual(await exercise(rig, captured).then((codes) => codes.slice(0, 2)), ["KEY_UNAVAILABLE", "RESTORE_DENIED"]);
  }
  const cryptoThrowers = [
    ...throwers,
    () => {
      throw tampered(RecordCryptoError, "RECORD_INTEGRITY");
    },
    () => {
      throw tampered(RecordCryptoError, "RECORD_LIMIT");
    },
  ];
  for (const thrower of cryptoThrowers) {
    const rig = await createRig();
    const captured = await captureOne(rig, { maxUses: 4 });
    rig.vault = await rig.open({ crypto: { ...rig.crypto, sealCapture: thrower, openCapture: thrower } });
    const codes = await exercise(rig, captured);
    assert.equal(codes[1], "RESTORE_DENIED");
    assert.equal(codes.length >= 2, true);
  }
});

test("callback faults: what a resolver, a policy, a lifecycle policy, a clock, or an audit hook throws never passes through", async () => {
  const thrower = () => {
    const error = foreignError();
    error.message = `${error.message} ${SECRET_A}`;
    throw error;
  };
  for (const override of [
    { resolvePrincipal: thrower },
    { resolveSession: thrower },
    { policy: thrower },
    { lifecyclePolicy: thrower },
    { policyRevision: thrower },
    { now: thrower },
  ]) {
    const rig = await createRig();
    const captured = await captureOne(rig, { maxUses: 4 });
    rig.vault = await rig.open(override).catch(() => undefined);
    if (rig.vault === undefined) continue;
    assert.ok((await exercise(rig, captured)).length >= 1, `${Object.keys(override)[0]}: the fault was reached`);
  }

  // An audit hook that throws changes no outcome, and its text goes nowhere.
  const rig = await createRig();
  let audited = 0;
  const noisy = await rig.open({
    onAudit: () => {
      audited += 1;
      thrower();
    },
  });
  const captured = await captureOne(rig, { vault: noisy });
  assert.equal((await noisy.restore(restoreRequest(captured))).fields.body, `secret ${SECRET_A} here`);
  assert.equal((await failureOf(noisy.restore(restoreRequest(captured)))).reason, "budget");
  assert.equal((await noisy.revoke({ context: CTX_A, captureId: captured.captureId })).outcome, "revoked");
  assert.equal(audited, 4);
});

test("request text: a value or a token placed in a denied request does not come back in the error", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  const token = captured.tokens[0].token;
  const requests = [
    restoreRequest(captured, { fields: { body: `${SECRET_B} ${token} rsv_` } }),
    restoreRequest(captured, { fields: { body: `${SECRET_B} ${token}` }, sink: "sink-not-granted" }),
    restoreRequest(captured, { fields: { [SECRET_B]: token } }),
    restoreRequest(captured, { fields: { body: token }, context: ctx({ tenant: "tenant-other-synthetic" }) }),
    restoreRequest(captured, { fields: { body: token }, captures: ["cap_bbbbbbbbbbbbbbbbbbbbbbbbbb"] }),
    restoreRequest(captured, { fields: { body: token }, attemptId: `bad attempt ${SECRET_B}` }),
    restoreRequest(captured, { fields: { body: token }, sink: 7, requestId: SECRET_B }),
  ];
  for (const request of requests) assert.ok((await failureOf(rig.vault.restore(request))) instanceof VaultServerError);
  assert.ok((await failureOf(rig.vault.capture(`${SECRET_A} ${token}`, { context: CTX_A, release: RELEASE }))) instanceof VaultServerError);
  assert.ok((await failureOf(rig.vault.capture(TWO, { context: CTX_A, release: [{ sink: SINK, paths: [7] }] }))) instanceof VaultServerError);
  assert.ok((await failureOf(rig.vault.revoke({ context: CTX_A, captureId: `cap_${SECRET_B}` }))) instanceof VaultServerError);
});

test("audit: across every operation and outcome, events carry only the documented fields and never a value, token, or key", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { text: TWO, maxUses: 2, requestId: "request-synthetic-0001" });
  await rig.vault.restore(restoreRequest(captured, { requestId: "request-synthetic-0002" }));
  await failureOf(rig.vault.restore(restoreRequest(captured, { sink: "sink-not-granted" })));
  await failureOf(rig.vault.restore(restoreRequest(captured, { context: {} })));
  rig.policy = () => {
    throw foreignError();
  };
  await failureOf(rig.vault.restore(restoreRequest(captured)));
  rig.policy = () => ({ allow: true });
  rig.failNext("commitRestore", { kind: "foreign-error", when: "after" });
  const ambiguous = await failureOf(rig.vault.restore(restoreRequest(captured)));
  await rig.vault.resolveAttempt(restoreRequest(captured, { attemptId: ambiguous.attemptId }));
  rig.lifecycle = () => ({ allow: false });
  await failureOf(rig.vault.revoke({ context: CTX_A, captureId: captured.captureId }));
  rig.lifecycle = () => ({ allow: true });
  await rig.vault.revoke({ context: CTX_A, captureId: captured.captureId });
  await rig.vault.deleteCaptureCiphertext({ context: CTX_A, captureId: captured.captureId });
  rig.failNext("createCapture", { kind: "foreign-error", when: "after" });
  await failureOf(rig.vault.capture(TWO, { context: CTX_A, release: RELEASE }));

  const operations = new Set(rig.audits.map((event) => `${event.operation}/${event.outcome}`));
  for (const expected of [
    "capture/committed",
    "capture/failed",
    "restore/committed",
    "restore/denied",
    "restore/failed",
    "resolve-principal/denied",
    "policy-error/failed",
    "resolve-attempt/committed",
    "revoke/denied",
    "revoke/committed",
    "delete-ciphertext/committed",
  ]) {
    assert.ok(operations.has(expected), `an audit event for ${expected}`);
  }
  for (const event of rig.audits) {
    assertAuditClean(event);
    assert.equal(event.at, rig.clock.now());
    if (event.tenant !== undefined) assert.equal(event.tenant, TENANT);
    if (event.purpose !== undefined) assert.equal(event.purpose, PURPOSE);
    assert.equal("path" in event, false);
  }
});

registerLeakHygiene({ minErrors: 150 });
