import assert from "node:assert/strict";
import { test } from "node:test";

import {
  isCaptureId,
  isEntryId,
  isIdentifier,
  isNamespace,
  isWellFormed,
  KeyProviderError,
  LIMITS,
  missingCapabilities,
  RecordCryptoError,
  StoreError,
  validateCommitRestore,
  validateCreateCapture,
  validateDeleteCiphertext,
  validateInitializeNamespace,
  validateInvalidateRecovered,
  validateReadCaptures,
  validateReadEntries,
  validateReplaceCaptureKey,
  validateRevokeCapture,
  validateSweep,
} from "../dist/index.js";

const scope = { namespace: "ns-synthetic", tenant: "tenant-acme-synthetic" };
const captureId = `cap_${"a".repeat(26)}`;
const entryId = "0".repeat(64);
const entryId2 = "1".repeat(64);
const caps = {
  contractVersion: 1,
  adapter: "test",
  profile: "test",
  atomicCreate: true,
  maxCreateEntries: 4,
  maxCreateBytes: 64,
  atomicRestore: true,
  maxRestoreEntries: 4,
  maxRestoreCaptures: 2,
  authoritativeCommit: true,
  revocationFences: true,
  attemptReceipts: true,
  storeClock: true,
  maxClockSkewMs: 2000,
  durability: "durable",
  crossProcess: true,
  restoreDetection: "none",
  maxEnvelopeBytes: 32,
};

const create = (patch = {}, capturePatch = {}, entries) => ({
  scope,
  epoch: 1,
  now: 1000,
  capture: {
    captureId,
    sessionTag: null,
    createdAt: 1000,
    expiresAt: 2000,
    lookupVersion: 1,
    keyRef: "local:k1",
    wrappedKey: new Uint8Array([1]),
    ...capturePatch,
  },
  entries: entries ?? [{ entryId, maxUses: 1, envelope: new Uint8Array(8) }],
  ...patch,
});

const commit = (patch = {}) => ({
  scope,
  epoch: 1,
  now: 1000,
  attempt: { attemptId: "attempt-1", requestDigest: new Uint8Array(32) },
  receiptExpiresAt: 3000,
  captures: [{ captureId, generation: 1 }],
  uses: [{ entryId, captureId, count: 1, lifecycleRevision: 1, ciphertextRevision: 1 }],
  ...patch,
});

const code = (fn) => {
  try {
    fn();
  } catch (thrown) {
    assert.ok(thrown instanceof StoreError);
    return thrown.code;
  }
  return "ok";
};

test("identifier predicates", () => {
  assert.ok(isNamespace("support-prod.eu:1"));
  assert.ok(!isNamespace("has space"));
  assert.ok(!isNamespace("x".repeat(129)));
  assert.ok(isIdentifier("tenant-\u{1F600}"));
  assert.ok(!isIdentifier("lone-\ud800"));
  assert.ok(!isIdentifier("\udc00-lone"));
  assert.ok(!isIdentifier(""));
  assert.ok(!isIdentifier("x".repeat(257)));
  assert.ok(isWellFormed("😀"));
  assert.ok(isCaptureId(captureId));
  assert.ok(!isCaptureId("cap_" + "A".repeat(26)));
  assert.ok(isEntryId(entryId));
  assert.ok(!isEntryId("F".repeat(64)));
});

test("errors carry a fixed message and no cause", () => {
  for (const error of [
    new StoreError("STORE_AMBIGUOUS"),
    new KeyProviderError("KEY_INTEGRITY"),
    new RecordCryptoError("RECORD_INTEGRITY"),
  ]) {
    assert.equal(error.cause, undefined);
    assert.deepEqual(Object.keys(error).sort(), ["code", "name"]);
    assert.match(error.message, /^[A-Za-z ;,.'-]+$/);
  }
});

test("missingCapabilities accepts a complete store and names each gap", () => {
  assert.deepEqual(missingCapabilities(caps), []);
  for (const flag of ["atomicCreate", "atomicRestore", "authoritativeCommit", "revocationFences", "attemptReceipts", "storeClock"]) {
    assert.deepEqual(missingCapabilities({ ...caps, [flag]: false }), [flag]);
  }
  assert.deepEqual(missingCapabilities({ ...caps, contractVersion: 2 }), ["contractVersion"]);
  assert.deepEqual(missingCapabilities({ ...caps, maxCreateEntries: LIMITS.maxCreateEntries + 1 }), ["maxCreateEntries"]);
  assert.deepEqual(missingCapabilities({ ...caps, maxRestoreCaptures: 0 }), ["maxRestoreCaptures"]);
  assert.deepEqual(missingCapabilities({ ...caps, maxClockSkewMs: 120_000 }), ["maxClockSkewMs"]);
  assert.deepEqual(missingCapabilities(null), ["capabilities"]);
});

test("createCapture validation", () => {
  assert.equal(code(() => validateCreateCapture(create(), caps)), "ok");
  const bad = [
    create({ scope: { namespace: "bad ns", tenant: "t" } }),
    create({ scope: { namespace: "ns", tenant: "lone-\ud800" } }),
    create({ epoch: 0 }),
    create({ now: 1.5 }),
    create({}, { captureId: "cap_short" }),
    create({}, { sessionTag: "nothex" }),
    create({}, { expiresAt: 1000 }),
    create({}, { expiresAt: 1000 + LIMITS.maxCaptureLifetimeMs + 1 }),
    create({}, { lookupVersion: 2 }),
    create({}, { keyRef: "" }),
    create({}, { wrappedKey: new Uint8Array(0) }),
    create({}, { wrappedKey: new Uint8Array(LIMITS.wrappedKeyMaxBytes + 1) }),
    create({}, {}, []),
    create({}, {}, [
      { entryId, maxUses: 1, envelope: new Uint8Array(8) },
      { entryId, maxUses: 1, envelope: new Uint8Array(8) },
    ]),
    create({}, {}, [{ entryId, maxUses: 0, envelope: new Uint8Array(8) }]),
    create({}, {}, [{ entryId, maxUses: LIMITS.maxUses + 1, envelope: new Uint8Array(8) }]),
    create({}, {}, [{ entryId, maxUses: 1, envelope: new Uint8Array(0) }]),
    create({}, {}, [{ entryId: "zz", maxUses: 1, envelope: new Uint8Array(8) }]),
  ];
  for (const input of bad) assert.equal(code(() => validateCreateCapture(input, caps)), "STORE_INVALID_ARGUMENT");
  assert.equal(code(() => validateCreateCapture(create({}, { sessionTag: "a".repeat(64) }), caps)), "ok");

  const many = Array.from({ length: 5 }, (_, i) => ({ entryId: String(i).repeat(64), maxUses: 1, envelope: new Uint8Array(1) }));
  assert.equal(code(() => validateCreateCapture(create({}, {}, many), caps)), "STORE_CAPABILITY");
  assert.equal(
    code(() => validateCreateCapture(create({}, {}, [{ entryId, maxUses: 1, envelope: new Uint8Array(33) }]), caps)),
    "STORE_CAPABILITY",
  );
  const heavy = Array.from({ length: 3 }, (_, i) => ({ entryId: String(i).repeat(64), maxUses: 1, envelope: new Uint8Array(32) }));
  assert.equal(code(() => validateCreateCapture(create({}, {}, heavy), caps)), "STORE_CAPABILITY");
});

test("commitRestore validation", () => {
  assert.equal(code(() => validateCommitRestore(commit(), caps)), "ok");
  const use = commit().uses[0];
  const bad = [
    commit({ attempt: { attemptId: "bad id", requestDigest: new Uint8Array(32) } }),
    commit({ attempt: { attemptId: "a", requestDigest: new Uint8Array(31) } }),
    commit({ captures: [] }),
    commit({ uses: [] }),
    commit({ uses: [use, use] }),
    commit({ captures: [{ captureId, generation: 1 }, { captureId, generation: 1 }] }),
    commit({ uses: [{ ...use, count: 0 }] }),
    commit({ uses: [{ ...use, count: -1 }] }),
    commit({ uses: [{ ...use, count: 1.5 }] }),
    commit({ uses: [{ ...use, captureId: `cap_${"b".repeat(26)}` }] }),
    commit({ captures: [{ captureId, generation: 1 }, { captureId: `cap_${"b".repeat(26)}`, generation: 1 }] }),
    commit({ uses: [{ ...use, lifecycleRevision: 0 }] }),
    commit({ receiptExpiresAt: -1 }),
    commit({ epoch: 1.2 }),
  ];
  for (const input of bad) assert.equal(code(() => validateCommitRestore(input, caps)), "STORE_INVALID_ARGUMENT");
  const five = Array.from({ length: 5 }, (_, i) => ({ ...use, entryId: String(i).repeat(64) }));
  assert.equal(code(() => validateCommitRestore(commit({ uses: five }), caps)), "STORE_CAPABILITY");
});

test("remaining operation validators", () => {
  assert.equal(code(() => validateReadEntries({ scope, entryIds: [entryId, entryId2] }, caps)), "ok");
  assert.equal(code(() => validateReadEntries({ scope, entryIds: [entryId, entryId] }, caps)), "STORE_INVALID_ARGUMENT");
  assert.equal(code(() => validateReadEntries({ scope, entryIds: [] }, caps)), "STORE_INVALID_ARGUMENT");
  assert.equal(code(() => validateReadCaptures({ scope, captureIds: [captureId] }, caps)), "ok");
  assert.equal(code(() => validateReadCaptures({ scope, captureIds: ["x"] }, caps)), "STORE_INVALID_ARGUMENT");

  const revoke = { scope, captureId, now: 1, retentionMs: 0, fenceAbsent: false };
  assert.equal(code(() => validateRevokeCapture(revoke)), "ok");
  assert.equal(code(() => validateRevokeCapture({ ...revoke, retentionMs: LIMITS.maxRetentionMs + 1 })), "STORE_INVALID_ARGUMENT");
  assert.equal(code(() => validateRevokeCapture({ ...revoke, fenceAbsent: "yes" })), "STORE_INVALID_ARGUMENT");

  const replace = { scope, captureId, keyRevision: 1, keyRef: "local:k2", wrappedKey: new Uint8Array([1]) };
  assert.equal(code(() => validateReplaceCaptureKey(replace)), "ok");
  assert.equal(code(() => validateReplaceCaptureKey({ ...replace, keyRef: "x".repeat(513) })), "STORE_INVALID_ARGUMENT");

  assert.equal(code(() => validateDeleteCiphertext({ scope, captureId, now: 1 })), "ok");
  assert.equal(code(() => validateDeleteCiphertext({ scope, captureId, now: -1 })), "STORE_INVALID_ARGUMENT");
  assert.equal(code(() => validateSweep({ namespace: "ns", now: 1, limit: 10 })), "ok");
  assert.equal(code(() => validateSweep({ namespace: "ns", now: 1, limit: 0 })), "STORE_INVALID_ARGUMENT");
  assert.equal(code(() => validateSweep({ namespace: "ns", now: 1, limit: LIMITS.maxSweepLimit + 1 })), "STORE_INVALID_ARGUMENT");
  assert.equal(code(() => validateInitializeNamespace({ namespace: "ns", epoch: 1 })), "ok");
  assert.equal(code(() => validateInitializeNamespace({ namespace: "ns", epoch: 0 })), "STORE_INVALID_ARGUMENT");
  assert.equal(code(() => validateInvalidateRecovered({ namespace: "ns", newEpoch: 2 })), "ok");
  assert.equal(code(() => validateInvalidateRecovered({ namespace: "n s", newEpoch: 2 })), "STORE_INVALID_ARGUMENT");
});
