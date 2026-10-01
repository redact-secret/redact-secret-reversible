// createPersistentServerVault: option validation, capability refusal, and the
// recovery check at creation (docs/specs/persistent-vault.md §8.2).
import assert from "node:assert/strict";
import test from "node:test";

import {
  createFaultyStore,
  createMemoryStore,
  createPersistentServerVault,
  createRig,
  CTX_A,
  DIGEST_KEY,
  foreignError,
  NAMESPACE,
  registerLeakHygiene,
  rejects,
  RELEASE,
  SECRET_A,
  spyStore,
} from "./helpers.mjs";

/** A rig whose namespace is serving, with no vault opened yet. */
function bare(options = {}) {
  return createRig({ open: false, ...options });
}

function without(options, key) {
  const copy = { ...options };
  delete copy[key];
  return copy;
}

test("factory: a complete configuration opens, and reports the namespace and the store's capabilities", async () => {
  const rig = await bare();
  const vault = await rig.open();
  assert.equal(vault.namespace, NAMESPACE);
  assert.equal(vault.storeCapabilities.adapter, "store-memory");
  assert.ok(Object.isFrozen(vault.storeCapabilities));
  // Creation reads; it never writes.
  assert.deepEqual(rig.spy.calls.map((call) => call.operation), ["recoveryState"]);
});

test("factory: the options object itself must be an object", async () => {
  for (const value of [undefined, null, "options", 7]) {
    await rejects(createPersistentServerVault(value), "INVALID_ARGUMENT");
  }
});

test("factory: every required option, when missing, is INVALID_ARGUMENT and the store is not touched", async () => {
  for (const key of ["namespace", "recoveryEpoch", "store", "crypto", "resolvePrincipal", "policy", "lifecyclePolicy"]) {
    const rig = await bare();
    await rejects(createPersistentServerVault(without(rig.options(), key)), "INVALID_ARGUMENT");
    assert.equal(rig.spy.calls.length, 0, `missing ${key}: no store call`);
  }
});

test("factory: every option, when malformed, is INVALID_ARGUMENT", async () => {
  const rig = await bare();
  const cases = {
    namespace: ["", "has space", "x".repeat(129), 7, null, "tenant/slash"],
    recoveryEpoch: [0, -1, 1.5, "1", Number.NaN, Number.MAX_SAFE_INTEGER + 1, null],
    store: [null, "store", {}],
    crypto: [null, "crypto", {}, { sealCapture() {} }, { openCapture() {} }],
    resolvePrincipal: [null, "resolver", {}],
    resolveSession: [null, "resolver", {}],
    policy: [null, "policy", {}],
    lifecyclePolicy: [null, "policy", {}],
    onAudit: [null, "audit", {}],
    policyRevision: [7, null, {}],
    now: [null, 7, "now"],
    digestKey: [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0), "k".repeat(32), Array.from({ length: 32 }, () => 1), null],
    resolverTimeoutMs: [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 10 * 60 * 1000 + 1, "5"],
    policyTimeoutMs: [0, -1, Number.NaN, 10 * 60 * 1000 + 1],
    storeTimeoutMs: [0, -1, Number.NaN, 10 * 60 * 1000 + 1],
    cryptoTimeoutMs: [0, -1, Number.NaN, 10 * 60 * 1000 + 1],
    maxCommitRetries: [-1, 1.5, 11, Number.NaN, "3"],
    receiptGraceMs: [-1, 1.5, 24 * 60 * 60 * 1000 + 1, Number.NaN],
    tombstoneRetentionMs: [-1, 1.5, 30 * 24 * 60 * 60 * 1000 + 1, Number.NaN],
    limits: ["limits", { unknownLimit: 1 }, { entryTtlMs: 0 }, { entryTtlMs: 24 * 60 * 60 * 1000 + 1 }, { maxUsesPerEntry: 1001 }],
    pii: ["pii", 7],
  };
  for (const [key, values] of Object.entries(cases)) {
    for (const value of values) {
      await rejects(createPersistentServerVault(rig.options({ [key]: value })), "INVALID_ARGUMENT");
    }
  }
  assert.equal(rig.spy.mutations(), 0);
});

test("factory: a store missing any method the server calls is INVALID_ARGUMENT", async () => {
  const rig = await bare();
  for (const method of [
    "capabilities",
    "createCapture",
    "readEntries",
    "readCaptures",
    "commitRestore",
    "revokeCapture",
    "inspectAttempt",
    "deleteCiphertext",
    "recoveryState",
  ]) {
    await rejects(createPersistentServerVault(rig.options({ store: without(rig.spy.store, method) })), "INVALID_ARGUMENT");
  }
});

test("factory: the digest key is required unless allowUnkeyedDigests, and the two together are rejected", async () => {
  const rig = await bare();
  await rejects(createPersistentServerVault(without(rig.options(), "digestKey")), "INVALID_ARGUMENT");
  await rejects(createPersistentServerVault(rig.options({ digestKey: undefined, allowUnkeyedDigests: false })), "INVALID_ARGUMENT");
  await rejects(createPersistentServerVault(rig.options({ digestKey: undefined, allowUnkeyedDigests: "yes" })), "INVALID_ARGUMENT");
  await rejects(createPersistentServerVault(rig.options({ digestKey: DIGEST_KEY, allowUnkeyedDigests: true })), "INVALID_ARGUMENT");
  // The explicit waiver alone opens.
  const unkeyed = await createPersistentServerVault(rig.options({ digestKey: undefined, allowUnkeyedDigests: true }));
  assert.equal(unkeyed.namespace, NAMESPACE);
});

test("factory: each missing required capability is UNSUPPORTED_STORE, before the store is read", async () => {
  const overrides = [
    { contractVersion: 2 },
    { contractVersion: undefined },
    { atomicCreate: false },
    { atomicRestore: false },
    { authoritativeCommit: false },
    { revocationFences: false },
    { attemptReceipts: false },
    { storeClock: false },
    { atomicCreate: "true" },
    { maxCreateEntries: 0 },
    { maxCreateEntries: 1025 },
    { maxCreateBytes: 0 },
    { maxRestoreEntries: 1025 },
    { maxRestoreCaptures: 65 },
    { maxRestoreCaptures: 0 },
    { maxEnvelopeBytes: 1024 * 1024 + 64 * 1024 + 1 },
    { maxClockSkewMs: -1 },
    { maxClockSkewMs: 60_001 },
    { durability: "eventual" },
    { crossProcess: "yes" },
    { restoreDetection: "" },
    { restoreDetection: undefined },
    { adapter: undefined },
  ];
  for (const capabilities of overrides) {
    const rig = await bare({ capabilities });
    await rejects(rig.open(), "UNSUPPORTED_STORE");
    assert.equal(rig.spy.calls.length, 0, `${JSON.stringify(capabilities)}: no store call`);
  }
});

test("factory: a store whose capabilities() throws, or returns no object, is UNSUPPORTED_STORE", async () => {
  const rig = await bare();
  const throwing = {
    ...rig.spy.store,
    capabilities: () => {
      throw foreignError();
    },
  };
  await rejects(createPersistentServerVault(rig.options({ store: throwing })), "UNSUPPORTED_STORE");
  for (const value of [null, undefined, "capabilities", 7]) {
    await rejects(createPersistentServerVault(rig.options({ store: { ...rig.spy.store, capabilities: () => value } })), "UNSUPPORTED_STORE");
  }
});

test("factory: a volatile or single-process store is refused without allowNonDurableStore", async () => {
  // store-memory is volatile and single-process.
  const memoryRig = await bare();
  await rejects(createPersistentServerVault(without(memoryRig.options(), "allowNonDurableStore")), "UNSUPPORTED_STORE");
  await rejects(createPersistentServerVault(memoryRig.options({ allowNonDurableStore: false })), "UNSUPPORTED_STORE");
  await rejects(createPersistentServerVault(memoryRig.options({ allowNonDurableStore: "true" })), "UNSUPPORTED_STORE");

  // Each of the two properties is enough to refuse.
  const volatile = await bare({ capabilities: { durability: "volatile", crossProcess: true, restoreDetection: "synthetic-tripwire" } });
  await rejects(volatile.open({ allowNonDurableStore: undefined }), "UNSUPPORTED_STORE");
  const singleProcess = await bare({ capabilities: { durability: "durable", crossProcess: false, restoreDetection: "synthetic-tripwire" } });
  await rejects(singleProcess.open({ allowNonDurableStore: undefined }), "UNSUPPORTED_STORE");
  // allowNoRestoreDetection is a different waiver and does not stand in for it.
  await rejects(volatile.open({ allowNonDurableStore: undefined, allowNoRestoreDetection: true }), "UNSUPPORTED_STORE");
  assert.equal(volatile.spy.calls.length + singleProcess.spy.calls.length + memoryRig.spy.calls.length, 0);

  assert.equal((await volatile.open({ allowNonDurableStore: true })).namespace, NAMESPACE);
});

test("factory: a durable store with restoreDetection \"none\" is refused without allowNoRestoreDetection", async () => {
  const durable = { durability: "durable", crossProcess: true };
  const noDetection = await bare({ capabilities: { ...durable, restoreDetection: "none" } });
  await rejects(noDetection.open({ allowNonDurableStore: undefined }), "UNSUPPORTED_STORE");
  // allowNonDurableStore is a different waiver and does not stand in for it.
  await rejects(noDetection.open({ allowNonDurableStore: true }), "UNSUPPORTED_STORE");
  await rejects(noDetection.open({ allowNonDurableStore: undefined, allowNoRestoreDetection: "true" }), "UNSUPPORTED_STORE");
  assert.equal(noDetection.spy.calls.length, 0);
  assert.equal((await noDetection.open({ allowNonDurableStore: undefined, allowNoRestoreDetection: true })).namespace, NAMESPACE);

  // A durable, cross-process store that declares a tripwire needs no waiver at all.
  const qualified = await bare({ capabilities: { ...durable, restoreDetection: "synthetic-tripwire" } });
  assert.equal((await qualified.open({ allowNonDurableStore: undefined })).namespace, NAMESPACE);
});

test("factory: a namespace that was never initialized is STORE_QUARANTINED, and the factory does not initialize it", async () => {
  const rig = await bare({ initialize: false });
  await rejects(rig.open(), "STORE_QUARANTINED");
  assert.deepEqual(rig.spy.calls.map((call) => call.operation), ["recoveryState"]);
  assert.deepEqual(await rig.memory.store.recoveryState({ namespace: NAMESPACE }), { epoch: 0, state: "uninitialized" });
  assert.deepEqual(rig.memory.control.counts(), { namespaces: 0, captures: 0, entries: 0, receipts: 0 });
  // Nothing claimed the namespace: the application can still initialize it.
  assert.deepEqual(await rig.memory.store.initializeNamespace({ namespace: NAMESPACE, epoch: 1 }), { outcome: "initialized" });
});

test("factory: a quarantined namespace is STORE_QUARANTINED and stays quarantined", async () => {
  const rig = await bare();
  await rig.memory.store.quarantine({ namespace: NAMESPACE });
  await rejects(rig.open(), "STORE_QUARANTINED");
  assert.deepEqual(await rig.memory.store.recoveryState({ namespace: NAMESPACE }), { epoch: 1, state: "quarantined" });
  assert.equal(rig.spy.mutations(), 0);
});

test("factory: a configured epoch that differs from the stored one, either way, is STORE_QUARANTINED", async () => {
  const stored2 = await bare({ epoch: 2 });
  await rejects(stored2.open({ recoveryEpoch: 1 }), "STORE_QUARANTINED");
  await rejects(stored2.open({ recoveryEpoch: 3 }), "STORE_QUARANTINED");
  assert.deepEqual(await stored2.memory.store.recoveryState({ namespace: NAMESPACE }), { epoch: 2, state: "serving" });
  assert.equal(stored2.spy.mutations(), 0);
  assert.equal((await stored2.open({ recoveryEpoch: 2 })).namespace, NAMESPACE);
});

test("factory: a recovery state the server cannot read or interpret fails closed", async () => {
  const rig = await bare();
  rig.failNext("recoveryState", { kind: "unavailable" });
  await rejects(rig.open(), "STORE_UNAVAILABLE");
  rig.failNext("recoveryState", { kind: "foreign-error", when: "before" });
  await rejects(rig.open(), "STORE_UNAVAILABLE");
  for (const shape of ["null", "wrong-types"]) {
    rig.failNext("recoveryState", { kind: "malformed", shape });
    await rejects(rig.open(), "STORE_QUARANTINED");
  }
  for (const result of [{ epoch: 1, state: "SERVING" }, { epoch: "1", state: "serving" }, { state: "serving" }, "serving"]) {
    rig.failNext("recoveryState", { kind: "result", result, delegate: false });
    await rejects(rig.open(), "STORE_QUARANTINED");
  }
  assert.equal(rig.spy.mutations(), 0);
});

test("factory: a recoveryState call that hangs past storeTimeoutMs fails closed", async () => {
  const rig = await bare();
  rig.failNext("recoveryState", { kind: "delay", beforeMs: 120 });
  await rejects(rig.open({ storeTimeoutMs: 20 }), "STORE_UNAVAILABLE");
});

test("factory: a capture lifetime and receipt grace that cannot fit the store's 48-hour receipt horizon is INVALID_ARGUMENT", async () => {
  // §7.5: receiptExpiresAt = latest expiresAt + skew bound + grace. §4.2: a store rejects one more than 48 hours past
  // its clock with STORE_INVALID_ARGUMENT. A configuration that can produce such a receipt would fail restores of a
  // fresh capture with INVARIANT_VIOLATION, so it is refused when the vault is created.
  const day = 24 * 60 * 60 * 1000;
  const skew = 2000;
  const rig = await bare();
  await rejects(rig.open({ limits: { entryTtlMs: day }, receiptGraceMs: day }), "INVALID_ARGUMENT");
  await rejects(rig.open({ limits: { entryTtlMs: day }, receiptGraceMs: day - 2 * skew + 1 }), "INVALID_ARGUMENT");
  await rejects(rig.open({ limits: { entryTtlMs: day - 1000 }, receiptGraceMs: day }), "INVALID_ARGUMENT");
  assert.equal(rig.spy.mutations(), 0);

  // At the bound every restore fits, immediately after the capture, even with the store's clock a full skew behind.
  const time = { server: 1_790_000_000_000, store: 1_790_000_000_000 - skew };
  const lagging = await createRig({
    clock: { now: () => time.server },
    storeClock: { now: () => time.store },
    vault: { limits: { entryTtlMs: day }, receiptGraceMs: day - 2 * skew },
  });
  const captured = await lagging.vault.capture(`secret ${SECRET_A} here`, { context: CTX_A, release: RELEASE });
  const restored = await lagging.vault.restore({
    context: CTX_A,
    sink: "sink-a",
    purpose: "purpose-synthetic-support-reply",
    captures: [captured.captureId],
    fields: { body: captured.text },
  });
  assert.equal(restored.fields.body, `secret ${SECRET_A} here`);
  const commit = lagging.spy.last("commitRestore").input;
  assert.equal(commit.receiptExpiresAt, captured.expiresAt + skew + (day - 2 * skew));
  assert.equal(commit.receiptExpiresAt - time.store, 2 * day);
});

test("factory: independent stores share nothing", async () => {
  const first = await createRig();
  const second = createMemoryStore();
  const spy = spyStore(createFaultyStore(second.store));
  await rejects(createPersistentServerVault(first.options({ store: spy.store })), "STORE_QUARANTINED");
  assert.equal(second.control.counts().namespaces, 0);
});

registerLeakHygiene({ minErrors: 100 });
