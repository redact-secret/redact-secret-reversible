// store-memory's own behavior: what the conformance harness cannot see.
// Every identifier and byte is synthetic.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";

import { LIMITS, missingCapabilities, StoreError } from "@redact-secret/vault-contracts";

import { createMemoryStore } from "../dist/index.js";
import { captureId, captureInput, commitInput, entryId, openStore, scope, START, synthetic } from "./helpers.mjs";

async function seeded(options) {
  const opened = openStore(options);
  assert.deepEqual(await opened.store.initializeNamespace({ namespace: scope.namespace, epoch: 1 }), { outcome: "initialized" });
  assert.deepEqual(await opened.store.createCapture(captureInput(START)), { outcome: "created" });
  return opened;
}

const storeError = (code) => (error) => error instanceof StoreError && error.code === code && error.cause === undefined;

test("restart loses all memory state", async () => {
  // A process restart is modelled the only way it can be for process memory:
  // the first instance is dropped and a new one is created. Nothing reopens
  // the old state, because there is nothing to reopen.
  const before = await seeded();
  assert.deepEqual(await before.store.commitRestore(commitInput(START)), { outcome: "committed" });
  assert.deepEqual(await before.store.revokeCapture({ scope, captureId, now: START, retentionMs: 0, fenceAbsent: false }), { outcome: "revoked", entries: 1 });
  assert.deepEqual(before.control.counts(), { namespaces: 1, captures: 1, entries: 1, receipts: 1 });

  const after = openStore();
  assert.deepEqual(after.control.counts(), { namespaces: 0, captures: 0, entries: 0, receipts: 0 });
  assert.deepEqual(await after.store.recoveryState({ namespace: scope.namespace }), { epoch: 0, state: "uninitialized" });
  assert.deepEqual(await after.store.readEntries({ scope, entryIds: [entryId] }), { recovery: { epoch: 0, state: "uninitialized" }, entries: [], captures: [] });
  assert.deepEqual(await after.store.readCaptures({ scope, captureIds: [captureId] }), []);
  assert.deepEqual(await after.store.inspectAttempt({ scope, attemptId: "attempt-synthetic-1" }), { state: "absent" });
  // The revocation and the consumed use are gone too: this is why the store is not persistence.
  assert.deepEqual(await after.store.initializeNamespace({ namespace: scope.namespace, epoch: 1 }), { outcome: "initialized" });
  assert.deepEqual(await after.store.createCapture(captureInput(START)), { outcome: "created" });
  assert.equal((await after.store.readEntries({ scope, entryIds: [entryId] })).entries[0].used, 0);
});

test("two instances in one process share nothing", async () => {
  const one = await seeded();
  const two = openStore();
  assert.deepEqual(await two.store.readCaptures({ scope, captureIds: [captureId] }), []);
  assert.equal((await one.store.readCaptures({ scope, captureIds: [captureId] })).length, 1);
});

test("capabilities never advertise durability or cross-process state", () => {
  const { store } = createMemoryStore();
  const capabilities = store.capabilities();
  assert.deepEqual(capabilities, {
    contractVersion: 1,
    adapter: "store-memory",
    profile: "process-memory",
    atomicCreate: true,
    maxCreateEntries: 1024,
    maxCreateBytes: 16 * 1024 * 1024,
    atomicRestore: true,
    maxRestoreEntries: 1024,
    maxRestoreCaptures: 64,
    authoritativeCommit: true,
    revocationFences: true,
    attemptReceipts: true,
    storeClock: true,
    maxClockSkewMs: 2000,
    durability: "volatile",
    crossProcess: false,
    restoreDetection: "none",
    maxEnvelopeBytes: LIMITS.maxEnvelopeBytes,
  });
  assert.deepEqual(missingCapabilities(capabilities), []);
  assert.ok(Object.isFrozen(capabilities));
  assert.equal(store.capabilities(), capabilities);
});

test("bounds can only be lowered", () => {
  const lowered = createMemoryStore({ maxClockSkewMs: 0, maxCreateEntries: 2, maxCreateBytes: 100, maxRestoreEntries: 3, maxRestoreCaptures: 1, maxEnvelopeBytes: 50 }).store.capabilities();
  assert.deepEqual(
    [lowered.maxClockSkewMs, lowered.maxCreateEntries, lowered.maxCreateBytes, lowered.maxRestoreEntries, lowered.maxRestoreCaptures, lowered.maxEnvelopeBytes],
    [0, 2, 100, 3, 1, 50],
  );
  const bad = [
    { maxCreateEntries: 1025 },
    { maxCreateBytes: 16 * 1024 * 1024 + 1 },
    { maxRestoreEntries: 1025 },
    { maxRestoreCaptures: 65 },
    { maxEnvelopeBytes: LIMITS.maxEnvelopeBytes + 1 },
    { maxCreateEntries: 0 },
    { maxRestoreCaptures: 1.5 },
    { maxClockSkewMs: -1 },
    { maxClockSkewMs: 60_001 },
    { now: 5 },
  ];
  for (const options of bad) assert.throws(() => createMemoryStore(options), TypeError);
});

test("a lowered bound is enforced with STORE_CAPABILITY before any write", async () => {
  const { store, control } = openStore({ maxCreateEntries: 1, maxEnvelopeBytes: 16 });
  await store.initializeNamespace({ namespace: scope.namespace, epoch: 1 });
  const twoEntries = captureInput(START, { entries: [{ entryId, maxUses: 1, envelope: synthetic(8, 1) }, { entryId: "1".repeat(64), maxUses: 1, envelope: synthetic(8, 1) }] });
  await assert.rejects(store.createCapture(twoEntries), storeError("STORE_CAPABILITY"));
  const bigEnvelope = captureInput(START, { entries: [{ entryId, maxUses: 1, envelope: synthetic(17, 1) }] });
  await assert.rejects(store.createCapture(bigEnvelope), storeError("STORE_CAPABILITY"));
  assert.deepEqual(control.counts(), { namespaces: 1, captures: 0, entries: 0, receipts: 0 });
});

test("the store object exposes the contract's methods and nothing else", () => {
  const { store, control } = createMemoryStore();
  assert.deepEqual(Object.keys(store).sort(), [
    "capabilities",
    "commitRestore",
    "createCapture",
    "deleteCiphertext",
    "initializeNamespace",
    "inspectAttempt",
    "invalidateRecovered",
    "quarantine",
    "readCaptures",
    "readEntries",
    "recoveryState",
    "replaceCaptureKey",
    "revokeCapture",
    "sweepExpired",
  ]);
  assert.ok(Object.isFrozen(store));
  assert.ok(Object.isFrozen(control));
  assert.equal(store.control, undefined);
  assert.deepEqual(Object.keys(control).sort(), ["clearHooks", "counts", "onPhase"]);
});

test("the default clock is Date.now, floored", async () => {
  const { store } = createMemoryStore();
  await store.initializeNamespace({ namespace: scope.namespace, epoch: 1 });
  assert.deepEqual(await store.createCapture(captureInput(Date.now())), { outcome: "created" });
  const fractional = createMemoryStore({ now: () => START + 0.9, maxClockSkewMs: 0 }).store;
  await fractional.initializeNamespace({ namespace: scope.namespace, epoch: 1 });
  assert.deepEqual(await fractional.createCapture(captureInput(START)), { outcome: "created" });
});

test("a clock that returns no usable time fails the call as STORE_UNAVAILABLE", async () => {
  const { store } = createMemoryStore({ now: () => Number.NaN });
  await assert.rejects(store.recoveryState({ namespace: scope.namespace }), storeError("STORE_UNAVAILABLE"));
});

test("an already aborted signal fails the call as STORE_UNAVAILABLE, with no effect", async () => {
  const { store, control } = await seeded();
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(store.commitRestore(commitInput(START), { signal: controller.signal }), storeError("STORE_UNAVAILABLE"));
  assert.equal(control.counts().receipts, 0);
  assert.equal((await store.readEntries({ scope, entryIds: [entryId] })).entries[0].used, 0);
});

test("a signal aborted while a hook holds the call open cancels it before it applies", async () => {
  const { store, control } = await seeded();
  const controller = new AbortController();
  control.onPhase("commitRestore", "before-apply", () => controller.abort());
  await assert.rejects(store.commitRestore(commitInput(START), { signal: controller.signal }), storeError("STORE_UNAVAILABLE"));
  assert.equal(control.counts().receipts, 0);
});

test("control hooks run at their phase, in order, with the call index, and can be removed", async () => {
  const { store, control } = await seeded();
  const seen = [];
  const removeFirst = control.onPhase("commitRestore", "before-validate", (info) => seen.push(["first", info]));
  control.onPhase("commitRestore", "before-validate", async (info) => {
    await null;
    seen.push(["second", info]);
  });
  control.onPhase("commitRestore", "before-apply", (info) => seen.push(["apply", info]));
  control.onPhase("readEntries", "before-apply", (info) => seen.push(["read", info]));

  assert.deepEqual(await store.commitRestore(commitInput(START)), { outcome: "committed" });
  assert.deepEqual(seen, [
    ["first", { operation: "commitRestore", phase: "before-validate", call: 0 }],
    ["second", { operation: "commitRestore", phase: "before-validate", call: 0 }],
    ["apply", { operation: "commitRestore", phase: "before-apply", call: 0 }],
  ]);

  seen.length = 0;
  removeFirst();
  removeFirst();
  await assert.rejects(store.commitRestore({ ...commitInput(START), uses: [] }), storeError("STORE_INVALID_ARGUMENT"));
  assert.deepEqual(seen.map(([label, info]) => [label, info.call]), [["second", 1]], "before-apply does not run for an input that fails validation");

  seen.length = 0;
  control.clearHooks();
  await store.readEntries({ scope, entryIds: [entryId] });
  assert.deepEqual(seen, []);
});

test("a hook that throws rejects the call before it changes anything", async () => {
  const { store, control } = await seeded();
  const failure = new Error("synthetic hook failure");
  for (const phase of ["before-validate", "before-apply"]) {
    const remove = control.onPhase("commitRestore", phase, () => {
      throw failure;
    });
    await assert.rejects(store.commitRestore(commitInput(START)), (error) => error === failure);
    remove();
  }
  assert.equal(control.counts().receipts, 0);
  assert.equal((await store.readEntries({ scope, entryIds: [entryId] })).entries[0].used, 0);
});

test("onPhase refuses an unknown operation, phase, or hook", () => {
  const { control } = createMemoryStore();
  assert.throws(() => control.onPhase("capabilities", "before-apply", () => {}), TypeError);
  assert.throws(() => control.onPhase("noSuchOperation", "before-apply", () => {}), TypeError);
  assert.throws(() => control.onPhase("commitRestore", "after-apply", () => {}), TypeError);
  assert.throws(() => control.onPhase("commitRestore", "before-apply", "not a function"), TypeError);
});

test("a before-apply hook can place a revocation between a caller's read and its commit; the commit then sees it", async () => {
  const { store, control } = await seeded();
  control.onPhase("commitRestore", "before-apply", async () => {
    assert.deepEqual(await store.revokeCapture({ scope, captureId, now: START, retentionMs: 0, fenceAbsent: false }), { outcome: "revoked", entries: 1 });
  });
  assert.deepEqual(await store.commitRestore(commitInput(START)), { outcome: "rejected", reason: "revoked" });
  assert.equal((await store.readEntries({ scope, entryIds: [entryId] })).entries[0].used, 0);
});

test("the atomic section reads the store clock after the hooks, not before", async () => {
  const { store, control, clock } = await seeded();
  control.onPhase("commitRestore", "before-apply", () => clock.set(START + 3_600_000));
  assert.deepEqual(await store.commitRestore(commitInput(START + 3_600_000)), { outcome: "rejected", reason: "expired" });
});

test("an input changed while a hook holds the call open does not change what is applied", async () => {
  const { store, control } = await seeded();
  const input = commitInput(START);
  control.onPhase("commitRestore", "before-apply", () => {
    input.uses[0].count = 2;
    input.attempt.requestDigest.fill(0xee);
    input.scope = { namespace: scope.namespace, tenant: "tenant-globex-synthetic" };
  });
  assert.deepEqual(await store.commitRestore(input), { outcome: "committed" });
  assert.equal((await store.readEntries({ scope, entryIds: [entryId] })).entries[0].used, 1);
  const receipt = await store.inspectAttempt({ scope, attemptId: "attempt-synthetic-1" });
  assert.deepEqual(receipt.requestDigest, synthetic(32, 0x33));
});

test("an input whose getters change between reads is validated as it is stored", async () => {
  const { store, control } = await seeded();
  let reads = 0;
  const input = commitInput(START);
  const use = { ...input.uses[0] };
  Object.defineProperty(use, "count", {
    enumerable: true,
    get() {
      reads += 1;
      return reads === 1 ? 1 : 5000;
    },
  });
  await assert.rejects(store.commitRestore({ ...input, uses: [use] }), storeError("STORE_INVALID_ARGUMENT"));
  assert.equal(control.counts().receipts, 0);
  assert.equal((await store.readEntries({ scope, entryIds: [entryId] })).entries[0].used, 0);
});

test("stored bytes are copied on the way in and on the way out", async () => {
  const { store } = openStore();
  await store.initializeNamespace({ namespace: scope.namespace, epoch: 1 });
  const input = captureInput(START);
  await store.createCapture(input);
  input.entries[0].envelope.fill(0xee);
  input.capture.wrappedKey.fill(0xee);
  const first = await store.readEntries({ scope, entryIds: [entryId] });
  assert.deepEqual(first.entries[0].envelope, synthetic(24, 0x22));
  assert.deepEqual(first.captures[0].wrappedKey, synthetic(40, 0x11));
  first.entries[0].envelope.fill(0xdd);
  first.captures[0].wrappedKey.fill(0xdd);
  const captures = await store.readCaptures({ scope, captureIds: [captureId] });
  captures[0].wrappedKey.fill(0xcc);
  const second = await store.readEntries({ scope, entryIds: [entryId] });
  assert.deepEqual(second.entries[0].envelope, synthetic(24, 0x22));
  assert.deepEqual(second.captures[0].wrappedKey, synthetic(40, 0x11));
  assert.notEqual(second.entries[0].envelope.buffer, first.entries[0].envelope.buffer);

  const key = { scope, captureId, keyRevision: 1, keyRef: "synthetic-key:v2", wrappedKey: synthetic(48, 0x44) };
  await store.replaceCaptureKey(key);
  key.wrappedKey.fill(0xee);
  assert.deepEqual((await store.readCaptures({ scope, captureIds: [captureId] }))[0].wrappedKey, synthetic(48, 0x44));
});

test("the envelope is opaque: arbitrary bytes are stored and returned unchanged", async () => {
  const { store } = openStore();
  await store.initializeNamespace({ namespace: scope.namespace, epoch: 1 });
  const envelope = Uint8Array.from({ length: 256 }, (_, index) => index);
  await store.createCapture(captureInput(START, { entries: [{ entryId, maxUses: 1, envelope }] }));
  assert.deepEqual((await store.readEntries({ scope, entryIds: [entryId] })).entries[0].envelope, envelope);
});

test("counts report rows, and a sweep releases an emptied namespace", async () => {
  const { store, control, clock } = await seeded();
  await store.commitRestore(commitInput(START));
  assert.deepEqual(control.counts(), { namespaces: 1, captures: 1, entries: 1, receipts: 1 });
  clock.set(START + 3 * 3_600_000);
  assert.deepEqual(await store.sweepExpired({ namespace: scope.namespace, now: clock.now(), limit: 100 }), { outcome: "swept", entries: 1, captures: 1, receipts: 1, more: false });
  assert.deepEqual(control.counts(), { namespaces: 1, captures: 0, entries: 0, receipts: 0 });
  assert.deepEqual(await store.recoveryState({ namespace: scope.namespace }), { epoch: 1, state: "serving" });
});

test("the built package uses no node: built-in, no Buffer, and imports only the contracts", () => {
  const dist = new URL("../dist/", import.meta.url);
  const files = readdirSync(dist).filter((name) => name.endsWith(".js"));
  assert.deepEqual(files, ["index.js"]);
  const source = readFileSync(new URL("index.js", dist), "utf8");
  const imports = [...source.matchAll(/from\s+"([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual([...new Set(imports)], ["@redact-secret/vault-contracts"]);
  // Comments say what the store never does; the code must not do it.
  const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  assert.doesNotMatch(code, /\bBuffer\b|\brequire\(|import\(|decrypt|plaintext|principal|policy|unwrap|\bcrypto\b|subtle|kms/i);
  const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.deepEqual(manifest.dependencies, { "@redact-secret/vault-contracts": "0.1.0-alpha.1" });
  assert.deepEqual(Object.keys(manifest.exports), [".", "./package.json"]);
});
