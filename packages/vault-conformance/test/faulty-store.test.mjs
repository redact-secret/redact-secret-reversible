// Unit tests of createFaultyStore. The inner store is the reference model
// store of this test directory; every identifier and byte is synthetic.
import assert from "node:assert/strict";
import test from "node:test";

import { StoreError } from "@redact-secret/vault-contracts";

import { createFaultyStore, runCases, storeConformanceCases, SYNTHETIC_SECRET_MARKER } from "../dist/index.js";
import { createModelStore, modelFactory, START } from "./model-store.mjs";

const scope = { namespace: "support-synthetic", tenant: "tenant-acme-synthetic" };
const captureId = "cap_aaaaaaaaaaaaaaaaaaaaaaaaaa";
const entryId = `${"0".repeat(63)}1`;

function createInput() {
  return {
    scope,
    epoch: 1,
    now: START,
    capture: {
      captureId,
      sessionTag: null,
      createdAt: START,
      expiresAt: START + 3_600_000,
      lookupVersion: 1,
      keyRef: "synthetic-key:v1",
      wrappedKey: new Uint8Array(40).fill(0x11),
    },
    entries: [{ entryId, maxUses: 3, envelope: new Uint8Array(24).fill(0x22) }],
  };
}

function commitInput(attemptId = "attempt-synthetic-1") {
  return {
    scope,
    epoch: 1,
    now: START,
    attempt: { attemptId, requestDigest: new Uint8Array(32).fill(0x33) },
    receiptExpiresAt: START + 2 * 3_600_000,
    captures: [{ captureId, generation: 1 }],
    uses: [{ entryId, captureId, count: 1, lifecycleRevision: 1, ciphertextRevision: 1 }],
  };
}

async function open(rules = [], plan = {}) {
  const { store: inner } = createModelStore();
  await inner.initializeNamespace({ namespace: scope.namespace, epoch: 1 });
  await inner.createCapture(createInput());
  return { inner, store: createFaultyStore(inner, { rules, ...plan }) };
}

async function used(inner) {
  return (await inner.readEntries({ scope, entryIds: [entryId] })).entries[0].used;
}

const storeError = (code) => (error) => {
  assert.ok(error instanceof StoreError);
  assert.equal(error.code, code);
  assert.equal(error.cause, undefined);
  return true;
};

test("with no rule the wrapper is transparent", async () => {
  const { inner, store } = await open();
  assert.deepEqual(store.capabilities(), inner.capabilities());
  assert.deepEqual(await store.commitRestore(commitInput()), { outcome: "committed" });
  assert.equal(await used(inner), 1);
  assert.equal(store.faults.calls("commitRestore"), 1);
  assert.equal(store.faults.calls("readEntries"), 0);
});

test("with no rule the wrapper passes the store conformance suite", async () => {
  const factory = async () => {
    const sut = await modelFactory()();
    const store = createFaultyStore(sut.store);
    return { ...sut, store, secondStore: store };
  };
  const results = await runCases(storeConformanceCases(factory, { parallelism: 8, modelSequences: 1, modelSteps: 150 }));
  assert.deepEqual(results.filter((result) => result.status === "failed"), []);
});

test("unavailable: throws STORE_UNAVAILABLE before delegating, so nothing is applied", async () => {
  const { inner, store } = await open([{ operation: "commitRestore", fault: { kind: "unavailable" } }]);
  await assert.rejects(store.commitRestore(commitInput()), storeError("STORE_UNAVAILABLE"));
  assert.equal(await used(inner), 0);
  assert.deepEqual(await inner.inspectAttempt({ scope, attemptId: "attempt-synthetic-1" }), { state: "absent" });
});

test("ambiguous with applied: true delegates, then loses the response", async () => {
  const { inner, store } = await open([{ operation: "commitRestore", call: 0, fault: { kind: "ambiguous", applied: true } }]);
  await assert.rejects(store.commitRestore(commitInput()), storeError("STORE_AMBIGUOUS"));
  assert.equal(await used(inner), 1);
  assert.equal((await store.inspectAttempt({ scope, attemptId: "attempt-synthetic-1" })).state, "committed");
  // The same attempt, retried through the wrapper, is deduplicated by the receipt.
  assert.deepEqual(await store.commitRestore(commitInput()), { outcome: "already-committed" });
  assert.equal(await used(inner), 1);
});

test("ambiguous with applied: false throws without delegating", async () => {
  const { inner, store } = await open([{ operation: "commitRestore", fault: { kind: "ambiguous", applied: false } }]);
  await assert.rejects(store.commitRestore(commitInput()), storeError("STORE_AMBIGUOUS"));
  assert.equal(await used(inner), 0);
  assert.equal((await inner.inspectAttempt({ scope, attemptId: "attempt-synthetic-1" })).state, "absent");
});

test("a rule with a call index applies to that call of that operation only", async () => {
  const { store } = await open([{ operation: "readEntries", call: 1, fault: { kind: "unavailable" } }]);
  const input = { scope, entryIds: [entryId] };
  assert.equal((await store.readEntries(input)).entries.length, 1);
  await assert.rejects(store.readEntries(input), storeError("STORE_UNAVAILABLE"));
  assert.equal((await store.readEntries(input)).entries.length, 1);
  assert.equal((await store.readCaptures({ scope, captureIds: [captureId] })).length, 1);
  assert.deepEqual(
    store.faults.log().map((entry) => [entry.operation, entry.call, entry.faults]),
    [
      ["readEntries", 0, []],
      ["readEntries", 1, ["unavailable"]],
      ["readEntries", 2, []],
      ["readCaptures", 0, []],
    ],
  );
});

test("delay waits before and after delegating, through the injected sleep", async () => {
  const order = [];
  const { inner, store: plain } = await open();
  const spied = {
    ...inner,
    commitRestore: async (input) => {
      order.push("inner");
      return inner.commitRestore(input);
    },
  };
  const store = createFaultyStore(spied, {
    rules: [{ operation: "commitRestore", fault: { kind: "delay", beforeMs: 30, afterMs: 70 } }],
    sleep: async (ms) => {
      order.push(`sleep ${ms}`);
    },
  });
  assert.deepEqual(await store.commitRestore(commitInput()), { outcome: "committed" });
  assert.deepEqual(order, ["sleep 30", "inner", "sleep 70"]);
  assert.equal(plain.faults.calls("commitRestore"), 0);
});

test("delay uses a real timer by default and composes with another fault", async () => {
  const { inner, store } = await open([
    { operation: "commitRestore", fault: { kind: "delay", afterMs: 5 } },
    { operation: "commitRestore", fault: { kind: "ambiguous", applied: true } },
  ]);
  await assert.rejects(store.commitRestore(commitInput()), storeError("STORE_AMBIGUOUS"));
  assert.equal(await used(inner), 1);
});

test("foreign-error throws a non-StoreError carrying the synthetic marker, before or after the effect", async () => {
  const { inner, store } = await open([
    { operation: "commitRestore", call: 0, fault: { kind: "foreign-error", when: "before" } },
    { operation: "commitRestore", call: 1, fault: { kind: "foreign-error", when: "after" } },
  ]);
  const foreign = (error) => {
    assert.ok(!(error instanceof StoreError));
    assert.ok(error instanceof Error);
    assert.ok(error.message.includes(SYNTHETIC_SECRET_MARKER));
    assert.ok(error.cause.message.includes(SYNTHETIC_SECRET_MARKER));
    assert.equal(error.detail, SYNTHETIC_SECRET_MARKER);
    return true;
  };
  await assert.rejects(store.commitRestore(commitInput()), foreign);
  assert.equal(await used(inner), 0);
  await assert.rejects(store.commitRestore(commitInput()), foreign);
  assert.equal(await used(inner), 1);
});

test("clock-skew shifts the input's now, so the inner store sees a skewed caller", async () => {
  const { inner, store } = await open([
    { operation: "commitRestore", call: 0, fault: { kind: "clock-skew", shiftMs: 120_000 } },
    { operation: "sweepExpired", fault: { kind: "clock-skew", shiftMs: -120_000 } },
  ]);
  const input = commitInput();
  assert.deepEqual(await store.commitRestore(input), { outcome: "rejected", reason: "clock-skew" });
  assert.equal(input.now, START, "the caller's input is not modified");
  assert.deepEqual(await store.sweepExpired({ namespace: scope.namespace, now: START, limit: 10 }), { outcome: "rejected", reason: "clock-skew" });
  assert.deepEqual(await store.commitRestore(input), { outcome: "committed" });
  assert.equal(await used(inner), 1);
  // An input without a now is passed through unchanged.
  store.faults.add({ operation: "readEntries", fault: { kind: "clock-skew", shiftMs: 5 } });
  assert.equal((await store.readEntries({ scope, entryIds: [entryId] })).entries.length, 1);
});

test("receipts unavailable: inspectAttempt throws STORE_UNAVAILABLE while commits still work", async () => {
  const { store } = await open([{ operation: "inspectAttempt", fault: { kind: "unavailable" } }]);
  assert.deepEqual(await store.commitRestore(commitInput()), { outcome: "committed" });
  await assert.rejects(store.inspectAttempt({ scope, attemptId: "attempt-synthetic-1" }), storeError("STORE_UNAVAILABLE"));
});

test("malformed shapes corrupt a read result without changing the inner store", async () => {
  const read = { scope, entryIds: [entryId] };
  const shape = async (name, operation = "readEntries") => {
    const { inner, store } = await open([{ operation, fault: { kind: "malformed", shape: name } }]);
    const honest = await inner.readEntries(read);
    return { honest, store, inner };
  };

  let t = await shape("wrong-types");
  const wrong = await t.store.readEntries(read);
  assert.equal(typeof wrong.entries, "string");
  assert.equal(wrong.captures, null);
  assert.equal(wrong.outcome, 42);

  t = await shape("null");
  assert.equal(await t.store.readEntries(read), null);

  t = await shape("foreign-entry");
  const foreign = await t.store.readEntries(read);
  assert.equal(foreign.entries.length, 2);
  assert.equal(foreign.captures.length, 2);
  assert.notEqual(foreign.entries[1].captureId, captureId);
  assert.notEqual(foreign.entries[1].entryId, entryId);

  t = await shape("mismatched-capture");
  const mismatched = await t.store.readEntries(read);
  assert.notEqual(mismatched.entries[0].captureId, captureId);
  assert.equal(mismatched.captures[0].captureId, captureId);

  t = await shape("missing-capture");
  const missing = await t.store.readEntries(read);
  assert.equal(missing.entries.length, 1);
  assert.equal(missing.captures.length, 0);

  t = await shape("duplicate-entry");
  const duplicated = await t.store.readEntries(read);
  assert.deepEqual(duplicated.entries.map((entry) => entry.entryId), [entryId, entryId]);

  t = await shape("revision-lie");
  const lied = await t.store.readEntries(read);
  assert.equal(lied.entries[0].lifecycleRevision, t.honest.entries[0].lifecycleRevision + 1);
  assert.equal(lied.captures[0].generation, t.honest.captures[0].generation + 1);

  t = await shape("budget-lie");
  await t.inner.commitRestore(commitInput());
  assert.equal((await t.inner.readEntries(read)).entries[0].used, 1);
  assert.equal((await t.store.readEntries(read)).entries[0].used, 0);

  t = await shape("foreign-entry", "readCaptures");
  const captures = await t.store.readCaptures({ scope, captureIds: [captureId] });
  assert.equal(captures.length, 2);
  t = await shape("revision-lie", "readCaptures");
  assert.equal((await t.store.readCaptures({ scope, captureIds: [captureId] }))[0].generation, 2);
  assert.equal((await t.inner.readCaptures({ scope, captureIds: [captureId] }))[0].generation, 1);

  t = await shape("wrong-types", "commitRestore");
  assert.equal((await t.store.commitRestore(commitInput())).outcome, 42);
});

test("result returns a fixed answer, with or without calling the inner store", async () => {
  const { inner, store } = await open([
    { operation: "commitRestore", call: 0, fault: { kind: "result", result: { outcome: "committed" }, delegate: false } },
    { operation: "commitRestore", call: 1, fault: { kind: "result", result: { outcome: "rejected", reason: "budget" }, delegate: true } },
  ]);
  assert.deepEqual(await store.commitRestore(commitInput()), { outcome: "committed" });
  assert.equal(await used(inner), 0, "a lying adapter said committed and applied nothing");
  assert.deepEqual(await store.commitRestore(commitInput()), { outcome: "rejected", reason: "budget" });
  assert.equal(await used(inner), 1, "a lying adapter said rejected and applied the use");
});

test("capabilities can be misdeclared", async () => {
  const { inner, store } = await open([], { capabilities: { storeClock: false, contractVersion: 2 } });
  assert.equal(store.capabilities().storeClock, false);
  assert.equal(store.capabilities().contractVersion, 2);
  assert.equal(store.capabilities().adapter, inner.capabilities().adapter);
  assert.equal(inner.capabilities().storeClock, true);
});

test("rules can be added and cleared; call counts keep running", async () => {
  const { store } = await open();
  const read = { scope, entryIds: [entryId] };
  await store.readEntries(read);
  store.faults.add({ operation: "readEntries", call: 1, fault: { kind: "unavailable" } });
  await assert.rejects(store.readEntries(read), storeError("STORE_UNAVAILABLE"));
  store.faults.add({ operation: "readEntries", fault: { kind: "unavailable" } });
  store.faults.clear();
  assert.equal((await store.readEntries(read)).entries.length, 1);
  assert.equal(store.faults.calls("readEntries"), 3);
});

test("an invalid rule is refused with a fixed message", async () => {
  const { store: inner } = createModelStore();
  const bad = [
    { operation: "capabilities", fault: { kind: "unavailable" } },
    { operation: "noSuchOperation", fault: { kind: "unavailable" } },
    { operation: "commitRestore", call: -1, fault: { kind: "unavailable" } },
    { operation: "commitRestore", call: 1.5, fault: { kind: "unavailable" } },
    { operation: "commitRestore", fault: { kind: "no-such-fault" } },
    { operation: "commitRestore" },
    { operation: "commitRestore", fault: { kind: "malformed", shape: "budget-lie" } },
    { operation: "readEntries", fault: { kind: "malformed", shape: "no-such-shape" } },
  ];
  for (const rule of bad) {
    assert.throws(() => createFaultyStore(inner, { rules: [rule] }), TypeError);
    assert.throws(() => createFaultyStore(inner).faults.add(rule), TypeError);
  }
});
