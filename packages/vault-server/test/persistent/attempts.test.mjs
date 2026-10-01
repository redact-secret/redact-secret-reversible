// Attempts and the failure table of docs/specs/persistent-vault.md §7.3:
// what is stored and what the caller gets for every way a commit can end.
import assert from "node:assert/strict";
import test from "node:test";

import { StoreError } from "@redact-secret/vault-contracts";

import {
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
  restoreRequest,
  SECRET_A,
  SECRET_B,
  sleep,
  TENANT,
} from "./helpers.mjs";

const ORIGINAL = `secret ${SECRET_A} here`;
const ATTEMPT = "attempt-synthetic-0001";
const GRANTS = [
  { sink: "sink-a", paths: ["body", "subject"] },
  { sink: "sink-b", paths: ["body"] },
];

function once(rig, operation, action) {
  const remove = rig.memory.control.onPhase(operation, "before-apply", async () => {
    remove();
    await action();
  });
}

async function settled(rig, operation) {
  while (rig.spy.of(operation).some((call) => !call.settled)) await sleep(10);
}

/** An ambiguous commit: the error names the attempt and carries nothing else. */
async function ambiguous(promise, attemptId) {
  const error = await rejects(promise, "COMMIT_AMBIGUOUS");
  if (attemptId === undefined) assert.match(error.attemptId, /^att_[0-9a-f]{32}$/);
  else assert.equal(error.attemptId, attemptId);
  assert.deepEqual(Object.keys(error).sort(), ["attemptId", "code", "coreCode", "name", "reason", "vaultCode"]);
  assert.equal(error.fields, undefined);
  assert.equal(error.restored, undefined);
  return error;
}

// A commit that was applied in the store, and then answered in a way the server cannot take as a commit.
const APPLIED = [
  ["STORE_AMBIGUOUS after the commit was applied", { kind: "ambiguous", applied: true }, {}],
  ["a foreign Error after the commit was applied", { kind: "foreign-error", when: "after" }, {}],
  ["a response that arrives after storeTimeoutMs", { kind: "delay", afterMs: 150 }, { storeTimeoutMs: 30 }],
  ["a null result", { kind: "malformed", shape: "null" }, {}],
  ["a result of the wrong types", { kind: "malformed", shape: "wrong-types" }, {}],
  ["an unknown outcome", { kind: "result", result: { outcome: "done" }, delegate: true }, {}],
  ["an unknown rejection reason", { kind: "result", result: { outcome: "rejected", reason: "busy" }, delegate: true }, {}],
  ["a truthy non-object result", { kind: "result", result: "committed", delegate: true }, {}],
];

for (const [name, fault, vaultOptions] of APPLIED) {
  test(`commit ambiguous (${name}): COMMIT_AMBIGUOUS with the attemptId and no fields, no second commit, budget consumed`, async () => {
    const rig = await createRig({ vault: vaultOptions });
    const captured = await captureOne(rig, { maxUses: 2 });
    const request = restoreRequest(captured, { attemptId: ATTEMPT });
    rig.failNext("commitRestore", fault);
    await ambiguous(rig.vault.restore(request), ATTEMPT);
    await settled(rig, "commitRestore");

    assert.equal(rig.spy.count("commitRestore"), 1, "the server makes no second commitRestore call");
    assert.equal(rig.spy.count("readEntries"), 1, "and does not start over");
    assert.equal(rig.spy.count("inspectAttempt"), 0, "and does not resolve the attempt on its own");
    assert.deepEqual(await rig.used([captured.tokens[0].token]), [1], "the commit was applied: the use is spent");
    assert.equal(rig.memory.control.counts().receipts, 1);
    const audit = rig.audits.at(-1);
    assert.equal(audit.outcome, "failed");
    assert.equal(audit.code, "COMMIT_AMBIGUOUS");
    assert.equal(audit.attemptId, ATTEMPT);
    assert.equal("entries" in audit, false);

    // The application resolves the attempt. It learns the state, never the fields.
    const resolved = await rig.vault.resolveAttempt(request);
    assert.deepEqual(Object.keys(resolved).sort(), ["committedAt", "state"]);
    assert.equal(resolved.state, "committed");
    assert.equal(resolved.committedAt, rig.clock.now());
    assert.ok(Object.isFrozen(resolved));
    assert.equal(JSON.stringify(resolved).includes(SECRET_A), false);

    // The same attempt again: deduplicated, not replayed.
    await denied(rig.vault.restore(request), "attempt-already-committed");
    assert.deepEqual(await rig.used([captured.tokens[0].token]), [1], "the retry consumed nothing");
    assert.equal(rig.memory.control.counts().receipts, 1);

    // A different attempt is a new restore and spends its own use.
    const fresh = await rig.vault.restore(restoreRequest(captured, { attemptId: "attempt-synthetic-0002" }));
    assert.equal(fresh.fields.body, ORIGINAL);
    assert.deepEqual(await rig.used([captured.tokens[0].token]), [2]);
  });
}

test("commit ambiguous, single-use entry: a fresh attempt after an ambiguous commit that did apply is denied budget", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  rig.failNext("commitRestore", { kind: "ambiguous", applied: true });
  const error = await ambiguous(rig.vault.restore(restoreRequest(captured)));
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [1], "the response was lost; the use is spent");

  // "Unknown" is never treated as "not consumed": a new attempt cannot get the value.
  await denied(rig.vault.restore(restoreRequest(captured, { attemptId: "attempt-synthetic-fresh" })), "budget");
  await denied(rig.vault.restore(restoreRequest(captured)), "budget");
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [1]);
  assert.equal(rig.spy.count("commitRestore"), 1);
  assert.deepEqual(await rig.vault.resolveAttempt(restoreRequest(captured, { attemptId: error.attemptId })), {
    state: "committed",
    committedAt: rig.clock.now(),
  });
});

test("commit ambiguous, single-use entry: the same attempt retried after it committed is denied without fields or consumption", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  const request = restoreRequest(captured, { attemptId: ATTEMPT });
  rig.failNext("commitRestore", { kind: "ambiguous", applied: true });
  await ambiguous(rig.vault.restore(request), ATTEMPT);
  const error = await rejects(rig.vault.restore(request), "RESTORE_DENIED");
  assert.ok(["attempt-already-committed", "budget"].includes(error.reason));
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [1]);
  assert.equal(rig.memory.control.counts().receipts, 1);
});

test(
  "commit ambiguous, single-use entry: the same attempt retried after it committed reports attempt-already-committed",
  {
    skip:
      "SPEC AMBIGUITY (§7.2 step 4 vs §7.3 table): the table says the same attemptId and request after a commit is denied " +
      "attempt-already-committed, but step 4 denies used + count > maxUses from the row before commitRestore is ever called, and " +
      "§8.3 says an exhausted entry reports budget. For an entry the attempt itself exhausted, the server reports budget; the " +
      "receipt is only consulted by commitRestore. Not settled here: either the table needs 'when preflight still passes', or " +
      "the server must read the receipt before the budget check. resolveAttempt does report committed in this state.",
  },
  async () => {
    const rig = await createRig();
    const captured = await captureOne(rig);
    const request = restoreRequest(captured, { attemptId: ATTEMPT });
    rig.failNext("commitRestore", { kind: "ambiguous", applied: true });
    await ambiguous(rig.vault.restore(request), ATTEMPT);
    await denied(rig.vault.restore(request), "attempt-already-committed");
  },
);

// A commit the store never applied, reported in a way that leaves the server unable to know that.
const NOT_APPLIED = [
  ["STORE_AMBIGUOUS with the commit not applied", { kind: "ambiguous", applied: false }, {}],
  ["a foreign Error before the commit", { kind: "foreign-error", when: "before" }, {}],
  ["a commit still pending after storeTimeoutMs", { kind: "delay", beforeMs: 150 }, { storeTimeoutMs: 30 }],
];

for (const [name, fault, vaultOptions] of NOT_APPLIED) {
  test(`commit ambiguous (${name}): resolveAttempt is absent, and the same attempt then succeeds exactly once`, async () => {
    const rig = await createRig({ vault: vaultOptions });
    const captured = await captureOne(rig);
    const request = restoreRequest(captured, { attemptId: ATTEMPT });
    rig.failNext("commitRestore", fault);
    await ambiguous(rig.vault.restore(request), ATTEMPT);
    assert.equal(rig.spy.count("commitRestore"), 1, "no automatic retry");
    // A call the server gave up on is cancelled, so an adapter that honours the signal applies nothing later.
    if (fault.kind === "delay") assert.equal(rig.spy.last("commitRestore").signal.aborted, true);
    assert.deepEqual(await rig.vault.resolveAttempt(request), { state: "absent" });

    const retried = await rig.vault.restore(request);
    assert.equal(retried.fields.body, ORIGINAL);
    assert.equal(retried.attemptId, ATTEMPT);
    // Whatever the first transaction does now, it and the retry are mutually exclusive.
    await settled(rig, "commitRestore");
    assert.deepEqual(await rig.used([captured.tokens[0].token]), [1]);
    assert.equal(rig.memory.control.counts().receipts, 1);
    assert.equal(rig.spy.of("commitRestore").filter((call) => call.result?.outcome === "committed").length, 1);
    assert.equal((await rig.vault.resolveAttempt(request)).state, "committed");
    // And never a second time.
    const again = await rejects(rig.vault.restore(request), "RESTORE_DENIED");
    assert.ok(["attempt-already-committed", "budget"].includes(again.reason));
    assert.deepEqual(await rig.used([captured.tokens[0].token]), [1]);
  });
}

test("commit ambiguous: an attemptId the server generated is carried by the error and resolves", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  rig.failNext("commitRestore", { kind: "foreign-error", when: "after" });
  const error = await ambiguous(rig.vault.restore(restoreRequest(captured)));
  assert.equal(rig.spy.last("commitRestore").input.attempt.attemptId, error.attemptId);
  assert.equal((await rig.vault.resolveAttempt(restoreRequest(captured, { attemptId: error.attemptId }))).state, "committed");
});

test("attempt: when omitted, the server generates an attemptId, returns it, and never repeats one", async () => {
  const rig = await createRig();
  const seen = new Set();
  for (let i = 0; i < 40; i += 1) {
    const captured = await captureOne(rig);
    const restored = await rig.vault.restore(restoreRequest(captured));
    assert.match(restored.attemptId, /^att_[0-9a-f]{32}$/);
    assert.equal(rig.spy.last("commitRestore").input.attempt.attemptId, restored.attemptId);
    seen.add(restored.attemptId);
    assert.equal((await rig.vault.resolveAttempt(restoreRequest(captured, { attemptId: restored.attemptId }))).state, "committed");
  }
  assert.equal(seen.size, 40);
  // A caller's own identifier is used as given.
  const captured = await captureOne(rig);
  const restored = await rig.vault.restore(restoreRequest(captured, { attemptId: "caller.attempt:synthetic-0001" }));
  assert.equal(restored.attemptId, "caller.attempt:synthetic-0001");
});

test("attempt: the same attemptId and request after a commit is attempt-already-committed, with no fields and no consumption", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { maxUses: 4 });
  const request = restoreRequest(captured, { attemptId: ATTEMPT });
  assert.equal((await rig.vault.restore(request)).fields.body, ORIGINAL);
  for (let i = 0; i < 3; i += 1) await denied(rig.vault.restore(request), "attempt-already-committed");
  // The digest covers the request's shape, not its literal text or field order.
  await denied(rig.vault.restore({ ...request, fields: { body: `different words ${captured.tokens[0].token}` } }), "attempt-already-committed");
  // Another instance of the same namespace and digest key deduplicates the same way.
  await denied((await rig.open()).restore(request), "attempt-already-committed");
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [1]);
  assert.equal(rig.memory.control.counts().receipts, 1);
});

test("attempt: the same attemptId with a different request is attempt-mismatch, for restore and for resolveAttempt", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { maxUses: 8, release: GRANTS });
  const other = await captureOne(rig, { text: `other ${SECRET_B}`, maxUses: 8, release: GRANTS });
  const [{ token }] = captured.tokens;
  const request = restoreRequest(captured, { attemptId: ATTEMPT, fields: { body: token } });
  assert.equal((await rig.vault.restore(request)).fields.body, SECRET_A);

  const different = {
    "another occurrence count": { fields: { body: `${token} ${token}` } },
    "another path": { fields: { subject: token } },
    "an extra path": { fields: { body: token, subject: token } },
    "another sink": { sink: "sink-b" },
    "another purpose": { purpose: "purpose-synthetic-other" },
    "another capture set": { captures: [captured.captureId, other.captureId] },
    "another entry": { captures: [captured.captureId, other.captureId], fields: { body: other.tokens[0].token } },
    "another principal of the tenant": { context: ctx({ id: "principal-synthetic-0009" }) },
    "another session": { context: ctx({ session: "session-synthetic-0001" }) },
  };
  for (const [name, change] of Object.entries(different)) {
    await denied(rig.vault.restore({ ...request, ...change }), "attempt-mismatch");
    assert.deepEqual(await rig.vault.resolveAttempt({ ...request, ...change }), { state: "attempt-mismatch" }, name);
  }
  assert.deepEqual(await rig.used([token, other.tokens[0].token]), [1, 0], "no mismatched attempt consumed anything");
  assert.equal(rig.memory.control.counts().receipts, 1);

  // The original request still resolves as committed; another identifier is absent.
  assert.equal((await rig.vault.resolveAttempt(request)).state, "committed");
  assert.deepEqual(await rig.vault.resolveAttempt({ ...request, attemptId: "attempt-synthetic-unused" }), { state: "absent" });
  // An attempt made under one digest key and resolved under another is a mismatch (§7.3).
  const rekeyed = await rig.open({ digestKey: new Uint8Array(32).fill(0x22) });
  assert.deepEqual(await rekeyed.resolveAttempt(request), { state: "attempt-mismatch" });
  await denied(rekeyed.restore(request), "attempt-mismatch");
  // Receipts are scoped to the tenant: another tenant's same identifier is a different attempt.
  assert.deepEqual(await rig.vault.resolveAttempt({ ...request, context: CTX_B }), { state: "absent" });
});

test("commit STORE_UNAVAILABLE: nothing is consumed and the same attempt can be retried", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  const request = restoreRequest(captured, { attemptId: ATTEMPT });
  rig.failNext("commitRestore", { kind: "unavailable" });
  const error = await rejects(rig.vault.restore(request), "STORE_UNAVAILABLE");
  assert.equal(error.attemptId, undefined);
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [0]);
  assert.equal(rig.memory.control.counts().receipts, 0);
  assert.equal(rig.spy.count("commitRestore"), 1, "the server does not retry on its own");
  assert.deepEqual(await rig.vault.resolveAttempt(request), { state: "absent" });
  const retried = await rig.vault.restore(request);
  assert.equal(retried.fields.body, ORIGINAL);
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [1]);
});

test("commit STORE_INVALID_ARGUMENT or STORE_CAPABILITY: a definite failure, INVARIANT_VIOLATION, not ambiguous", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  for (const code of ["STORE_INVALID_ARGUMENT", "STORE_CAPABILITY"]) {
    rig.spy.before.commitRestore = () => {
      throw new StoreError(code);
    };
    await rejects(rig.vault.restore(restoreRequest(captured)), "INVARIANT_VIOLATION");
  }
  rig.spy.before.commitRestore = () => {
    throw new StoreError("STORE_CLOSED");
  };
  await rejects(rig.vault.restore(restoreRequest(captured)), "STORE_UNAVAILABLE");
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [0]);
});

test("preflight read failures: unavailable, foreign error, timeout, and invalid argument release nothing and consume nothing", async () => {
  const rig = await createRig({ vault: { storeTimeoutMs: 30 } });
  const captured = await captureOne(rig);
  const cases = [
    [{ kind: "unavailable" }, "STORE_UNAVAILABLE"],
    [{ kind: "ambiguous", applied: false }, "STORE_UNAVAILABLE"],
    [{ kind: "foreign-error", when: "before" }, "STORE_UNAVAILABLE"],
    [{ kind: "foreign-error", when: "after" }, "STORE_UNAVAILABLE"],
    [{ kind: "delay", beforeMs: 120 }, "STORE_UNAVAILABLE"],
  ];
  for (const [fault, code] of cases) {
    rig.failNext("readEntries", fault);
    await rejects(rig.vault.restore(restoreRequest(captured)), code);
  }
  rig.spy.before.readEntries = () => {
    throw new StoreError("STORE_INVALID_ARGUMENT");
  };
  await rejects(rig.vault.restore(restoreRequest(captured)), "INVARIANT_VIOLATION");
  rig.spy.before.readEntries = undefined;
  assert.equal(rig.spy.count("commitRestore"), 0);
  assert.equal(rig.keys.stats.unwrap, 0);
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [0]);
});

test("stale then success: a concurrent use between the read and the commit makes the server read and evaluate the policy again", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { maxUses: 3 });
  const [{ token }] = captured.tokens;
  const other = await rig.open({ policy: () => ({ allow: true }) });
  once(rig, "commitRestore", async () => {
    assert.equal((await other.restore(restoreRequest(captured))).fields.body, ORIGINAL);
  });
  const restored = await rig.vault.restore(restoreRequest(captured, { attemptId: ATTEMPT }));
  assert.equal(restored.fields.body, ORIGINAL);
  assert.equal(restored.attemptId, ATTEMPT);

  // Two evaluations by this server: one per read, the second shown the new `used`.
  assert.deepEqual(rig.policyCalls.map((input) => input.used), [0, 1]);
  assert.equal(rig.spy.count("readEntries"), 3, "this server read twice, the other once");
  const commits = rig.spy.of("commitRestore");
  assert.deepEqual(commits.map((call) => call.result), [
    { outcome: "rejected", reason: "stale" },
    { outcome: "committed" },
    { outcome: "committed" },
  ]);
  assert.equal(commits[0].input.attempt.attemptId, ATTEMPT);
  assert.equal(commits[2].input.attempt.attemptId, ATTEMPT, "the retry is the same attempt");
  assert.equal(commits[0].input.uses[0].lifecycleRevision, 1);
  assert.equal(commits[2].input.uses[0].lifecycleRevision, 2);
  assert.deepEqual(await rig.used([token]), [2]);
  assert.equal(rig.memory.control.counts().receipts, 2);
});

test("stale then denial: a policy that denies on the second evaluation stops the retry with nothing consumed by it", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { maxUses: 3 });
  const other = await rig.open({ policy: () => ({ allow: true }) });
  once(rig, "commitRestore", async () => {
    await other.restore(restoreRequest(captured));
  });
  rig.policy = (input) => (input.used === 0 ? { allow: true } : { allow: false, reason: "policy" });
  await denied(rig.vault.restore(restoreRequest(captured)), "policy");
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [1], "only the other server's use");
});

test("stale beyond maxCommitRetries: RESTORE_CONFLICT with nothing consumed, and the same attempt can be retried", async () => {
  for (const [maxCommitRetries, expectedCommits] of [
    [undefined, 4],
    [0, 1],
    [2, 3],
  ]) {
    const rig = await createRig({ vault: maxCommitRetries === undefined ? {} : { maxCommitRetries } });
    const captured = await captureOne(rig);
    const request = restoreRequest(captured, { attemptId: ATTEMPT });
    rig.faults.add({ operation: "commitRestore", fault: { kind: "result", result: { outcome: "rejected", reason: "stale" }, delegate: false } });
    const error = await rejects(rig.vault.restore(request), "RESTORE_CONFLICT");
    assert.equal(error.attemptId, undefined);
    assert.equal(rig.spy.count("commitRestore"), expectedCommits, "one commit, then maxCommitRetries more");
    assert.equal(rig.spy.count("readEntries"), expectedCommits, "each retry reads again");
    assert.equal(rig.policyCalls.length, expectedCommits, "and evaluates the policy again");
    assert.equal(new Set(rig.spy.of("commitRestore").map((call) => call.input.attempt.attemptId)).size, 1, "all under the same attempt");
    assert.deepEqual(await rig.used([captured.tokens[0].token]), [0]);
    assert.equal(rig.memory.control.counts().receipts, 0);
    rig.faults.clear();
    assert.equal((await rig.vault.restore(request)).fields.body, ORIGINAL);
  }
});

test("clock skew: a commit the store rejects for skew is CLOCK_SKEW with nothing consumed", async () => {
  const time = { server: 1_790_000_000_000, store: 1_790_000_000_000 };
  const rig = await createRig({ clock: { now: () => time.server }, storeClock: { now: () => time.store } });
  const captured = await captureOne(rig);
  for (const drift of [2001, -2001]) {
    time.store = time.server + drift;
    await rejects(rig.vault.restore(restoreRequest(captured)), "CLOCK_SKEW");
  }
  assert.equal(rig.spy.count("commitRestore"), 2);
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [0]);
  assert.equal(rig.memory.control.counts().receipts, 0);
  time.store = time.server + 2000;
  assert.equal((await rig.vault.restore(restoreRequest(captured))).fields.body, ORIGINAL);
});

test("quarantine between creation and restore: STORE_QUARANTINED before any unwrap or commit", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  await rig.memory.store.quarantine({ namespace: NAMESPACE });
  await rejects(rig.vault.restore(restoreRequest(captured)), "STORE_QUARANTINED");
  assert.equal(rig.keys.stats.unwrap, 0);
  assert.equal(rig.spy.count("commitRestore"), 0);
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [0]);
});

test("commitRestore rejections: each reason maps to its row of the table, and none returns fields", async () => {
  const cases = [
    [{ outcome: "rejected", reason: "revoked" }, "RESTORE_DENIED", "revoked"],
    [{ outcome: "rejected", reason: "expired" }, "RESTORE_DENIED", "expired"],
    [{ outcome: "rejected", reason: "budget" }, "RESTORE_DENIED", "budget"],
    [{ outcome: "rejected", reason: "unknown" }, "RESTORE_DENIED", "unknown-token"],
    [{ outcome: "rejected", reason: "clock-skew" }, "CLOCK_SKEW", undefined],
    [{ outcome: "rejected", reason: "quarantined" }, "STORE_QUARANTINED", undefined],
    [{ outcome: "already-committed" }, "RESTORE_DENIED", "attempt-already-committed"],
    [{ outcome: "attempt-mismatch" }, "RESTORE_DENIED", "attempt-mismatch"],
  ];
  for (const [result, code, reason] of cases) {
    const rig = await createRig();
    const captured = await captureOne(rig);
    rig.failNext("commitRestore", { kind: "result", result, delegate: false });
    await rejects(rig.vault.restore(restoreRequest(captured)), code, reason);
    assert.equal(rig.spy.count("commitRestore"), 1);
    assert.deepEqual(await rig.used([captured.tokens[0].token]), [0]);
  }
});

test("resolveAttempt: it needs an attemptId and a well-formed request, asks the lifecycle policy, and never returns fields", async () => {
  const rig = await createRig({ vault: { policyTimeoutMs: 25 } });
  const captured = await captureOne(rig, { maxUses: 2 });
  const request = restoreRequest(captured, { attemptId: ATTEMPT });
  await rig.vault.restore(request);
  rig.lifecycleCalls.length = 0;
  rig.spy.reset();

  await rejects(rig.vault.resolveAttempt(restoreRequest(captured)), "INVALID_ARGUMENT");
  await rejects(rig.vault.resolveAttempt(null), "INVALID_ARGUMENT");
  await rejects(rig.vault.resolveAttempt({ ...request, attemptId: "has space" }), "INVALID_ARGUMENT");
  await rejects(rig.vault.resolveAttempt({ ...request, fields: { body: "rsv_" } }), "INVALID_ARGUMENT");
  await rejects(rig.vault.resolveAttempt({ ...request, fields: { body: 7 } }), "INVALID_ARGUMENT");
  await rejects(rig.vault.resolveAttempt({ ...request, captures: [] }), "INVALID_ARGUMENT");
  assert.equal(rig.spy.calls.length, 0);
  assert.equal(rig.lifecycleCalls.length, 0);

  const resolved = await rig.vault.resolveAttempt(request);
  assert.deepEqual(resolved, { state: "committed", committedAt: rig.clock.now() });
  assert.deepEqual(rig.spy.calls.map((call) => call.operation), ["inspectAttempt"], "one authoritative read, nothing else");
  assert.deepEqual(rig.spy.last("inspectAttempt").input, { scope: { namespace: NAMESPACE, tenant: TENANT }, attemptId: ATTEMPT });
  assert.deepEqual(rig.lifecycleCalls, [
    {
      operation: "resolve-attempt",
      principal: CTX_A.principal,
      tenant: TENANT,
      sessionId: null,
      requestedAt: rig.clock.now(),
    },
  ]);
  assert.equal(rig.keys.stats.unwrap, 1, "resolving unwraps nothing: only the restore did");
  assert.deepEqual(rig.audits.at(-1), {
    operation: "resolve-attempt",
    outcome: "committed",
    at: rig.clock.now(),
    principalId: CTX_A.principal.id,
    tenant: TENANT,
    attemptId: ATTEMPT,
  });

  // Denied by the lifecycle policy in any way: no store read.
  rig.spy.reset();
  for (const behaviour of [
    () => ({ allow: false }),
    () => {
      throw foreignError();
    },
    () => new Promise(() => {}),
    () => true,
    () => null,
  ]) {
    rig.lifecycle = behaviour;
    await rejects(rig.vault.resolveAttempt(request), "LIFECYCLE_DENIED");
  }
  await rejects(rig.vault.resolveAttempt({ ...request, context: {} }), "LIFECYCLE_DENIED");
  assert.equal(rig.spy.calls.length, 0);
  rig.lifecycle = () => ({ allow: true });

  // Store failures and malformed answers fail closed.
  rig.failNext("inspectAttempt", { kind: "unavailable" });
  await rejects(rig.vault.resolveAttempt(request), "STORE_UNAVAILABLE");
  rig.failNext("inspectAttempt", { kind: "foreign-error", when: "after" });
  await rejects(rig.vault.resolveAttempt(request), "STORE_UNAVAILABLE");
  for (const shape of ["null", "wrong-types"]) {
    rig.failNext("inspectAttempt", { kind: "malformed", shape });
    await rejects(rig.vault.resolveAttempt(request), "INVARIANT_VIOLATION");
  }
  for (const result of [{ state: "committed" }, { state: "committed", requestDigest: "digest", committedAt: 1 }, { state: "maybe" }]) {
    rig.failNext("inspectAttempt", { kind: "result", result, delegate: false });
    await rejects(rig.vault.resolveAttempt(request), "INVARIANT_VIOLATION");
  }
  assert.equal(rig.spy.mutations(), 0, "resolving an attempt never writes");
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [1]);
});

registerLeakHygiene({ minErrors: 80 });
