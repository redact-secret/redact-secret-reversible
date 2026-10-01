// Atomicity, budgets, races, and several server instances over one store
// (docs/specs/persistent-vault.md §5.2, §7.1, §7.2; issue #105 acceptance).
//
// The interleavings are placed with store-memory's control hooks, not with
// timing: a hook runs between a server's preflight read and its commit.
import assert from "node:assert/strict";
import test from "node:test";

import {
  captureOne,
  createMemoryStore,
  createRig,
  CTX_A,
  ctx,
  deferred,
  denied,
  NAMESPACE,
  recordError,
  registerLeakHygiene,
  rejects,
  restoreRequest,
  SECRET_A,
  SECRET_B,
  SECRET_C,
  TENANT,
  VaultServerError,
} from "./helpers.mjs";

const ORIGINAL = `secret ${SECRET_A} here`;

/** Runs `action` once, the next time `operation` reaches the store's atomic section. */
function once(rig, operation, action) {
  const remove = rig.memory.control.onPhase(operation, "before-apply", async () => {
    remove();
    await action();
  });
  return remove;
}

/** Settles every promise and sorts the outcomes; every rejection must be a clean VaultServerError. */
async function settle(promises) {
  const settled = await Promise.allSettled(promises);
  const fulfilled = [];
  const rejected = [];
  for (const result of settled) {
    if (result.status === "fulfilled") fulfilled.push(result.value);
    else {
      assert.ok(result.reason instanceof VaultServerError, "a restore rejects only with a VaultServerError");
      rejected.push(recordError(result.reason));
    }
  }
  return { fulfilled, rejected };
}

function tally(errors) {
  const counts = {};
  for (const error of errors) {
    const key = error.code === "RESTORE_DENIED" ? error.reason : error.code;
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}

test("budget: a token repeated across fields consumes its total occurrence count in one commit", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { maxUses: 3 });
  const [{ token }] = captured.tokens;
  const restored = await rig.vault.restore(restoreRequest(captured, { fields: { body: `${token} and ${token}`, subject: token } }));
  assert.equal(restored.fields.body, `${SECRET_A} and ${SECRET_A}`);
  assert.equal(restored.fields.subject, SECRET_A);
  assert.equal(restored.restored, 3);
  assert.equal(rig.spy.count("commitRestore"), 1);
  const { uses, captures } = rig.spy.last("commitRestore").input;
  assert.equal(uses.length, 1, "the entry appears once in the commit");
  assert.equal(uses[0].count, 3, "with its total occurrence count");
  assert.deepEqual(captures.map((capture) => capture.captureId), [captured.captureId]);
  assert.deepEqual(await rig.used([token]), [3]);
  assert.equal(rig.memory.control.counts().receipts, 1);
});

test("budget: one occurrence over maxUses is denied budget with no consumption at all", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { maxUses: 3 });
  const [{ token }] = captured.tokens;
  await denied(
    rig.vault.restore(restoreRequest(captured, { fields: { body: `${token} ${token}`, subject: `${token} ${token}` } })),
    "budget",
  );
  assert.deepEqual(await rig.used([token]), [0], "not three of the four: none");
  assert.equal(rig.spy.count("commitRestore"), 0);
  assert.equal(rig.keys.stats.unwrap, 0);
  assert.equal(rig.memory.control.counts().receipts, 0);

  // Partially used: two of three spent, a request for two more is denied and spends nothing.
  await rig.vault.restore(restoreRequest(captured, { fields: { body: `${token} ${token}` } }));
  await denied(rig.vault.restore(restoreRequest(captured, { fields: { body: `${token} ${token}` } })), "budget");
  assert.deepEqual(await rig.used([token]), [2]);
  await rig.vault.restore(restoreRequest(captured, { fields: { body: token } }));
  assert.deepEqual(await rig.used([token]), [3]);
  await denied(rig.vault.restore(restoreRequest(captured, { fields: { body: token } })), "budget");
  assert.deepEqual(await rig.used([token]), [3]);
});

test("all-or-nothing: a request whose last entry is over budget consumes nothing for any entry", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { text: `a ${SECRET_A} b ${SECRET_B} c ${SECRET_C}` });
  const [a, b, c] = captured.tokens.map(({ token }) => token);
  await denied(rig.vault.restore(restoreRequest(captured, { fields: { body: `${a} ${b} ${c} ${c}` } })), "budget");
  assert.deepEqual(await rig.used([a, b, c]), [0, 0, 0]);
  assert.equal(rig.spy.count("commitRestore"), 0);
  // The same entries restore once the request is within budget.
  const restored = await rig.vault.restore(restoreRequest(captured, { fields: { body: `${a} ${b} ${c}` } }));
  assert.equal(restored.fields.body, `${SECRET_A} ${SECRET_B} ${SECRET_C}`);
  assert.deepEqual(await rig.used([a, b, c]), [1, 1, 1]);
});

test("all-or-nothing: a request whose last entry belongs to a revoked capture consumes nothing", async () => {
  const rig = await createRig();
  const first = await captureOne(rig);
  const second = await captureOne(rig, { text: `other ${SECRET_B}` });
  await rig.vault.revoke({ context: CTX_A, captureId: second.captureId });
  await denied(
    rig.vault.restore(
      restoreRequest(first, { captures: [first.captureId, second.captureId], fields: { body: first.text, subject: second.text } }),
    ),
    "revoked",
  );
  assert.deepEqual(await rig.used([first.tokens[0].token]), [0]);
  assert.equal(rig.spy.count("commitRestore"), 0);
  assert.equal((await rig.vault.restore(restoreRequest(first))).fields.body, ORIGINAL);
});

test("all-or-nothing: a request whose last entry is used on a path it was not granted consumes nothing", async () => {
  const rig = await createRig();
  const wide = await captureOne(rig);
  const narrow = await captureOne(rig, { text: `other ${SECRET_B}`, release: [{ sink: "sink-a", paths: ["body"] }] });
  await denied(
    rig.vault.restore(
      restoreRequest(wide, { captures: [wide.captureId, narrow.captureId], fields: { body: wide.text, subject: narrow.text } }),
    ),
    "sink-or-path",
  );
  assert.deepEqual(await rig.used([wide.tokens[0].token]), [0]);
  assert.deepEqual(await rig.used([narrow.tokens[0].token]), [0]);
  assert.equal(rig.spy.count("commitRestore"), 0);
});

test("all-or-nothing: a request whose last entry the policy denies consumes nothing", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { text: `a ${SECRET_A} b ${SECRET_B}` });
  let asked = 0;
  rig.policy = () => ((asked += 1) === 2 ? { allow: false, reason: "policy" } : { allow: true });
  await denied(rig.vault.restore(restoreRequest(captured)), "policy");
  assert.equal(asked, 2);
  assert.deepEqual(await rig.used(captured.tokens.map(({ token }) => token)), [0, 0]);
  assert.equal(rig.spy.count("commitRestore"), 0);
});

test("all-or-nothing: an entry exhausted by another server between the read and the commit denies the whole request", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { text: `a ${SECRET_A} b ${SECRET_B}` });
  const [a, b] = captured.tokens.map(({ token }) => token);
  const other = await rig.open();
  once(rig, "commitRestore", async () => {
    await other.restore(restoreRequest(captured, { fields: { body: b } }));
  });
  await denied(rig.vault.restore(restoreRequest(captured)), "budget");
  assert.deepEqual(await rig.used([a, b]), [0, 1], "the first entry of the denied request was not consumed");
  assert.equal(rig.memory.control.counts().receipts, 1, "only the other server's attempt has a receipt");
});

test("concurrency: 100 parallel restores of one single-use token release it exactly once", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  const { fulfilled, rejected } = await settle(Array.from({ length: 100 }, () => rig.vault.restore(restoreRequest(captured))));
  assert.equal(fulfilled.length, 1, "exactly one restore returns fields");
  assert.equal(fulfilled[0].fields.body, ORIGINAL);
  assert.equal(rejected.length, 99);
  for (const error of rejected) {
    assert.ok(
      (error.code === "RESTORE_DENIED" && error.reason === "budget") || error.code === "RESTORE_CONFLICT",
      `unexpected outcome ${error.code}/${error.reason}`,
    );
    assert.equal(error.fields, undefined);
  }
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [1]);
  assert.equal(rig.memory.control.counts().receipts, 1);
  assert.equal(rig.spy.of("commitRestore").filter((call) => call.result?.outcome === "committed").length, 1);
  assert.equal(new Set(rig.spy.of("commitRestore").map((call) => call.input.attempt.attemptId)).size, 100, "each restore has its own attempt");
});

test("concurrency: 100 parallel restores split over two server instances still release a single-use token once", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  const other = await rig.open();
  const { fulfilled, rejected } = await settle(
    Array.from({ length: 100 }, (_unused, index) => (index % 2 === 0 ? rig.vault : other).restore(restoreRequest(captured))),
  );
  assert.equal(fulfilled.length, 1);
  assert.deepEqual(Object.keys(tally(rejected)).filter((key) => key !== "budget" && key !== "RESTORE_CONFLICT"), []);
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [1]);
});

test("concurrency: parallel restores of a multi-use token never exceed maxUses, and every success is counted", async () => {
  const rig = await createRig({ vault: { maxCommitRetries: 10 } });
  const captured = await captureOne(rig, { maxUses: 5 });
  const { fulfilled, rejected } = await settle(Array.from({ length: 100 }, () => rig.vault.restore(restoreRequest(captured))));
  const [used] = await rig.used([captured.tokens[0].token]);
  assert.ok(fulfilled.length >= 1 && fulfilled.length <= 5, `successes within the budget, got ${fulfilled.length}`);
  assert.equal(used, fulfilled.length, "used equals the number of restores that returned fields");
  assert.equal(rig.memory.control.counts().receipts, fulfilled.length);
  assert.deepEqual(Object.keys(tally(rejected)).filter((key) => key !== "budget" && key !== "RESTORE_CONFLICT"), []);
});

test("concurrency: 100 parallel restores against one revoke; nothing started after the revoke succeeds", async () => {
  const rig = await createRig({ vault: { limits: { maxUsesPerEntry: 1000 }, maxCommitRetries: 10 } });
  const captured = await captureOne(rig, { maxUses: 1000 });
  const [{ token }] = captured.tokens;

  // The order in which operations reach the store's atomic section.
  // The revocation starts once commits are already arriving, so it lands in the middle of them.
  const order = [];
  const revoked = deferred();
  rig.memory.control.onPhase("commitRestore", "before-apply", ({ call }) => {
    order.push(`commit#${call}`);
    if (call === 3) rig.vault.revoke({ context: CTX_A, captureId: captured.captureId }).then(revoked.resolve, revoked.reject);
  });
  rig.memory.control.onPhase("revokeCapture", "before-apply", () => {
    order.push("revoke");
  });

  const racing = settle(Array.from({ length: 100 }, () => rig.vault.restore(restoreRequest(captured))));
  assert.equal((await revoked.promise).outcome, "revoked");
  // Started strictly after the revocation resolved.
  const late = await settle(Array.from({ length: 20 }, () => rig.vault.restore(restoreRequest(captured))));
  assert.equal(late.fulfilled.length, 0, "no restore that started after the revoke resolved succeeds");
  assert.deepEqual(tally(late.rejected), { revoked: 20 });

  const { fulfilled, rejected } = await racing;
  assert.equal(fulfilled.length + rejected.length, 100);
  assert.ok(fulfilled.length >= 1, "the race is real: a restore committed before the revocation");
  assert.ok((tally(rejected).revoked ?? 0) >= 1, "the race is real: a restore lost to the revocation");
  assert.deepEqual(Object.keys(tally(rejected)).filter((key) => key !== "revoked" && key !== "RESTORE_CONFLICT"), []);
  // Every success is one consumed use, and nothing else was consumed.
  assert.deepEqual(await rig.used([token]), [fulfilled.length]);
  assert.equal(rig.memory.control.counts().receipts, fulfilled.length);
  // No commit that reached the store after the revocation was accepted.
  const commits = rig.spy.of("commitRestore");
  const revokeAt = order.indexOf("revoke");
  assert.ok(revokeAt >= 0);
  for (const [index, label] of order.entries()) {
    if (!label.startsWith("commit#")) continue;
    const outcome = commits[Number(label.slice("commit#".length))].result;
    if (index > revokeAt) assert.notEqual(outcome.outcome, "committed", "a commit after the revocation must not succeed");
  }
  assert.equal((await rig.captureRow(captured.captureId)).state, "revoked");
});

test("race: a revocation committed between a restore's read and its commit denies the restore", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { maxUses: 4 });
  const other = await rig.open();
  once(rig, "commitRestore", async () => {
    assert.equal((await other.revoke({ context: CTX_A, captureId: captured.captureId })).outcome, "revoked");
  });
  await denied(rig.vault.restore(restoreRequest(captured)), "revoked");
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [0]);
  assert.equal(rig.memory.control.counts().receipts, 0);
  assert.equal(rig.spy.of("commitRestore").filter((call) => call.result?.outcome === "committed").length, 0);
});

test("race: a quarantine or an invalidation between a restore's read and its commit fails the restore closed", async () => {
  for (const interfere of [
    (store) => store.quarantine({ namespace: NAMESPACE }),
    (store) => store.invalidateRecovered({ namespace: NAMESPACE, newEpoch: 2 }),
  ]) {
    const rig = await createRig();
    const captured = await captureOne(rig);
    once(rig, "commitRestore", () => interfere(rig.memory.store));
    await rejects(rig.vault.restore(restoreRequest(captured)), "STORE_QUARANTINED");
    assert.deepEqual(await rig.used([captured.tokens[0].token]), [0]);
    assert.equal(rig.memory.control.counts().receipts, 0);
  }
});

test("race: a revoke after a create leaves a revoked capture; a fence before a create makes the create fail", async () => {
  // Create first, then revoke: live, then revoked.
  const rig = await createRig();
  const captured = await captureOne(rig);
  assert.equal((await rig.vault.revoke({ context: CTX_A, captureId: captured.captureId })).outcome, "revoked");
  await denied(rig.vault.restore(restoreRequest(captured)), "revoked");

  // Fence first: the store refuses the create, the capture fails, and nothing is live.
  const fenced = await createRig();
  let captureId;
  fenced.spy.before.createCapture = async (input) => {
    captureId = input.capture.captureId;
    const result = await fenced.memory.store.revokeCapture({
      scope: input.scope,
      captureId,
      now: fenced.clock.now(),
      retentionMs: 0,
      fenceAbsent: true,
    });
    assert.deepEqual(result, { outcome: "fenced" });
  };
  await rejects(fenced.vault.capture(ORIGINAL, { context: CTX_A, release: [{ sink: "sink-a", paths: ["body"] }] }), "INVARIANT_VIOLATION");
  assert.deepEqual(fenced.spy.last("createCapture").result, { outcome: "rejected", reason: "fenced" });
  assert.equal((await fenced.captureRow(captureId)).state, "revoked");
  assert.equal(fenced.memory.control.counts().entries, 0);
});

test("race: a quarantine committed between a capture's checks and its create stores nothing", async () => {
  const rig = await createRig();
  once(rig, "createCapture", () => rig.memory.store.quarantine({ namespace: NAMESPACE }));
  await rejects(rig.vault.capture(ORIGINAL, { context: CTX_A, release: [{ sink: "sink-a", paths: ["body"] }] }), "STORE_QUARANTINED");
  assert.deepEqual(rig.memory.control.counts(), { namespaces: 1, captures: 0, entries: 0, receipts: 0 });
});

test("two instances over one store: capture on one, restore on the other; a revoke on one denies on the other", async () => {
  const rig = await createRig();
  const a = rig.vault;
  const b = await rig.open();
  const first = await captureOne(rig, { vault: a });
  assert.equal((await b.restore(restoreRequest(first))).fields.body, ORIGINAL);
  // The budget is the store's, not an instance's.
  await denied(a.restore(restoreRequest(first)), "budget");
  await denied(b.restore(restoreRequest(first)), "budget");

  const shared = await captureOne(rig, { vault: b, maxUses: 2 });
  assert.equal((await a.restore(restoreRequest(shared))).fields.body, ORIGINAL);
  assert.equal((await b.restore(restoreRequest(shared))).fields.body, ORIGINAL);
  await denied(a.restore(restoreRequest(shared)), "budget");

  const second = await captureOne(rig, { vault: a, maxUses: 4 });
  assert.equal((await a.restore(restoreRequest(second))).fields.body, ORIGINAL);
  assert.equal((await b.revoke({ context: CTX_A, captureId: second.captureId })).outcome, "revoked");
  await denied(a.restore(restoreRequest(second)), "revoked");
  await denied(b.restore(restoreRequest(second)), "revoked");
  assert.deepEqual(await rig.used([second.tokens[0].token]), [1]);

  // A session-bound capture is bound to the session, not to the instance that captured it.
  const session = "session-synthetic-0001";
  const bound = await captureOne(rig, { vault: a, context: ctx({ session }) });
  await denied(b.restore(restoreRequest(bound, { context: ctx({ session: "session-synthetic-0002" }) })), "source");
  assert.equal((await b.restore(restoreRequest(bound, { context: ctx({ session }) }))).fields.body, ORIGINAL);
});

test("restart: a new instance over the same store restores; a new memory store has lost everything", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { maxUses: 3 });
  await rig.vault.restore(restoreRequest(captured));
  await rig.vault.close();

  const restarted = await rig.open();
  assert.equal((await restarted.restore(restoreRequest(captured))).fields.body, ORIGINAL);
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [2], "the budget survived the restart");

  // A fresh store with the same keys and configuration: the token means nothing there.
  const fresh = await createRig({ memory: createMemoryStore({ now: rig.clock.now }), clock: rig.clock });
  await denied(fresh.vault.restore(restoreRequest(captured)), "unknown-token");
  assert.deepEqual(fresh.memory.control.counts(), { namespaces: 1, captures: 0, entries: 0, receipts: 0 });
});

test("recovery: after invalidateRecovered, an instance at the old epoch fails closed and one at the new epoch sees old captures revoked", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { maxUses: 4 });
  await rig.memory.store.quarantine({ namespace: NAMESPACE });
  await rejects(rig.vault.restore(restoreRequest(captured)), "STORE_QUARANTINED");
  // Revocation still works in a quarantined namespace (§5.6): not exercised here, see lifecycle tests.
  const invalidated = await rig.memory.store.invalidateRecovered({ namespace: NAMESPACE, newEpoch: 2 });
  assert.equal(invalidated.outcome, "invalidated");

  // The instance still configured with epoch 1 serves nothing.
  await rejects(rig.vault.restore(restoreRequest(captured)), "STORE_QUARANTINED");
  await rejects(rig.vault.capture(ORIGINAL, { context: CTX_A, release: [{ sink: "sink-a", paths: ["body"] }] }), "STORE_QUARANTINED");
  await rejects(rig.open(), "STORE_QUARANTINED");
  assert.equal(rig.keys.stats.unwrap, 0);

  const next = await rig.open({ recoveryEpoch: 2 });
  await denied(next.restore(restoreRequest(captured)), "revoked");
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [0]);
  const fresh = await captureOne(rig, { vault: next });
  assert.equal((await next.restore(restoreRequest(fresh))).fields.body, ORIGINAL);
  assert.equal(TENANT, fresh.tenant);
});

registerLeakHygiene({ minErrors: 100 });
