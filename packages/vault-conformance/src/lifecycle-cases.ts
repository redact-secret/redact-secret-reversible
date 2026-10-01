/**
 * Deterministic store cases for cleanup (§5.7), recovery (§5.8, §9.3), and
 * buffer ownership.
 */
import type { SweepResult } from "@redact-secret/vault-contracts";
import { commit, expectAbsent, FAR_MS, revoke, revokeInput } from "./store-cases.js";
import type { Add } from "./store-cases.js";
import { altered, at, check, DAY_MS, equal, fail, HOUR_MS, outcome, rejected, sameBytes } from "./support.js";
import type { Bench } from "./support.js";

async function sweep(b: Bench, limit = 10_000, namespace = b.namespace): Promise<Extract<SweepResult, { outcome: "swept" }>> {
  const result = await b.store.sweepExpired({ namespace, now: b.now(), limit });
  if (result.outcome !== "swept") fail("sweepExpired with an agreeing clock must sweep");
  return result;
}

function expectSwept(result: Extract<SweepResult, { outcome: "swept" }>, entries: number, captures: number, receipts: number, what: string): void {
  equal(result.entries, entries, `${what}: entries removed`);
  equal(result.captures, captures, `${what}: capture rows removed`);
  equal(result.receipts, receipts, `${what}: receipts removed`);
}

export function addSweepCases(add: Add): void {
  add("sweep", "rejects clock-skew when the caller's now is outside the bound, and removes nothing", async (b) => {
    await b.serving();
    const h = await b.createExpired({ entries: 2 });
    for (const delta of [b.skew + FAR_MS, -(b.skew + FAR_MS)]) {
      rejected(await b.store.sweepExpired({ namespace: b.namespace, now: b.now() + delta, limit: 100 }), "clock-skew", "sweepExpired with a skewed now");
    }
    equal((await b.read(h.scope, h.entryIds)).entries.length, 2, "the expired entries are still there");
  });

  add("sweep", "never removes an unexpired capture, its entries, a revoked capture's unexpired entries, or an unexpired receipt", async (b) => {
    await b.serving();
    const live = await b.create({ entries: 2, maxUses: 3 });
    const revoked = await b.create({ entries: 2 });
    const input = await b.commitInput([{ capture: live }]);
    await commit(b, input);
    await revoke(b, revoked);
    const before = await b.fingerprint([live, revoked]);
    const result = await sweep(b);
    expectSwept(result, 0, 0, 0, "a sweep with nothing expired");
    equal(result.more, false, "a sweep with nothing expired reports no more work");
    equal(await b.fingerprint([live, revoked]), before, "every row is unchanged");
    equal((await b.store.inspectAttempt({ scope: input.scope, attemptId: input.attempt.attemptId })).state, "committed", "the receipt is kept before receiptExpiresAt");
  });

  add("sweep", "removes the entries and the row of an expired capture, and nothing of a live one", async (b) => {
    await b.serving();
    const expired = await b.createExpired({ entries: 2 });
    const live = await b.create({ entries: 1 });
    const result = await sweep(b);
    expectSwept(result, 2, 1, 0, "a sweep over one expired capture");
    equal(result.more, false, "nothing is left to sweep");
    equal((await b.read(expired.scope, expired.entryIds)).entries.length, 0, "the expired entries are gone");
    equal((await b.store.readCaptures({ scope: expired.scope, captureIds: [expired.captureId] })).length, 0, "the expired capture row is gone");
    equal((await b.capture(live)).state, "live", "the live capture is untouched");
    equal((await b.read(live.scope, live.entryIds)).entries.length, 1, "the live entry is untouched");
  });

  add("sweep", "removes at most limit rows per kind and reports more until nothing is left", async (b) => {
    await b.serving();
    for (let i = 0; i < 3; i += 1) await b.createExpired({ entries: 2 });
    let entries = 0;
    let captures = 0;
    let rounds = 0;
    let result = await sweep(b, 1);
    equal(result.more, true, "the first limited sweep leaves work and reports more");
    for (;;) {
      check(result.entries <= 1 && result.captures <= 1 && result.receipts <= 1, "a sweep removes at most limit rows per kind");
      entries += result.entries;
      captures += result.captures;
      rounds += 1;
      if (!result.more) break;
      check(rounds < 50, "limited sweeps must finish");
      result = await sweep(b, 1);
    }
    equal(entries, 6, "every expired entry was eventually removed");
    equal(captures, 3, "every expired capture row was eventually removed");
    const after = await sweep(b, 1);
    expectSwept(after, 0, 0, 0, "a sweep after more was false");
  });

  add("sweep", "is scoped to its namespace", async (b) => {
    await b.serving();
    await b.serving(1, b.otherNamespace);
    const scope = { namespace: b.otherNamespace, tenant: b.tenantA.tenant };
    const other = await b.createExpired({ scope, entries: 2 });
    const result = await sweep(b);
    expectSwept(result, 0, 0, 0, "a sweep of a namespace with nothing expired");
    equal((await b.read(other.scope, other.entryIds)).entries.length, 2, "another namespace's expired entries are untouched");
  });

  add("sweep", "keeps a receipt until receiptExpiresAt, and a replay of the swept attempt is denied", async (b) => {
    const clock = b.timeTravel();
    await b.serving();
    const h = await b.create({ maxUses: 5, lifetimeMs: HOUR_MS });
    const input = await b.commitInput([{ capture: h }]);
    await commit(b, input);
    const target = { scope: input.scope, attemptId: input.attempt.attemptId };
    clock.set(input.receiptExpiresAt - 1);
    const early = await sweep(b);
    equal(early.receipts, 0, "no receipt is removed before receiptExpiresAt");
    equal((await b.store.inspectAttempt(target)).state, "committed", "the receipt still deduplicates its attempt");
    const replayEarly = altered(input, (copy) => { copy.now = clock.now(); });
    outcome(await b.store.commitRestore(replayEarly), "already-committed", "a replay before the receipt is swept");
    clock.set(input.receiptExpiresAt + 1);
    const late = await sweep(b);
    equal(late.receipts, 1, "the receipt is removed after receiptExpiresAt");
    equal((await b.store.inspectAttempt(target)).state, "absent", "the swept receipt is gone");
    const replayLate = altered(input, (copy) => { copy.now = clock.now(); });
    rejected(await b.store.commitRestore(replayLate), ["expired", "unknown"], "a replay of a swept attempt: every capture it touched has expired");
    equal((await b.store.inspectAttempt(target)).state, "absent", "the denied replay writes no receipt");
  });

  add("sweep", "an expired capture is denied at commit whether or not it was swept", async (b) => {
    const clock = b.timeTravel();
    await b.serving();
    const h = await b.create({ maxUses: 5, lifetimeMs: HOUR_MS });
    const prepared = await b.commitInput([{ capture: h }]);
    clock.set(h.input.capture.expiresAt + 5);
    const unswept = altered(prepared, (copy) => { copy.now = clock.now(); });
    rejected(await b.store.commitRestore(unswept), "expired", "commitRestore of an expired, unswept capture");
    await sweep(b);
    const swept = altered(prepared, (copy) => { copy.now = clock.now(); copy.attempt.attemptId = b.attemptId(); });
    rejected(await b.store.commitRestore(swept), ["expired", "unknown"], "commitRestore of an expired, swept capture");
  });

  add("sweep", "keeps a revocation tombstone until the capture's expiry plus retention, and it fences creation meanwhile", async (b) => {
    const clock = b.timeTravel();
    await b.serving();
    const h = await b.create({ entries: 2, lifetimeMs: HOUR_MS });
    const retentionMs = 3 * HOUR_MS;
    outcome(await b.store.revokeCapture(revokeInput(b, h, false, retentionMs)), "revoked", "revokeCapture with a retention");
    const keepUntil = h.input.capture.expiresAt + retentionMs;
    clock.set(keepUntil - 1);
    const early = await sweep(b);
    expectSwept(early, 2, 0, 0, "a sweep past expiry and before the retention bound");
    equal((await b.store.readCaptures({ scope: h.scope, captureIds: [h.captureId] })).length, 1, "the tombstone is kept");
    rejected(await b.store.createCapture(b.captureInput({ captureId: h.captureId })), "fenced", "createCapture of a tombstoned identifier");
    clock.set(keepUntil + 1);
    const late = await sweep(b);
    expectSwept(late, 0, 1, 0, "a sweep past the retention bound");
    equal((await b.store.readCaptures({ scope: h.scope, captureIds: [h.captureId] })).length, 0, "the tombstone is gone");
  });

  add("sweep", "keeps the tombstone of a capture revoked after its expiry for retention past the revocation", async (b) => {
    const clock = b.timeTravel();
    await b.serving();
    const h = await b.create({ lifetimeMs: HOUR_MS });
    clock.set(h.input.capture.expiresAt + 2 * HOUR_MS);
    const revokedAt = clock.now();
    outcome(await b.store.revokeCapture(revokeInput(b, h, false, HOUR_MS)), "revoked", "revokeCapture of an expired capture");
    clock.set(revokedAt + HOUR_MS - 1);
    equal((await sweep(b)).captures, 0, "the tombstone is kept until the store clock at revocation plus retention");
    clock.set(revokedAt + HOUR_MS + 1);
    equal((await sweep(b)).captures, 1, "the tombstone is removed after that");
  });

  add("sweep", "keeps a fence for its retention", async (b) => {
    const clock = b.timeTravel();
    await b.serving();
    const input = b.captureInput();
    const target = { scope: input.scope, captureId: input.capture.captureId };
    const fencedAt = clock.now();
    outcome(await b.store.revokeCapture(revokeInput(b, target, true, DAY_MS)), "fenced", "fencing an absent identifier");
    clock.set(fencedAt + DAY_MS - 1);
    expectSwept(await sweep(b), 0, 0, 0, "a sweep before the fence's retention bound");
    rejected(await b.store.createCapture(b.captureInput({ captureId: input.capture.captureId })), "fenced", "createCapture of a fenced identifier");
    clock.set(fencedAt + DAY_MS + 1);
    expectSwept(await sweep(b), 0, 1, 0, "a sweep past the fence's retention bound");
  });
}

export function addRecoveryCases(add: Add): void {
  add("recovery", "a namespace is uninitialized until initializeNamespace, which refuses a second call", async (b) => {
    const fresh = await b.store.recoveryState({ namespace: b.namespace });
    equal(fresh.state, "uninitialized", "recoveryState of a namespace with no record");
    equal(fresh.epoch, 0, "epoch of a namespace with no record");
    await b.serving(5);
    const serving = await b.store.recoveryState({ namespace: b.namespace });
    equal(serving.state, "serving", "recoveryState after initializeNamespace");
    equal(serving.epoch, 5, "epoch after initializeNamespace");
    rejected(await b.store.initializeNamespace({ namespace: b.namespace, epoch: 6 }), "exists", "initializeNamespace of an initialized namespace");
    equal((await b.store.recoveryState({ namespace: b.namespace })).epoch, 5, "the refused call left the epoch");
    equal((await b.store.recoveryState({ namespace: b.otherNamespace })).state, "uninitialized", "another namespace is unaffected");
  });

  add("recovery", "initializeNamespace refuses a namespace that already holds a row", async (b) => {
    const target = { scope: b.tenantA, captureId: b.rng.captureId() };
    outcome(await b.store.revokeCapture(revokeInput(b, target, true)), "fenced", "fencing an identifier in a namespace with no record");
    rejected(await b.store.initializeNamespace({ namespace: b.namespace, epoch: 1 }), "not-empty", "initializeNamespace of a namespace that holds a capture row");
    equal((await b.store.recoveryState({ namespace: b.namespace })).state, "uninitialized", "the refused call created no record");
  });

  add("recovery", "quarantine does not create a record", async (b) => {
    const result = await b.store.quarantine({ namespace: b.namespace });
    equal(result.state, "uninitialized", "quarantine of a namespace with no record");
    equal(result.epoch, 0, "epoch of a namespace with no record");
    await b.serving();
  });

  add("recovery", "quarantine blocks create and commit, and revocation still works", async (b) => {
    await b.serving(2);
    const h = await b.create({ epoch: 2, maxUses: 5 });
    const prepared = await b.commitInput([{ capture: h }]);
    const state = await b.store.quarantine({ namespace: b.namespace });
    equal(state.state, "quarantined", "quarantine returns the new state");
    equal(state.epoch, 2, "quarantine keeps the epoch");
    equal((await b.store.recoveryState({ namespace: b.namespace })).state, "quarantined", "recoveryState after quarantine");
    const blocked = b.captureInput({ epoch: 2 });
    rejected(await b.store.createCapture(blocked), "quarantined", "createCapture in a quarantined namespace");
    await expectAbsent(b, blocked, "createCapture in a quarantined namespace");
    rejected(await b.store.commitRestore(prepared), "quarantined", "commitRestore in a quarantined namespace");
    equal((await b.entry(h)).used, 0, "the blocked commit consumed nothing");
    equal((await b.store.quarantine({ namespace: b.namespace })).state, "quarantined", "quarantine is idempotent");
    await revoke(b, h);
  });

  add("recovery", "invalidateRecovered refuses an epoch that is not greater and an uninitialized namespace", async (b) => {
    rejected(await b.store.invalidateRecovered({ namespace: b.namespace, newEpoch: 2 }), "uninitialized", "invalidateRecovered of a namespace with no record");
    equal((await b.store.recoveryState({ namespace: b.namespace })).state, "uninitialized", "the refused call created no record");
    await b.serving(4);
    for (const newEpoch of [4, 3, 1]) {
      rejected(await b.store.invalidateRecovered({ namespace: b.namespace, newEpoch }), "epoch-not-greater", "invalidateRecovered with an epoch that is not greater");
    }
    const state = await b.store.recoveryState({ namespace: b.namespace });
    equal(state.epoch, 4, "the refused calls left the epoch");
    equal(state.state, "serving", "the refused calls left the state");
  });

  add("recovery", "invalidateRecovered raises the epoch and returns a quarantined namespace to serving", async (b) => {
    await b.serving(1);
    await b.store.quarantine({ namespace: b.namespace });
    const result = await b.store.invalidateRecovered({ namespace: b.namespace, newEpoch: 9 });
    if (result.outcome !== "invalidated") fail("invalidateRecovered with a greater epoch must succeed");
    equal(result.recovery.epoch, 9, "the returned epoch");
    equal(result.recovery.state, "serving", "the returned state");
    const state = await b.store.recoveryState({ namespace: b.namespace });
    equal(state.epoch, 9, "the stored epoch");
    equal(state.state, "serving", "the stored state");
  });

  add("recovery", "every capture of an earlier epoch is treated as revoked by every operation", async (b) => {
    await b.serving(1);
    const h = await b.create({ entries: 2, maxUses: 5 });
    const extra = await b.create({ maxUses: 5 });
    const prepared = await b.commitInput([{ capture: h }]);
    outcome(await b.store.invalidateRecovered({ namespace: b.namespace, newEpoch: 2 }), "invalidated", "invalidateRecovered");
    const read = await b.read(h.scope, h.entryIds);
    equal(read.entries.length, 2, "entries of an earlier epoch are still returned");
    equal(at(read.captures, 0).state, "revoked", "readEntries reports a capture of an earlier epoch revoked");
    equal(at(read.captures, 0).epoch, 1, "the capture keeps the epoch it was created under");
    equal((await b.capture(h)).state, "revoked", "readCaptures reports a capture of an earlier epoch revoked");
    rejected(await b.store.commitRestore(prepared), "quarantined", "commitRestore carrying the old epoch");
    const current = altered(prepared, (copy) => { copy.epoch = 2; copy.attempt.attemptId = b.attemptId(); });
    rejected(await b.store.commitRestore(current), "revoked", "commitRestore of an earlier epoch's capture under the new epoch");
    equal((await b.entry(h)).used, 0, "nothing was consumed");
    outcome(await b.store.revokeCapture(revokeInput(b, h)), "already-revoked", "revokeCapture of an earlier epoch's capture");
    rejected(
      await b.store.replaceCaptureKey({ scope: h.scope, captureId: h.captureId, keyRevision: 1, keyRef: "synthetic-key:v2", wrappedKey: b.rng.bytes(40) }),
      "revoked",
      "replaceCaptureKey of an earlier epoch's capture",
    );
    rejected(await b.store.createCapture(b.captureInput({ epoch: 2, captureId: h.captureId })), "fenced", "createCapture reusing an earlier epoch's capture identifier");
    const deleted = await b.store.deleteCiphertext({ scope: extra.scope, captureId: extra.captureId, now: b.now() + b.skew + FAR_MS });
    outcome(deleted, "deleted", "deleteCiphertext of an earlier epoch's capture, whatever the clocks say");
  });

  add("recovery", "captures under the new epoch work, and the old epoch no longer does", async (b) => {
    await b.serving(1);
    await b.create();
    outcome(await b.store.invalidateRecovered({ namespace: b.namespace, newEpoch: 2 }), "invalidated", "invalidateRecovered");
    const stale = b.captureInput({ epoch: 1 });
    rejected(await b.store.createCapture(stale), "quarantined", "createCapture carrying the old epoch");
    await expectAbsent(b, stale, "createCapture carrying the old epoch");
    const h = await b.create({ epoch: 2, maxUses: 2 });
    equal((await b.capture(h)).epoch, 2, "a new capture carries the new epoch");
    equal((await b.capture(h)).state, "live", "a new capture is live");
    await commit(b, await b.commitInput([{ capture: h }]));
    equal((await b.entry(h)).used, 1, "a commit under the new epoch applies");
  });
}

export function addAliasingCases(add: Add): void {
  add("aliasing", "a caller that changes its buffers after createCapture does not change the store", async (b) => {
    await b.serving();
    const input = b.captureInput({ entries: 2 });
    const envelope = new Uint8Array(at(input.entries, 0).envelope);
    const wrappedKey = new Uint8Array(input.capture.wrappedKey);
    outcome(await b.store.createCapture(input), "created", "createCapture");
    at(input.entries, 0).envelope.fill(0xee);
    input.capture.wrappedKey.fill(0xee);
    const h = b.handle(input);
    check(sameBytes((await b.entry(h)).envelope, envelope), "the stored envelope is the bytes given at the call");
    check(sameBytes((await b.capture(h)).wrappedKey, wrappedKey), "the stored wrappedKey is the bytes given at the call");
  });

  add("aliasing", "a caller that changes returned buffers does not change the store", async (b) => {
    await b.serving();
    const h = await b.create();
    const first = await b.read(h.scope, h.entryIds);
    at(first.entries, 0).envelope.fill(0xee);
    at(first.captures, 0).wrappedKey.fill(0xee);
    (await b.capture(h)).wrappedKey.fill(0xdd);
    check(sameBytes((await b.entry(h)).envelope, at(h.input.entries, 0).envelope), "the stored envelope is unchanged");
    check(sameBytes((await b.capture(h)).wrappedKey, h.input.capture.wrappedKey), "the stored wrappedKey is unchanged");
    const second = await b.read(h.scope, h.entryIds);
    check(sameBytes(at(second.captures, 0).wrappedKey, h.input.capture.wrappedKey), "readEntries returns the stored wrappedKey");
  });

  add("aliasing", "a caller that changes its digest or key buffers after the call does not change the store", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 3 });
    const input = await b.commitInput([{ capture: h }]);
    const digest = new Uint8Array(input.attempt.requestDigest);
    await commit(b, input);
    input.attempt.requestDigest.fill(0xee);
    const target = { scope: input.scope, attemptId: input.attempt.attemptId };
    const receipt = await b.store.inspectAttempt(target);
    if (receipt.state !== "committed") fail("inspectAttempt after the commit must report committed");
    check(sameBytes(receipt.requestDigest, digest), "the receipt holds the digest given at the call");
    receipt.requestDigest.fill(0xdd);
    const again = await b.store.inspectAttempt(target);
    check(again.state === "committed" && sameBytes(again.requestDigest, digest), "changing a returned digest does not change the receipt");
    const replay = altered(input, (copy) => { copy.attempt.requestDigest = new Uint8Array(digest); });
    outcome(await b.store.commitRestore(replay), "already-committed", "a replay with the original digest");
    const key = { scope: h.scope, captureId: h.captureId, keyRevision: 1, keyRef: "synthetic-key:v2", wrappedKey: b.rng.bytes(48) };
    const wrappedKey = new Uint8Array(key.wrappedKey);
    outcome(await b.store.replaceCaptureKey(key), "replaced", "replaceCaptureKey");
    key.wrappedKey.fill(0xee);
    check(sameBytes((await b.capture(h)).wrappedKey, wrappedKey), "the stored wrappedKey is the bytes given at the call");
  });
}
