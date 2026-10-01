/**
 * Concurrency cases (§7.1) and the two-connection schedules of §5.2. They use
 * only the public `Store` interface, plus the factory's optional
 * `secondStore` and `interleave`.
 */
import type { CommitRestoreResult, CreateCaptureResult, Store } from "@redact-secret/vault-contracts";
import { expectAbsent, revokeInput } from "./store-cases.js";
import type { Add } from "./store-cases.js";
import { at, check, equal, fail, outcome, rejected } from "./support.js";
import type { Bench, CaptureHandle, UseSpec } from "./support.js";
import { ConformanceSkip } from "./types.js";

function pick(b: Bench, index: number): Store {
  return index % 2 === 0 ? b.store : b.second;
}

function isCommitted(result: CommitRestoreResult): boolean {
  return result.outcome === "committed";
}

/** Commits as a server would: read, commit, and on `stale` read again. Returns the final outcome. */
async function commitWithRetry(b: Bench, store: Store, specs: readonly UseSpec[], bound: number): Promise<string> {
  for (let attempt = 0; attempt < bound; attempt += 1) {
    const result = await store.commitRestore(await b.commitInput(specs));
    if (result.outcome === "committed") return "committed";
    if (result.outcome !== "rejected") fail("a fresh attempt can only be committed or rejected");
    if (result.reason !== "stale") return result.reason;
  }
  fail("a commit was still stale after every retry; retries must make progress");
}

async function readAll(b: Bench, handle: CaptureHandle): Promise<Map<string, number>> {
  const used = new Map<string, number>();
  const size = b.caps.maxRestoreEntries;
  for (let offset = 0; offset < handle.entryIds.length; offset += size) {
    const read = await b.read(handle.scope, handle.entryIds.slice(offset, offset + size));
    for (const entry of read.entries) used.set(entry.entryId, entry.used);
  }
  return used;
}

export function addConcurrencyCases(add: Add, parallelism: number): void {
  add("concurrency", "parallel restores of one single-use entry: exactly one commits", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 1 });
    const read = await b.read(h.scope, h.entryIds);
    const inputs = Array.from({ length: parallelism }, () => b.commitFromRead(read, [{ capture: h }]));
    const results = await Promise.all(inputs.map((input, index) => pick(b, index).commitRestore(input)));
    equal(results.filter(isCommitted).length, 1, "exactly one of the parallel restores commits");
    for (const result of results) {
      if (!isCommitted(result)) rejected(result, ["budget", "stale"], "a parallel restore that lost");
    }
    const entry = await b.entry(h);
    equal(entry.used, 1, "used after the parallel restores");
    equal(entry.lifecycleRevision, 2, "lifecycleRevision after the parallel restores");
    let receipts = 0;
    for (const [index, input] of inputs.entries()) {
      const receipt = await b.store.inspectAttempt({ scope: input.scope, attemptId: input.attempt.attemptId });
      if (receipt.state === "committed") receipts += 1;
      equal(receipt.state === "committed", isCommitted(at(results, index)), "an attempt has a receipt exactly when it committed");
    }
    equal(receipts, 1, "exactly one receipt was written");
  });

  add("concurrency", "parallel restores of one entry with maxUses 7, retried on stale: exactly seven commit", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 7 });
    const outcomes = await Promise.all(
      Array.from({ length: parallelism }, (_, index) => commitWithRetry(b, pick(b, index), [{ capture: h }], 20 * parallelism)),
    );
    equal(outcomes.filter((result) => result === "committed").length, Math.min(7, parallelism), "exactly maxUses restores commit");
    for (const result of outcomes) check(result === "committed" || result === "budget", "a restore either commits or is denied for budget");
    const entry = await b.entry(h);
    equal(entry.used, Math.min(7, parallelism), "used never exceeds maxUses");
  });

  add("concurrency", "parallel restores racing one revocation are consistent with a single order", async (b) => {
    await b.serving();
    const count = Math.min(parallelism, b.caps.maxCreateEntries);
    const h = await b.create({ entries: count, maxUses: 1000, envelopeBytes: 8 });
    const inputs = [];
    for (let index = 0; index < parallelism; index += 1) {
      inputs.push(await b.commitInput([{ capture: h, entry: index % count }]));
    }
    const lateFrom = Math.floor((parallelism * 3) / 4);
    const pending: Promise<CommitRestoreResult>[] = [];
    for (let index = 0; index < Math.floor(parallelism / 2); index += 1) pending.push(pick(b, index).commitRestore(at(inputs, index)));
    const revocation = b.second.revokeCapture(revokeInput(b, h));
    for (let index = Math.floor(parallelism / 2); index < lateFrom; index += 1) pending.push(pick(b, index).commitRestore(at(inputs, index)));
    outcome(await revocation, "revoked", "the revocation");
    for (let index = lateFrom; index < parallelism; index += 1) pending.push(pick(b, index).commitRestore(at(inputs, index)));
    const results = await Promise.all(pending);
    const expected = new Map<string, number>();
    for (const [index, result] of results.entries()) {
      const entryId = at(at(inputs, index).uses, 0).entryId;
      if (isCommitted(result)) {
        check(index < lateFrom, "a restore started after the revocation was acknowledged must not commit");
        expected.set(entryId, (expected.get(entryId) ?? 0) + 1);
      } else {
        rejected(result, ["revoked", "stale"], "a restore that lost to the revocation or to another restore");
      }
    }
    const used = await readAll(b, h);
    let total = 0;
    for (const entryId of h.entryIds) {
      equal(used.get(entryId), expected.get(entryId) ?? 0, "each entry's used equals the restores that committed on it");
      total += used.get(entryId) ?? 0;
    }
    equal(total, results.filter(isCommitted).length, "total used equals the number of committed restores");
    equal((await b.capture(h)).state, "revoked", "the capture ends revoked");
    for (const [index, input] of inputs.entries()) {
      const receipt = await b.store.inspectAttempt({ scope: input.scope, attemptId: input.attempt.attemptId });
      equal(receipt.state === "committed", isCommitted(at(results, index)), "an attempt has a receipt exactly when it committed");
    }
  });

  add("concurrency", "parallel identical attempts: one commits, the others are already-committed, used moves once", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 1000 });
    const input = await b.commitInput([{ capture: h, count: 2 }]);
    const attempt = async (store: Store): Promise<string> => {
      for (let tries = 0; tries < 20 * parallelism; tries += 1) {
        const result = await store.commitRestore(input);
        // A store may abort a transaction that conflicts with its twin; the same attempt is then retried.
        if (result.outcome === "rejected" && result.reason === "stale") continue;
        return result.outcome;
      }
      fail("an identical attempt was still stale after every retry");
    };
    const outcomes = await Promise.all(Array.from({ length: parallelism }, (_, index) => attempt(pick(b, index))));
    equal(outcomes.filter((result) => result === "committed").length, 1, "exactly one of the identical attempts commits");
    equal(outcomes.filter((result) => result === "already-committed").length, parallelism - 1, "every other identical attempt is already-committed");
    const entry = await b.entry(h);
    equal(entry.used, 2, "used was incremented once");
    equal(entry.lifecycleRevision, 2, "lifecycleRevision was incremented once");
  });

  add("concurrency", "a creation racing a fence of the same identifier: created then revoked, or fenced", async (b) => {
    await b.serving();
    const rounds = Math.max(8, Math.floor(parallelism / 4));
    for (let round = 0; round < rounds; round += 1) {
      const input = b.captureInput({ entries: 2 });
      const fence = revokeInput(b, { scope: input.scope, captureId: input.capture.captureId }, true);
      let created: CreateCaptureResult;
      let revoked: Awaited<ReturnType<Store["revokeCapture"]>>;
      if (round % 2 === 0) {
        const first = b.store.createCapture(input);
        const second = b.second.revokeCapture(fence);
        [created, revoked] = [await first, await second];
      } else {
        const first = b.second.revokeCapture(fence);
        const second = b.store.createCapture(input);
        [revoked, created] = [await first, await second];
      }
      const entries = (await b.read(input.scope, input.entries.map((entry) => entry.entryId))).entries.length;
      if (created.outcome === "created") {
        outcome(revoked, "revoked", "a fence that follows the creation revokes the capture");
        equal(entries, 2, "the created capture's entries exist");
      } else {
        rejected(created, ["fenced", "stale"], "a creation that lost to the fence");
        outcome(revoked, "fenced", "a fence that precedes the creation");
        equal(entries, 0, "a fenced creation leaves no entry");
      }
      const rows = await b.store.readCaptures({ scope: input.scope, captureIds: [input.capture.captureId] });
      equal(rows.length, 1, "the identifier has one row");
      equal(at(rows, 0).state, "revoked", "the identifier ends revoked either way");
      rejected(await b.store.createCapture(b.captureInput({ captureId: input.capture.captureId })), "fenced", "a later creation of the same identifier");
    }
  });

  add("concurrency", "multi-entry restores under contention never apply part of a batch", async (b) => {
    await b.serving();
    const h = await b.create({ entries: 2, maxUses: [1000, 3] });
    const pairs = Math.floor(parallelism / 2);
    const singles = parallelism - pairs;
    check(parallelism <= 1000, "this case supports a parallelism of at most 1000");
    const work: Promise<string>[] = [];
    for (let index = 0; index < parallelism; index += 1) {
      const specs = index < pairs ? [{ capture: h, entry: 0 }, { capture: h, entry: 1 }] : [{ capture: h, entry: 0 }];
      work.push(commitWithRetry(b, pick(b, index), specs, 40 * parallelism));
    }
    const outcomes = await Promise.all(work);
    const pairCommitted = outcomes.slice(0, pairs).filter((result) => result === "committed").length;
    const singleCommitted = outcomes.slice(pairs).filter((result) => result === "committed").length;
    equal(pairCommitted, Math.min(3, pairs), "exactly as many two-entry restores commit as the scarcer entry allows");
    equal(singleCommitted, singles, "every single-entry restore commits");
    for (const result of outcomes.slice(0, pairs)) check(result === "committed" || result === "budget", "a two-entry restore commits or is denied for budget");
    equal((await b.entry(h, 1)).used, pairCommitted, "the scarce entry's used equals the two-entry restores that committed");
    equal((await b.entry(h, 0)).used, pairCommitted + singleCommitted, "the other entry's used counts no rolled-back batch");
  });
}

interface Interleaved<T> {
  readonly result: T;
  /** The competing call was acknowledged while the primary call was still open. */
  readonly concurrentFirst: boolean;
}

async function interleaved<T>(
  b: Bench,
  operation: "commitRestore" | "createCapture",
  primary: () => Promise<T>,
  concurrent: (second: Store) => Promise<void>,
): Promise<Interleaved<T>> {
  const interleave = b.sut.interleave;
  if (interleave === undefined) {
    throw new ConformanceSkip("the factory supplies no interleave capability, so the two-connection schedules of §5.2 cannot be run");
  }
  let primaryCalls = 0;
  let primarySettled = false;
  let startedWhileOpen = false;
  let concurrentSettled = false;
  let concurrentFirst = false;
  let concurrentError: unknown;
  const result = await interleave({
    operation,
    primary: async () => {
      primaryCalls += 1;
      try {
        return await primary();
      } finally {
        primarySettled = true;
      }
    },
    concurrent: async (second) => {
      startedWhileOpen = !primarySettled;
      try {
        await concurrent(second);
        concurrentFirst = !primarySettled;
      } catch (error) {
        concurrentError = error;
      } finally {
        concurrentSettled = true;
      }
    },
  });
  if (concurrentError !== undefined) throw concurrentError;
  equal(primaryCalls, 1, "interleave must start the primary call exactly once");
  check(startedWhileOpen, "interleave must start the competing call while the primary call is open");
  check(concurrentSettled, "interleave must not resolve before the competing call has settled");
  return { result, concurrentFirst };
}

export function addInterleaveCases(add: Add): void {
  add("interleave", "a revocation committed between a restore's read and its commit: the restore does not commit", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 5 });
    const prepared = await b.commitInput([{ capture: h }]);
    const { result, concurrentFirst } = await interleaved(
      b,
      "commitRestore",
      () => b.store.commitRestore(prepared),
      async (second) => outcome(await second.revokeCapture(revokeInput(b, h)), "revoked", "the competing revocation"),
    );
    if (concurrentFirst) rejected(result, ["revoked", "stale"], "a restore whose capture was revoked before its commit");
    else if (result.outcome !== "committed") rejected(result, ["revoked", "stale"], "a restore that did not commit");
    const committed = result.outcome === "committed";
    equal((await b.entry(h)).used, committed ? 1 : 0, "used matches the restore's outcome");
    equal((await b.store.inspectAttempt({ scope: prepared.scope, attemptId: prepared.attempt.attemptId })).state, committed ? "committed" : "absent", "the receipt matches the restore's outcome");
    equal((await b.capture(h)).state, "revoked", "the capture ends revoked");
  });

  add("interleave", "a quarantine committed between a creation's check and its commit: the creation does not succeed", async (b) => {
    await b.serving();
    const input = b.captureInput({ entries: 2 });
    const { result, concurrentFirst } = await interleaved(
      b,
      "createCapture",
      () => b.store.createCapture(input),
      async (second) => equal((await second.quarantine({ namespace: b.namespace })).state, "quarantined", "the competing quarantine"),
    );
    if (concurrentFirst || result.outcome !== "created") {
      rejected(result, ["quarantined", "stale"], "a creation whose namespace was quarantined before its commit");
      await expectAbsent(b, input, "a creation that lost to a quarantine");
    } else {
      equal((await b.read(input.scope, input.entries.map((entry) => entry.entryId))).entries.length, 2, "a creation ordered before the quarantine is complete");
    }
    equal((await b.store.recoveryState({ namespace: b.namespace })).state, "quarantined", "the namespace ends quarantined");
  });

  add("interleave", "a quarantine committed between a restore's read and its commit: the restore does not commit", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 5 });
    const prepared = await b.commitInput([{ capture: h }]);
    const { result, concurrentFirst } = await interleaved(
      b,
      "commitRestore",
      () => b.store.commitRestore(prepared),
      async (second) => equal((await second.quarantine({ namespace: b.namespace })).state, "quarantined", "the competing quarantine"),
    );
    if (concurrentFirst || result.outcome !== "committed") rejected(result, ["quarantined", "stale"], "a restore whose namespace was quarantined before its commit");
    equal((await b.entry(h)).used, result.outcome === "committed" ? 1 : 0, "used matches the restore's outcome");
  });

  add("interleave", "an invalidation committed between a restore's read and its commit: the restore does not commit", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 5 });
    const prepared = await b.commitInput([{ capture: h }]);
    const { result, concurrentFirst } = await interleaved(
      b,
      "commitRestore",
      () => b.store.commitRestore(prepared),
      async (second) => outcome(await second.invalidateRecovered({ namespace: b.namespace, newEpoch: 2 }), "invalidated", "the competing invalidation"),
    );
    if (concurrentFirst || result.outcome !== "committed") rejected(result, ["quarantined", "revoked", "stale"], "a restore whose namespace was invalidated before its commit");
    equal((await b.entry(h)).used, result.outcome === "committed" ? 1 : 0, "used matches the restore's outcome");
  });

  add("interleave", "a fence committed between a creation's check and its commit: the creation does not succeed", async (b) => {
    await b.serving();
    const input = b.captureInput({ entries: 2 });
    let fenceOutcome = "";
    const { result, concurrentFirst } = await interleaved(
      b,
      "createCapture",
      () => b.store.createCapture(input),
      async (second) => {
        fenceOutcome = (await second.revokeCapture(revokeInput(b, { scope: input.scope, captureId: input.capture.captureId }, true))).outcome;
      },
    );
    if (fenceOutcome === "fenced") {
      rejected(result, ["fenced", "stale"], "a creation whose identifier was fenced before its commit");
      equal((await b.read(input.scope, input.entries.map((entry) => entry.entryId))).entries.length, 0, "a fenced creation leaves no entry");
    } else {
      equal(fenceOutcome, "revoked", "a fence ordered after the creation revokes it");
      check(!concurrentFirst, "a fence acknowledged before the creation committed cannot have found the capture");
      outcome(result, "created", "a creation ordered before the fence");
    }
    const rows = await b.store.readCaptures({ scope: input.scope, captureIds: [input.capture.captureId] });
    equal(at(rows, 0).state, "revoked", "the identifier ends revoked either way");
  });
}
