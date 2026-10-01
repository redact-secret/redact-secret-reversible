// Mutation controls: the harness must fail a store that has exactly one
// defect. Each mutant is the reference model with one decision broken (a
// subclass defined here, never shipped), or the model store deciding on a
// stale read. The unbroken model store is the control and must pass.
//
// The "model" group compares a store with the reference model, so it would
// catch a mutant of that model trivially. Each mutant therefore also names a
// deterministic case that must fail on its own.
import assert from "node:assert/strict";
import test from "node:test";

import { ReferenceModel, runCases, storeConformanceCases } from "../dist/index.js";
import { modelFactory } from "./model-store.mjs";

const OPTIONS = { parallelism: 16, modelSequences: 2, modelSteps: 250 };

class IgnoresRevocationAtCommit extends ReferenceModel {
  commitCaptureVerdict(capture, expected, _input, storeNow) {
    if (capture === undefined) return "unknown";
    if (capture.generation !== expected.generation) return "stale";
    if (storeNow >= capture.expiresAt) return "expired";
    return null;
  }
}

class AppliesBatchPartially extends ReferenceModel {
  commitRestore(input, storeNow) {
    if (this.notServing(input.scope.namespace, input.epoch)) return { outcome: "rejected", reason: "quarantined" };
    const receipt = this.findReceipt(input.scope, input.attempt.attemptId);
    if (receipt !== undefined) return super.commitRestore(input, storeNow);
    if (this.skewed(storeNow, input.now)) return { outcome: "rejected", reason: "clock-skew" };
    for (const expected of input.captures) {
      const verdict = this.commitCaptureVerdict(this.findCapture(input.scope, expected.captureId), expected, input, storeNow);
      if (verdict !== null) return { outcome: "rejected", reason: verdict };
    }
    for (const use of input.uses) {
      const entry = this.findEntry(input.scope, use.entryId);
      const verdict = this.commitUseVerdict(entry, use);
      // The defect: earlier uses were already applied and are not rolled back.
      if (verdict !== null) return { outcome: "rejected", reason: verdict };
      entry.used += use.count;
      entry.lifecycleRevision += 1;
    }
    this.receipts.set(this.key(input.scope, input.attempt.attemptId), {
      namespace: input.scope.namespace,
      tenant: input.scope.tenant,
      attemptId: input.attempt.attemptId,
      requestDigest: new Uint8Array(input.attempt.requestDigest),
      committedAt: storeNow,
      receiptExpiresAt: input.receiptExpiresAt,
    });
    return { outcome: "committed" };
  }
}

class NoReceiptUniqueness extends ReferenceModel {
  findReceipt(scope, attemptId) {
    // Receipts are written and inspectable, but a commit never consults them.
    return this.inspecting ? super.findReceipt(scope, attemptId) : undefined;
  }

  inspectAttempt(input, storeNow) {
    this.inspecting = true;
    try {
      return super.inspectAttempt(input, storeNow);
    } finally {
      this.inspecting = false;
    }
  }
}

class BudgetOffByOne extends ReferenceModel {
  commitUseVerdict(entry, use) {
    if (entry !== undefined && entry.captureId === use.captureId && entry.used + use.count === entry.maxUses + 1) {
      const lenient = { ...entry, maxUses: entry.maxUses + 1 };
      return super.commitUseVerdict(lenient, use);
    }
    return super.commitUseVerdict(entry, use);
  }
}

class JudgesExpiryOnCallerClock extends ReferenceModel {
  commitCaptureVerdict(capture, expected, input, _storeNow) {
    return super.commitCaptureVerdict(capture, expected, input, input.now);
  }
}

class FencesWithoutBeingAsked extends ReferenceModel {
  revokeCapture(input, storeNow) {
    if (this.findCapture(input.scope, input.captureId) === undefined && !input.fenceAbsent) {
      super.revokeCapture({ ...input, fenceAbsent: true }, storeNow);
      return { outcome: "not-found" };
    }
    return super.revokeCapture(input, storeNow);
  }
}

class CreateOverwrites extends ReferenceModel {
  createCapture(input, storeNow) {
    const present = this.findCapture(input.scope, input.capture.captureId);
    if (present !== undefined && !this.treatedAsRevoked(present)) {
      for (const entry of this.entriesOf(present)) this.entries.delete(this.key(input.scope, entry.entryId));
      this.captures.delete(this.key(input.scope, input.capture.captureId));
    }
    return super.createCapture(input, storeNow);
  }
}

class IgnoresTenantOnRead extends ReferenceModel {
  readEntries(input, storeNow) {
    const reading = this.findEntry;
    this.findEntry = (scope, entryId) => {
      for (const entry of this.entries.values()) {
        if (entry.namespace === scope.namespace && entry.entryId === entryId) return entry;
      }
      return undefined;
    };
    try {
      return super.readEntries(input, storeNow);
    } finally {
      this.findEntry = reading;
    }
  }
}

class SweepsReceiptsEarly extends ReferenceModel {
  receiptSweepable() {
    return true;
  }
}

class IgnoresEpochAtCommit extends ReferenceModel {
  commitRestore(input, storeNow) {
    const stored = this.recoveryOf(input.scope.namespace).epoch;
    return super.commitRestore(stored === 0 ? input : { ...input, epoch: stored }, storeNow);
  }
}

class RekeyResetsUsed extends ReferenceModel {
  replaceCaptureKey(input, storeNow) {
    const result = super.replaceCaptureKey(input, storeNow);
    if (result.outcome === "replaced") {
      for (const entry of this.entriesOf(this.findCapture(input.scope, input.captureId))) entry.used = 0;
    }
    return result;
  }
}

class RevokeKeepsGeneration extends ReferenceModel {
  revokeCapture(input, storeNow) {
    const result = super.revokeCapture(input, storeNow);
    if (result.outcome === "revoked") this.findCapture(input.scope, input.captureId).generation -= 1;
    return result;
  }
}

class SweepIgnoresTombstoneRetention extends ReferenceModel {
  captureSweepable(capture, storeNow) {
    return storeNow >= capture.expiresAt;
  }
}

class NoSkewCheckAtCommit extends ReferenceModel {
  commitRestore(input, storeNow) {
    return super.commitRestore({ ...input, now: storeNow }, storeNow);
  }
}

class EarlierEpochStaysLive extends ReferenceModel {
  treatedAsRevoked(capture) {
    return capture.state === "revoked";
  }
}

class DeleteKeepsKey extends ReferenceModel {
  deleteCiphertext(input, storeNow) {
    const capture = this.findCapture(input.scope, input.captureId);
    const kept = capture === undefined ? null : { keyRef: capture.keyRef, wrappedKey: capture.wrappedKey, keyless: capture.keyless };
    const result = super.deleteCiphertext(input, storeNow);
    if (result.outcome === "deleted") Object.assign(capture, kept);
    return result;
  }
}

class ReturnsStoredBuffers extends ReferenceModel {
  viewEntry(entry) {
    return { ...super.viewEntry(entry), envelope: entry.envelope };
  }
}

// [number, defect, factory options, a deterministic case that must fail]
const MUTANTS = [
  [1, "commit does not check capture state (revoked ignored)", { Model: IgnoresRevocationAtCommit }, "commit: rejects revoked after a revocation"],
  [2, "commit applies entries one by one and does not roll back", { Model: AppliesBatchPartially }, "commit: is all-or-nothing: a batch whose last use fails"],
  [3, "no receipt uniqueness (same attempt commits twice)", { Model: NoReceiptUniqueness }, "commit: answers already-committed for the same attempt and digest"],
  [4, "budget check off by one (allows maxUses + 1)", { Model: BudgetOffByOne }, "commit: accepts a budget exactly at maxUses and rejects one over"],
  [5, "expiry judged on the caller's now, not the store clock", { Model: JudgesExpiryOnCallerClock }, "commit: judges expiry on the store's clock"],
  [6, "revoke of an absent capture writes a tombstone without fenceAbsent", { Model: FencesWithoutBeingAsked }, "revoke: answers not-found for an absent capture and writes nothing"],
  [7, "createCapture overwrites an existing capture", { Model: CreateOverwrites }, "create: rejects exists for a live capture identifier"],
  [8, "tenant scope ignored on read", { Model: IgnoresTenantOnRead }, "read: another tenant's identifiers return nothing"],
  [9, "sweep deletes receipts before receiptExpiresAt", { Model: SweepsReceiptsEarly }, "sweep: never removes an unexpired capture"],
  [10, "epoch not checked at commit", { Model: IgnoresEpochAtCommit }, "commit: rejects quarantined for an uninitialized namespace and for an epoch that differs"],
  [11, "replaceCaptureKey resets used", { Model: RekeyResetsUsed }, "rekey: a restore prepared before the re-wrap still commits"],
  [12, "commit reads the capture without conflicting with a concurrent revoke (§5.2 write skew)", { staleCommitRead: true }, "interleave: a revocation committed between a restore's read and its commit"],
  [13, "create reads the recovery record without conflicting with a concurrent quarantine (§5.2)", { staleCreateRead: true }, "interleave: a quarantine committed between a creation's check and its commit"],
  [14, "revoke does not increment the generation", { Model: RevokeKeepsGeneration }, "revoke: revokes a live capture, increments its generation"],
  [15, "sweep removes a tombstone at expiry, ignoring retention", { Model: SweepIgnoresTombstoneRetention }, "sweep: keeps a revocation tombstone until the capture's expiry plus retention"],
  [16, "no clock-skew check at commit", { Model: NoSkewCheckAtCommit }, "commit: rejects clock-skew when the caller's now is outside the bound"],
  [17, "captures of an earlier epoch stay live", { Model: EarlierEpochStaysLive }, "recovery: every capture of an earlier epoch is treated as revoked"],
  [18, "deleteCiphertext keeps the stored key", { Model: DeleteKeepsKey }, "delete: deletes a revoked capture's ciphertext whatever the clocks say"],
  [19, "reads return the store's own buffers", { Model: ReturnsStoredBuffers }, "aliasing: a caller that changes returned buffers"],
];

test("control: the unbroken reference model passes every case and skips none", async () => {
  const results = await runCases(storeConformanceCases(modelFactory(), OPTIONS));
  assert.deepEqual(results.filter((result) => result.status !== "passed"), []);
});

for (const [number, defect, options, mustFail] of MUTANTS) {
  test(`mutant ${number}: ${defect}`, async (t) => {
    const results = await runCases(storeConformanceCases(modelFactory(options), OPTIONS));
    const failed = results.filter((result) => result.status === "failed");
    assert.ok(failed.length > 0, "the harness must report at least one failing case");
    const deterministic = failed.filter((result) => result.group !== "model");
    assert.ok(
      deterministic.some((result) => result.name.startsWith(mustFail)),
      `expected the case "${mustFail}…" to fail; failing cases: ${failed.map((result) => result.name).join(" | ")}`,
    );
    t.diagnostic(`mutant ${number} failed ${failed.length} case(s): ${failed.map((result) => result.name).join(" | ")}`);
  });
}

test("mutant 12 is invisible without interleave: the write skew is only detectable through it", async () => {
  const factory = async () => {
    const { store, clock } = await modelFactory({ staleCommitRead: true })();
    return { store, clock };
  };
  const results = await runCases(storeConformanceCases(factory, OPTIONS));
  assert.deepEqual(results.filter((result) => result.status === "failed"), []);
  const skipped = results.filter((result) => result.status === "skipped");
  assert.ok(skipped.length > 0);
  assert.ok(skipped.every((result) => result.group === "interleave" && /interleave/.test(result.detail)));
});
