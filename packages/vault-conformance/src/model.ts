/**
 * The transaction oracle: a pure reference model of the store state machine
 * of docs/specs/persistent-vault.md §5. Every operation is one synchronous
 * function of (state, input, store clock), so it is trivially serial.
 *
 * The harness drives a store and this model with the same operations and
 * compares every result. The model assumes its inputs already passed the
 * mechanical validation of §4.2; it is not a `Store` and performs no I/O.
 *
 * Each decision is its own method so that a test can subclass the model and
 * break exactly one of them.
 */
import { LIMITS, StoreError } from "@redact-secret/vault-contracts";
import type {
  CommitRejection,
  CommitRestoreInput,
  CommitRestoreResult,
  CreateCaptureInput,
  CreateCaptureResult,
  DeleteCiphertextInput,
  DeleteCiphertextResult,
  InitializeNamespaceResult,
  InspectAttemptInput,
  InspectAttemptResult,
  InvalidateRecoveredInput,
  InvalidateRecoveredResult,
  ReadCapturesInput,
  ReadEntriesInput,
  ReadEntriesResult,
  RecoveryState,
  ReplaceCaptureKeyInput,
  ReplaceCaptureKeyResult,
  RevokeCaptureInput,
  RevokeCaptureResult,
  StoredCapture,
  StoredEntry,
  StoreScope,
  SweepInput,
  SweepResult,
} from "@redact-secret/vault-contracts";

export interface ModelRecovery {
  epoch: number;
  state: "serving" | "quarantined";
}

export interface ModelCapture {
  readonly namespace: string;
  readonly tenant: string;
  readonly captureId: string;
  state: "live" | "revoked";
  generation: number;
  keyRevision: number;
  readonly epoch: number;
  readonly sessionTag: string | null;
  readonly createdAt: number;
  readonly expiresAt: number;
  keyRef: string;
  wrappedKey: Uint8Array;
  /** A fence, or a capture whose ciphertext was deleted. */
  keyless: boolean;
  /** Written by `revokeCapture` with `fenceAbsent`; its times are the store clock's. */
  readonly fence: boolean;
  /** The tombstone is kept while the store clock is at or before this. Null until revoked. */
  keepUntil: number | null;
}

export interface ModelEntry {
  readonly namespace: string;
  readonly tenant: string;
  readonly entryId: string;
  readonly captureId: string;
  readonly maxUses: number;
  used: number;
  lifecycleRevision: number;
  ciphertextRevision: number;
  envelope: Uint8Array;
}

export interface ModelReceipt {
  readonly namespace: string;
  readonly tenant: string;
  readonly attemptId: string;
  readonly requestDigest: Uint8Array;
  readonly committedAt: number;
  readonly receiptExpiresAt: number;
}

function copy(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

export class ReferenceModel {
  readonly maxClockSkewMs: number;
  readonly recovery = new Map<string, ModelRecovery>();
  readonly captures = new Map<string, ModelCapture>();
  readonly entries = new Map<string, ModelEntry>();
  readonly receipts = new Map<string, ModelReceipt>();

  constructor(options: { readonly maxClockSkewMs: number }) {
    this.maxClockSkewMs = options.maxClockSkewMs;
  }

  // ---- Lookups and decisions -------------------------------------------------

  /** Rows are keyed by (namespace, tenant, identifier); JSON keeps the three apart whatever they contain. */
  key(scope: StoreScope, id: string): string {
    return JSON.stringify([scope.namespace, scope.tenant, id]);
  }

  findCapture(scope: StoreScope, captureId: string): ModelCapture | undefined {
    return this.captures.get(this.key(scope, captureId));
  }

  findEntry(scope: StoreScope, entryId: string): ModelEntry | undefined {
    return this.entries.get(this.key(scope, entryId));
  }

  findReceipt(scope: StoreScope, attemptId: string): ModelReceipt | undefined {
    return this.receipts.get(this.key(scope, attemptId));
  }

  entriesOf(capture: ModelCapture): ModelEntry[] {
    const found: ModelEntry[] = [];
    for (const entry of this.entries.values()) {
      if (
        entry.namespace === capture.namespace &&
        entry.tenant === capture.tenant &&
        entry.captureId === capture.captureId
      ) {
        found.push(entry);
      }
    }
    return found;
  }

  recoveryOf(namespace: string): RecoveryState {
    const record = this.recovery.get(namespace);
    return record === undefined ? { epoch: 0, state: "uninitialized" } : { epoch: record.epoch, state: record.state };
  }

  /** §5.1: revoked, or created under an epoch lower than the namespace's. */
  treatedAsRevoked(capture: ModelCapture): boolean {
    return capture.state === "revoked" || capture.epoch < this.recoveryOf(capture.namespace).epoch;
  }

  /** §5.3 and §5.5 step 1. */
  notServing(namespace: string, epoch: number): boolean {
    const record = this.recovery.get(namespace);
    return record === undefined || record.state !== "serving" || record.epoch !== epoch;
  }

  skewed(storeNow: number, other: number): boolean {
    return Math.abs(storeNow - other) > this.maxClockSkewMs;
  }

  /** §5.5 step 4, for one named capture. */
  commitCaptureVerdict(
    capture: ModelCapture | undefined,
    expected: { readonly captureId: string; readonly generation: number },
    _input: CommitRestoreInput,
    storeNow: number,
  ): CommitRejection | null {
    if (capture === undefined) return "unknown";
    if (this.treatedAsRevoked(capture)) return "revoked";
    if (capture.generation !== expected.generation) return "stale";
    if (storeNow >= capture.expiresAt) return "expired";
    return null;
  }

  /** §5.5 step 5, for one use. */
  commitUseVerdict(entry: ModelEntry | undefined, use: CommitRestoreInput["uses"][number]): CommitRejection | null {
    if (entry === undefined || entry.captureId !== use.captureId) return "unknown";
    if (entry.lifecycleRevision !== use.lifecycleRevision || entry.ciphertextRevision !== use.ciphertextRevision) {
      return "stale";
    }
    if (entry.used + use.count > entry.maxUses) return "budget";
    return null;
  }

  /** §5.7: whether a sweep at `storeNow` may remove this receipt. */
  receiptSweepable(receipt: ModelReceipt, storeNow: number): boolean {
    return storeNow > receipt.receiptExpiresAt;
  }

  /** §5.7: whether a sweep at `storeNow` may remove this capture row once it has no entry. */
  captureSweepable(capture: ModelCapture, storeNow: number): boolean {
    return capture.keepUntil === null ? storeNow >= capture.expiresAt : storeNow > capture.keepUntil;
  }

  viewCapture(capture: ModelCapture): StoredCapture {
    return {
      captureId: capture.captureId,
      state: this.treatedAsRevoked(capture) ? "revoked" : "live",
      generation: capture.generation,
      keyRevision: capture.keyRevision,
      epoch: capture.epoch,
      sessionTag: capture.sessionTag,
      createdAt: capture.createdAt,
      expiresAt: capture.expiresAt,
      keyRef: capture.keyless ? "" : capture.keyRef,
      wrappedKey: capture.keyless ? new Uint8Array(0) : copy(capture.wrappedKey),
    };
  }

  viewEntry(entry: ModelEntry): StoredEntry {
    return {
      entryId: entry.entryId,
      captureId: entry.captureId,
      maxUses: entry.maxUses,
      used: entry.used,
      lifecycleRevision: entry.lifecycleRevision,
      ciphertextRevision: entry.ciphertextRevision,
      envelope: copy(entry.envelope),
    };
  }

  // ---- Operations ------------------------------------------------------------

  createCapture(input: CreateCaptureInput, storeNow: number): CreateCaptureResult {
    const { scope, capture } = input;
    if (this.notServing(scope.namespace, input.epoch)) return { outcome: "rejected", reason: "quarantined" };
    if (this.skewed(storeNow, input.now) || this.skewed(storeNow, capture.createdAt)) {
      return { outcome: "rejected", reason: "clock-skew" };
    }
    const present = this.findCapture(scope, capture.captureId);
    if (present !== undefined) {
      return { outcome: "rejected", reason: this.treatedAsRevoked(present) ? "fenced" : "exists" };
    }
    for (const entry of input.entries) {
      if (this.findEntry(scope, entry.entryId) !== undefined) return { outcome: "rejected", reason: "exists" };
    }
    this.captures.set(this.key(scope, capture.captureId), {
      namespace: scope.namespace,
      tenant: scope.tenant,
      captureId: capture.captureId,
      state: "live",
      generation: 1,
      keyRevision: 1,
      epoch: input.epoch,
      sessionTag: capture.sessionTag,
      createdAt: capture.createdAt,
      expiresAt: capture.expiresAt,
      keyRef: capture.keyRef,
      wrappedKey: copy(capture.wrappedKey),
      keyless: false,
      fence: false,
      keepUntil: null,
    });
    for (const entry of input.entries) {
      this.entries.set(this.key(scope, entry.entryId), {
        namespace: scope.namespace,
        tenant: scope.tenant,
        entryId: entry.entryId,
        captureId: capture.captureId,
        maxUses: entry.maxUses,
        used: 0,
        lifecycleRevision: 1,
        ciphertextRevision: 1,
        envelope: copy(entry.envelope),
      });
    }
    return { outcome: "created" };
  }

  readEntries(input: ReadEntriesInput, _storeNow: number): ReadEntriesResult {
    const entries: StoredEntry[] = [];
    const captures = new Map<string, StoredCapture>();
    for (const entryId of input.entryIds) {
      const entry = this.findEntry(input.scope, entryId);
      if (entry === undefined) continue;
      const capture = this.captures.get(
        this.key({ namespace: entry.namespace, tenant: entry.tenant }, entry.captureId),
      );
      if (capture === undefined || capture.keyless) continue;
      entries.push(this.viewEntry(entry));
      if (!captures.has(capture.captureId)) captures.set(capture.captureId, this.viewCapture(capture));
    }
    return { recovery: this.recoveryOf(input.scope.namespace), entries, captures: [...captures.values()] };
  }

  readCaptures(input: ReadCapturesInput, _storeNow: number): readonly StoredCapture[] {
    const found: StoredCapture[] = [];
    for (const captureId of input.captureIds) {
      const capture = this.findCapture(input.scope, captureId);
      if (capture !== undefined) found.push(this.viewCapture(capture));
    }
    return found;
  }

  commitRestore(input: CommitRestoreInput, storeNow: number): CommitRestoreResult {
    if (input.receiptExpiresAt - storeNow > LIMITS.maxReceiptHorizonMs) {
      throw new StoreError("STORE_INVALID_ARGUMENT");
    }
    const { scope } = input;
    if (this.notServing(scope.namespace, input.epoch)) return { outcome: "rejected", reason: "quarantined" };
    const receipt = this.findReceipt(scope, input.attempt.attemptId);
    if (receipt !== undefined) {
      return equalBytes(receipt.requestDigest, input.attempt.requestDigest)
        ? { outcome: "already-committed" }
        : { outcome: "attempt-mismatch" };
    }
    if (this.skewed(storeNow, input.now)) return { outcome: "rejected", reason: "clock-skew" };
    let latestExpiry = 0;
    for (const expected of input.captures) {
      const capture = this.findCapture(scope, expected.captureId);
      const verdict = this.commitCaptureVerdict(capture, expected, input, storeNow);
      if (verdict !== null) return { outcome: "rejected", reason: verdict };
      if (capture !== undefined && capture.expiresAt > latestExpiry) latestExpiry = capture.expiresAt;
    }
    const targets: ModelEntry[] = [];
    for (const use of input.uses) {
      const entry = this.findEntry(scope, use.entryId);
      const verdict = this.commitUseVerdict(entry, use);
      if (verdict !== null) return { outcome: "rejected", reason: verdict };
      if (entry !== undefined) targets.push(entry);
    }
    if (input.receiptExpiresAt < latestExpiry) throw new StoreError("STORE_INVALID_ARGUMENT");
    input.uses.forEach((use, index) => {
      const entry = targets[index];
      if (entry === undefined) return;
      entry.used += use.count;
      entry.lifecycleRevision += 1;
    });
    this.receipts.set(this.key(scope, input.attempt.attemptId), {
      namespace: scope.namespace,
      tenant: scope.tenant,
      attemptId: input.attempt.attemptId,
      requestDigest: copy(input.attempt.requestDigest),
      committedAt: storeNow,
      receiptExpiresAt: input.receiptExpiresAt,
    });
    return { outcome: "committed" };
  }

  revokeCapture(input: RevokeCaptureInput, storeNow: number): RevokeCaptureResult {
    const capture = this.findCapture(input.scope, input.captureId);
    if (capture === undefined) {
      if (!input.fenceAbsent) return { outcome: "not-found" };
      this.captures.set(this.key(input.scope, input.captureId), {
        namespace: input.scope.namespace,
        tenant: input.scope.tenant,
        captureId: input.captureId,
        state: "revoked",
        generation: 1,
        keyRevision: 1,
        epoch: this.recoveryOf(input.scope.namespace).epoch,
        sessionTag: null,
        createdAt: storeNow,
        expiresAt: storeNow,
        keyRef: "",
        wrappedKey: new Uint8Array(0),
        keyless: true,
        fence: true,
        keepUntil: storeNow + input.retentionMs,
      });
      return { outcome: "fenced" };
    }
    const entries = this.entriesOf(capture).length;
    if (this.treatedAsRevoked(capture)) return { outcome: "already-revoked", entries };
    capture.state = "revoked";
    capture.generation += 1;
    capture.keepUntil = Math.max(capture.expiresAt, storeNow) + input.retentionMs;
    return { outcome: "revoked", entries };
  }

  inspectAttempt(input: InspectAttemptInput, _storeNow: number): InspectAttemptResult {
    const receipt = this.findReceipt(input.scope, input.attemptId);
    if (receipt === undefined) return { state: "absent" };
    return { state: "committed", requestDigest: copy(receipt.requestDigest), committedAt: receipt.committedAt };
  }

  replaceCaptureKey(input: ReplaceCaptureKeyInput, storeNow: number): ReplaceCaptureKeyResult {
    const capture = this.findCapture(input.scope, input.captureId);
    if (capture === undefined) return { outcome: "rejected", reason: "unknown" };
    if (capture.keyless || this.treatedAsRevoked(capture)) return { outcome: "rejected", reason: "revoked" };
    if (storeNow >= capture.expiresAt) return { outcome: "rejected", reason: "expired" };
    if (capture.keyRevision !== input.keyRevision) return { outcome: "rejected", reason: "stale" };
    capture.keyRef = input.keyRef;
    capture.wrappedKey = copy(input.wrappedKey);
    capture.keyRevision += 1;
    return { outcome: "replaced", keyRevision: capture.keyRevision };
  }

  deleteCiphertext(input: DeleteCiphertextInput, storeNow: number): DeleteCiphertextResult {
    const capture = this.findCapture(input.scope, input.captureId);
    if (capture === undefined) return { outcome: "rejected", reason: "not-found" };
    if (!this.treatedAsRevoked(capture)) {
      if (this.skewed(storeNow, input.now)) return { outcome: "rejected", reason: "clock-skew" };
      if (storeNow < capture.expiresAt) return { outcome: "rejected", reason: "live" };
    }
    const owned = this.entriesOf(capture);
    for (const entry of owned) this.entries.delete(this.key(input.scope, entry.entryId));
    capture.keyRef = "";
    capture.wrappedKey = new Uint8Array(0);
    capture.keyless = true;
    capture.keyRevision += 1;
    capture.state = "revoked";
    return { outcome: "deleted", entries: owned.length };
  }

  sweepExpired(input: SweepInput, storeNow: number): SweepResult {
    if (this.skewed(storeNow, input.now)) return { outcome: "rejected", reason: "clock-skew" };
    let entries = 0;
    let captures = 0;
    let receipts = 0;
    let more = false;
    for (const [key, entry] of [...this.entries]) {
      if (entry.namespace !== input.namespace) continue;
      const capture = this.captures.get(
        this.key({ namespace: entry.namespace, tenant: entry.tenant }, entry.captureId),
      );
      if (capture !== undefined && storeNow < capture.expiresAt) continue;
      if (entries >= input.limit) {
        more = true;
        break;
      }
      this.entries.delete(key);
      entries += 1;
    }
    for (const [key, capture] of [...this.captures]) {
      if (capture.namespace !== input.namespace || !this.captureSweepable(capture, storeNow)) continue;
      if (this.entriesOf(capture).length > 0 || captures >= input.limit) {
        more = true;
        continue;
      }
      this.captures.delete(key);
      captures += 1;
    }
    for (const [key, receipt] of [...this.receipts]) {
      if (receipt.namespace !== input.namespace || !this.receiptSweepable(receipt, storeNow)) continue;
      if (receipts >= input.limit) {
        more = true;
        break;
      }
      this.receipts.delete(key);
      receipts += 1;
    }
    return { outcome: "swept", entries, captures, receipts, more };
  }

  recoveryState(input: { readonly namespace: string }, _storeNow: number): RecoveryState {
    return this.recoveryOf(input.namespace);
  }

  initializeNamespace(
    input: { readonly namespace: string; readonly epoch: number },
    _storeNow: number,
  ): InitializeNamespaceResult {
    if (this.recovery.has(input.namespace)) return { outcome: "rejected", reason: "exists" };
    for (const rows of [this.captures, this.entries, this.receipts]) {
      for (const row of rows.values()) {
        if (row.namespace === input.namespace) return { outcome: "rejected", reason: "not-empty" };
      }
    }
    this.recovery.set(input.namespace, { epoch: input.epoch, state: "serving" });
    return { outcome: "initialized" };
  }

  quarantine(input: { readonly namespace: string }, _storeNow: number): RecoveryState {
    const record = this.recovery.get(input.namespace);
    if (record !== undefined) record.state = "quarantined";
    return this.recoveryOf(input.namespace);
  }

  invalidateRecovered(input: InvalidateRecoveredInput, _storeNow: number): InvalidateRecoveredResult {
    const record = this.recovery.get(input.namespace);
    if (record === undefined) return { outcome: "rejected", reason: "uninitialized" };
    if (input.newEpoch <= record.epoch) return { outcome: "rejected", reason: "epoch-not-greater" };
    record.epoch = input.newEpoch;
    record.state = "serving";
    return { outcome: "invalidated", recovery: this.recoveryOf(input.namespace) };
  }
}
