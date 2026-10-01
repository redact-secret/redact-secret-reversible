/**
 * `@redact-secret/store-memory`: a ciphertext-only, non-durable,
 * single-process reference `Store` (docs/specs/persistent-vault.md §5).
 *
 * It holds envelopes, wrapped keys, counters, and receipts in process memory.
 * It never decrypts, never holds a key, never resolves a principal, and never
 * evaluates a policy. Everything is lost when the process exits.
 */
import {
  LIMITS,
  StoreError,
  validateCommitRestore,
  validateCreateCapture,
  validateDeleteCiphertext,
  validateInitializeNamespace,
  validateInspectAttempt,
  validateInvalidateRecovered,
  validateNamespace,
  validateReadCaptures,
  validateReadEntries,
  validateReplaceCaptureKey,
  validateRevokeCapture,
  validateSweep,
} from "@redact-secret/vault-contracts";
import type {
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
  Store,
  StoreCallOptions,
  StoreCapabilities,
  StoredCapture,
  StoredEntry,
  StoreScope,
  SweepInput,
  SweepResult,
} from "@redact-secret/vault-contracts";

/** Every `Store` operation that takes an input. */
export type MemoryStoreOperation = Exclude<keyof Store, "capabilities">;

/**
 * Where a control hook runs.
 *
 * - `"before-validate"`: before the input is validated and copied.
 * - `"before-apply"`: after validation and the defensive copy, before the
 *   operation's atomic section starts. The section then reads the store's
 *   clock and all state afresh.
 */
export type MemoryStorePhase = "before-validate" | "before-apply";

export interface MemoryStoreHookInfo {
  readonly operation: MemoryStoreOperation;
  readonly phase: MemoryStorePhase;
  /** Zero-based index of this call among all calls of `operation` on this store. */
  readonly call: number;
}

export type MemoryStoreHook = (info: MemoryStoreHookInfo) => void | Promise<void>;

/**
 * Test-only controls. They are returned next to the store, never on it, so a
 * `Store` handed to a server carries no way to reach them.
 */
export interface MemoryStoreControl {
  /**
   * Runs `hook` at `phase` of every later call of `operation`, awaited, in
   * registration order. Returns a function that removes the hook. A hook that
   * throws makes the operation reject with that error before it changed
   * anything.
   *
   * A hook can run other operations of the same store to completion while
   * the hooked call is suspended, which is how a test places a revocation or
   * a quarantine between a caller's preflight read and its commit. A hook
   * cannot run inside an operation's atomic section: that section is
   * synchronous, so nothing can be interleaved with its read-check-write.
   */
  onPhase(operation: MemoryStoreOperation, phase: MemoryStorePhase, hook: MemoryStoreHook): () => void;
  /** Removes every hook. */
  clearHooks(): void;
  /** Row counts across all namespaces and tenants. No identifier and no stored byte is exposed. */
  counts(): { readonly namespaces: number; readonly captures: number; readonly entries: number; readonly receipts: number };
}

export interface MemoryStoreOptions {
  /** The store's own clock, in milliseconds. Floored. Default `Date.now`. */
  readonly now?: () => number;
  /** Default 2000. 0 to 60 000. */
  readonly maxClockSkewMs?: number;
  /** Each bound may only be lowered from its default. */
  readonly maxCreateEntries?: number;
  readonly maxCreateBytes?: number;
  readonly maxRestoreEntries?: number;
  readonly maxRestoreCaptures?: number;
  readonly maxEnvelopeBytes?: number;
}

export interface MemoryStore {
  /** The `Store` to hand to a server. It has the contract's methods and nothing else. */
  readonly store: Store;
  /** Test-only controls. Do not pass them to a server. */
  readonly control: MemoryStoreControl;
}

const DEFAULT_MAX_CLOCK_SKEW_MS = 2000;
const MAX_CLOCK_SKEW_CEILING_MS = 60_000;
const DEFAULT_MAX_CREATE_BYTES = 16 * 1024 * 1024;

interface RecoveryRecord {
  epoch: number;
  state: "serving" | "quarantined";
}

interface CaptureRow {
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
  /** A fence, or a capture whose ciphertext was deleted: it holds no key. */
  keyless: boolean;
  /** Set by a revocation: the tombstone is kept while the store clock is at or before this. */
  keepUntil: number | null;
  readonly entryIds: Set<string>;
}

interface EntryRow {
  readonly entryId: string;
  readonly captureId: string;
  readonly maxUses: number;
  used: number;
  lifecycleRevision: number;
  readonly ciphertextRevision: number;
  readonly envelope: Uint8Array;
}

interface ReceiptRow {
  readonly requestDigest: Uint8Array;
  readonly committedAt: number;
  readonly receiptExpiresAt: number;
}

interface TenantRows {
  readonly captures: Map<string, CaptureRow>;
  readonly entries: Map<string, EntryRow>;
  readonly receipts: Map<string, ReceiptRow>;
}

interface NamespaceRows {
  recovery: RecoveryRecord | null;
  readonly tenants: Map<string, TenantRows>;
}

function copyBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let difference = 0;
  for (let i = 0; i < a.byteLength; i += 1) difference |= (a[i] as number) ^ (b[i] as number);
  return difference === 0;
}

function copyScope(scope: StoreScope): StoreScope {
  return { namespace: scope.namespace, tenant: scope.tenant };
}

function cancelled(options: StoreCallOptions | undefined): boolean {
  return options?.signal?.aborted === true;
}

function lowered(name: string, value: number | undefined, ceiling: number): number {
  if (value === undefined) return ceiling;
  if (!Number.isSafeInteger(value) || value < 1 || value > ceiling) {
    throw new TypeError(`createMemoryStore: ${name} must be an integer from 1 to its default.`);
  }
  return value;
}

/**
 * Creates an empty store. Each call is an independent instance that shares
 * nothing with any other: there is no way to reopen the state of an earlier
 * instance, in this process or another.
 */
export function createMemoryStore(options: MemoryStoreOptions = {}): MemoryStore {
  const readClock = options.now ?? Date.now;
  if (typeof readClock !== "function") throw new TypeError("createMemoryStore: now must be a function.");
  const skew = options.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS;
  if (!Number.isSafeInteger(skew) || skew < 0 || skew > MAX_CLOCK_SKEW_CEILING_MS) {
    throw new TypeError("createMemoryStore: maxClockSkewMs must be an integer from 0 to 60000.");
  }

  const capabilities: StoreCapabilities = Object.freeze({
    contractVersion: 1,
    adapter: "store-memory",
    profile: "process-memory",
    atomicCreate: true,
    maxCreateEntries: lowered("maxCreateEntries", options.maxCreateEntries, LIMITS.maxCreateEntries),
    maxCreateBytes: lowered("maxCreateBytes", options.maxCreateBytes, DEFAULT_MAX_CREATE_BYTES),
    atomicRestore: true,
    maxRestoreEntries: lowered("maxRestoreEntries", options.maxRestoreEntries, LIMITS.maxRestoreEntries),
    maxRestoreCaptures: lowered("maxRestoreCaptures", options.maxRestoreCaptures, LIMITS.maxRestoreCaptures),
    authoritativeCommit: true,
    revocationFences: true,
    attemptReceipts: true,
    storeClock: true,
    maxClockSkewMs: skew,
    durability: "volatile",
    crossProcess: false,
    restoreDetection: "none",
    maxEnvelopeBytes: lowered("maxEnvelopeBytes", options.maxEnvelopeBytes, LIMITS.maxEnvelopeBytes),
  });

  const namespaces = new Map<string, NamespaceRows>();
  const hooks = new Map<string, MemoryStoreHook[]>();
  const calls = new Map<MemoryStoreOperation, number>();

  function storeNow(): number {
    const value = Math.floor(readClock());
    if (!Number.isSafeInteger(value) || value < 0) throw new StoreError("STORE_UNAVAILABLE");
    return value;
  }

  function skewed(now: number, other: number): boolean {
    return Math.abs(now - other) > skew;
  }

  async function fire(operation: MemoryStoreOperation, phase: MemoryStorePhase, call: number): Promise<void> {
    const registered = hooks.get(`${operation}/${phase}`);
    if (registered === undefined || registered.length === 0) return;
    for (const hook of [...registered]) await hook({ operation, phase, call });
  }

  /**
   * Runs one operation: validate and copy the input, then apply it in one
   * synchronous section. `prepare` and `apply` contain no `await`, so two
   * operations can never interleave inside either.
   */
  async function run<I, S, R>(
    operation: MemoryStoreOperation,
    input: I,
    options: StoreCallOptions | undefined,
    prepare: (input: I) => S,
    apply: (snapshot: S, now: number) => R,
  ): Promise<R> {
    const call = calls.get(operation) ?? 0;
    calls.set(operation, call + 1);
    // A call cancelled before its atomic section definitely had no effect.
    if (cancelled(options)) throw new StoreError("STORE_UNAVAILABLE");
    await fire(operation, "before-validate", call);
    const snapshot = prepare(input);
    await fire(operation, "before-apply", call);
    if (cancelled(options)) throw new StoreError("STORE_UNAVAILABLE");
    return apply(snapshot, storeNow());
  }

  /** Validates the caller's object, copies it, and validates the copy the store will use. */
  function prepared<I>(validate: (input: I) => void, copy: (input: I) => I): (input: I) => I {
    return (input) => {
      validate(input);
      let snapshot: I;
      try {
        snapshot = copy(input);
      } catch {
        throw new StoreError("STORE_INVALID_ARGUMENT");
      }
      validate(snapshot);
      return snapshot;
    };
  }

  function tenantRows(scope: StoreScope): TenantRows | undefined {
    return namespaces.get(scope.namespace)?.tenants.get(scope.tenant);
  }

  function ensureTenantRows(scope: StoreScope): TenantRows {
    let namespace = namespaces.get(scope.namespace);
    if (namespace === undefined) {
      namespace = { recovery: null, tenants: new Map() };
      namespaces.set(scope.namespace, namespace);
    }
    let rows = namespace.tenants.get(scope.tenant);
    if (rows === undefined) {
      rows = { captures: new Map(), entries: new Map(), receipts: new Map() };
      namespace.tenants.set(scope.tenant, rows);
    }
    return rows;
  }

  function recoveryOf(namespace: string): RecoveryState {
    const record = namespaces.get(namespace)?.recovery;
    if (record === undefined || record === null) return { epoch: 0, state: "uninitialized" };
    return { epoch: record.epoch, state: record.state };
  }

  /** A capture created under a lower epoch is treated as revoked by every operation (§5.1). */
  function isRevoked(row: CaptureRow, namespaceEpoch: number): boolean {
    return row.state === "revoked" || row.epoch < namespaceEpoch;
  }

  function notServing(namespace: string, epoch: number): boolean {
    const record = namespaces.get(namespace)?.recovery;
    return record === undefined || record === null || record.state !== "serving" || record.epoch !== epoch;
  }

  function viewCapture(row: CaptureRow, namespaceEpoch: number): StoredCapture {
    return {
      captureId: row.captureId,
      state: isRevoked(row, namespaceEpoch) ? "revoked" : "live",
      generation: row.generation,
      keyRevision: row.keyRevision,
      epoch: row.epoch,
      sessionTag: row.sessionTag,
      createdAt: row.createdAt,
      expiresAt: row.expiresAt,
      keyRef: row.keyless ? "" : row.keyRef,
      wrappedKey: row.keyless ? new Uint8Array(0) : copyBytes(row.wrappedKey),
    };
  }

  function viewEntry(row: EntryRow): StoredEntry {
    return {
      entryId: row.entryId,
      captureId: row.captureId,
      maxUses: row.maxUses,
      used: row.used,
      lifecycleRevision: row.lifecycleRevision,
      ciphertextRevision: row.ciphertextRevision,
      envelope: copyBytes(row.envelope),
    };
  }

  function removeEntries(rows: TenantRows, capture: CaptureRow): number {
    let removed = 0;
    for (const entryId of capture.entryIds) {
      if (rows.entries.delete(entryId)) removed += 1;
    }
    capture.entryIds.clear();
    return removed;
  }

  const store: Store = {
    capabilities: () => capabilities,

    createCapture: (input: CreateCaptureInput, options?: StoreCallOptions): Promise<CreateCaptureResult> =>
      run(
        "createCapture",
        input,
        options,
        prepared(
          (value) => validateCreateCapture(value, capabilities),
          (value) => ({
            scope: copyScope(value.scope),
            epoch: value.epoch,
            now: value.now,
            capture: {
              captureId: value.capture.captureId,
              sessionTag: value.capture.sessionTag,
              createdAt: value.capture.createdAt,
              expiresAt: value.capture.expiresAt,
              lookupVersion: value.capture.lookupVersion,
              keyRef: value.capture.keyRef,
              wrappedKey: copyBytes(value.capture.wrappedKey),
            },
            entries: value.entries.map((entry) => ({
              entryId: entry.entryId,
              maxUses: entry.maxUses,
              envelope: copyBytes(entry.envelope),
            })),
          }),
        ),
        (snapshot, now) => {
          const { scope, capture, entries } = snapshot;
          if (notServing(scope.namespace, snapshot.epoch)) return { outcome: "rejected", reason: "quarantined" };
          if (skewed(now, snapshot.now) || skewed(now, capture.createdAt)) {
            return { outcome: "rejected", reason: "clock-skew" };
          }
          const existing = tenantRows(scope);
          const present = existing?.captures.get(capture.captureId);
          if (present !== undefined) {
            return { outcome: "rejected", reason: isRevoked(present, snapshot.epoch) ? "fenced" : "exists" };
          }
          for (const entry of entries) {
            if (existing?.entries.has(entry.entryId) === true) return { outcome: "rejected", reason: "exists" };
          }
          const rows = ensureTenantRows(scope);
          const row: CaptureRow = {
            captureId: capture.captureId,
            state: "live",
            generation: 1,
            keyRevision: 1,
            epoch: snapshot.epoch,
            sessionTag: capture.sessionTag,
            createdAt: capture.createdAt,
            expiresAt: capture.expiresAt,
            keyRef: capture.keyRef,
            wrappedKey: capture.wrappedKey,
            keyless: false,
            keepUntil: null,
            entryIds: new Set(),
          };
          rows.captures.set(row.captureId, row);
          for (const entry of entries) {
            row.entryIds.add(entry.entryId);
            rows.entries.set(entry.entryId, {
              entryId: entry.entryId,
              captureId: row.captureId,
              maxUses: entry.maxUses,
              used: 0,
              lifecycleRevision: 1,
              ciphertextRevision: 1,
              envelope: entry.envelope,
            });
          }
          return { outcome: "created" };
        },
      ),

    readEntries: (input: ReadEntriesInput, options?: StoreCallOptions): Promise<ReadEntriesResult> =>
      run(
        "readEntries",
        input,
        options,
        prepared(
          (value) => validateReadEntries(value, capabilities),
          (value) => ({ scope: copyScope(value.scope), entryIds: [...value.entryIds] }),
        ),
        (snapshot) => {
          const recovery = recoveryOf(snapshot.scope.namespace);
          const rows = tenantRows(snapshot.scope);
          const entries: StoredEntry[] = [];
          const captures = new Map<string, StoredCapture>();
          if (rows !== undefined) {
            for (const entryId of snapshot.entryIds) {
              const entry = rows.entries.get(entryId);
              if (entry === undefined) continue;
              const capture = rows.captures.get(entry.captureId);
              if (capture === undefined || capture.keyless) continue;
              entries.push(viewEntry(entry));
              if (!captures.has(capture.captureId)) {
                captures.set(capture.captureId, viewCapture(capture, recovery.epoch));
              }
            }
          }
          return { recovery, entries, captures: [...captures.values()] };
        },
      ),

    readCaptures: (input: ReadCapturesInput, options?: StoreCallOptions): Promise<readonly StoredCapture[]> =>
      run(
        "readCaptures",
        input,
        options,
        prepared(
          (value) => validateReadCaptures(value, capabilities),
          (value) => ({ scope: copyScope(value.scope), captureIds: [...value.captureIds] }),
        ),
        (snapshot) => {
          const epoch = recoveryOf(snapshot.scope.namespace).epoch;
          const rows = tenantRows(snapshot.scope);
          const found: StoredCapture[] = [];
          if (rows !== undefined) {
            for (const captureId of snapshot.captureIds) {
              const capture = rows.captures.get(captureId);
              if (capture !== undefined) found.push(viewCapture(capture, epoch));
            }
          }
          return found;
        },
      ),

    commitRestore: (input: CommitRestoreInput, options?: StoreCallOptions): Promise<CommitRestoreResult> =>
      run(
        "commitRestore",
        input,
        options,
        prepared(
          (value) => validateCommitRestore(value, capabilities),
          (value) => ({
            scope: copyScope(value.scope),
            epoch: value.epoch,
            now: value.now,
            attempt: {
              attemptId: value.attempt.attemptId,
              requestDigest: copyBytes(value.attempt.requestDigest),
            },
            receiptExpiresAt: value.receiptExpiresAt,
            captures: value.captures.map((capture) => ({
              captureId: capture.captureId,
              generation: capture.generation,
            })),
            uses: value.uses.map((use) => ({
              entryId: use.entryId,
              captureId: use.captureId,
              count: use.count,
              lifecycleRevision: use.lifecycleRevision,
              ciphertextRevision: use.ciphertextRevision,
            })),
          }),
        ),
        (snapshot, now) => {
          const { scope } = snapshot;
          // Step 1.
          if (notServing(scope.namespace, snapshot.epoch)) return { outcome: "rejected", reason: "quarantined" };
          // Step 2.
          const rows = tenantRows(scope);
          const receipt = rows?.receipts.get(snapshot.attempt.attemptId);
          if (receipt !== undefined) {
            return sameBytes(receipt.requestDigest, snapshot.attempt.requestDigest)
              ? { outcome: "already-committed" }
              : { outcome: "attempt-mismatch" };
          }
          // Step 3.
          if (skewed(now, snapshot.now)) return { outcome: "rejected", reason: "clock-skew" };
          // §4.2: the one mechanical check that needs the store's clock. After
          // steps 1 and 2, whose order §5.5 fixes.
          if (snapshot.receiptExpiresAt - now > LIMITS.maxReceiptHorizonMs) {
            throw new StoreError("STORE_INVALID_ARGUMENT");
          }
          if (rows === undefined) return { outcome: "rejected", reason: "unknown" };
          // Step 4.
          let latestExpiry = 0;
          for (const expected of snapshot.captures) {
            const capture = rows.captures.get(expected.captureId);
            if (capture === undefined) return { outcome: "rejected", reason: "unknown" };
            if (isRevoked(capture, snapshot.epoch)) return { outcome: "rejected", reason: "revoked" };
            if (capture.generation !== expected.generation) return { outcome: "rejected", reason: "stale" };
            if (now >= capture.expiresAt) return { outcome: "rejected", reason: "expired" };
            if (capture.expiresAt > latestExpiry) latestExpiry = capture.expiresAt;
          }
          // Step 5.
          const targets: EntryRow[] = [];
          for (const use of snapshot.uses) {
            const entry = rows.entries.get(use.entryId);
            if (entry === undefined || entry.captureId !== use.captureId) {
              return { outcome: "rejected", reason: "unknown" };
            }
            if (
              entry.lifecycleRevision !== use.lifecycleRevision ||
              entry.ciphertextRevision !== use.ciphertextRevision
            ) {
              return { outcome: "rejected", reason: "stale" };
            }
            if (entry.used + use.count > entry.maxUses) return { outcome: "rejected", reason: "budget" };
            targets.push(entry);
          }
          // Step 6.
          if (snapshot.receiptExpiresAt < latestExpiry) throw new StoreError("STORE_INVALID_ARGUMENT");
          // Step 7. Nothing above wrote; nothing below can fail.
          snapshot.uses.forEach((use, index) => {
            const entry = targets[index] as EntryRow;
            entry.used += use.count;
            entry.lifecycleRevision += 1;
          });
          rows.receipts.set(snapshot.attempt.attemptId, {
            requestDigest: snapshot.attempt.requestDigest,
            committedAt: now,
            receiptExpiresAt: snapshot.receiptExpiresAt,
          });
          return { outcome: "committed" };
        },
      ),

    revokeCapture: (input: RevokeCaptureInput, options?: StoreCallOptions): Promise<RevokeCaptureResult> =>
      run(
        "revokeCapture",
        input,
        options,
        prepared(validateRevokeCapture, (value) => ({
          scope: copyScope(value.scope),
          captureId: value.captureId,
          now: value.now,
          retentionMs: value.retentionMs,
          fenceAbsent: value.fenceAbsent,
        })),
        (snapshot, now) => {
          const epoch = recoveryOf(snapshot.scope.namespace).epoch;
          const capture = tenantRows(snapshot.scope)?.captures.get(snapshot.captureId);
          if (capture === undefined) {
            if (!snapshot.fenceAbsent) return { outcome: "not-found" };
            ensureTenantRows(snapshot.scope).captures.set(snapshot.captureId, {
              captureId: snapshot.captureId,
              state: "revoked",
              generation: 1,
              keyRevision: 1,
              epoch,
              sessionTag: null,
              createdAt: now,
              expiresAt: now,
              keyRef: "",
              wrappedKey: new Uint8Array(0),
              keyless: true,
              keepUntil: now + snapshot.retentionMs,
              entryIds: new Set(),
            });
            return { outcome: "fenced" };
          }
          if (isRevoked(capture, epoch)) return { outcome: "already-revoked", entries: capture.entryIds.size };
          capture.state = "revoked";
          capture.generation += 1;
          capture.keepUntil = Math.max(capture.expiresAt, now) + snapshot.retentionMs;
          return { outcome: "revoked", entries: capture.entryIds.size };
        },
      ),

    inspectAttempt: (input: InspectAttemptInput, options?: StoreCallOptions): Promise<InspectAttemptResult> =>
      run(
        "inspectAttempt",
        input,
        options,
        prepared(validateInspectAttempt, (value) => ({
          scope: copyScope(value.scope),
          attemptId: value.attemptId,
        })),
        (snapshot) => {
          const receipt = tenantRows(snapshot.scope)?.receipts.get(snapshot.attemptId);
          if (receipt === undefined) return { state: "absent" };
          return {
            state: "committed",
            requestDigest: copyBytes(receipt.requestDigest),
            committedAt: receipt.committedAt,
          };
        },
      ),

    replaceCaptureKey: (
      input: ReplaceCaptureKeyInput,
      options?: StoreCallOptions,
    ): Promise<ReplaceCaptureKeyResult> =>
      run(
        "replaceCaptureKey",
        input,
        options,
        prepared(validateReplaceCaptureKey, (value) => ({
          scope: copyScope(value.scope),
          captureId: value.captureId,
          keyRevision: value.keyRevision,
          keyRef: value.keyRef,
          wrappedKey: copyBytes(value.wrappedKey),
        })),
        (snapshot, now) => {
          const epoch = recoveryOf(snapshot.scope.namespace).epoch;
          const capture = tenantRows(snapshot.scope)?.captures.get(snapshot.captureId);
          if (capture === undefined) return { outcome: "rejected", reason: "unknown" };
          if (capture.keyless || isRevoked(capture, epoch)) return { outcome: "rejected", reason: "revoked" };
          if (now >= capture.expiresAt) return { outcome: "rejected", reason: "expired" };
          if (capture.keyRevision !== snapshot.keyRevision) return { outcome: "rejected", reason: "stale" };
          capture.keyRef = snapshot.keyRef;
          capture.wrappedKey = snapshot.wrappedKey;
          capture.keyRevision += 1;
          return { outcome: "replaced", keyRevision: capture.keyRevision };
        },
      ),

    deleteCiphertext: (input: DeleteCiphertextInput, options?: StoreCallOptions): Promise<DeleteCiphertextResult> =>
      run(
        "deleteCiphertext",
        input,
        options,
        prepared(validateDeleteCiphertext, (value) => ({
          scope: copyScope(value.scope),
          captureId: value.captureId,
          now: value.now,
        })),
        (snapshot, now) => {
          const epoch = recoveryOf(snapshot.scope.namespace).epoch;
          const rows = tenantRows(snapshot.scope);
          const capture = rows?.captures.get(snapshot.captureId);
          if (rows === undefined || capture === undefined) return { outcome: "rejected", reason: "not-found" };
          if (!isRevoked(capture, epoch)) {
            // The decision rests on expiry, so the clocks must agree.
            if (skewed(now, snapshot.now)) return { outcome: "rejected", reason: "clock-skew" };
            if (now < capture.expiresAt) return { outcome: "rejected", reason: "live" };
          }
          const entries = removeEntries(rows, capture);
          capture.keyRef = "";
          capture.wrappedKey = new Uint8Array(0);
          capture.keyless = true;
          capture.keyRevision += 1;
          capture.state = "revoked";
          return { outcome: "deleted", entries };
        },
      ),

    sweepExpired: (input: SweepInput, options?: StoreCallOptions): Promise<SweepResult> =>
      run(
        "sweepExpired",
        input,
        options,
        prepared(validateSweep, (value) => ({ namespace: value.namespace, now: value.now, limit: value.limit })),
        (snapshot, now) => {
          if (skewed(now, snapshot.now)) return { outcome: "rejected", reason: "clock-skew" };
          const namespace = namespaces.get(snapshot.namespace);
          let entries = 0;
          let captures = 0;
          let receipts = 0;
          let more = false;
          if (namespace === undefined) return { outcome: "swept", entries, captures, receipts, more };
          for (const rows of namespace.tenants.values()) {
            for (const capture of rows.captures.values()) {
              if (now < capture.expiresAt) continue;
              for (const entryId of [...capture.entryIds]) {
                if (entries >= snapshot.limit) {
                  more = true;
                  break;
                }
                capture.entryIds.delete(entryId);
                rows.entries.delete(entryId);
                entries += 1;
              }
            }
            for (const capture of [...rows.captures.values()]) {
              const due = capture.keepUntil === null ? now >= capture.expiresAt : now > capture.keepUntil;
              if (!due) continue;
              // A capture row outlives its entries, so an entry never points at nothing.
              if (capture.entryIds.size > 0 || captures >= snapshot.limit) {
                more = true;
                continue;
              }
              rows.captures.delete(capture.captureId);
              captures += 1;
            }
            for (const [attemptId, receipt] of [...rows.receipts]) {
              if (now <= receipt.receiptExpiresAt) continue;
              if (receipts >= snapshot.limit) {
                more = true;
                break;
              }
              rows.receipts.delete(attemptId);
              receipts += 1;
            }
          }
          for (const [tenant, rows] of [...namespace.tenants]) {
            if (rows.captures.size === 0 && rows.entries.size === 0 && rows.receipts.size === 0) {
              namespace.tenants.delete(tenant);
            }
          }
          if (namespace.recovery === null && namespace.tenants.size === 0) namespaces.delete(snapshot.namespace);
          return { outcome: "swept", entries, captures, receipts, more };
        },
      ),

    recoveryState: (input: { readonly namespace: string }, options?: StoreCallOptions): Promise<RecoveryState> =>
      run(
        "recoveryState",
        input,
        options,
        prepared(validateNamespace, (value) => ({ namespace: value.namespace })),
        (snapshot) => recoveryOf(snapshot.namespace),
      ),

    initializeNamespace: (
      input: { readonly namespace: string; readonly epoch: number },
      options?: StoreCallOptions,
    ): Promise<InitializeNamespaceResult> =>
      run(
        "initializeNamespace",
        input,
        options,
        prepared(validateInitializeNamespace, (value) => ({ namespace: value.namespace, epoch: value.epoch })),
        (snapshot) => {
          const namespace = namespaces.get(snapshot.namespace);
          if (namespace !== undefined && namespace.recovery !== null) return { outcome: "rejected", reason: "exists" };
          if (namespace !== undefined) {
            for (const rows of namespace.tenants.values()) {
              if (rows.captures.size > 0 || rows.entries.size > 0 || rows.receipts.size > 0) {
                return { outcome: "rejected", reason: "not-empty" };
              }
            }
          }
          namespaces.set(snapshot.namespace, {
            recovery: { epoch: snapshot.epoch, state: "serving" },
            tenants: namespace?.tenants ?? new Map(),
          });
          return { outcome: "initialized" };
        },
      ),

    quarantine: (input: { readonly namespace: string }, options?: StoreCallOptions): Promise<RecoveryState> =>
      run(
        "quarantine",
        input,
        options,
        prepared(validateNamespace, (value) => ({ namespace: value.namespace })),
        (snapshot) => {
          // Only initializeNamespace creates the record; with none there is nothing to quarantine.
          const record = namespaces.get(snapshot.namespace)?.recovery;
          if (record !== undefined && record !== null) record.state = "quarantined";
          return recoveryOf(snapshot.namespace);
        },
      ),

    invalidateRecovered: (
      input: InvalidateRecoveredInput,
      options?: StoreCallOptions,
    ): Promise<InvalidateRecoveredResult> =>
      run(
        "invalidateRecovered",
        input,
        options,
        prepared(validateInvalidateRecovered, (value) => ({
          namespace: value.namespace,
          newEpoch: value.newEpoch,
        })),
        (snapshot) => {
          const record = namespaces.get(snapshot.namespace)?.recovery;
          if (record === undefined || record === null) return { outcome: "rejected", reason: "uninitialized" };
          if (snapshot.newEpoch <= record.epoch) return { outcome: "rejected", reason: "epoch-not-greater" };
          record.epoch = snapshot.newEpoch;
          record.state = "serving";
          return { outcome: "invalidated", recovery: recoveryOf(snapshot.namespace) };
        },
      ),
  };

  const control: MemoryStoreControl = {
    onPhase(operation, phase, hook) {
      if (typeof hook !== "function") throw new TypeError("onPhase: hook must be a function.");
      if (!(operation in store) || operation === ("capabilities" as string)) {
        throw new TypeError("onPhase: unknown operation.");
      }
      if (phase !== "before-validate" && phase !== "before-apply") throw new TypeError("onPhase: unknown phase.");
      const key = `${operation}/${phase}`;
      const registered = hooks.get(key) ?? [];
      registered.push(hook);
      hooks.set(key, registered);
      return () => {
        const index = registered.indexOf(hook);
        if (index >= 0) registered.splice(index, 1);
      };
    },
    clearHooks() {
      hooks.clear();
    },
    counts() {
      let captures = 0;
      let entries = 0;
      let receipts = 0;
      for (const namespace of namespaces.values()) {
        for (const rows of namespace.tenants.values()) {
          captures += rows.captures.size;
          entries += rows.entries.size;
          receipts += rows.receipts.size;
        }
      }
      return { namespaces: namespaces.size, captures, entries, receipts };
    },
  };

  return { store: Object.freeze(store), control: Object.freeze(control) };
}
