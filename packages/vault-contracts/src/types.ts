/**
 * The frozen contract surface of docs/specs/persistent-vault.md §4 and §5,
 * transcribed from that document's code blocks. The specification is
 * authoritative for semantics; change it first.
 */

export interface StoreScope {
  readonly namespace: string;
  readonly tenant: string;
}

export interface StoreCapabilities {
  readonly contractVersion: 1;
  /** Package or implementation name. Descriptive. */
  readonly adapter: string;
  /** The deployment profile the adapter verified or was told it runs under. */
  readonly profile: string;
  readonly atomicCreate: boolean;
  readonly maxCreateEntries: number;
  readonly maxCreateBytes: number;
  readonly atomicRestore: boolean;
  readonly maxRestoreEntries: number;
  readonly maxRestoreCaptures: number;
  /** Commit, revoke, and inspect are evaluated against authoritative state. */
  readonly authoritativeCommit: boolean;
  readonly revocationFences: boolean;
  readonly attemptReceipts: boolean;
  /** The store judges expiry and skew with its own clock. */
  readonly storeClock: boolean;
  /** Largest difference the store accepts between its clock and a caller's `now`. */
  readonly maxClockSkewMs: number;
  /** "volatile": state is lost when the process exits. */
  readonly durability: "volatile" | "durable";
  /** Independent processes share one authoritative state. */
  readonly crossProcess: boolean;
  /** What the adapter does to notice a restored or rolled-back database: a short identifier, or "none". */
  readonly restoreDetection: string;
  readonly maxEnvelopeBytes: number;
}

export interface StoredKey {
  readonly keyRef: string;
  readonly wrappedKey: Uint8Array;
}

export interface NewEntry {
  readonly entryId: string;
  readonly maxUses: number;
  readonly envelope: Uint8Array;
}

export interface CreateCaptureInput {
  readonly scope: StoreScope;
  readonly epoch: number;
  readonly now: number;
  readonly capture: StoredKey & {
    readonly captureId: string;
    /** 64 hexadecimal characters, or null for a capture that is not session-bound. */
    readonly sessionTag: string | null;
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly lookupVersion: 1;
  };
  readonly entries: readonly NewEntry[];
}

export type CreateCaptureResult =
  | { readonly outcome: "created" }
  | { readonly outcome: "rejected"; readonly reason: "exists" | "fenced" | "clock-skew" | "quarantined" | "stale" };

export interface StoredEntry {
  readonly entryId: string;
  readonly captureId: string;
  readonly maxUses: number;
  readonly used: number;
  readonly lifecycleRevision: number;
  readonly ciphertextRevision: number;
  readonly envelope: Uint8Array;
}

export interface StoredCapture extends StoredKey {
  readonly captureId: string;
  readonly state: "live" | "revoked";
  readonly generation: number;
  readonly keyRevision: number;
  readonly epoch: number;
  readonly sessionTag: string | null;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface ReadEntriesInput {
  readonly scope: StoreScope;
  readonly entryIds: readonly string[];
}

export interface ReadCapturesInput {
  readonly scope: StoreScope;
  readonly captureIds: readonly string[];
}

export interface ReadEntriesResult {
  readonly recovery: RecoveryState;
  /** Entries found, in no particular order. A missing identifier is simply absent. */
  readonly entries: readonly StoredEntry[];
  /** The capture of every returned entry. */
  readonly captures: readonly StoredCapture[];
}

export interface CommitRestoreInput {
  readonly scope: StoreScope;
  readonly epoch: number;
  readonly now: number;
  readonly attempt: { readonly attemptId: string; readonly requestDigest: Uint8Array };
  readonly receiptExpiresAt: number;
  /** Exactly the captures of the entries in `uses`, each once. */
  readonly captures: readonly { readonly captureId: string; readonly generation: number }[];
  /** Each entry once, with its total occurrence count across the request. */
  readonly uses: readonly {
    readonly entryId: string;
    readonly captureId: string;
    readonly count: number;
    readonly lifecycleRevision: number;
    readonly ciphertextRevision: number;
  }[];
}

export type CommitRejection =
  | "revoked" | "expired" | "budget" | "stale" | "unknown" | "clock-skew" | "quarantined";

export type CommitRestoreResult =
  | { readonly outcome: "committed" }
  | { readonly outcome: "already-committed" }
  | { readonly outcome: "attempt-mismatch" }
  | { readonly outcome: "rejected"; readonly reason: CommitRejection };

export interface StoreCallOptions {
  readonly signal?: AbortSignal;
}

export interface Store {
  capabilities(): StoreCapabilities;
  createCapture(input: CreateCaptureInput, options?: StoreCallOptions): Promise<CreateCaptureResult>;
  readEntries(input: ReadEntriesInput, options?: StoreCallOptions): Promise<ReadEntriesResult>;
  readCaptures(input: ReadCapturesInput, options?: StoreCallOptions): Promise<readonly StoredCapture[]>;
  commitRestore(input: CommitRestoreInput, options?: StoreCallOptions): Promise<CommitRestoreResult>;
  revokeCapture(input: RevokeCaptureInput, options?: StoreCallOptions): Promise<RevokeCaptureResult>;
  inspectAttempt(input: InspectAttemptInput, options?: StoreCallOptions): Promise<InspectAttemptResult>;
  replaceCaptureKey(input: ReplaceCaptureKeyInput, options?: StoreCallOptions): Promise<ReplaceCaptureKeyResult>;
  deleteCiphertext(input: DeleteCiphertextInput, options?: StoreCallOptions): Promise<DeleteCiphertextResult>;
  sweepExpired(input: SweepInput, options?: StoreCallOptions): Promise<SweepResult>;
  recoveryState(input: { readonly namespace: string }, options?: StoreCallOptions): Promise<RecoveryState>;
  initializeNamespace(input: { readonly namespace: string; readonly epoch: number }, options?: StoreCallOptions): Promise<InitializeNamespaceResult>;
  quarantine(input: { readonly namespace: string }, options?: StoreCallOptions): Promise<RecoveryState>;
  invalidateRecovered(input: InvalidateRecoveredInput, options?: StoreCallOptions): Promise<InvalidateRecoveredResult>;
}

export interface KeyContext {
  readonly namespace: string;
  readonly tenant: string;
  readonly captureId: string;
}

export interface KeyCallOptions {
  readonly signal?: AbortSignal;
}

export interface DataKey extends StoredKey {
  /** 32 bytes. The caller overwrites it after use. */
  readonly plaintextKey: Uint8Array;
}

export interface KeyProvider {
  /** Profile identifier, for diagnostics and qualification records. Not secret. */
  readonly profile: string;
  generateDataKey(context: KeyContext, options?: KeyCallOptions): Promise<DataKey>;
  unwrapDataKey(input: StoredKey & { readonly context: KeyContext }, options?: KeyCallOptions): Promise<Uint8Array>;
  rewrapDataKey(input: StoredKey & { readonly context: KeyContext }, options?: KeyCallOptions): Promise<StoredKey>;
}

/** Everything authenticated but not encrypted for one entry (§3.4), from trusted scope and the row. */
export interface RecordBinding {
  readonly namespace: string;
  readonly tenant: string;
  readonly captureId: string;
  readonly entryId: string;
  readonly sessionId: string | null;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly maxUses: number;
}

/** Everything encrypted for one entry (§3.5). */
export interface RecordPayload {
  /** UTF-8 bytes. The caller decodes them only when the value is about to be returned, and overwrites them otherwise. */
  readonly value: Uint8Array;
  readonly type: string;
  readonly grants: readonly { readonly sink: string; readonly paths: readonly string[] }[];
  readonly policyRevision: string | null;
}

export interface SealCaptureInput {
  readonly context: KeyContext;
  readonly records: readonly { readonly binding: RecordBinding; readonly payload: RecordPayload }[];
}
export interface SealedCapture extends StoredKey {
  /** In the order of `records`. */
  readonly envelopes: readonly Uint8Array[];
}

export interface OpenCaptureInput extends StoredKey {
  readonly context: KeyContext;
  readonly records: readonly { readonly binding: RecordBinding; readonly envelope: Uint8Array }[];
}

export interface RecordCrypto {
  /** Profile identifier. Not secret. */
  readonly profile: string;
  sealCapture(input: SealCaptureInput, options?: KeyCallOptions): Promise<SealedCapture>;
  /** Payloads in the order of `records`. All of them, or an error: never a partial result. */
  openCapture(input: OpenCaptureInput, options?: KeyCallOptions): Promise<readonly RecordPayload[]>;
  rewrapCaptureKey(input: StoredKey & { readonly context: KeyContext }, options?: KeyCallOptions): Promise<StoredKey>;
}

export interface RevokeCaptureInput {
  readonly scope: StoreScope;
  readonly captureId: string;
  readonly now: number;
  /** How long past the capture's expiry (or past now, if later) the tombstone is kept. */
  readonly retentionMs: number;
  /** Write a fence when the capture does not exist. Only for an identifier the server itself issued. */
  readonly fenceAbsent: boolean;
}
export type RevokeCaptureResult =
  | { readonly outcome: "revoked" | "already-revoked"; readonly entries: number }
  | { readonly outcome: "not-found" }
  | { readonly outcome: "fenced" };

export interface InspectAttemptInput { readonly scope: StoreScope; readonly attemptId: string }
export type InspectAttemptResult =
  | { readonly state: "committed"; readonly requestDigest: Uint8Array; readonly committedAt: number }
  | { readonly state: "absent" };

export interface ReplaceCaptureKeyInput extends StoredKey {
  readonly scope: StoreScope;
  readonly captureId: string;
  readonly keyRevision: number;
}
export type ReplaceCaptureKeyResult =
  | { readonly outcome: "replaced"; readonly keyRevision: number }
  | { readonly outcome: "rejected"; readonly reason: "stale" | "unknown" | "revoked" | "expired" };

export interface DeleteCiphertextInput { readonly scope: StoreScope; readonly captureId: string; readonly now: number }
export type DeleteCiphertextResult =
  | { readonly outcome: "deleted"; readonly entries: number }
  | { readonly outcome: "rejected"; readonly reason: "live" | "not-found" | "clock-skew" };

export interface SweepInput { readonly namespace: string; readonly now: number; readonly limit: number }
export type SweepResult =
  | { readonly outcome: "swept"; readonly entries: number; readonly captures: number; readonly receipts: number; readonly more: boolean }
  | { readonly outcome: "rejected"; readonly reason: "clock-skew" };

export interface RecoveryState {
  /** 0 when the namespace has no recovery record. */
  readonly epoch: number;
  readonly state: "uninitialized" | "serving" | "quarantined";
}
export type InitializeNamespaceResult =
  | { readonly outcome: "initialized" }
  | { readonly outcome: "rejected"; readonly reason: "exists" | "not-empty" };
export interface InvalidateRecoveredInput { readonly namespace: string; readonly newEpoch: number }
export type InvalidateRecoveredResult =
  | { readonly outcome: "invalidated"; readonly recovery: RecoveryState }
  | { readonly outcome: "rejected"; readonly reason: "epoch-not-greater" | "uninitialized" };
