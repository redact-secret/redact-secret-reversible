/**
 * Mechanical validation shared by every store adapter and by the server
 * (docs/specs/persistent-vault.md §3.2, §4.2). These checks protect a
 * store's own invariants against a faulty caller. They are not authorization.
 */
import { StoreError } from "./errors.js";
import { LIMITS } from "./limits.js";
import type {
  CommitRestoreInput,
  CreateCaptureInput,
  DeleteCiphertextInput,
  InspectAttemptInput,
  InvalidateRecoveredInput,
  ReadCapturesInput,
  ReadEntriesInput,
  ReplaceCaptureKeyInput,
  RevokeCaptureInput,
  StoreCapabilities,
  StoreScope,
  SweepInput,
} from "./types.js";

const NAMESPACE = /^[A-Za-z0-9._:-]{1,128}$/;
const ATTEMPT_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const CAPTURE_ID = /^cap_[a-z2-7]{26}$/;
const ENTRY_ID = /^[0-9a-f]{64}$/;
const SESSION_TAG = /^[0-9a-f]{64}$/;

/** True when `text` has no lone surrogate. */
export function isWellFormed(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

export function isNamespace(value: unknown): value is string {
  return typeof value === "string" && NAMESPACE.test(value);
}

/** A tenant, session, sink, path, or principal identifier: 1 to 256 code units, well-formed. */
export function isIdentifier(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= LIMITS.identifierMaxLength &&
    isWellFormed(value)
  );
}

export function isCaptureId(value: unknown): value is string {
  return typeof value === "string" && CAPTURE_ID.test(value);
}

export function isEntryId(value: unknown): value is string {
  return typeof value === "string" && ENTRY_ID.test(value);
}

export function isAttemptId(value: unknown): value is string {
  return typeof value === "string" && ATTEMPT_ID.test(value);
}

export function isSessionTag(value: unknown): value is string {
  return typeof value === "string" && SESSION_TAG.test(value);
}

export function isTimestamp(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1;
}

function isBytes(value: unknown, min: number, max: number): value is Uint8Array {
  return value instanceof Uint8Array && value.byteLength >= min && value.byteLength <= max;
}

function utf8Length(text: string): number {
  let bytes = 0;
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit < 0x80) bytes += 1;
    else if (unit < 0x800) bytes += 2;
    else if (unit >= 0xd800 && unit <= 0xdbff) {
      bytes += 4;
      i += 1;
    } else bytes += 3;
  }
  return bytes;
}

export function isKeyRef(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    isWellFormed(value) &&
    utf8Length(value) <= LIMITS.keyRefMaxBytes
  );
}

function invalid(): never {
  throw new StoreError("STORE_INVALID_ARGUMENT");
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function checkScope(scope: unknown): asserts scope is StoreScope {
  if (!isObject(scope) || !isNamespace(scope.namespace) || !isIdentifier(scope.tenant)) invalid();
}

function checkStoredKey(input: { keyRef: unknown; wrappedKey: unknown }): void {
  if (!isKeyRef(input.keyRef) || !isBytes(input.wrappedKey, 1, LIMITS.wrappedKeyMaxBytes)) invalid();
}

/**
 * The capabilities a persistent server requires. Returns the names of the
 * ones a store lacks or declares out of range; an empty array means the
 * store may be used. Durability and restore detection are judged by the
 * caller, which may hold explicit opt-ins.
 */
export function missingCapabilities(capabilities: unknown): readonly string[] {
  if (!isObject(capabilities)) return ["capabilities"];
  const c = capabilities as Partial<StoreCapabilities>;
  const missing: string[] = [];
  if (c.contractVersion !== LIMITS.contractVersion) missing.push("contractVersion");
  for (const flag of [
    "atomicCreate",
    "atomicRestore",
    "authoritativeCommit",
    "revocationFences",
    "attemptReceipts",
    "storeClock",
  ] as const) {
    if (c[flag] !== true) missing.push(flag);
  }
  const bounded = (value: unknown, ceiling: number): boolean => isPositiveInteger(value) && value <= ceiling;
  if (!bounded(c.maxCreateEntries, LIMITS.maxCreateEntries)) missing.push("maxCreateEntries");
  if (!isPositiveInteger(c.maxCreateBytes)) missing.push("maxCreateBytes");
  if (!bounded(c.maxRestoreEntries, LIMITS.maxRestoreEntries)) missing.push("maxRestoreEntries");
  if (!bounded(c.maxRestoreCaptures, LIMITS.maxRestoreCaptures)) missing.push("maxRestoreCaptures");
  if (!bounded(c.maxEnvelopeBytes, LIMITS.maxEnvelopeBytes)) missing.push("maxEnvelopeBytes");
  if (!isTimestamp(c.maxClockSkewMs) || (c.maxClockSkewMs as number) > 60_000) missing.push("maxClockSkewMs");
  if (c.durability !== "volatile" && c.durability !== "durable") missing.push("durability");
  if (typeof c.crossProcess !== "boolean") missing.push("crossProcess");
  if (typeof c.restoreDetection !== "string" || c.restoreDetection.length === 0) missing.push("restoreDetection");
  if (typeof c.adapter !== "string" || typeof c.profile !== "string") missing.push("adapter");
  return missing;
}

export function validateCreateCapture(input: CreateCaptureInput, capabilities: StoreCapabilities): void {
  if (!isObject(input)) invalid();
  checkScope(input.scope);
  if (!isPositiveInteger(input.epoch) || !isTimestamp(input.now)) invalid();
  const capture = input.capture;
  if (!isObject(capture) || !isCaptureId(capture.captureId)) invalid();
  if (capture.sessionTag !== null && !isSessionTag(capture.sessionTag)) invalid();
  if (!isTimestamp(capture.createdAt) || !isTimestamp(capture.expiresAt)) invalid();
  const lifetime = capture.expiresAt - capture.createdAt;
  if (lifetime <= 0 || lifetime > LIMITS.maxCaptureLifetimeMs) invalid();
  if (capture.lookupVersion !== 1) invalid();
  checkStoredKey(capture);
  if (!Array.isArray(input.entries) || input.entries.length === 0) invalid();
  if (input.entries.length > capabilities.maxCreateEntries) throw new StoreError("STORE_CAPABILITY");
  const seen = new Set<string>();
  let bytes = 0;
  for (const entry of input.entries) {
    if (!isObject(entry) || !isEntryId(entry.entryId) || seen.has(entry.entryId)) invalid();
    seen.add(entry.entryId);
    if (!isPositiveInteger(entry.maxUses) || entry.maxUses > LIMITS.maxUses) invalid();
    if (!isBytes(entry.envelope, 1, LIMITS.maxEnvelopeBytes)) invalid();
    if (entry.envelope.byteLength > capabilities.maxEnvelopeBytes) throw new StoreError("STORE_CAPABILITY");
    bytes += entry.envelope.byteLength;
  }
  if (bytes > capabilities.maxCreateBytes) throw new StoreError("STORE_CAPABILITY");
}

export function validateReadEntries(input: ReadEntriesInput, capabilities: StoreCapabilities): void {
  if (!isObject(input)) invalid();
  checkScope(input.scope);
  if (!Array.isArray(input.entryIds) || input.entryIds.length === 0) invalid();
  if (input.entryIds.length > capabilities.maxRestoreEntries) throw new StoreError("STORE_CAPABILITY");
  const seen = new Set<string>();
  for (const id of input.entryIds) {
    if (!isEntryId(id) || seen.has(id)) invalid();
    seen.add(id);
  }
}

export function validateReadCaptures(input: ReadCapturesInput, capabilities: StoreCapabilities): void {
  if (!isObject(input)) invalid();
  checkScope(input.scope);
  if (!Array.isArray(input.captureIds) || input.captureIds.length === 0) invalid();
  if (input.captureIds.length > capabilities.maxRestoreCaptures) throw new StoreError("STORE_CAPABILITY");
  const seen = new Set<string>();
  for (const id of input.captureIds) {
    if (!isCaptureId(id) || seen.has(id)) invalid();
    seen.add(id);
  }
}

export function validateCommitRestore(input: CommitRestoreInput, capabilities: StoreCapabilities): void {
  if (!isObject(input)) invalid();
  checkScope(input.scope);
  if (!isPositiveInteger(input.epoch) || !isTimestamp(input.now) || !isTimestamp(input.receiptExpiresAt)) invalid();
  const attempt = input.attempt;
  if (!isObject(attempt) || !isAttemptId(attempt.attemptId)) invalid();
  if (!isBytes(attempt.requestDigest, LIMITS.requestDigestBytes, LIMITS.requestDigestBytes)) invalid();
  if (!Array.isArray(input.captures) || input.captures.length === 0) invalid();
  if (!Array.isArray(input.uses) || input.uses.length === 0) invalid();
  if (input.captures.length > capabilities.maxRestoreCaptures) throw new StoreError("STORE_CAPABILITY");
  if (input.uses.length > capabilities.maxRestoreEntries) throw new StoreError("STORE_CAPABILITY");
  const captures = new Set<string>();
  for (const capture of input.captures) {
    if (!isObject(capture) || !isCaptureId(capture.captureId) || captures.has(capture.captureId)) invalid();
    if (!isPositiveInteger(capture.generation)) invalid();
    captures.add(capture.captureId);
  }
  const entries = new Set<string>();
  const used = new Set<string>();
  for (const use of input.uses) {
    if (!isObject(use) || !isEntryId(use.entryId) || entries.has(use.entryId)) invalid();
    entries.add(use.entryId);
    if (!isCaptureId(use.captureId) || !captures.has(use.captureId)) invalid();
    used.add(use.captureId);
    if (!isPositiveInteger(use.count) || use.count > LIMITS.maxUses) invalid();
    if (!isPositiveInteger(use.lifecycleRevision) || !isPositiveInteger(use.ciphertextRevision)) invalid();
  }
  if (used.size !== captures.size) invalid();
}

export function validateRevokeCapture(input: RevokeCaptureInput): void {
  if (!isObject(input)) invalid();
  checkScope(input.scope);
  if (!isCaptureId(input.captureId) || !isTimestamp(input.now)) invalid();
  if (!isTimestamp(input.retentionMs) || input.retentionMs > LIMITS.maxRetentionMs) invalid();
  if (typeof input.fenceAbsent !== "boolean") invalid();
}

export function validateInspectAttempt(input: InspectAttemptInput): void {
  if (!isObject(input)) invalid();
  checkScope(input.scope);
  if (!isAttemptId(input.attemptId)) invalid();
}

export function validateReplaceCaptureKey(input: ReplaceCaptureKeyInput): void {
  if (!isObject(input)) invalid();
  checkScope(input.scope);
  if (!isCaptureId(input.captureId) || !isPositiveInteger(input.keyRevision)) invalid();
  checkStoredKey(input);
}

export function validateDeleteCiphertext(input: DeleteCiphertextInput): void {
  if (!isObject(input)) invalid();
  checkScope(input.scope);
  if (!isCaptureId(input.captureId) || !isTimestamp(input.now)) invalid();
}

export function validateSweep(input: SweepInput): void {
  if (!isObject(input) || !isNamespace(input.namespace) || !isTimestamp(input.now)) invalid();
  if (!isPositiveInteger(input.limit) || input.limit > LIMITS.maxSweepLimit) invalid();
}

export function validateNamespace(input: { readonly namespace: string }): void {
  if (!isObject(input) || !isNamespace(input.namespace)) invalid();
}

export function validateInitializeNamespace(input: { readonly namespace: string; readonly epoch: number }): void {
  validateNamespace(input);
  if (!isPositiveInteger(input.epoch)) invalid();
}

export function validateInvalidateRecovered(input: InvalidateRecoveredInput): void {
  validateNamespace(input);
  if (!isPositiveInteger(input.newEpoch)) invalid();
}
