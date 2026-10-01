import { VaultError } from "@redact-secret/vault";
import { openCapturePlanner, resolveCaptureLimits } from "@redact-secret/vault/internal/capture-plan";
import type { CapturePlan, CapturePlanner } from "@redact-secret/vault/internal/capture-plan";
import type { VaultLimits } from "@redact-secret/vault";
import {
  isAttemptId,
  isCaptureId,
  isEntryId,
  isIdentifier,
  isKeyRef,
  isNamespace,
  isSessionTag,
  isTimestamp,
  isWellFormed,
  KeyProviderError,
  LIMITS,
  missingCapabilities,
  RecordCryptoError,
  StoreError,
} from "@redact-secret/vault-contracts";
import type {
  CommitRestoreInput,
  ReadEntriesResult,
  RecordBinding,
  RecordCrypto,
  RecordPayload,
  Store,
  StoreCapabilities,
  StoreScope,
  StoredCapture,
  StoredEntry,
} from "@redact-secret/vault-contracts";

import { VaultServerError } from "../errors.js";
import type { ServerVaultErrorCode } from "../errors.js";
import { countMatches, MARKER_PATTERN, TOKEN_PATTERN } from "../token-pattern.js";
import type {
  PolicyDecision,
  Principal,
  PrincipalResolver,
  RestoreDecisionInput,
  ServerAuditEvent,
  ServerAuditHook,
  ServerDenialReason,
  ServerReleasePolicy,
} from "../types.js";
import { createDigester, deriveEntryId, equalBytes, equalTags } from "./digests.js";
import type { Digester, RequestDigestInput } from "./digests.js";
import type {
  DeleteCiphertextResult,
  LifecycleOperation,
  LifecyclePolicy,
  LifecycleRequest,
  PersistentCaptureOptions,
  PersistentCaptureResult,
  PersistentRestoreRequest,
  PersistentRestoreResult,
  PersistentServerVault,
  PersistentServerVaultOptions,
  ResolveAttemptRequest,
  ResolveAttemptResult,
  RevokeResult,
  SessionResolver,
} from "./types.js";

const DEFAULT_CALLBACK_TIMEOUT_MS = 5000;
const DEFAULT_STORE_TIMEOUT_MS = 10_000;
const DEFAULT_CRYPTO_TIMEOUT_MS = 15_000;
const DEFAULT_COMMIT_RETRIES = 3;
const MAX_COMMIT_RETRIES = 10;
const DEFAULT_RECEIPT_GRACE_MS = 60 * 60 * 1000;
const DEFAULT_TOMBSTONE_RETENTION_MS = 24 * 60 * 60 * 1000;
const MAX_TIMEOUT_MS = 10 * 60 * 1000;

/** Reasons a `ServerReleasePolicy` may return; anything else is `policy-evaluation-error`. */
const POLICY_DENIAL_REASONS: ReadonlySet<string> = new Set<ServerDenialReason>([
  "invalid-request",
  "malformed-token",
  "unknown-token",
  "source",
  "expired",
  "sink-or-path",
  "budget",
  "policy",
  "unauthenticated",
  "tenant-mismatch",
  "missing-purpose",
  "revoked",
  "stale-policy",
  "rate-limited",
  "policy-evaluation-error",
]);

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

class Timeout extends Error {}

/** How a store call failed, with nothing of the adapter's own error kept. */
class StoreFailure {
  readonly kind: "unavailable" | "ambiguous" | "invalid";
  constructor(kind: "unavailable" | "ambiguous" | "invalid") {
    this.kind = kind;
  }
}

function withTimeout<T>(value: T | Promise<T>, ms: number): Promise<T> {
  const settled = value instanceof Promise ? value : Promise.resolve(value);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Timeout()), ms);
  });
  return Promise.race([settled, deadline]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

function timeoutOption(value: number | undefined, fallback: number): number {
  const resolved = value ?? fallback;
  if (!Number.isFinite(resolved) || resolved <= 0 || resolved > MAX_TIMEOUT_MS) {
    throw new VaultServerError("INVALID_ARGUMENT");
  }
  return resolved;
}

function durationOption(value: number | undefined, fallback: number, ceiling: number): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 0 || resolved > ceiling) {
    throw new VaultServerError("INVALID_ARGUMENT");
  }
  return resolved;
}

function utf8Length(text: string): number {
  let bytes = 0;
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit < 0x80) bytes += 1;
    else if (unit < 0x800) bytes += 2;
    else if (unit >= 0xd800 && unit <= 0xdbff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        i += 1;
      } else bytes += 3;
    } else bytes += 3;
  }
  return bytes;
}

function newAttemptId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let out = "att_";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  bytes.fill(0);
  return out;
}

function wipe(payloads: readonly RecordPayload[]): void {
  for (const payload of payloads) {
    if (payload !== undefined && payload.value instanceof Uint8Array) payload.value.fill(0);
  }
}

interface Use {
  readonly token: string;
  readonly entryId: string;
  count: number;
  readonly paths: Map<string, number>;
}

interface Resolved {
  readonly principal: Principal;
  readonly tenant: string;
  readonly sessionId: string | null;
}

/**
 * Opens the persistent server profile of docs/specs/persistent-vault.md §8.2.
 *
 * Nothing here is a lock: every instance, in this process or another, may run
 * operations concurrently, and the store's transactions are the only thing
 * that orders them (§5.2, §7.1).
 */
export async function createPersistentServerVault<Context = unknown>(
  options: PersistentServerVaultOptions<Context>,
): Promise<PersistentServerVault<Context>> {
  if (typeof options !== "object" || options === null) throw new VaultServerError("INVALID_ARGUMENT");
  const { namespace, recoveryEpoch, store, crypto: recordCrypto } = options;
  if (!isNamespace(namespace)) throw new VaultServerError("INVALID_ARGUMENT");
  if (!Number.isSafeInteger(recoveryEpoch) || recoveryEpoch < 1) throw new VaultServerError("INVALID_ARGUMENT");
  if (typeof options.resolvePrincipal !== "function") throw new VaultServerError("INVALID_ARGUMENT");
  if (options.resolveSession !== undefined && typeof options.resolveSession !== "function") {
    throw new VaultServerError("INVALID_ARGUMENT");
  }
  if (typeof options.policy !== "function") throw new VaultServerError("INVALID_ARGUMENT");
  if (typeof options.lifecyclePolicy !== "function") throw new VaultServerError("INVALID_ARGUMENT");
  if (options.onAudit !== undefined && typeof options.onAudit !== "function") {
    throw new VaultServerError("INVALID_ARGUMENT");
  }
  if (
    options.policyRevision !== undefined &&
    typeof options.policyRevision !== "string" &&
    typeof options.policyRevision !== "function"
  ) {
    throw new VaultServerError("INVALID_ARGUMENT");
  }
  if (options.now !== undefined && typeof options.now !== "function") throw new VaultServerError("INVALID_ARGUMENT");

  for (const method of [
    "capabilities",
    "createCapture",
    "readEntries",
    "readCaptures",
    "commitRestore",
    "revokeCapture",
    "inspectAttempt",
    "deleteCiphertext",
    "recoveryState",
  ] as const) {
    if (typeof store !== "object" || store === null || typeof store[method] !== "function") {
      throw new VaultServerError("INVALID_ARGUMENT");
    }
  }
  if (
    typeof recordCrypto !== "object" ||
    recordCrypto === null ||
    typeof recordCrypto.sealCapture !== "function" ||
    typeof recordCrypto.openCapture !== "function"
  ) {
    throw new VaultServerError("INVALID_ARGUMENT");
  }

  // Digest key: required, or explicitly waived. Never defaulted.
  let digestKey: Uint8Array | null;
  if (options.digestKey !== undefined) {
    if (!(options.digestKey instanceof Uint8Array) || options.digestKey.byteLength !== 32) {
      throw new VaultServerError("INVALID_ARGUMENT");
    }
    if (options.allowUnkeyedDigests === true) throw new VaultServerError("INVALID_ARGUMENT");
    digestKey = options.digestKey;
  } else {
    if (options.allowUnkeyedDigests !== true) throw new VaultServerError("INVALID_ARGUMENT");
    digestKey = null;
  }

  const timeouts = {
    resolver: timeoutOption(options.resolverTimeoutMs, DEFAULT_CALLBACK_TIMEOUT_MS),
    policy: timeoutOption(options.policyTimeoutMs, DEFAULT_CALLBACK_TIMEOUT_MS),
    store: timeoutOption(options.storeTimeoutMs, DEFAULT_STORE_TIMEOUT_MS),
    crypto: timeoutOption(options.cryptoTimeoutMs, DEFAULT_CRYPTO_TIMEOUT_MS),
  };
  const maxCommitRetries = durationOption(options.maxCommitRetries, DEFAULT_COMMIT_RETRIES, MAX_COMMIT_RETRIES);
  const receiptGraceMs = durationOption(options.receiptGraceMs, DEFAULT_RECEIPT_GRACE_MS, LIMITS.maxCaptureLifetimeMs);
  const tombstoneRetentionMs = durationOption(
    options.tombstoneRetentionMs,
    DEFAULT_TOMBSTONE_RETENTION_MS,
    LIMITS.maxRetentionMs,
  );

  // Capabilities are read once and judged before anything else touches the store.
  let capabilities: StoreCapabilities;
  try {
    capabilities = Object.freeze({ ...store.capabilities() });
  } catch {
    throw new VaultServerError("UNSUPPORTED_STORE");
  }
  if (missingCapabilities(capabilities).length > 0) throw new VaultServerError("UNSUPPORTED_STORE");
  if ((capabilities.durability !== "durable" || !capabilities.crossProcess) && options.allowNonDurableStore !== true) {
    throw new VaultServerError("UNSUPPORTED_STORE");
  }
  if (
    capabilities.durability === "durable" &&
    capabilities.restoreDetection === "none" &&
    options.allowNoRestoreDetection !== true
  ) {
    throw new VaultServerError("UNSUPPORTED_STORE");
  }

  let limits: VaultLimits;
  let planner: CapturePlanner;
  try {
    limits = resolveCaptureLimits(options.limits);
    planner = await openCapturePlanner({
      ...(options.pii === undefined ? {} : { pii: options.pii }),
      ...(options.expectPiiActivation === undefined ? {} : { expectPiiActivation: options.expectPiiActivation }),
    });
  } catch (thrown) {
    if (thrown instanceof VaultError) {
      if (thrown.code === "INVALID_ARGUMENT") throw new VaultServerError("INVALID_ARGUMENT");
      throw new VaultServerError("VAULT_FAILURE", { vaultCode: thrown.code, coreCode: thrown.coreCode });
    }
    throw new VaultServerError("INVARIANT_VIOLATION");
  }
  if (limits.entryTtlMs > LIMITS.maxCaptureLifetimeMs) throw new VaultServerError("INVALID_ARGUMENT");

  const digester = await createDigester(digestKey);

  const vault = new PersistentServerVaultImpl<Context>({
    namespace,
    recoveryEpoch,
    store,
    recordCrypto,
    capabilities,
    limits,
    planner,
    digester,
    resolvePrincipal: options.resolvePrincipal,
    resolveSession: options.resolveSession,
    policy: options.policy,
    lifecyclePolicy: options.lifecyclePolicy,
    onAudit: options.onAudit,
    policyRevision: options.policyRevision,
    rawClock: options.now ?? Date.now,
    timeouts,
    maxCommitRetries,
    receiptGraceMs,
    tombstoneRetentionMs,
  });
  // Fail closed at creation when the namespace is not serving at the configured epoch.
  await vault.assertServing();
  return vault;
}

interface Internals<Context> {
  readonly namespace: string;
  readonly recoveryEpoch: number;
  readonly store: Store;
  readonly recordCrypto: RecordCrypto;
  readonly capabilities: StoreCapabilities;
  readonly limits: VaultLimits;
  readonly planner: CapturePlanner;
  readonly digester: Digester;
  readonly resolvePrincipal: PrincipalResolver<Context>;
  readonly resolveSession: SessionResolver<Context> | undefined;
  readonly policy: ServerReleasePolicy;
  readonly lifecyclePolicy: LifecyclePolicy;
  readonly onAudit: ServerAuditHook | undefined;
  readonly policyRevision: string | (() => string) | undefined;
  readonly rawClock: () => number;
  readonly timeouts: { readonly resolver: number; readonly policy: number; readonly store: number; readonly crypto: number };
  readonly maxCommitRetries: number;
  readonly receiptGraceMs: number;
  readonly tombstoneRetentionMs: number;
}

class PersistentServerVaultImpl<Context> implements PersistentServerVault<Context> {
  readonly #i: Internals<Context>;
  #latest = 0;
  #closed = false;

  constructor(internals: Internals<Context>) {
    this.#i = internals;
  }

  get namespace(): string {
    return this.#i.namespace;
  }

  get piiActivation(): string | null {
    return this.#i.planner.piiActivation;
  }

  get storeCapabilities(): StoreCapabilities {
    return this.#i.capabilities;
  }

  async close(): Promise<void> {
    this.#closed = true;
  }

  async assertServing(): Promise<void> {
    let state: { readonly epoch: number; readonly state: string };
    try {
      state = await this.#store(false, (signal) => this.#i.store.recoveryState({ namespace: this.#i.namespace }, { signal }));
    } catch {
      throw new VaultServerError("STORE_UNAVAILABLE");
    }
    if (typeof state !== "object" || state === null || state.state !== "serving" || state.epoch !== this.#i.recoveryEpoch) {
      throw new VaultServerError("STORE_QUARANTINED");
    }
  }

  // ---------------------------------------------------------------- capture

  async capture(input: string, options: PersistentCaptureOptions<Context>): Promise<PersistentCaptureResult> {
    this.#open();
    if (typeof input !== "string") throw new VaultServerError("INVALID_ARGUMENT");
    if (typeof options !== "object" || options === null) throw new VaultServerError("INVALID_ARGUMENT");
    const { context, requestId, ...captureOptions } = options;
    if (requestId !== undefined && typeof requestId !== "string") throw new VaultServerError("INVALID_ARGUMENT");
    const at = this.#now();
    const fail = (code: ServerVaultErrorCode, who?: Resolved, detail: { vaultCode?: VaultError["code"]; coreCode?: string | undefined } = {}): never => {
      this.#audit({
        operation: "capture",
        outcome: code === "LIFECYCLE_DENIED" ? "denied" : "failed",
        at,
        ...(who === undefined ? {} : { principalId: who.principal.id, tenant: who.tenant }),
        code,
        ...(requestId === undefined ? {} : { requestId }),
      });
      throw new VaultServerError(code, detail);
    };

    const who = await this.#resolve(context).catch(() => fail("LIFECYCLE_DENIED"));

    // The same capture gate the in-memory vault runs: block rejects, warn and
    // allow pass through only when asked, PII needs its exact-type allowlist.
    let plan: CapturePlan;
    try {
      plan = this.#i.planner.plan(input, captureOptions, this.#i.limits);
    } catch (thrown) {
      if (thrown instanceof VaultError) return fail("VAULT_FAILURE", who, { vaultCode: thrown.code, coreCode: thrown.coreCode });
      return fail("INVARIANT_VIOLATION", who);
    }

    const captureId = this.#i.planner.newCaptureId();
    if (!isCaptureId(captureId)) return fail("INVARIANT_VIOLATION", who);
    const expiresAt = at + this.#i.limits.entryTtlMs;
    const { capabilities } = this.#i;
    if (plan.retained.length > capabilities.maxCreateEntries) return fail("LIMIT_EXCEEDED", who);

    // Values are sliced from the caller's own input; the plan carries ranges only.
    const values: Uint8Array[] = [];
    let bytes = 0;
    for (const entry of plan.retained) {
      const value = input.slice(entry.start, entry.end);
      if (!isWellFormed(value)) {
        wipeBytes(values);
        return fail("INVALID_ARGUMENT", who);
      }
      const encoded = encoder.encode(value);
      values.push(encoded);
      bytes += encoded.byteLength;
    }

    try {
      await this.#lifecycle({
        operation: "capture",
        principal: who.principal,
        tenant: who.tenant,
        sessionId: who.sessionId,
        entries: plan.retained.length,
        bytes,
        requestedAt: at,
      });
    } catch {
      wipeBytes(values);
      return fail("LIFECYCLE_DENIED", who);
    }

    const result = (): PersistentCaptureResult =>
      Object.freeze({
        captureId,
        text: plan.text,
        tokens: Object.freeze(plan.retained.map((entry) => Object.freeze({ token: entry.token, type: entry.type }))),
        passedThrough: plan.passedThrough,
        passedThroughTypes: plan.passedThroughTypes,
        unrestorable: plan.unrestorable,
        expiresAt,
        tenant: who.tenant,
        sessionBound: plan.retained.length > 0 && who.sessionId !== null,
      });

    // A capture that retains nothing has nothing to store or revoke (§5.3).
    if (plan.retained.length === 0) {
      this.#audit({ operation: "capture", outcome: "committed", at, principalId: who.principal.id, tenant: who.tenant, entries: 0, ...(requestId === undefined ? {} : { requestId }) });
      return result();
    }

    const scope: StoreScope = { namespace: this.#i.namespace, tenant: who.tenant };
    const context_ = { namespace: this.#i.namespace, tenant: who.tenant, captureId };
    const revision = typeof this.#i.policyRevision === "function" ? this.#policyRevision() : (this.#i.policyRevision ?? null);

    let sealed: Awaited<ReturnType<RecordCrypto["sealCapture"]>>;
    let entryIds: string[];
    let sessionTag: string | null;
    try {
      entryIds = await Promise.all(plan.retained.map((entry) => deriveEntryId(this.#i.namespace, who.tenant, entry.token)));
      sessionTag =
        who.sessionId === null
          ? null
          : await this.#i.digester.sessionTag({ namespace: this.#i.namespace, tenant: who.tenant, captureId, sessionId: who.sessionId });
      const records = plan.retained.map((entry, index) => ({
        binding: {
          namespace: this.#i.namespace,
          tenant: who.tenant,
          captureId,
          entryId: entryIds[index] as string,
          sessionId: who.sessionId,
          createdAt: at,
          expiresAt,
          maxUses: plan.maxUses,
        } satisfies RecordBinding,
        payload: {
          value: values[index] as Uint8Array,
          type: entry.type,
          grants: plan.grants,
          policyRevision: revision,
        } satisfies RecordPayload,
      }));
      sealed = await this.#crypto((signal) => this.#i.recordCrypto.sealCapture({ context: context_, records }, { signal }));
    } catch (thrown) {
      if (thrown instanceof RecordCryptoError && thrown.code === "RECORD_LIMIT") return fail("LIMIT_EXCEEDED", who);
      if (thrown instanceof RecordCryptoError) return fail("INVARIANT_VIOLATION", who);
      return fail("KEY_UNAVAILABLE", who);
    } finally {
      wipeBytes(values);
    }

    // Never trust the injected crypto layer's shape with the store's bounds.
    if (
      typeof sealed !== "object" ||
      sealed === null ||
      !isKeyRef(sealed.keyRef) ||
      !(sealed.wrappedKey instanceof Uint8Array) ||
      sealed.wrappedKey.byteLength === 0 ||
      sealed.wrappedKey.byteLength > LIMITS.wrappedKeyMaxBytes ||
      !Array.isArray(sealed.envelopes) ||
      sealed.envelopes.length !== plan.retained.length
    ) {
      return fail("INVARIANT_VIOLATION", who);
    }
    let envelopeBytes = 0;
    for (const envelope of sealed.envelopes) {
      if (!(envelope instanceof Uint8Array) || envelope.byteLength === 0) return fail("INVARIANT_VIOLATION", who);
      if (envelope.byteLength > capabilities.maxEnvelopeBytes) return fail("LIMIT_EXCEEDED", who);
      envelopeBytes += envelope.byteLength;
    }
    if (envelopeBytes > capabilities.maxCreateBytes) return fail("LIMIT_EXCEEDED", who);

    let created: Awaited<ReturnType<Store["createCapture"]>>;
    try {
      created = await this.#store(true, (signal) =>
        this.#i.store.createCapture(
          {
            scope,
            epoch: this.#i.recoveryEpoch,
            now: this.#now(),
            capture: {
              captureId,
              sessionTag,
              createdAt: at,
              expiresAt,
              lookupVersion: 1,
              keyRef: sealed.keyRef,
              wrappedKey: sealed.wrappedKey,
            },
            entries: sealed.envelopes.map((envelope, index) => ({
              entryId: entryIds[index] as string,
              maxUses: plan.maxUses,
              envelope,
            })),
          },
          { signal },
        ),
      );
    } catch (thrown) {
      if (thrown instanceof StoreFailure && thrown.kind === "ambiguous") {
        // The capture may exist. No token left this call, so it is unusable
        // either way; a fence makes that durable. One attempt, never awaited
        // into the caller's outcome.
        await this.#store(true, (signal) =>
          this.#i.store.revokeCapture(
            { scope, captureId, now: this.#now(), retentionMs: this.#i.tombstoneRetentionMs, fenceAbsent: true },
            { signal },
          ),
        ).catch(() => undefined);
        return fail("STORE_UNAVAILABLE", who);
      }
      if (thrown instanceof StoreFailure && thrown.kind === "invalid") return fail("INVARIANT_VIOLATION", who);
      return fail("STORE_UNAVAILABLE", who);
    }

    if (typeof created !== "object" || created === null) return fail("INVARIANT_VIOLATION", who);
    if (created.outcome !== "created") {
      const reason = created.outcome === "rejected" ? created.reason : undefined;
      if (reason === "quarantined") return fail("STORE_QUARANTINED", who);
      if (reason === "clock-skew") return fail("CLOCK_SKEW", who);
      if (reason === "stale") return fail("STORE_UNAVAILABLE", who);
      return fail("INVARIANT_VIOLATION", who);
    }

    this.#audit({
      operation: "capture",
      outcome: "committed",
      at,
      principalId: who.principal.id,
      tenant: who.tenant,
      entries: plan.retained.length,
      captureId,
      ...(requestId === undefined ? {} : { requestId }),
    });
    return result();
  }

  // ---------------------------------------------------------------- restore

  async restore(request: PersistentRestoreRequest<Context>): Promise<PersistentRestoreResult> {
    this.#open();
    const parsed = this.#parseRestore(request);
    const { sink, purpose, requestId } = parsed;
    const at = this.#now();
    const attemptId = parsed.attemptId ?? newAttemptId();

    let who: Resolved | undefined;
    const deny = (reason: ServerDenialReason): never => {
      this.#audit({
        operation: reason === "unauthenticated" ? "resolve-principal" : reason === "policy-evaluation-error" ? "policy-error" : "restore",
        outcome: reason === "policy-evaluation-error" ? "failed" : "denied",
        at,
        ...(who === undefined ? {} : { principalId: who.principal.id, tenant: who.tenant }),
        sink,
        purpose,
        reason,
        attemptId,
        ...(requestId === undefined ? {} : { requestId }),
      });
      throw new VaultServerError("RESTORE_DENIED", { reason });
    };
    const fail = (code: ServerVaultErrorCode): never => {
      this.#audit({
        operation: "restore",
        outcome: "failed",
        at,
        ...(who === undefined ? {} : { principalId: who.principal.id, tenant: who.tenant }),
        sink,
        purpose,
        code,
        attemptId,
        ...(requestId === undefined ? {} : { requestId }),
      });
      throw new VaultServerError(code, code === "COMMIT_AMBIGUOUS" ? { attemptId } : {});
    };

    if (parsed.invalid) return deny("invalid-request");

    // Step 2: principal and session, from trusted context only.
    who = await this.#resolve(parsed.context).catch(() => deny("unauthenticated"));
    const resolved = who as Resolved;

    if (parsed.malformed) return deny("malformed-token");
    if (purpose.length === 0) return deny("missing-purpose");

    // Step 3: nothing to restore. No store call, no attempt.
    if (parsed.uses.size === 0) {
      const fields: Record<string, string> = {};
      for (const [path, text] of parsed.snapshot) Object.defineProperty(fields, path, { value: text, enumerable: true, writable: false });
      this.#audit({ operation: "restore", outcome: "committed", at, principalId: resolved.principal.id, tenant: resolved.tenant, sink, purpose, entries: 0, ...(requestId === undefined ? {} : { requestId }) });
      return Object.freeze({ fields: Object.freeze(fields), restored: 0, principalId: resolved.principal.id, tenant: resolved.tenant });
    }
    if (parsed.uses.size > this.#i.capabilities.maxRestoreEntries) return deny("invalid-request");

    const scope: StoreScope = { namespace: this.#i.namespace, tenant: resolved.tenant };
    const uses = new Map<string, Use>();
    for (const [token, use] of parsed.uses) {
      const entryId = await deriveEntryId(this.#i.namespace, resolved.tenant, token);
      uses.set(entryId, { token, entryId, count: use.count, paths: use.paths });
    }
    let requestDigest: Uint8Array;
    try {
      requestDigest = await this.#i.digester.requestDigest(this.#digestInput(resolved, parsed, uses));
    } catch {
      return deny("invalid-request");
    }

    for (let round = 0; ; round += 1) {
      const outcome = await this.#restoreOnce({ parsed, resolved, scope, uses, requestDigest, attemptId, at, deny, fail });
      if (outcome !== "stale") {
        this.#audit({
          operation: "restore",
          outcome: "committed",
          at,
          principalId: resolved.principal.id,
          tenant: resolved.tenant,
          sink,
          purpose,
          entries: uses.size,
          attemptId,
          ...(requestId === undefined ? {} : { requestId }),
        });
        return outcome;
      }
      if (round >= this.#i.maxCommitRetries) return fail("RESTORE_CONFLICT");
    }
  }

  /** Steps 4 to 10 of specification §7.2: one read, one evaluation, one commit. */
  async #restoreOnce(input: {
    readonly parsed: ParsedRestore<Context>;
    readonly resolved: Resolved;
    readonly scope: StoreScope;
    readonly uses: ReadonlyMap<string, Use>;
    readonly requestDigest: Uint8Array;
    readonly attemptId: string;
    readonly at: number;
    readonly deny: (reason: ServerDenialReason) => never;
    readonly fail: (code: ServerVaultErrorCode) => never;
  }): Promise<PersistentRestoreResult | "stale"> {
    const { parsed, resolved, scope, uses, requestDigest, attemptId, deny, fail } = input;
    const { sink, purpose } = parsed;
    const now = this.#now();

    // Step 4: bounded read. It authorizes nothing; the commit checks again.
    let read: ReadEntriesResult;
    try {
      read = await this.#store(false, (signal) => this.#i.store.readEntries({ scope, entryIds: [...uses.keys()] }, { signal }));
    } catch (thrown) {
      return fail(thrown instanceof StoreFailure && thrown.kind === "invalid" ? "INVARIANT_VIOLATION" : "STORE_UNAVAILABLE");
    }
    const view = inspectRead(read, uses);
    if (view === undefined) return fail("INVARIANT_VIOLATION");
    if (view.recovery.state !== "serving" || view.recovery.epoch !== this.#i.recoveryEpoch) return fail("STORE_QUARANTINED");

    for (const use of uses.values()) {
      if (!view.entries.has(use.entryId)) return deny("unknown-token");
    }
    for (const capture of view.captures.values()) {
      if (capture.state !== "live") return deny("revoked");
    }
    for (const capture of view.captures.values()) {
      if (!parsed.sources.has(capture.captureId)) return deny("source");
    }
    // Session: checked on the keyed tag, before any key is unwrapped.
    for (const capture of view.captures.values()) {
      if (capture.sessionTag === null) continue;
      if (resolved.sessionId === null) return deny("source");
      const expected = await this.#i.digester.sessionTag({
        namespace: this.#i.namespace,
        tenant: resolved.tenant,
        captureId: capture.captureId,
        sessionId: resolved.sessionId,
      });
      if (!equalTags(expected, capture.sessionTag)) return deny("source");
    }
    for (const capture of view.captures.values()) {
      if (now >= capture.expiresAt) return deny("expired");
    }
    for (const use of uses.values()) {
      const entry = view.entries.get(use.entryId) as StoredEntry;
      if (entry.used + use.count > entry.maxUses) return deny("budget");
    }

    // Step 5: one unwrap per capture; every entry authenticated against the
    // binding rebuilt from trusted scope. All of them, or a denial.
    const opened = new Map<string, RecordPayload>();
    const release = (): void => wipe([...opened.values()]);
    try {
      const byCapture = new Map<string, StoredEntry[]>();
      for (const use of uses.values()) {
        const entry = view.entries.get(use.entryId) as StoredEntry;
        const list = byCapture.get(entry.captureId) ?? [];
        list.push(entry);
        byCapture.set(entry.captureId, list);
      }
      try {
        await this.#crypto(async (signal) => {
          for (const [captureId, entries] of byCapture) {
            const capture = view.captures.get(captureId) as StoredCapture;
            const payloads = await this.#i.recordCrypto.openCapture(
              {
                context: { namespace: this.#i.namespace, tenant: resolved.tenant, captureId },
                keyRef: capture.keyRef,
                wrappedKey: capture.wrappedKey,
                records: entries.map((entry) => ({
                  binding: {
                    namespace: this.#i.namespace,
                    tenant: resolved.tenant,
                    captureId,
                    entryId: entry.entryId,
                    sessionId: capture.sessionTag === null ? null : resolved.sessionId,
                    createdAt: capture.createdAt,
                    expiresAt: capture.expiresAt,
                    maxUses: entry.maxUses,
                  },
                  envelope: entry.envelope,
                })),
              },
              { signal },
            );
            if (!Array.isArray(payloads) || payloads.length !== entries.length) throw new RecordCryptoError("RECORD_MALFORMED");
            entries.forEach((entry, index) => {
              const payload = payloads[index] as RecordPayload;
              if (!isPayload(payload)) throw new RecordCryptoError("RECORD_MALFORMED");
              opened.set(entry.entryId, payload);
            });
          }
        });
      } catch (thrown) {
        if (thrown instanceof KeyProviderError && thrown.code !== "KEY_INTEGRITY") return deny("key-unavailable");
        if (thrown instanceof KeyProviderError || thrown instanceof RecordCryptoError) return deny("integrity-failure");
        return deny("key-unavailable");
      }

      // Step 6: grants, from the authenticated record.
      for (const use of uses.values()) {
        const payload = opened.get(use.entryId) as RecordPayload;
        const grant = payload.grants.find((candidate) => candidate.sink === sink);
        for (const path of use.paths.keys()) {
          if (grant === undefined || !grant.paths.includes(path)) return deny("sink-or-path");
        }
      }

      // Step 7: the application's policy, fresh for every entry and path,
      // outside any store transaction.
      const revisionBefore = typeof this.#i.policyRevision === "function" ? this.#policyRevision() : undefined;
      for (const use of uses.values()) {
        const entry = view.entries.get(use.entryId) as StoredEntry;
        const capture = view.captures.get(entry.captureId) as StoredCapture;
        const payload = opened.get(use.entryId) as RecordPayload;
        for (const [path, occurrences] of use.paths) {
          const decisionInput: RestoreDecisionInput = Object.freeze({
            principal: resolved.principal,
            tenant: resolved.tenant,
            source: Object.freeze({
              captureId: capture.captureId,
              issuedTenant: resolved.tenant,
              ...(capture.sessionTag === null || resolved.sessionId === null ? {} : { sessionId: resolved.sessionId }),
            }),
            sink,
            path,
            purpose,
            type: payload.type,
            occurrences,
            totalOccurrences: use.count,
            used: entry.used,
            maxUses: entry.maxUses,
            ...(payload.policyRevision === null ? {} : { policyRevision: payload.policyRevision }),
            requestedAt: now,
          });
          let decision: PolicyDecision;
          try {
            decision = await withTimeout(this.#i.policy(decisionInput), this.#i.timeouts.policy);
          } catch {
            return deny("policy-evaluation-error");
          }
          if (typeof decision !== "object" || decision === null || typeof decision.allow !== "boolean") {
            return deny("policy-evaluation-error");
          }
          if (!decision.allow) {
            const reason = (decision as { reason?: unknown }).reason;
            return deny(typeof reason === "string" && POLICY_DENIAL_REASONS.has(reason) ? (reason as ServerDenialReason) : "policy-evaluation-error");
          }
        }
      }
      // §7.4: narrow, not close, the window between policy and commit.
      if (revisionBefore !== undefined && this.#policyRevision() !== revisionBefore) return deny("stale-policy");

      // Step 8: values become strings only now, when they are about to be returned.
      const values = new Map<string, string>();
      try {
        for (const use of uses.values()) values.set(use.token, decoder.decode((opened.get(use.entryId) as RecordPayload).value));
      } catch {
        return deny("integrity-failure");
      }
      const staged: Record<string, string> = {};
      let restored = 0;
      for (const [path, text] of parsed.snapshot) {
        TOKEN_PATTERN.lastIndex = 0;
        const replaced = text.replace(TOKEN_PATTERN, (token) => {
          restored += 1;
          return values.get(token) as string;
        });
        TOKEN_PATTERN.lastIndex = 0;
        Object.defineProperty(staged, path, { value: replaced, enumerable: true, writable: false });
      }

      // Step 9: the one transaction that consumes every use and records the attempt.
      let latestExpiry = 0;
      for (const capture of view.captures.values()) latestExpiry = Math.max(latestExpiry, capture.expiresAt);
      const commit: CommitRestoreInput = {
        scope,
        epoch: this.#i.recoveryEpoch,
        now: this.#now(),
        attempt: { attemptId, requestDigest },
        receiptExpiresAt: latestExpiry + this.#i.capabilities.maxClockSkewMs + this.#i.receiptGraceMs,
        captures: [...view.captures.values()].map((capture) => ({ captureId: capture.captureId, generation: capture.generation })),
        uses: [...uses.values()].map((use) => {
          const entry = view.entries.get(use.entryId) as StoredEntry;
          return {
            entryId: use.entryId,
            captureId: entry.captureId,
            count: use.count,
            lifecycleRevision: entry.lifecycleRevision,
            ciphertextRevision: entry.ciphertextRevision,
          };
        }),
      };
      let committed: Awaited<ReturnType<Store["commitRestore"]>>;
      try {
        committed = await this.#store(true, (signal) => this.#i.store.commitRestore(commit, { signal }));
      } catch (thrown) {
        if (thrown instanceof StoreFailure && thrown.kind === "unavailable") return fail("STORE_UNAVAILABLE");
        if (thrown instanceof StoreFailure && thrown.kind === "invalid") return fail("INVARIANT_VIOLATION");
        // Unknown outcome: release nothing, retry nothing (§7.3).
        return fail("COMMIT_AMBIGUOUS");
      }

      // Step 10: fields leave only on a definitive commit.
      const outcome = typeof committed === "object" && committed !== null ? committed.outcome : undefined;
      if (outcome === "committed") {
        return Object.freeze({
          fields: Object.freeze(staged),
          restored,
          principalId: resolved.principal.id,
          tenant: resolved.tenant,
          attemptId,
        });
      }
      if (outcome === "already-committed") return deny("attempt-already-committed");
      if (outcome === "attempt-mismatch") return deny("attempt-mismatch");
      if (outcome === "rejected") {
        const reason = (committed as { reason?: unknown }).reason;
        if (reason === "stale") return "stale";
        if (reason === "revoked") return deny("revoked");
        if (reason === "expired") return deny("expired");
        if (reason === "budget") return deny("budget");
        if (reason === "unknown") return deny("unknown-token");
        if (reason === "clock-skew") return fail("CLOCK_SKEW");
        if (reason === "quarantined") return fail("STORE_QUARANTINED");
      }
      // A result this server cannot interpret is not a commit.
      return fail("COMMIT_AMBIGUOUS");
    } finally {
      release();
    }
  }

  // -------------------------------------------------------------- lifecycle

  async revoke(request: LifecycleRequest<Context>): Promise<RevokeResult> {
    this.#open();
    const { who, capture, scope, at, fail, done } = await this.#lifecycleStart("revoke", request);
    if (capture === undefined) return done({ outcome: "not-found", entries: 0 }, 0);
    const result = await this.#revokeInStore(scope, request.captureId, () => fail("STORE_UNAVAILABLE", who));
    if (result === undefined) return fail("INVARIANT_VIOLATION", who);
    void at;
    return done(result, result.entries);
  }

  async deleteCaptureCiphertext(request: LifecycleRequest<Context>): Promise<DeleteCiphertextResult> {
    this.#open();
    const { who, capture, scope, fail, done } = await this.#lifecycleStart("delete-ciphertext", request);
    if (capture === undefined) return done({ outcome: "not-found", entries: 0, keyRetired: false }, 0);
    const revoked = await this.#revokeInStore(scope, request.captureId, () => fail("STORE_UNAVAILABLE", who));
    if (revoked === undefined) return fail("INVARIANT_VIOLATION", who);
    if (revoked.outcome === "not-found") return done({ outcome: "not-found", entries: 0, keyRetired: false }, 0);
    let deleted: Awaited<ReturnType<Store["deleteCiphertext"]>>;
    try {
      deleted = await this.#store(true, (signal) =>
        this.#i.store.deleteCiphertext({ scope, captureId: request.captureId, now: this.#now() }, { signal }),
      );
    } catch (thrown) {
      return fail(thrown instanceof StoreFailure && thrown.kind === "invalid" ? "INVARIANT_VIOLATION" : "STORE_UNAVAILABLE", who);
    }
    if (typeof deleted !== "object" || deleted === null) return fail("INVARIANT_VIOLATION", who);
    if (deleted.outcome === "deleted" && Number.isSafeInteger(deleted.entries) && deleted.entries >= 0) {
      return done({ outcome: "deleted", entries: deleted.entries, keyRetired: false }, deleted.entries);
    }
    if (deleted.outcome === "rejected" && deleted.reason === "not-found") {
      return done({ outcome: "not-found", entries: 0, keyRetired: false }, 0);
    }
    if (deleted.outcome === "rejected" && deleted.reason === "clock-skew") return fail("CLOCK_SKEW", who);
    // "live" after a successful revoke means the store contradicted itself.
    return fail("INVARIANT_VIOLATION", who);
  }

  async resolveAttempt(request: ResolveAttemptRequest<Context>): Promise<ResolveAttemptResult> {
    this.#open();
    const parsed = this.#parseRestore(request);
    if (parsed.attemptId === undefined || parsed.invalid || parsed.malformed) throw new VaultServerError("INVALID_ARGUMENT");
    const at = this.#now();
    const { requestId } = parsed;
    let who: Resolved | undefined;
    const fail = (code: ServerVaultErrorCode): never => {
      this.#audit({
        operation: "resolve-attempt",
        outcome: code === "LIFECYCLE_DENIED" ? "denied" : "failed",
        at,
        ...(who === undefined ? {} : { principalId: who.principal.id, tenant: who.tenant }),
        code,
        attemptId: parsed.attemptId as string,
        ...(requestId === undefined ? {} : { requestId }),
      });
      throw new VaultServerError(code);
    };
    who = await this.#resolve(parsed.context).catch(() => fail("LIFECYCLE_DENIED"));
    const resolved = who as Resolved;
    try {
      await this.#lifecycle({
        operation: "resolve-attempt",
        principal: resolved.principal,
        tenant: resolved.tenant,
        sessionId: resolved.sessionId,
        requestedAt: at,
      });
    } catch {
      return fail("LIFECYCLE_DENIED");
    }
    const uses = new Map<string, Use>();
    for (const [token, use] of parsed.uses) {
      const entryId = await deriveEntryId(this.#i.namespace, resolved.tenant, token);
      uses.set(entryId, { token, entryId, count: use.count, paths: use.paths });
    }
    let digest: Uint8Array;
    try {
      digest = await this.#i.digester.requestDigest(this.#digestInput(resolved, parsed, uses));
    } catch {
      throw new VaultServerError("INVALID_ARGUMENT");
    }
    let inspected: Awaited<ReturnType<Store["inspectAttempt"]>>;
    try {
      inspected = await this.#store(false, (signal) =>
        this.#i.store.inspectAttempt(
          { scope: { namespace: this.#i.namespace, tenant: resolved.tenant }, attemptId: parsed.attemptId as string },
          { signal },
        ),
      );
    } catch (thrown) {
      return fail(thrown instanceof StoreFailure && thrown.kind === "invalid" ? "INVARIANT_VIOLATION" : "STORE_UNAVAILABLE");
    }
    let result: ResolveAttemptResult;
    if (typeof inspected !== "object" || inspected === null) return fail("INVARIANT_VIOLATION");
    if (inspected.state === "absent") result = Object.freeze({ state: "absent" });
    else if (
      inspected.state === "committed" &&
      inspected.requestDigest instanceof Uint8Array &&
      isTimestamp(inspected.committedAt)
    ) {
      result = equalBytes(inspected.requestDigest, digest)
        ? Object.freeze({ state: "committed", committedAt: inspected.committedAt })
        : Object.freeze({ state: "attempt-mismatch" });
    } else return fail("INVARIANT_VIOLATION");
    this.#audit({
      operation: "resolve-attempt",
      outcome: "committed",
      at,
      principalId: resolved.principal.id,
      tenant: resolved.tenant,
      attemptId: parsed.attemptId,
      ...(requestId === undefined ? {} : { requestId }),
    });
    return result;
  }

  /** Shared start of `revoke` and `deleteCaptureCiphertext`: resolve, read the capture, check its session, ask the policy. */
  async #lifecycleStart(operation: "revoke" | "delete-ciphertext", request: LifecycleRequest<Context>) {
    if (typeof request !== "object" || request === null) throw new VaultServerError("INVALID_ARGUMENT");
    const { context, captureId, requestId } = request;
    if (!isCaptureId(captureId)) throw new VaultServerError("INVALID_ARGUMENT");
    if (requestId !== undefined && typeof requestId !== "string") throw new VaultServerError("INVALID_ARGUMENT");
    const at = this.#now();
    const fail = (code: ServerVaultErrorCode, who?: Resolved): never => {
      this.#audit({
        operation,
        outcome: code === "LIFECYCLE_DENIED" ? "denied" : "failed",
        at,
        ...(who === undefined ? {} : { principalId: who.principal.id, tenant: who.tenant }),
        code,
        captureId,
        ...(requestId === undefined ? {} : { requestId }),
      });
      throw new VaultServerError(code);
    };
    const who = await this.#resolve(context).catch(() => fail("LIFECYCLE_DENIED"));
    const scope: StoreScope = { namespace: this.#i.namespace, tenant: who.tenant };
    const done = <T extends object>(result: T, entries: number): T => {
      this.#audit({
        operation,
        outcome: "committed",
        at,
        principalId: who.principal.id,
        tenant: who.tenant,
        entries,
        captureId,
        ...(requestId === undefined ? {} : { requestId }),
      });
      return Object.freeze(result);
    };

    let captures: readonly StoredCapture[];
    try {
      captures = await this.#store(false, (signal) => this.#i.store.readCaptures({ scope, captureIds: [captureId] }, { signal }));
    } catch (thrown) {
      return fail(thrown instanceof StoreFailure && thrown.kind === "invalid" ? "INVARIANT_VIOLATION" : "STORE_UNAVAILABLE", who);
    }
    if (!Array.isArray(captures) || captures.length > 1) return fail("INVARIANT_VIOLATION", who);
    const capture = captures[0] as StoredCapture | undefined;
    if (capture !== undefined) {
      if (typeof capture !== "object" || capture === null || capture.captureId !== captureId) return fail("INVARIANT_VIOLATION", who);
      if (capture.sessionTag !== null && !isSessionTag(capture.sessionTag)) return fail("INVARIANT_VIOLATION", who);
      // A session-bound capture is managed only from its own session.
      if (capture.sessionTag !== null) {
        if (who.sessionId === null) return fail("LIFECYCLE_DENIED", who);
        const expected = await this.#i.digester.sessionTag({
          namespace: this.#i.namespace,
          tenant: who.tenant,
          captureId,
          sessionId: who.sessionId,
        });
        if (!equalTags(expected, capture.sessionTag)) return fail("LIFECYCLE_DENIED", who);
      }
    }
    try {
      await this.#lifecycle({
        operation,
        principal: who.principal,
        tenant: who.tenant,
        sessionId: who.sessionId,
        captureId,
        ...(capture === undefined ? {} : { sessionBound: capture.sessionTag !== null }),
        requestedAt: at,
      });
    } catch {
      return fail("LIFECYCLE_DENIED", who);
    }
    return { who, capture, scope, at, fail, done };
  }

  /** Revocation is idempotent, so an unknown outcome is reported as unavailable and the caller retries. */
  async #revokeInStore(scope: StoreScope, captureId: string, unavailable: () => never): Promise<RevokeResult | undefined> {
    let result: Awaited<ReturnType<Store["revokeCapture"]>>;
    try {
      result = await this.#store(true, (signal) =>
        this.#i.store.revokeCapture(
          { scope, captureId, now: this.#now(), retentionMs: this.#i.tombstoneRetentionMs, fenceAbsent: false },
          { signal },
        ),
      );
    } catch (thrown) {
      if (thrown instanceof StoreFailure && thrown.kind === "invalid") return undefined;
      return unavailable();
    }
    if (typeof result !== "object" || result === null) return undefined;
    if (result.outcome === "not-found") return { outcome: "not-found", entries: 0 };
    if (
      (result.outcome === "revoked" || result.outcome === "already-revoked") &&
      Number.isSafeInteger(result.entries) &&
      result.entries >= 0
    ) {
      return { outcome: result.outcome, entries: result.entries };
    }
    return undefined;
  }

  // ---------------------------------------------------------------- helpers

  #open(): void {
    if (this.#closed) throw new VaultServerError("CLOSED");
  }

  /** Integer milliseconds, never decreasing within this instance. */
  #now(): number {
    let value: unknown;
    try {
      value = this.#i.rawClock();
    } catch {
      throw new VaultServerError("INVALID_ARGUMENT");
    }
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > LIMITS.maxTimestamp) {
      throw new VaultServerError("INVALID_ARGUMENT");
    }
    this.#latest = Math.max(this.#latest, Math.floor(value));
    return this.#latest;
  }

  #policyRevision(): string | null {
    const source = this.#i.policyRevision;
    if (source === undefined) return null;
    let value: unknown;
    try {
      value = typeof source === "function" ? source() : source;
    } catch {
      throw new VaultServerError("INVALID_ARGUMENT");
    }
    if (typeof value !== "string" || !isWellFormed(value) || utf8Length(value) > LIMITS.policyRevisionMaxBytes) {
      throw new VaultServerError("INVALID_ARGUMENT");
    }
    return value;
  }

  /** Principal and session from trusted context. Any failure rejects; callers map it to their denial. */
  async #resolve(context: Context): Promise<Resolved> {
    const principal = await withTimeout(this.#i.resolvePrincipal(context), this.#i.timeouts.resolver);
    if (typeof principal !== "object" || principal === null || !isIdentifier(principal.id) || !isIdentifier(principal.tenant)) {
      throw new Error("malformed principal");
    }
    let sessionId: string | null = null;
    if (this.#i.resolveSession !== undefined) {
      const session = await withTimeout(this.#i.resolveSession(context), this.#i.timeouts.resolver);
      if (session !== null && session !== undefined) {
        if (!isIdentifier(session)) throw new Error("malformed session");
        sessionId = session;
      }
    }
    return { principal, tenant: principal.tenant, sessionId };
  }

  async #lifecycle(input: Parameters<LifecyclePolicy>[0] & { operation: LifecycleOperation }): Promise<void> {
    const decision = await withTimeout(this.#i.lifecyclePolicy(Object.freeze(input)), this.#i.timeouts.policy);
    if (typeof decision !== "object" || decision === null || decision.allow !== true) throw new Error("denied");
  }

  /**
   * One store call with a deadline. Whatever the adapter throws is reduced to
   * a `StoreFailure`; nothing of its error survives. A mutating call that
   * times out, or fails in a way the adapter did not classify, has an
   * unknown outcome.
   */
  async #store<T>(mutating: boolean, call: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const controller = new AbortController();
    try {
      return await withTimeout(call(controller.signal), this.#i.timeouts.store);
    } catch (thrown) {
      controller.abort();
      if (thrown instanceof StoreError) {
        if (thrown.code === "STORE_UNAVAILABLE" || thrown.code === "STORE_CLOSED") throw new StoreFailure("unavailable");
        if (thrown.code === "STORE_INVALID_ARGUMENT" || thrown.code === "STORE_CAPABILITY") throw new StoreFailure("invalid");
        throw new StoreFailure("ambiguous");
      }
      throw new StoreFailure(mutating ? "ambiguous" : "unavailable");
    }
  }

  /** All crypto and key-provider work of one operation, under one deadline. */
  async #crypto<T>(work: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const controller = new AbortController();
    try {
      return await withTimeout(work(controller.signal), this.#i.timeouts.crypto);
    } catch (thrown) {
      controller.abort();
      if (thrown instanceof KeyProviderError || thrown instanceof RecordCryptoError) throw thrown;
      throw new KeyProviderError(thrown instanceof Timeout ? "KEY_TIMEOUT" : "KEY_UNAVAILABLE");
    }
  }

  #digestInput(resolved: Resolved, parsed: ParsedRestore<Context>, uses: ReadonlyMap<string, Use>): RequestDigestInput {
    return {
      namespace: this.#i.namespace,
      tenant: resolved.tenant,
      principalId: resolved.principal.id,
      sessionId: resolved.sessionId,
      sink: parsed.sink,
      purpose: parsed.purpose,
      captureIds: [...parsed.sources],
      uses: [...uses.values()].map((use) => ({
        entryId: use.entryId,
        paths: [...use.paths].map(([path, occurrences]) => ({ path, occurrences })),
      })),
    };
  }

  /**
   * Shape validation and the field snapshot (§7.2 step 1). Programming errors
   * throw `INVALID_ARGUMENT`; anything a model's output could cause is
   * recorded and denied by the caller after the principal is known.
   */
  #parseRestore(request: PersistentRestoreRequest<Context>): ParsedRestore<Context> {
    if (typeof request !== "object" || request === null) throw new VaultServerError("INVALID_ARGUMENT");
    const { context, sink, purpose, captures, fields, attemptId, requestId } = request;
    if (!isIdentifier(sink)) throw new VaultServerError("INVALID_ARGUMENT");
    if (typeof purpose !== "string" || !isWellFormed(purpose) || utf8Length(purpose) > LIMITS.purposeMaxBytes) {
      throw new VaultServerError("INVALID_ARGUMENT");
    }
    if (attemptId !== undefined && !isAttemptId(attemptId)) throw new VaultServerError("INVALID_ARGUMENT");
    if (requestId !== undefined && typeof requestId !== "string") throw new VaultServerError("INVALID_ARGUMENT");
    if (!Array.isArray(captures) || captures.length === 0 || captures.length > this.#i.capabilities.maxRestoreCaptures) {
      throw new VaultServerError("INVALID_ARGUMENT");
    }
    const sources = new Set<string>();
    for (const id of captures as unknown[]) {
      if (!isCaptureId(id)) throw new VaultServerError("INVALID_ARGUMENT");
      sources.add(id);
    }
    if (typeof fields !== "object" || fields === null || Array.isArray(fields)) throw new VaultServerError("INVALID_ARGUMENT");

    const parsed: ParsedRestore<Context> = {
      context,
      sink,
      purpose,
      sources,
      attemptId,
      requestId,
      snapshot: [],
      uses: new Map(),
      invalid: false,
      malformed: false,
    };
    const keys = Object.keys(fields);
    if (keys.length > this.#i.limits.maxRestoreFields) {
      parsed.invalid = true;
      return parsed;
    }
    for (const path of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(fields, path);
      const text: unknown = descriptor !== undefined && "value" in descriptor ? descriptor.value : undefined;
      if (!isIdentifier(path) || typeof text !== "string" || utf8Length(text) > this.#i.limits.maxRestoreFieldBytes) {
        parsed.invalid = true;
        return parsed;
      }
      parsed.snapshot.push([path, text]);
    }
    for (const [path, text] of parsed.snapshot) {
      TOKEN_PATTERN.lastIndex = 0;
      const tokens = text.match(TOKEN_PATTERN) ?? [];
      TOKEN_PATTERN.lastIndex = 0;
      if (countMatches(MARKER_PATTERN, text) !== tokens.length) {
        parsed.malformed = true;
        return parsed;
      }
      for (const token of tokens) {
        const use = parsed.uses.get(token) ?? { count: 0, paths: new Map<string, number>() };
        use.count += 1;
        use.paths.set(path, (use.paths.get(path) ?? 0) + 1);
        parsed.uses.set(token, use);
      }
    }
    return parsed;
  }

  #audit(event: ServerAuditEvent): void {
    if (this.#i.onAudit === undefined) return;
    try {
      this.#i.onAudit(Object.freeze(event));
    } catch {
      // Audit delivery never changes an operation's outcome.
    }
  }
}

interface ParsedRestore<Context> {
  readonly context: Context;
  readonly sink: string;
  readonly purpose: string;
  readonly sources: ReadonlySet<string>;
  readonly attemptId: string | undefined;
  readonly requestId: string | undefined;
  readonly snapshot: Array<[string, string]>;
  /** By issued token. */
  readonly uses: Map<string, { count: number; readonly paths: Map<string, number> }>;
  invalid: boolean;
  malformed: boolean;
}

function wipeBytes(buffers: readonly Uint8Array[]): void {
  for (const buffer of buffers) buffer.fill(0);
}

function isPayload(payload: unknown): payload is RecordPayload {
  if (typeof payload !== "object" || payload === null) return false;
  const candidate = payload as Partial<RecordPayload>;
  if (!(candidate.value instanceof Uint8Array) || typeof candidate.type !== "string") return false;
  if (candidate.policyRevision !== null && typeof candidate.policyRevision !== "string") return false;
  if (!Array.isArray(candidate.grants)) return false;
  for (const grant of candidate.grants as unknown[]) {
    if (typeof grant !== "object" || grant === null) return false;
    const { sink, paths } = grant as { sink?: unknown; paths?: unknown };
    if (typeof sink !== "string" || !Array.isArray(paths) || paths.some((path) => typeof path !== "string")) return false;
  }
  return true;
}

/**
 * Checks what a store returned from `readEntries` before any of it is used.
 * A store is trusted code, but a faulty or hostile one must not be able to
 * make the server act on an entry it did not ask for, an entry without its
 * capture, or a malformed number. Returns `undefined` when the result is not
 * usable; the caller fails closed.
 */
function inspectRead(
  read: ReadEntriesResult,
  uses: ReadonlyMap<string, Use>,
):
  | {
      readonly recovery: { readonly epoch: number; readonly state: string };
      readonly entries: ReadonlyMap<string, StoredEntry>;
      readonly captures: ReadonlyMap<string, StoredCapture>;
    }
  | undefined {
  if (typeof read !== "object" || read === null) return undefined;
  const { recovery, entries, captures } = read;
  if (typeof recovery !== "object" || recovery === null || typeof recovery.state !== "string" || !Number.isSafeInteger(recovery.epoch)) {
    return undefined;
  }
  if (!Array.isArray(entries) || !Array.isArray(captures)) return undefined;
  const positive = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 1;

  const captureMap = new Map<string, StoredCapture>();
  for (const capture of captures as StoredCapture[]) {
    if (typeof capture !== "object" || capture === null || !isCaptureId(capture.captureId)) return undefined;
    if (captureMap.has(capture.captureId)) return undefined;
    if (capture.state !== "live" && capture.state !== "revoked") return undefined;
    if (!positive(capture.generation) || !isTimestamp(capture.createdAt) || !isTimestamp(capture.expiresAt)) return undefined;
    if (capture.sessionTag !== null && !isSessionTag(capture.sessionTag)) return undefined;
    if (capture.state === "live") {
      if (!isKeyRef(capture.keyRef) || !(capture.wrappedKey instanceof Uint8Array) || capture.wrappedKey.byteLength === 0) return undefined;
      // A lower epoch must already read as revoked (§5.1); a live one from another epoch is a contradiction.
      if (capture.epoch !== recovery.epoch) return undefined;
    }
    captureMap.set(capture.captureId, capture);
  }

  const entryMap = new Map<string, StoredEntry>();
  const usedCaptures = new Set<string>();
  for (const entry of entries as StoredEntry[]) {
    if (typeof entry !== "object" || entry === null || !isEntryId(entry.entryId)) return undefined;
    if (!uses.has(entry.entryId) || entryMap.has(entry.entryId)) return undefined;
    if (!isCaptureId(entry.captureId) || !captureMap.has(entry.captureId)) return undefined;
    if (!positive(entry.maxUses) || entry.maxUses > LIMITS.maxUses) return undefined;
    if (!Number.isSafeInteger(entry.used) || entry.used < 0) return undefined;
    if (!positive(entry.lifecycleRevision) || !positive(entry.ciphertextRevision)) return undefined;
    if (!(entry.envelope instanceof Uint8Array) || entry.envelope.byteLength === 0 || entry.envelope.byteLength > LIMITS.maxEnvelopeBytes) {
      return undefined;
    }
    entryMap.set(entry.entryId, entry);
    usedCaptures.add(entry.captureId);
  }
  // Only the captures of returned entries are considered.
  for (const captureId of [...captureMap.keys()]) {
    if (!usedCaptures.has(captureId)) captureMap.delete(captureId);
  }
  return { recovery, entries: entryMap, captures: captureMap };
}
