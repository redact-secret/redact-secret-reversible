import { createVault, DEFAULT_LIMITS, VaultError } from "@redact-secret/vault";
import type { CaptureResult, ReleaseGrant, RestoreRequest, Vault } from "@redact-secret/vault";

import { VaultServerError } from "./errors.js";
import { countMatches, MARKER_PATTERN, TOKEN_PATTERN } from "./token-pattern.js";
import type {
  Principal,
  PolicyDecision,
  PrincipalResolver,
  RestoreDecisionInput,
  ServerAuditEvent,
  ServerAuditHook,
  ServerAuditOperation,
  ServerCaptureOptions,
  ServerDenialReason,
  ServerReleasePolicy,
  ServerRestoreRequest,
  ServerRestoreResult,
  ServerVault,
  ServerVaultOptions,
  ServerVaultStats,
} from "./types.js";

const MAX_IDENTIFIER_LENGTH = 256;
const MAX_CAPTURES = 1024;
const DEFAULT_TIMEOUT_MS = 5000;

const SERVER_DENIAL_REASONS: ReadonlySet<string> = new Set<ServerDenialReason>([
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

function isServerDenialReason(value: unknown): value is ServerDenialReason {
  return typeof value === "string" && SERVER_DENIAL_REASONS.has(value);
}

function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_IDENTIFIER_LENGTH;
}

/** UTF-8 length without materializing an encoded copy of the value. */
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

function shadowGrants(release: readonly ReleaseGrant[]): ReadonlyMap<string, ReadonlySet<string>> {
  const grants = new Map<string, Set<string>>();
  for (const grant of release) {
    const set = grants.get(grant.sink) ?? new Set<string>();
    for (const path of grant.paths) set.add(path);
    grants.set(grant.sink, set);
  }
  return grants;
}

/** Monotonic, non-decreasing wrapper shared between this package and the underlying vault's own clock. */
function makeClock(raw: (() => number) | undefined): () => number {
  const base = raw ?? Date.now;
  let latest = Number.NEGATIVE_INFINITY;
  return () => {
    let value: unknown;
    try {
      value = base();
    } catch {
      throw new VaultServerError("INVALID_ARGUMENT");
    }
    if (typeof value !== "number" || !Number.isFinite(value)) throw new VaultServerError("INVALID_ARGUMENT");
    latest = Math.max(latest, value);
    return latest;
  };
}

/**
 * Races a possibly-async value against a deadline. The underlying promise is
 * not cancelled on timeout (JavaScript cannot cancel an arbitrary consumer
 * callback); a slow `PrincipalResolver`/`ServerReleasePolicy` keeps running
 * in the background, but this operation treats it as failed and denies.
 */
function withTimeout<T>(value: T | Promise<T>, ms: number, onTimeout: () => Error): Promise<T> {
  const settled = value instanceof Promise ? value : Promise.resolve(value);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(onTimeout()), ms);
  });
  return Promise.race([settled, deadline]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

interface ShadowEntry {
  readonly captureId: string;
  readonly issuedTenant: string;
  readonly type: string;
  readonly grants: ReadonlyMap<string, ReadonlySet<string>>;
  readonly maxUses: number;
  used: number;
  readonly expiresAt: number;
  readonly policyRevision: string | undefined;
}

/**
 * Opens a server authority layer over one `@redact-secret/vault` in-memory
 * instance: `PrincipalResolver` and `ServerReleasePolicy` are enforced on
 * every `restore`, per the evaluation order fixed by
 * docs/decisions/2026-09-27-define-server-authority-interface.md §3.
 *
 * This package keeps a small metadata shadow (token → issuing capture,
 * tenant, grants, budget — never the plaintext value, which stays inside
 * the wrapped vault) so the tenant/purpose checks the ADR inserts into that
 * order can run *before* any commit, ahead of the point where the wrapped
 * vault would otherwise be the first and only place those checks could
 * happen. The wrapped vault remains the sole source of truth for token
 * minting, value retention, and the final atomic substitution + budget
 * consumption — this layer never reinvents that.
 */
export async function createServerVault<Context = unknown>(
  options: ServerVaultOptions<Context>,
): Promise<ServerVault<Context>> {
  if (typeof options !== "object" || options === null) throw new VaultServerError("INVALID_ARGUMENT");
  const {
    resolvePrincipal,
    policy,
    onAudit,
    limits,
    now,
    policyRevision,
    revocationMemoryMs,
    resolverTimeoutMs,
    policyTimeoutMs,
  } = options;
  if (typeof resolvePrincipal !== "function") throw new VaultServerError("INVALID_ARGUMENT");
  if (typeof policy !== "function") throw new VaultServerError("INVALID_ARGUMENT");
  if (onAudit !== undefined && typeof onAudit !== "function") throw new VaultServerError("INVALID_ARGUMENT");
  if (
    policyRevision !== undefined &&
    typeof policyRevision !== "string" &&
    typeof policyRevision !== "function"
  ) {
    throw new VaultServerError("INVALID_ARGUMENT");
  }
  const resolvedResolverTimeout = resolverTimeoutMs ?? DEFAULT_TIMEOUT_MS;
  const resolvedPolicyTimeout = policyTimeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isFinite(resolvedResolverTimeout) || resolvedResolverTimeout <= 0) {
    throw new VaultServerError("INVALID_ARGUMENT");
  }
  if (!Number.isFinite(resolvedPolicyTimeout) || resolvedPolicyTimeout <= 0) {
    throw new VaultServerError("INVALID_ARGUMENT");
  }

  const clock = makeClock(now);
  const maxRestoreFields = limits?.maxRestoreFields ?? DEFAULT_LIMITS.maxRestoreFields;
  const maxRestoreFieldBytes = limits?.maxRestoreFieldBytes ?? DEFAULT_LIMITS.maxRestoreFieldBytes;
  const resolvedRevocationMemoryMs =
    revocationMemoryMs ?? limits?.entryTtlMs ?? DEFAULT_LIMITS.entryTtlMs;
  if (!Number.isFinite(resolvedRevocationMemoryMs) || resolvedRevocationMemoryMs < 0) {
    throw new VaultServerError("INVALID_ARGUMENT");
  }

  let vault: Vault;
  try {
    vault = await createVault({
      ...(limits === undefined ? {} : { limits }),
      now: clock,
      ...(options.onVaultAudit === undefined ? {} : { onAudit: options.onVaultAudit }),
    });
  } catch (thrown) {
    if (thrown instanceof VaultError) throw new VaultServerError("VAULT_FAILURE", { vaultCode: thrown.code });
    throw new VaultServerError("INVARIANT_VIOLATION");
  }

  return new ServerVaultImpl<Context>(
    vault,
    clock,
    resolvePrincipal,
    policy,
    onAudit,
    policyRevision,
    maxRestoreFields,
    maxRestoreFieldBytes,
    resolvedRevocationMemoryMs,
    resolvedResolverTimeout,
    resolvedPolicyTimeout,
  );
}

class ServerVaultImpl<Context> implements ServerVault<Context> {
  readonly #vault: Vault;
  readonly #clock: () => number;
  readonly #resolvePrincipal: PrincipalResolver<Context>;
  readonly #policy: ServerReleasePolicy;
  readonly #onAudit: ServerAuditHook | undefined;
  readonly #policyRevision: string | (() => string) | undefined;
  readonly #maxRestoreFields: number;
  readonly #maxRestoreFieldBytes: number;
  readonly #revocationMemoryMs: number;
  readonly #resolverTimeoutMs: number;
  readonly #policyTimeoutMs: number;

  readonly #shadow = new Map<string, ShadowEntry>();
  readonly #captureTokens = new Map<string, Set<string>>();
  readonly #tombstones = new Map<string, number>();
  readonly #tombstoneTokens = new Map<string, string>();
  #disposed = false;

  /**
   * The linearization point this package proves for itself, per the
   * transaction-boundary ADR's requirement that a server authority layer
   * "define one linearization point" of its own (F4/#9, generalized by
   * #16): every `capture`/`restore`/`revoke`/`dispose`/`stats` call is
   * queued onto this single FIFO chain, so at most one is ever in flight
   * and each fully completes (commits or denies) before the next begins —
   * including across the `await`s a synchronous vault operation never has.
   * `resolverTimeoutMs`/`policyTimeoutMs` bound how long a call can hold
   * this queue, converting a stuck or reentrant consumer callback into a
   * bounded denial instead of a deadlock.
   */
  #tail: Promise<unknown> = Promise.resolve();

  constructor(
    vault: Vault,
    clock: () => number,
    resolvePrincipal: PrincipalResolver<Context>,
    policy: ServerReleasePolicy,
    onAudit: ServerAuditHook | undefined,
    policyRevision: string | (() => string) | undefined,
    maxRestoreFields: number,
    maxRestoreFieldBytes: number,
    revocationMemoryMs: number,
    resolverTimeoutMs: number,
    policyTimeoutMs: number,
  ) {
    this.#vault = vault;
    this.#clock = clock;
    this.#resolvePrincipal = resolvePrincipal;
    this.#policy = policy;
    this.#onAudit = onAudit;
    this.#policyRevision = policyRevision;
    this.#maxRestoreFields = maxRestoreFields;
    this.#maxRestoreFieldBytes = maxRestoreFieldBytes;
    this.#revocationMemoryMs = revocationMemoryMs;
    this.#resolverTimeoutMs = resolverTimeoutMs;
    this.#policyTimeoutMs = policyTimeoutMs;
  }

  capture(input: string, options: ServerCaptureOptions): Promise<CaptureResult> {
    return this.#run(() => this.#capture(input, options));
  }

  restore(request: ServerRestoreRequest<Context>): Promise<ServerRestoreResult> {
    return this.#run(() => this.#restore(request));
  }

  revoke(captureId: string): Promise<number> {
    return this.#run(() => this.#revoke(captureId));
  }

  dispose(): Promise<void> {
    // Bypasses the disposed-check below deliberately: dispose() itself must
    // stay idempotent (mirrors @redact-secret/vault's own `dispose()`), not
    // reject once the instance is already disposed.
    return this.#run(() => this.#dispose(), true);
  }

  stats(): Promise<ServerVaultStats> {
    return this.#run(() => this.#stats());
  }

  #run<T>(body: () => Promise<T>, allowDisposed = false): Promise<T> {
    const run = this.#tail.then(() => {
      if (this.#disposed && !allowDisposed) throw new VaultServerError("DISPOSED");
      return body();
    });
    this.#tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  async #capture(input: string, options: ServerCaptureOptions): Promise<CaptureResult> {
    if (typeof options !== "object" || options === null) throw new VaultServerError("INVALID_ARGUMENT");
    const { issuedTenant, ...captureOptions } = options;
    if (!isIdentifier(issuedTenant)) throw new VaultServerError("INVALID_ARGUMENT");

    const at = this.#clock();
    this.#sweepShadow(at);
    this.#sweepTombstones(at);

    let result: CaptureResult;
    try {
      result = this.#vault.capture(input, captureOptions);
    } catch (thrown) {
      if (thrown instanceof VaultError) {
        if (thrown.code === "DISPOSED") {
          this.#disposed = true;
          throw new VaultServerError("DISPOSED");
        }
        throw new VaultServerError("VAULT_FAILURE", { vaultCode: thrown.code });
      }
      throw new VaultServerError("INVARIANT_VIOLATION");
    }

    const grants = shadowGrants(captureOptions.release);
    const maxUses = captureOptions.maxUses ?? 1;
    const revision =
      typeof this.#policyRevision === "function" ? this.#policyRevision() : this.#policyRevision;
    const tokens = new Set<string>();
    for (const issued of result.tokens) {
      this.#shadow.set(issued.token, {
        captureId: result.captureId,
        issuedTenant,
        type: issued.type,
        grants,
        maxUses,
        used: 0,
        expiresAt: result.expiresAt,
        policyRevision: revision,
      });
      tokens.add(issued.token);
    }
    if (tokens.size > 0) this.#captureTokens.set(result.captureId, tokens);
    return result;
  }

  async #restore(request: ServerRestoreRequest<Context>): Promise<ServerRestoreResult> {
    if (typeof request !== "object" || request === null) throw new VaultServerError("INVALID_ARGUMENT");
    const { context, sink, purpose, captures, fields, sessionId, requestId } = request;
    const tenantOverride = request.tenant;
    if (!isIdentifier(sink)) throw new VaultServerError("INVALID_ARGUMENT");
    if (typeof purpose !== "string") throw new VaultServerError("INVALID_ARGUMENT");
    if (sessionId !== undefined && typeof sessionId !== "string") throw new VaultServerError("INVALID_ARGUMENT");
    if (requestId !== undefined && typeof requestId !== "string") throw new VaultServerError("INVALID_ARGUMENT");
    if (tenantOverride !== undefined && !isIdentifier(tenantOverride)) {
      throw new VaultServerError("INVALID_ARGUMENT");
    }
    if (!Array.isArray(captures) || captures.length === 0 || captures.length > MAX_CAPTURES) {
      throw new VaultServerError("INVALID_ARGUMENT");
    }
    const sources = new Set<string>();
    for (const id of captures as unknown[]) {
      if (!isIdentifier(id)) throw new VaultServerError("INVALID_ARGUMENT");
      sources.add(id as string);
    }
    if (typeof fields !== "object" || fields === null || Array.isArray(fields)) {
      throw new VaultServerError("INVALID_ARGUMENT");
    }

    const at = this.#clock();
    // Deliberately not sweeping expired shadow entries here: doing so before
    // the preflight below would turn an "expired" denial into "unknown-token"
    // by deleting the very entry the expiry check (step 5) needs to see,
    // matching the vault's own `#restore` (which also defers its sweep until
    // after a decision is reached). Tombstones are unaffected by this — a
    // tombstone that has aged out must already read as "unknown-token" by
    // the time the known-entry check below runs.
    this.#sweepTombstones(at);

    const deny = (reason: ServerDenialReason, principal?: Principal): never => {
      this.#sweepShadow(this.#clock());
      const operation: ServerAuditOperation =
        reason === "unauthenticated"
          ? "resolve-principal"
          : reason === "policy-evaluation-error"
            ? "policy-error"
            : "restore";
      this.#auditEvent({
        operation,
        outcome: reason === "policy-evaluation-error" ? "failed" : "denied",
        at,
        ...(principal === undefined ? {} : { principalId: principal.id, tenant: tenantOverride ?? principal.tenant }),
        sink,
        purpose,
        reason,
        ...(requestId === undefined ? {} : { requestId }),
      });
      throw new VaultServerError("RESTORE_DENIED", { reason });
    };

    // Snapshot own-data-properties only; reject getters (mirrors the vault's
    // own restore-request snapshot).
    const keys = Object.keys(fields);
    if (keys.length > this.#maxRestoreFields) throw deny("invalid-request");
    const snapshot: Array<[string, string]> = [];
    for (const path of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(fields, path);
      if (descriptor === undefined || !("value" in descriptor)) throw deny("invalid-request");
      const text: unknown = descriptor?.value;
      if (!isIdentifier(path) || typeof text !== "string") throw deny("invalid-request");
      if (utf8Length(text as string) > this.#maxRestoreFieldBytes) throw deny("invalid-request");
      snapshot.push([path, text as string]);
    }

    // 1. Resolve principal → "unauthenticated" on failure, timeout, or a
    // malformed/partial return (never a default or shared principal).
    let principal: Principal;
    try {
      const resolved = await withTimeout(
        this.#resolvePrincipal(context),
        this.#resolverTimeoutMs,
        () => new Error("resolver timeout"),
      );
      if (
        typeof resolved !== "object" ||
        resolved === null ||
        !isIdentifier((resolved as Principal).id) ||
        !isIdentifier((resolved as Principal).tenant)
      ) {
        throw new Error("malformed principal");
      }
      principal = resolved;
    } catch {
      throw deny("unauthenticated");
    }
    const tenant = tenantOverride ?? principal.tenant;

    // 2. Marker/grammar + known-entry, extended with the revoked-tombstone
    // distinction the ADR permits (§4): "unchanged from the vault" other
    // than that one addition.
    interface Use {
      readonly entry: ShadowEntry;
      count: number;
      readonly paths: Map<string, number>;
    }
    const uses = new Map<string, Use>();
    for (const [path, text] of snapshot) {
      TOKEN_PATTERN.lastIndex = 0;
      const tokens = text.match(TOKEN_PATTERN) ?? [];
      TOKEN_PATTERN.lastIndex = 0;
      if (countMatches(MARKER_PATTERN, text) !== tokens.length) throw deny("malformed-token", principal);
      for (const token of tokens) {
        const entry = this.#shadow.get(token);
        if (entry === undefined) {
          throw deny(this.#tombstoneTokens.has(token) ? "revoked" : "unknown-token", principal);
        }
        const use = uses.get(token) ?? { entry: entry as ShadowEntry, count: 0, paths: new Map<string, number>() };
        use.count += 1;
        use.paths.set(path, (use.paths.get(path) ?? 0) + 1);
        uses.set(token, use);
      }
    }

    // 3. Source binding.
    for (const { entry } of uses.values()) {
      if (!sources.has(entry.captureId)) throw deny("source", principal);
    }
    // 4. Tenant match.
    for (const { entry } of uses.values()) {
      if (entry.issuedTenant !== tenant) throw deny("tenant-mismatch", principal);
    }
    // 5. Expiry.
    for (const { entry } of uses.values()) {
      if (at >= entry.expiresAt) throw deny("expired", principal);
    }
    // 6. Sink/path grant.
    for (const { entry, paths } of uses.values()) {
      const allowed = entry.grants.get(sink);
      for (const path of paths.keys()) {
        if (allowed === undefined || !allowed.has(path)) throw deny("sink-or-path", principal);
      }
    }
    // 7. Purpose presence.
    if (purpose.length === 0) throw deny("missing-purpose", principal);
    // 8. Budget.
    for (const { entry, count } of uses.values()) {
      if (entry.used + count > entry.maxUses) throw deny("budget", principal);
    }

    // 9. ServerReleasePolicy — fresh for every occurrence of every path.
    for (const { entry, paths, count: total } of uses.values()) {
      for (const [path, count] of paths) {
        const input: RestoreDecisionInput = Object.freeze({
          principal,
          tenant,
          source: Object.freeze({
            captureId: entry.captureId,
            issuedTenant: entry.issuedTenant,
            ...(sessionId === undefined ? {} : { sessionId }),
          }),
          sink,
          path,
          purpose,
          type: entry.type,
          occurrences: count,
          totalOccurrences: total,
          used: entry.used,
          maxUses: entry.maxUses,
          ...(entry.policyRevision === undefined ? {} : { policyRevision: entry.policyRevision }),
          requestedAt: at,
        });
        let decision: PolicyDecision;
        try {
          decision = await withTimeout(this.#policy(input), this.#policyTimeoutMs, () => new Error("policy timeout"));
        } catch {
          throw deny("policy-evaluation-error", principal);
        }
        if (typeof decision !== "object" || decision === null || typeof decision.allow !== "boolean") {
          throw deny("policy-evaluation-error", principal);
        }
        if (!decision.allow) {
          throw deny(isServerDenialReason(decision.reason) ? decision.reason : "policy-evaluation-error", principal);
        }
      }
    }

    // Commit: the wrapped vault is the sole source of truth for token →
    // value substitution and for atomically consuming budget at its own
    // linearization point (F4). Every check above already passed against
    // shadow state kept in lockstep with it (same grants/maxUses at
    // capture, same clock) and under this instance's own single-flight
    // queue, so this call re-validating and succeeding is expected, not
    // merely hoped for.
    let result;
    try {
      result = this.#vault.restore({ sink, captures: [...sources], fields } satisfies RestoreRequest);
    } catch {
      // A denial here despite our preflight passing means the shadow and
      // the wrapped vault have drifted — a bug in this package, not a
      // legitimate authorization outcome. Fail closed either way.
      this.#auditEvent({
        operation: "restore",
        outcome: "failed",
        at,
        principalId: principal.id,
        tenant,
        sink,
        purpose,
        code: "INVARIANT_VIOLATION",
        ...(requestId === undefined ? {} : { requestId }),
      });
      throw new VaultServerError("INVARIANT_VIOLATION");
    }

    for (const [token, { entry, count }] of uses) {
      entry.used += count;
      if (entry.used >= entry.maxUses) this.#removeShadowEntry(token, entry);
    }
    this.#sweepShadow(this.#clock());

    this.#auditEvent({
      operation: "restore",
      outcome: "committed",
      at,
      principalId: principal.id,
      tenant,
      sink,
      purpose,
      entries: uses.size,
      ...(requestId === undefined ? {} : { requestId }),
    });
    return { fields: result.fields, restored: result.restored, principalId: principal.id, tenant };
  }

  async #revoke(captureId: string): Promise<number> {
    if (!isIdentifier(captureId)) throw new VaultServerError("INVALID_ARGUMENT");
    const at = this.#clock();

    let removed: number;
    try {
      removed = this.#vault.revoke(captureId);
    } catch (thrown) {
      if (thrown instanceof VaultError && thrown.code === "DISPOSED") {
        this.#disposed = true;
        throw new VaultServerError("DISPOSED");
      }
      throw new VaultServerError("INVARIANT_VIOLATION");
    }

    const tokens = this.#captureTokens.get(captureId);
    if (tokens !== undefined) {
      for (const token of tokens) {
        this.#shadow.delete(token);
        this.#tombstoneTokens.set(token, captureId);
      }
      this.#captureTokens.delete(captureId);
    }
    this.#tombstones.set(captureId, at);
    this.#sweepTombstones(at);

    this.#auditEvent({ operation: "revoke", outcome: "committed", at, entries: removed });
    return removed;
  }

  async #dispose(): Promise<void> {
    if (this.#disposed) return;
    try {
      this.#vault.dispose();
    } catch {
      // Best-effort: this instance is being torn down regardless.
    }
    this.#shadow.clear();
    this.#captureTokens.clear();
    this.#tombstones.clear();
    this.#tombstoneTokens.clear();
    this.#disposed = true;
  }

  async #stats(): Promise<ServerVaultStats> {
    const at = this.#clock();
    this.#sweepShadow(at);
    this.#sweepTombstones(at);
    let vaultDisposed = this.#disposed;
    try {
      vaultDisposed = this.#vault.stats().disposed || vaultDisposed;
    } catch {
      // A failing clock leaves the counters as they are, mirroring the vault.
    }
    if (vaultDisposed) this.#disposed = true;
    return Object.freeze({
      entries: this.#shadow.size,
      captures: this.#captureTokens.size,
      revokedCaptures: this.#tombstones.size,
      disposed: this.#disposed,
    });
  }

  #removeShadowEntry(token: string, entry: ShadowEntry): void {
    this.#shadow.delete(token);
    const tokens = this.#captureTokens.get(entry.captureId);
    if (tokens !== undefined) {
      tokens.delete(token);
      if (tokens.size === 0) this.#captureTokens.delete(entry.captureId);
    }
  }

  #sweepShadow(at: number): void {
    for (const [token, entry] of [...this.#shadow]) {
      if (at >= entry.expiresAt) this.#removeShadowEntry(token, entry);
    }
  }

  #sweepTombstones(at: number): void {
    for (const [captureId, revokedAt] of [...this.#tombstones]) {
      if (at - revokedAt >= this.#revocationMemoryMs) this.#tombstones.delete(captureId);
    }
    for (const [token, captureId] of [...this.#tombstoneTokens]) {
      if (!this.#tombstones.has(captureId)) this.#tombstoneTokens.delete(token);
    }
  }

  #auditEvent(event: ServerAuditEvent): void {
    if (this.#onAudit === undefined) return;
    try {
      this.#onAudit(Object.freeze(event));
    } catch {
      // Audit delivery never changes an operation's outcome.
    }
  }
}
