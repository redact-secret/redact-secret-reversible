import { installedCore } from "./core-module.js";
import type { CoreModule } from "./core-module.js";
import {
  establishCapture,
  isIdentifier,
  MAX_GRANTS,
  newCaptureIdFrom,
  planCaptureWith,
  resolveCaptureLimits,
  TOKEN_ATTEMPTS,
  utf8Length,
} from "./capture-plan.js";
import type { PlanRandom } from "./capture-plan.js";
import { VaultError } from "./errors.js";
import type { DenialReason, VaultErrorCode } from "./errors.js";
import { ExpiryQueue } from "./expiry-queue.js";
import { isPiiActive } from "./pii.js";
import { countMatches, MARKER_PATTERN, TOKEN_PATTERN } from "./token.js";
import type {
  AuditEvent,
  AuditHook,
  CaptureOptions,
  CaptureResult,
  IssuedToken,
  ReleasePolicy,
  RestoreRequest,
  RestoreResult,
  Vault,
  VaultLimits,
  VaultOptions,
  VaultStats,
} from "./types.js";

export { DEFAULT_LIMITS, LIMIT_CEILINGS } from "./capture-plan.js";

interface Entry {
  readonly captureId: string;
  value: string;
  readonly bytes: number;
  readonly type: string;
  readonly grants: ReadonlyMap<string, ReadonlySet<string>>;
  readonly maxUses: number;
  used: number;
  readonly expiresAt: number;
}

/** One committed capture's place in the expiry queue. */
interface CaptureExpiry {
  readonly expiresAt: number;
  readonly captureId: string;
  /** The capture's live token set, compared by identity to detect staleness. */
  readonly tokens: Set<string>;
}

/** Stale queue items tolerated beyond the live captures before compacting. */
const EXPIRY_QUEUE_SLACK = 64;

/**
 * The later of wall-clock time and a monotonic timeline anchored to it.
 * `performance.now()` keeps a backwards system-clock change from extending a
 * TTL; `Date.now()` keeps time that the monotonic clock may not count (such
 * as system sleep) from extending one. Combined with the never-decreasing
 * clamp in `createVault`, neither can lengthen a lifetime.
 */
function monotonicEpochClock(): () => number {
  const perf = (globalThis as { performance?: { now(): number } }).performance;
  if (perf === undefined || typeof perf.now !== "function") return Date.now;
  const base = Date.now() - perf.now();
  return () => Math.max(Date.now(), base + perf.now());
}

/**
 * Opens an explicit, bounded, in-memory vault session.
 *
 * Importing this package creates nothing; only this call does. It captures
 * the platform CSPRNG, failing with `UNSUPPORTED_RUNTIME` when
 * `crypto.getRandomValues` is unavailable, then establishes the core:
 *
 * - On a core without a PII surface (beta.9) it awaits `initialize()`; any
 *   PII option fails `PII_UNAVAILABLE` first (`pii: []` equals omission).
 * - On a core with a PII surface it forwards `options.pii` to
 *   `initialize({ pii })` when supplied, and otherwise adopts the activation
 *   the application already established without calling any initializer.
 *
 * See docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md §3.
 */
export async function createVault(options: VaultOptions = {}): Promise<Vault> {
  return openVault(installedCore, options);
}

/**
 * `createVault` against an explicit core module. Internal: not exported from
 * the package entry point. It exists so tests can exercise the PII
 * activation contract against a fake core without replacing the installed
 * `@redact-secret/core`.
 */
export async function openVault(core: CoreModule, options: VaultOptions = {}): Promise<Vault> {
  if (typeof options !== "object" || options === null) throw new VaultError("INVALID_ARGUMENT");
  const limits = resolveCaptureLimits(options.limits);
  const releasePolicy: ReleasePolicy | undefined = options.releasePolicy;
  const onAudit: AuditHook | undefined = options.onAudit;
  const clock = options.now ?? monotonicEpochClock();
  if (releasePolicy !== undefined && typeof releasePolicy !== "function") {
    throw new VaultError("INVALID_ARGUMENT");
  }
  if (onAudit !== undefined && typeof onAudit !== "function") {
    throw new VaultError("INVALID_ARGUMENT");
  }
  if (typeof clock !== "function") throw new VaultError("INVALID_ARGUMENT");

  // The CSPRNG check (`UNSUPPORTED_RUNTIME`), then ADR §3 steps 1 to 6.
  const { random, piiActivation } = await establishCapture(core, options);

  let latest = Number.NEGATIVE_INFINITY;
  const now = (): number => {
    let value: unknown;
    try {
      value = clock();
    } catch {
      throw new VaultError("INVALID_ARGUMENT");
    }
    if (typeof value !== "number" || !Number.isFinite(value)) {
      throw new VaultError("INVALID_ARGUMENT");
    }
    // Monotonic: a clock moving backwards cannot extend any lifetime.
    latest = Math.max(latest, value);
    return latest;
  };

  return new InMemoryVault(
    core,
    piiActivation,
    limits,
    random,
    now,
    releasePolicy,
    onAudit,
    now() + limits.vaultTtlMs,
  );
}

class InMemoryVault implements Vault {
  readonly piiActivation: string | null;
  readonly #core: CoreModule;
  readonly #piiActive: boolean;
  readonly #limits: VaultLimits;
  readonly #random: PlanRandom;
  readonly #now: () => number;
  readonly #releasePolicy: ReleasePolicy | undefined;
  readonly #onAudit: AuditHook | undefined;
  readonly #expiresAt: number;
  readonly #entries = new Map<string, Entry>();
  readonly #captures = new Map<string, Set<string>>();
  // Every tracked capture has an item here keyed by its entries' earliest
  // expiry; items of revoked or fully consumed captures go stale and are
  // skipped or compacted away. Holds tokens only, never values.
  readonly #expiry = new ExpiryQueue<CaptureExpiry>();
  #retainedBytes = 0;
  #disposed = false;
  #busy = false;

  constructor(
    core: CoreModule,
    piiActivation: string | null,
    limits: VaultLimits,
    random: PlanRandom,
    now: () => number,
    releasePolicy: ReleasePolicy | undefined,
    onAudit: AuditHook | undefined,
    expiresAt: number,
  ) {
    this.#core = core;
    this.piiActivation = piiActivation;
    this.#piiActive = isPiiActive(piiActivation);
    Object.defineProperty(this, "piiActivation", { value: piiActivation, writable: false, enumerable: true, configurable: false });
    this.#limits = limits;
    this.#random = random;
    this.#now = now;
    this.#releasePolicy = releasePolicy;
    this.#onAudit = onAudit;
    this.#expiresAt = expiresAt;
  }

  capture(input: string, options: CaptureOptions): CaptureResult {
    return this.#run("capture", (at) => this.#capture(input, options, at));
  }

  restore(request: RestoreRequest): RestoreResult {
    return this.#run("restore", (at) => this.#restore(request, at));
  }

  revoke(captureId: string): number {
    if (this.#disposed) return 0;
    return this.#run("revoke", (at) => {
      if (typeof captureId !== "string") throw new VaultError("INVALID_ARGUMENT");
      const removed = this.#removeCapture(captureId);
      this.#audit({ operation: "revoke", outcome: "committed", at, entries: removed });
      return removed;
    });
  }

  dispose(): void {
    if (this.#disposed) return;
    if (this.#busy) throw new VaultError("BUSY");
    this.#busy = true;
    try {
      const removed = this.#disposeAll();
      this.#audit({ operation: "dispose", outcome: "committed", at: this.#safeNow(), entries: removed });
    } finally {
      this.#busy = false;
    }
  }

  stats(): VaultStats {
    // Apply expiry before reporting, unless an operation is in progress (a
    // callback reading stats must not mutate the vault mid-operation).
    if (!this.#disposed && !this.#busy) {
      this.#busy = true;
      try {
        const at = this.#now();
        if (at >= this.#expiresAt) {
          const removed = this.#disposeAll();
          this.#audit({ operation: "dispose", outcome: "committed", at, entries: removed });
        } else this.#sweep(at);
      } catch {
        // A failing clock leaves the counters as they are.
      } finally {
        this.#busy = false;
      }
    }
    return Object.freeze({
      entries: this.#entries.size,
      retainedBytes: this.#retainedBytes,
      captures: this.#captures.size,
      disposed: this.#disposed,
      expiresAt: this.#expiresAt,
    });
  }

  /**
   * The operation boundary: one synchronous call at a time, checked for
   * disposal and vault expiry, with a sanitized failure audit. Consumer
   * callbacks run inside it, so a callback that re-enters the vault gets
   * `BUSY` rather than interleaving with a half-finished operation.
   */
  #run<T>(operation: "capture" | "restore" | "revoke", body: (at: number) => T): T {
    if (this.#busy) throw new VaultError("BUSY");
    if (this.#disposed) throw new VaultError("DISPOSED");
    this.#busy = true;
    try {
      let at: number;
      try {
        at = this.#now();
      } catch (thrown) {
        const error = thrown instanceof VaultError ? thrown : new VaultError("INVALID_ARGUMENT");
        this.#audit({ operation, outcome: "failed", at: Number.NaN, code: error.code });
        throw error;
      }
      if (at >= this.#expiresAt) {
        const removed = this.#disposeAll();
        this.#audit({ operation: "dispose", outcome: "committed", at, entries: removed });
        throw new VaultError("DISPOSED");
      }
      try {
        return body(at);
      } catch (thrown) {
        const error =
          thrown instanceof VaultError ? thrown : new VaultError("INVARIANT_VIOLATION");
        if (error.code !== "DISPOSED") {
          this.#audit({
            operation,
            outcome: error.code === "RESTORE_DENIED" ? "denied" : "failed",
            at,
            code: error.code,
            ...(error.reason === undefined ? {} : { reason: error.reason }),
          });
        }
        throw error;
      }
    } finally {
      this.#busy = false;
    }
  }

  #capture(input: string, options: CaptureOptions, at: number): CaptureResult {
    // Everything up to the commit is the shared capture plan: validation, the
    // core scan, the action gate, limits, token issuance, and output checks.
    const plan = planCaptureWith(this.#core, this.#piiActive, input, options, this.#limits, {
      random: this.#random,
      isTaken: (token) => this.#entries.has(token),
      budget: () => {
        this.#sweep(at);
        return { liveEntries: this.#entries.size, retainedBytes: this.#retainedBytes };
      },
    });

    // Commit.
    const captureId = this.#issueCaptureId();
    const expiresAt = at + this.#limits.entryTtlMs;
    const grants = new Map<string, ReadonlySet<string>>();
    for (const grant of plan.grants) grants.set(grant.sink, new Set(grant.paths));
    const maxUses = plan.maxUses;
    const tokens: IssuedToken[] = [];
    const captureTokens = new Set<string>();
    let stagedBytes = 0;
    for (const planned of plan.retained) {
      const value = input.slice(planned.start, planned.end);
      const bytes = utf8Length(value);
      stagedBytes += bytes;
      this.#entries.set(planned.token, {
        captureId,
        value,
        bytes,
        type: planned.type,
        grants,
        maxUses,
        used: 0,
        expiresAt,
      });
      captureTokens.add(planned.token);
      tokens.push(Object.freeze({ token: planned.token, type: planned.type }));
    }
    this.#retainedBytes += stagedBytes;
    // A capture that retained nothing has nothing to revoke; do not track it.
    if (captureTokens.size > 0) {
      this.#captures.set(captureId, captureTokens);
      this.#expiry.push({ expiresAt, captureId, tokens: captureTokens });
    }

    this.#audit({ operation: "capture", outcome: "committed", at, entries: tokens.length });
    return Object.freeze({
      captureId,
      text: plan.text,
      tokens: Object.freeze(tokens),
      passedThrough: plan.passedThrough,
      passedThroughTypes: plan.passedThroughTypes,
      unrestorable: plan.unrestorable,
      expiresAt,
    });
  }

  #restore(request: RestoreRequest, at: number): RestoreResult {
    if (typeof request !== "object" || request === null) throw new VaultError("INVALID_ARGUMENT");
    const { sink, fields, captures } = request;
    if (!isIdentifier(sink)) throw new VaultError("INVALID_ARGUMENT");
    if (typeof fields !== "object" || fields === null || Array.isArray(fields)) {
      throw new VaultError("INVALID_ARGUMENT");
    }
    if (!Array.isArray(captures) || captures.length === 0 || captures.length > MAX_GRANTS * 16) {
      throw new VaultError("INVALID_ARGUMENT");
    }
    const sources = new Set<string>();
    for (const id of captures as unknown[]) {
      if (!isIdentifier(id)) throw new VaultError("INVALID_ARGUMENT");
      sources.add(id);
    }
    const deny = (reason: DenialReason): never => {
      // Expired entries seen by a denied request are dropped now rather than
      // left in memory until the next successful operation.
      this.#sweep(at);
      throw new VaultError("RESTORE_DENIED", { reason });
    };

    // Snapshot the request once so getters or later mutation cannot change it.
    const keys = Object.keys(fields);
    if (keys.length > this.#limits.maxRestoreFields) deny("invalid-request");
    const snapshot: Array<[string, string]> = [];
    for (const path of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(fields, path);
      if (descriptor === undefined || !("value" in descriptor)) deny("invalid-request");
      const text: unknown = descriptor?.value;
      if (!isIdentifier(path) || typeof text !== "string") deny("invalid-request");
      if (utf8Length(text as string) > this.#limits.maxRestoreFieldBytes) deny("invalid-request");
      snapshot.push([path, text as string]);
    }

    // Preflight every occurrence before any plaintext or budget changes.
    interface Use {
      readonly entry: Entry;
      count: number;
      readonly paths: Map<string, number>;
    }
    const uses = new Map<string, Use>();
    let occurrences = 0;
    for (const [path, text] of snapshot) {
      const tokens = text.match(TOKEN_PATTERN) ?? [];
      TOKEN_PATTERN.lastIndex = 0;
      if (countMatches(MARKER_PATTERN, text) !== tokens.length) deny("malformed-token");
      for (const token of tokens) {
        const entry = this.#entries.get(token);
        if (entry === undefined) deny("unknown-token");
        const use = uses.get(token) ?? { entry: entry as Entry, count: 0, paths: new Map() };
        use.count += 1;
        use.paths.set(path, (use.paths.get(path) ?? 0) + 1);
        uses.set(token, use);
        occurrences += 1;
      }
    }
    for (const { entry } of uses.values()) {
      if (!sources.has(entry.captureId)) deny("source");
    }
    for (const { entry } of uses.values()) {
      if (at >= entry.expiresAt) deny("expired");
    }
    for (const { entry, paths } of uses.values()) {
      const allowed = entry.grants.get(sink);
      for (const path of paths.keys()) {
        if (allowed === undefined || !allowed.has(path)) deny("sink-or-path");
      }
    }
    for (const { entry, count } of uses.values()) {
      if (entry.used + count > entry.maxUses) deny("budget");
    }
    if (this.#releasePolicy !== undefined) {
      for (const { entry, paths, count: total } of uses.values()) {
        for (const [path, count] of paths) {
          let allowed = false;
          try {
            allowed =
              this.#releasePolicy(
                Object.freeze({
                  captureId: entry.captureId,
                  sink,
                  path,
                  type: entry.type,
                  occurrences: count,
                  totalOccurrences: total,
                  used: entry.used,
                }),
              ) === true;
          } catch {
            allowed = false;
          }
          if (!allowed) deny("policy");
        }
      }
      // A policy callback cannot mutate this vault (re-entry fails BUSY), so
      // the entries validated above are still the live ones.
    }

    // Commit: consume budgets, then build the restored fields.
    const out: Record<string, string> = {};
    for (const [path, text] of snapshot) {
      const restored = text.replace(TOKEN_PATTERN, (token) => (uses.get(token) as Use).entry.value);
      TOKEN_PATTERN.lastIndex = 0;
      Object.defineProperty(out, path, { value: restored, enumerable: true, writable: false });
    }
    for (const [token, { entry, count }] of uses) {
      entry.used += count;
      if (entry.used >= entry.maxUses) this.#removeEntry(token, entry);
    }
    this.#sweep(at);
    this.#audit({
      operation: "restore",
      outcome: "committed",
      at,
      entries: uses.size,
      sink,
      fields: snapshot.length,
    });
    return Object.freeze({ fields: Object.freeze(out), restored: occurrences });
  }

  #issueCaptureId(): string {
    for (let attempt = 0; attempt < TOKEN_ATTEMPTS; attempt += 1) {
      const id = newCaptureIdFrom(this.#random);
      if (!this.#captures.has(id)) return id;
    }
    throw new VaultError("TOKEN_GENERATION_FAILED");
  }

  #removeEntry(token: string, entry: Entry): void {
    this.#entries.delete(token);
    this.#retainedBytes -= entry.bytes;
    entry.value = "";
    const tokens = this.#captures.get(entry.captureId);
    if (tokens !== undefined) {
      tokens.delete(token);
      if (tokens.size === 0) this.#captures.delete(entry.captureId);
    }
  }

  #removeCapture(captureId: string): number {
    const tokens = this.#captures.get(captureId);
    if (tokens === undefined) return 0;
    let removed = 0;
    for (const token of [...tokens]) {
      const entry = this.#entries.get(token);
      if (entry !== undefined) {
        this.#removeEntry(token, entry);
        removed += 1;
      }
    }
    this.#captures.delete(captureId);
    return removed;
  }

  /**
   * Removes every entry with `at >= expiresAt`, visiting only captures that
   * are due: cost follows the expired entries plus a logarithmic queue step
   * per due capture, not the number of retained entries.
   */
  #sweep(at: number): void {
    const queue = this.#expiry;
    for (let next = queue.peek(); next !== undefined && at >= next.expiresAt; next = queue.peek()) {
      queue.pop();
      const { captureId, tokens } = next;
      // Revoked or fully consumed since it was queued (or its id reissued).
      if (this.#captures.get(captureId) !== tokens) continue;
      let remaining = Number.POSITIVE_INFINITY;
      // Deleting the visited element while iterating a Set is well defined.
      for (const token of tokens) {
        const entry = this.#entries.get(token);
        if (entry === undefined) continue;
        if (at >= entry.expiresAt) this.#removeEntry(token, entry);
        else remaining = Math.min(remaining, entry.expiresAt);
      }
      // A capture's entries share one expiry today; requeue any survivor
      // anyway so no live entry can drop out of later sweeps.
      if (remaining !== Number.POSITIVE_INFINITY) {
        queue.push({ expiresAt: remaining, captureId, tokens });
      }
    }
    if (queue.size > 2 * this.#captures.size + EXPIRY_QUEUE_SLACK) {
      queue.retain((item) => this.#captures.get(item.captureId) === item.tokens);
    }
  }

  #disposeAll(): number {
    const removed = this.#entries.size;
    for (const entry of this.#entries.values()) entry.value = "";
    this.#entries.clear();
    this.#captures.clear();
    this.#expiry.clear();
    this.#retainedBytes = 0;
    this.#disposed = true;
    return removed;
  }

  #safeNow(): number {
    try {
      return this.#now();
    } catch {
      return Number.NaN;
    }
  }

  #audit(event: AuditEvent): void {
    if (this.#onAudit === undefined) return;
    try {
      this.#onAudit(Object.freeze(event));
    } catch {
      // Audit delivery never changes an operation's outcome.
    }
  }
}

export type { VaultErrorCode };
