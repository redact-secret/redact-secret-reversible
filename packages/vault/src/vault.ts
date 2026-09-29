import type {
  PlaceholderContext,
  PlaceholderFormatter,
  SecretFinding,
} from "@redact-secret/core";

import { activateCore, installedCore } from "./core-module.js";
import type { CoreModule } from "./core-module.js";
import { coreCodeOf, VaultError } from "./errors.js";
import type { DenialReason, VaultErrorCode } from "./errors.js";
import {
  isPiiActive,
  isPiiFindingType,
  resolveExpectedPiiActivation,
  resolvePiiRetention,
  resolvePiiSelection,
} from "./pii.js";
import {
  countMatches,
  holdsExactlyOnce,
  MARKER_PATTERN,
  newCaptureId,
  newToken,
  resolveRandomFill,
  TOKEN_PATTERN,
} from "./token.js";
import type { RandomFill } from "./token.js";
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

export const DEFAULT_LIMITS: Readonly<VaultLimits> = Object.freeze({
  maxEntries: 256,
  maxRetainedBytes: 64 * 1024,
  maxValueBytes: 8 * 1024,
  entryTtlMs: 10 * 60 * 1000,
  vaultTtlMs: 60 * 60 * 1000,
  maxInputBytes: 1024 * 1024,
  maxFindings: 1024,
  maxRestoreFields: 64,
  maxRestoreFieldBytes: 1024 * 1024,
  maxUsesPerEntry: 16,
});

/** Hard ceilings: a configured limit above these is rejected, not clamped. */
export const LIMIT_CEILINGS: Readonly<VaultLimits> = Object.freeze({
  maxEntries: 100_000,
  maxRetainedBytes: 64 * 1024 * 1024,
  maxValueBytes: 1024 * 1024,
  entryTtlMs: 24 * 60 * 60 * 1000,
  vaultTtlMs: 24 * 60 * 60 * 1000,
  maxInputBytes: 64 * 1024 * 1024,
  maxFindings: 50_000,
  maxRestoreFields: 10_000,
  maxRestoreFieldBytes: 64 * 1024 * 1024,
  maxUsesPerEntry: 1_000,
});

const MAX_IDENTIFIER_LENGTH = 256;
const MAX_GRANTS = 64;
const MAX_PATHS_PER_GRANT = 256;
const TOKEN_ATTEMPTS = 4;

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

interface Staged {
  readonly findingId: string;
  readonly token: string;
  readonly value: string;
  readonly bytes: number;
  readonly type: string;
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

function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_IDENTIFIER_LENGTH;
}

function isCount(value: unknown, ceiling: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1 && value <= ceiling;
}

function resolveLimits(partial: Partial<VaultLimits> | undefined): VaultLimits {
  if (partial !== undefined && (typeof partial !== "object" || partial === null)) {
    throw new VaultError("INVALID_ARGUMENT");
  }
  const resolved: Record<string, number> = { ...DEFAULT_LIMITS };
  for (const key of Object.keys(partial ?? {})) {
    if (!Object.hasOwn(DEFAULT_LIMITS, key)) throw new VaultError("INVALID_ARGUMENT");
    const value = (partial as Record<string, unknown>)[key];
    if (value === undefined) continue;
    if (!isCount(value, LIMIT_CEILINGS[key as keyof VaultLimits])) {
      throw new VaultError("INVALID_ARGUMENT");
    }
    resolved[key] = value;
  }
  return Object.freeze(resolved) as unknown as VaultLimits;
}

function resolveGrants(release: unknown): Map<string, Set<string>> {
  if (!Array.isArray(release) || release.length === 0 || release.length > MAX_GRANTS) {
    throw new VaultError("INVALID_ARGUMENT");
  }
  const grants = new Map<string, Set<string>>();
  for (const grant of release as unknown[]) {
    if (typeof grant !== "object" || grant === null) throw new VaultError("INVALID_ARGUMENT");
    const { sink, paths } = grant as { sink?: unknown; paths?: unknown };
    if (!isIdentifier(sink) || !Array.isArray(paths)) throw new VaultError("INVALID_ARGUMENT");
    if (paths.length === 0 || paths.length > MAX_PATHS_PER_GRANT) {
      throw new VaultError("INVALID_ARGUMENT");
    }
    const set = grants.get(sink) ?? new Set<string>();
    for (const path of paths as unknown[]) {
      if (!isIdentifier(path)) throw new VaultError("INVALID_ARGUMENT");
      set.add(path);
    }
    grants.set(sink, set);
  }
  return grants;
}

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
  const limits = resolveLimits(options.limits);
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

  const fill = resolveRandomFill();
  if (fill === undefined) throw new VaultError("UNSUPPORTED_RUNTIME");

  // ADR §3 step 1: shape only. The core owns selector grammar.
  const selection = resolvePiiSelection(options.pii);
  const expected = resolveExpectedPiiActivation(options.expectPiiActivation);
  // Steps 2 to 6: forward the application's selection or adopt; observe once.
  const piiActivation = await activateCore(core, selection, expected);

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
    fill,
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
  readonly #fill: RandomFill;
  readonly #now: () => number;
  readonly #releasePolicy: ReleasePolicy | undefined;
  readonly #onAudit: AuditHook | undefined;
  readonly #expiresAt: number;
  readonly #entries = new Map<string, Entry>();
  readonly #captures = new Map<string, Set<string>>();
  #retainedBytes = 0;
  #disposed = false;
  #busy = false;

  constructor(
    core: CoreModule,
    piiActivation: string | null,
    limits: VaultLimits,
    fill: RandomFill,
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
    this.#fill = fill;
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
    if (typeof input !== "string") throw new VaultError("INVALID_ARGUMENT");
    if (typeof options !== "object" || options === null) throw new VaultError("INVALID_ARGUMENT");
    const grants = resolveGrants(options.release);
    const maxUses = options.maxUses ?? 1;
    if (!isCount(maxUses, this.#limits.maxUsesPerEntry)) throw new VaultError("INVALID_ARGUMENT");
    const mode = options.unredacted ?? "reject";
    if (mode !== "reject" && mode !== "pass-through") throw new VaultError("INVALID_ARGUMENT");
    const eligible = options.eligible;
    const display: PlaceholderFormatter =
      options.displayFormatter ?? this.#core.defaultPlaceholderFormatter;
    if (eligible !== undefined && typeof eligible !== "function") {
      throw new VaultError("INVALID_ARGUMENT");
    }
    if (typeof display !== "function") throw new VaultError("INVALID_ARGUMENT");
    // PII retention allowlist (ADR §1): validated before the core runs, and
    // refused outright when the core cannot produce PII findings at all.
    const piiRetain = resolvePiiRetention(options.pii);
    if (piiRetain !== undefined && !this.#piiActive) throw new VaultError("PII_UNAVAILABLE");

    if (utf8Length(input) > this.#limits.maxInputBytes) throw new VaultError("LIMIT_EXCEEDED");
    // A token-like literal in the input would be indistinguishable from an
    // issued token after redaction; refuse rather than guess provenance.
    MARKER_PATTERN.lastIndex = 0;
    if (MARKER_PATTERN.test(input)) {
      MARKER_PATTERN.lastIndex = 0;
      throw new VaultError("TOKEN_LITERAL_IN_INPUT");
    }
    MARKER_PATTERN.lastIndex = 0;

    this.#sweep(at);
    const coreLimits = {
      maxInputBytes: this.#limits.maxInputBytes,
      maxFindings: this.#limits.maxFindings,
    };

    let findings: readonly SecretFinding[];
    try {
      findings = this.#core.scan(input, {
        ...(options.policy === undefined ? {} : { policy: options.policy }),
        ...(options.ruleset === undefined ? {} : { ruleset: options.ruleset }),
        limits: coreLimits,
      });
    } catch (thrown) {
      throw new VaultError("CORE_FAILURE", { coreCode: coreCodeOf(thrown) });
    }

    // Gate on every finalized action before staging anything.
    let passedThrough = 0;
    const passedTypes = new Set<string>();
    const retain: SecretFinding[] = [];
    let unrestorable = 0;
    let previousEnd = 0;
    for (const finding of findings) {
      const { start, end } = finding;
      if (
        !Number.isSafeInteger(start) ||
        !Number.isSafeInteger(end) ||
        start < previousEnd ||
        end <= start ||
        end > input.length
      ) {
        throw new VaultError("INVARIANT_VIOLATION");
      }
      previousEnd = end;
      switch (finding.action) {
        case "block":
          throw new VaultError("BLOCKED_FINDING");
        case "warn":
        case "allow":
          passedThrough += 1;
          passedTypes.add(finding.type);
          break;
        case "redact": {
          let keep = true;
          if (isPiiFindingType(finding.type) && (piiRetain === undefined || !piiRetain.has(finding.type))) {
            // A PII finding outside the exact-type allowlist is never
            // retained, and `eligible` is not consulted: it may narrow the
            // allowlist, never widen it.
            keep = false;
          } else if (eligible !== undefined) {
            try {
              keep = eligible(finding) === true;
            } catch {
              throw new VaultError("INVALID_ARGUMENT");
            }
          }
          if (keep) retain.push(finding);
          else unrestorable += 1;
          break;
        }
        default:
          throw new VaultError("INVARIANT_VIOLATION");
      }
    }
    if (passedThrough > 0 && mode === "reject") throw new VaultError("UNREDACTED_FINDINGS");

    if (this.#entries.size + retain.length > this.#limits.maxEntries) {
      throw new VaultError("LIMIT_EXCEEDED");
    }

    // Stage: nothing below is visible to any other operation until commit.
    const staged = new Map<string, Staged>();
    const stagedTokens = new Set<string>();
    let stagedBytes = 0;
    for (const finding of retain) {
      const value = input.slice(finding.start, finding.end);
      const bytes = utf8Length(value);
      stagedBytes += bytes;
      if (bytes > this.#limits.maxValueBytes || this.#retainedBytes + stagedBytes > this.#limits.maxRetainedBytes) {
        throw new VaultError("LIMIT_EXCEEDED");
      }
      const token = this.#issueToken(stagedTokens);
      stagedTokens.add(token);
      staged.set(finding.id, { findingId: finding.id, token, value, bytes, type: finding.type });
    }

    const formatted = new Set<string>();
    let formatterFault = false;
    const formatter: PlaceholderFormatter = (finding: SecretFinding, context: PlaceholderContext) => {
      const entry = staged.get(finding.id);
      if (entry !== undefined) {
        if (formatted.has(finding.id)) formatterFault = true;
        formatted.add(finding.id);
        return entry.token;
      }
      const label = display(finding, context);
      MARKER_PATTERN.lastIndex = 0;
      const spoof = typeof label !== "string" || MARKER_PATTERN.test(label);
      MARKER_PATTERN.lastIndex = 0;
      if (spoof) {
        formatterFault = true;
        throw new Error("display placeholder rejected");
      }
      return label;
    };

    let text: string;
    try {
      text = this.#core.redact(input, findings, { placeholderFormatter: formatter, limits: coreLimits });
    } catch (thrown) {
      if (thrown instanceof VaultError) throw thrown;
      throw new VaultError("CORE_FAILURE", { coreCode: coreCodeOf(thrown) });
    }

    // Validate the output corresponds exactly to the staged tokens.
    if (formatterFault || formatted.size !== staged.size) throw new VaultError("INVARIANT_VIOLATION");
    // One pass over the output (#88): each staged token exactly once, no other marker.
    if (stagedTokens.size !== staged.size || !holdsExactlyOnce(text, stagedTokens)) {
      throw new VaultError("INVARIANT_VIOLATION");
    }

    // Commit.
    const captureId = this.#issueCaptureId();
    const expiresAt = at + this.#limits.entryTtlMs;
    const tokens: IssuedToken[] = [];
    const captureTokens = new Set<string>();
    for (const entry of staged.values()) {
      this.#entries.set(entry.token, {
        captureId,
        value: entry.value,
        bytes: entry.bytes,
        type: entry.type,
        grants,
        maxUses,
        used: 0,
        expiresAt,
      });
      captureTokens.add(entry.token);
      tokens.push(Object.freeze({ token: entry.token, type: entry.type }));
    }
    this.#retainedBytes += stagedBytes;
    // A capture that retained nothing has nothing to revoke; do not track it.
    if (captureTokens.size > 0) this.#captures.set(captureId, captureTokens);
    staged.clear();

    this.#audit({ operation: "capture", outcome: "committed", at, entries: tokens.length });
    return Object.freeze({
      captureId,
      text,
      tokens: Object.freeze(tokens),
      passedThrough,
      passedThroughTypes: Object.freeze([...passedTypes].sort()),
      unrestorable,
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

  #issueToken(staged: ReadonlySet<string>): string {
    for (let attempt = 0; attempt < TOKEN_ATTEMPTS; attempt += 1) {
      let token: string;
      try {
        token = newToken(this.#fill);
      } catch {
        throw new VaultError("TOKEN_GENERATION_FAILED");
      }
      if (!this.#entries.has(token) && !staged.has(token)) return token;
    }
    throw new VaultError("TOKEN_GENERATION_FAILED");
  }

  #issueCaptureId(): string {
    for (let attempt = 0; attempt < TOKEN_ATTEMPTS; attempt += 1) {
      let id: string;
      try {
        id = newCaptureId(this.#fill);
      } catch {
        throw new VaultError("TOKEN_GENERATION_FAILED");
      }
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

  #sweep(at: number): void {
    for (const [token, entry] of [...this.#entries]) {
      if (at >= entry.expiresAt) this.#removeEntry(token, entry);
    }
  }

  #disposeAll(): number {
    const removed = this.#entries.size;
    for (const entry of this.#entries.values()) entry.value = "";
    this.#entries.clear();
    this.#captures.clear();
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
