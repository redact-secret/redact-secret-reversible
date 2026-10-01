/**
 * The capture plan: everything a capture decides before anything is retained.
 *
 * One input goes in; out come the redacted text and, for each finding that
 * may be retained, the issued token, the finding type, and the finding's
 * range in that input. No value is returned: the caller slices the input it
 * already holds. The module reads no vault and keeps no mapping, so the
 * in-memory vault and a persistent server share one implementation of capture
 * eligibility (argument validation, the action gate, the PII allowlist,
 * `eligible`, limits, token issuance, formatting, and output validation).
 *
 * Internal. It is reachable as `@redact-secret/vault/internal/capture-plan`
 * for `@redact-secret/vault-server` only, is not re-exported from the package
 * root or the Worker entry points, and has no stability guarantee.
 */
import type {
  PlaceholderContext,
  PlaceholderFormatter,
  SecretFinding,
} from "@redact-secret/core";

import { activateCore, installedCore } from "./core-module.js";
import type { CoreModule } from "./core-module.js";
import { coreCodeOf, VaultError } from "./errors.js";
import {
  isPiiActive,
  isPiiFindingType,
  resolveExpectedPiiActivation,
  resolvePiiRetention,
  resolvePiiSelection,
} from "./pii.js";
import {
  holdsExactlyOnce,
  MARKER_PATTERN,
  newCaptureId,
  newToken,
  resolveRandomFill,
} from "./token.js";
import type { RandomFill } from "./token.js";
import type { CaptureOptions, VaultLimits, VaultOptions } from "./types.js";

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

export const MAX_IDENTIFIER_LENGTH = 256;
export const MAX_GRANTS = 64;
export const MAX_PATHS_PER_GRANT = 256;
/** Attempts at a fresh token or capture identifier before giving up. */
export const TOKEN_ATTEMPTS = 4;

/** One retained finding: its issued token, type, and range in the input. */
export interface PlannedEntry {
  readonly token: string;
  /** UTF-16 offset into the planned input, inclusive. */
  readonly start: number;
  /** UTF-16 offset into the planned input, exclusive. */
  readonly end: number;
  readonly type: string;
}

/** One release grant, deduplicated: a sink and the paths allowed in it. */
export interface PlannedGrant {
  readonly sink: string;
  readonly paths: readonly string[];
}

export interface CapturePlan {
  /** The redacted text: each retained token exactly once, no other marker. */
  readonly text: string;
  /** Retained findings, in input order. Holds ranges, never values. */
  readonly retained: readonly PlannedEntry[];
  readonly passedThrough: number;
  /** Sorted, deduplicated types of the `warn` and `allow` findings. */
  readonly passedThroughTypes: readonly string[];
  readonly unrestorable: number;
  /** `options.release`, validated; one item per sink, paths deduplicated. */
  readonly grants: readonly PlannedGrant[];
  /** The effective `options.maxUses` (default 1). */
  readonly maxUses: number;
}

/**
 * What the caller already holds, counted against `maxEntries` and
 * `maxRetainedBytes`. A caller that holds nothing in this address space (a
 * persistent server) passes zeros.
 */
export interface CapturePlanBudget {
  readonly liveEntries: number;
  readonly retainedBytes: number;
}

declare const planRandomBrand: unique symbol;

/**
 * An opaque handle to the platform CSPRNG as it was when the handle was
 * acquired. Only `acquirePlanRandom` mints one, so no caller can supply its
 * own random source.
 */
export interface PlanRandom {
  readonly [planRandomBrand]: true;
}

/** What the in-memory vault supplies beyond the plain plan arguments. */
export interface CapturePlanHooks {
  readonly random: PlanRandom;
  /** Whether the holder already has a live entry under `token`. */
  readonly isTaken?: (token: string) => boolean;
  /**
   * Read once, after the input checks and before the core scan, so the
   * holder can drop expired entries at that point and report what remains.
   */
  readonly budget: () => CapturePlanBudget;
}

const randomSources = new WeakMap<PlanRandom, RandomFill>();
let platformRandom: PlanRandom | undefined;

/**
 * Captures the platform CSPRNG (`crypto.getRandomValues`) behind an opaque
 * handle. Fails `UNSUPPORTED_RUNTIME` when the runtime has none.
 */
export function acquirePlanRandom(): PlanRandom {
  const fill = resolveRandomFill();
  if (fill === undefined) throw new VaultError("UNSUPPORTED_RUNTIME");
  const handle = Object.freeze({}) as PlanRandom;
  randomSources.set(handle, fill);
  return handle;
}

function fillOf(random: PlanRandom): RandomFill {
  const fill = randomSources.get(random);
  if (fill === undefined) throw new VaultError("INVALID_ARGUMENT");
  return fill;
}

/** The platform CSPRNG, resolved on first use and kept for the module's life. */
function platform(): PlanRandom {
  platformRandom ??= acquirePlanRandom();
  return platformRandom;
}

/**
 * UTF-8 length of `text.slice(start, end)` without materializing the slice
 * or an encoded copy. A surrogate pair split by `end` counts as a lone
 * surrogate, exactly as it would in the slice.
 */
export function utf8Length(text: string, start = 0, end = text.length): number {
  let bytes = 0;
  for (let i = start; i < end; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit < 0x80) bytes += 1;
    else if (unit < 0x800) bytes += 2;
    else if (unit >= 0xd800 && unit <= 0xdbff && i + 1 < end) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        i += 1;
      } else bytes += 3;
    } else bytes += 3;
  }
  return bytes;
}

export function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_IDENTIFIER_LENGTH;
}

export function isCount(value: unknown, ceiling: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1 && value <= ceiling;
}

/**
 * Applies `partial` over `DEFAULT_LIMITS`. An unknown key, or a value that is
 * not a positive safe integer at or below its ceiling, fails
 * `INVALID_ARGUMENT`. The result is frozen.
 */
export function resolveCaptureLimits(partial: Partial<VaultLimits> | undefined): VaultLimits {
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

function issueToken(
  fill: RandomFill,
  staged: ReadonlySet<string>,
  isTaken: ((token: string) => boolean) | undefined,
): string {
  for (let attempt = 0; attempt < TOKEN_ATTEMPTS; attempt += 1) {
    let token: string;
    try {
      token = newToken(fill);
    } catch {
      throw new VaultError("TOKEN_GENERATION_FAILED");
    }
    if (!(isTaken?.(token) ?? false) && !staged.has(token)) return token;
  }
  throw new VaultError("TOKEN_GENERATION_FAILED");
}

interface Staged {
  readonly token: string;
  readonly start: number;
  readonly end: number;
  readonly type: string;
}

/**
 * The plan as the in-memory vault runs it: with the random handle the vault
 * acquired when it was opened, a check against its live tokens, and a budget
 * read at the point where it sweeps expired entries. `planCapture` is this
 * function with the platform's random source, no live tokens, and a fixed
 * budget.
 *
 * Throws only `VaultError`, with the codes and in the order a capture has
 * always used.
 */
export function planCaptureWith(
  core: CoreModule,
  piiActive: boolean,
  input: string,
  options: CaptureOptions,
  limits: VaultLimits,
  hooks: CapturePlanHooks,
): CapturePlan {
  if (typeof input !== "string") throw new VaultError("INVALID_ARGUMENT");
  if (typeof options !== "object" || options === null) throw new VaultError("INVALID_ARGUMENT");
  const grants = resolveGrants(options.release);
  const maxUses = options.maxUses ?? 1;
  if (!isCount(maxUses, limits.maxUsesPerEntry)) throw new VaultError("INVALID_ARGUMENT");
  const mode = options.unredacted ?? "reject";
  if (mode !== "reject" && mode !== "pass-through") throw new VaultError("INVALID_ARGUMENT");
  const eligible = options.eligible;
  const display: PlaceholderFormatter =
    options.displayFormatter ?? core.defaultPlaceholderFormatter;
  if (eligible !== undefined && typeof eligible !== "function") {
    throw new VaultError("INVALID_ARGUMENT");
  }
  if (typeof display !== "function") throw new VaultError("INVALID_ARGUMENT");
  // PII retention allowlist (ADR §1): validated before the core runs, and
  // refused outright when the core cannot produce PII findings at all.
  const piiRetain = resolvePiiRetention(options.pii);
  if (piiRetain !== undefined && !piiActive) throw new VaultError("PII_UNAVAILABLE");

  if (utf8Length(input) > limits.maxInputBytes) throw new VaultError("LIMIT_EXCEEDED");
  // A token-like literal in the input would be indistinguishable from an
  // issued token after redaction; refuse rather than guess provenance.
  MARKER_PATTERN.lastIndex = 0;
  if (MARKER_PATTERN.test(input)) {
    MARKER_PATTERN.lastIndex = 0;
    throw new VaultError("TOKEN_LITERAL_IN_INPUT");
  }
  MARKER_PATTERN.lastIndex = 0;

  const fill = fillOf(hooks.random);
  const budget = hooks.budget();
  const coreLimits = {
    maxInputBytes: limits.maxInputBytes,
    maxFindings: limits.maxFindings,
  };

  let findings: readonly SecretFinding[];
  try {
    findings = core.scan(input, {
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

  if (budget.liveEntries + retain.length > limits.maxEntries) {
    throw new VaultError("LIMIT_EXCEEDED");
  }

  // Stage: ranges and tokens only. The values stay in the caller's input.
  const staged = new Map<string, Staged>();
  const stagedTokens = new Set<string>();
  let stagedBytes = 0;
  for (const finding of retain) {
    const bytes = utf8Length(input, finding.start, finding.end);
    stagedBytes += bytes;
    if (bytes > limits.maxValueBytes || budget.retainedBytes + stagedBytes > limits.maxRetainedBytes) {
      throw new VaultError("LIMIT_EXCEEDED");
    }
    const token = issueToken(fill, stagedTokens, hooks.isTaken);
    stagedTokens.add(token);
    staged.set(finding.id, { token, start: finding.start, end: finding.end, type: finding.type });
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
    text = core.redact(input, findings, { placeholderFormatter: formatter, limits: coreLimits });
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

  const retained: PlannedEntry[] = [];
  for (const entry of staged.values()) retained.push(Object.freeze({ ...entry }));
  const plannedGrants: PlannedGrant[] = [];
  for (const [sink, paths] of grants) {
    plannedGrants.push(Object.freeze({ sink, paths: Object.freeze([...paths]) }));
  }
  return Object.freeze({
    text,
    retained: Object.freeze(retained),
    passedThrough,
    passedThroughTypes: Object.freeze([...passedTypes].sort()),
    unrestorable,
    grants: Object.freeze(plannedGrants),
    maxUses,
  });
}

function isBudgetCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/**
 * Plans the capture of one input for a caller that holds its own mapping.
 *
 * Tokens come from the platform CSPRNG, resolved inside this module; there is
 * no parameter for a random source. They are unique within the plan; whether
 * one collides with an entry the caller already holds is for the caller's
 * store to reject (a token carries 128 random bits).
 *
 * Fails `UNSUPPORTED_RUNTIME` without `crypto.getRandomValues`, and otherwise
 * with the same codes as `Vault.capture`.
 */
export function planCapture(
  core: CoreModule,
  piiActive: boolean,
  input: string,
  options: CaptureOptions,
  limits: VaultLimits,
  budget: CapturePlanBudget,
): CapturePlan {
  const random = platform();
  if (typeof budget !== "object" || budget === null) throw new VaultError("INVALID_ARGUMENT");
  const { liveEntries, retainedBytes } = budget;
  if (!isBudgetCount(liveEntries) || !isBudgetCount(retainedBytes)) {
    throw new VaultError("INVALID_ARGUMENT");
  }
  const held = { liveEntries, retainedBytes };
  return planCaptureWith(core, piiActive, input, options, limits, { random, budget: () => held });
}

/**
 * One capture identifier from a random handle. Fails
 * `TOKEN_GENERATION_FAILED` when the source throws.
 */
export function newCaptureIdFrom(random: PlanRandom): string {
  const fill = fillOf(random);
  try {
    return newCaptureId(fill);
  } catch {
    throw new VaultError("TOKEN_GENERATION_FAILED");
  }
}

/**
 * A fresh capture identifier (`cap_` + 26 base32 characters, 128 random
 * bits) from the platform CSPRNG. Uniqueness against identifiers the caller
 * already holds is for the caller's store to enforce.
 */
export function newPlannedCaptureId(): string {
  return newCaptureIdFrom(platform());
}

/** The part of `VaultOptions` that selects and checks the core's PII activation. */
export interface CapturePlannerOptions {
  readonly pii?: VaultOptions["pii"];
  readonly expectPiiActivation?: VaultOptions["expectPiiActivation"];
}

/**
 * Plans captures against one established core, for a caller that holds its
 * own mapping. It retains nothing between calls.
 */
export interface CapturePlanner {
  /** Same value `Vault.piiActivation` reports. */
  readonly piiActivation: string | null;
  /** `planCapture` with nothing already held and no live tokens to avoid. */
  plan(input: string, options: CaptureOptions, limits: VaultLimits): CapturePlan;
  /** A fresh capture identifier; see `newPlannedCaptureId`. */
  newCaptureId(): string;
}

/**
 * What opening a vault and opening a planner share: capture the platform
 * CSPRNG (`UNSUPPORTED_RUNTIME` when absent), shape-check the PII options
 * (ADR §3 step 1), then forward or adopt the core's activation and observe
 * it once (steps 2 to 6).
 */
export async function establishCapture(
  core: CoreModule,
  options: CapturePlannerOptions,
): Promise<{ readonly random: PlanRandom; readonly piiActivation: string | null }> {
  const random = acquirePlanRandom();
  const selection = resolvePiiSelection(options.pii);
  const expected = resolveExpectedPiiActivation(options.expectPiiActivation);
  const piiActivation = await activateCore(core, selection, expected);
  return { random, piiActivation };
}

const NOTHING_HELD: CapturePlanBudget = Object.freeze({ liveEntries: 0, retainedBytes: 0 });

/**
 * `openCapturePlanner` against an explicit core module. It exists so tests
 * can run the planner against a fake core, as `openVault` does for the vault.
 */
export async function openCapturePlannerFor(
  core: CoreModule,
  options: CapturePlannerOptions = {},
): Promise<CapturePlanner> {
  if (typeof options !== "object" || options === null) throw new VaultError("INVALID_ARGUMENT");
  const { random, piiActivation } = await establishCapture(core, options);
  const piiActive = isPiiActive(piiActivation);
  const held = (): CapturePlanBudget => NOTHING_HELD;
  return Object.freeze({
    piiActivation,
    plan: (input: string, capture: CaptureOptions, limits: VaultLimits): CapturePlan =>
      planCaptureWith(core, piiActive, input, capture, limits, { random, budget: held }),
    newCaptureId: (): string => newCaptureIdFrom(random),
  });
}

/**
 * Establishes the installed `@redact-secret/core` exactly as `createVault`
 * does, without opening a vault: it checks the CSPRNG, forwards
 * `options.pii` to the core when supplied or adopts the existing activation
 * otherwise, and compares `options.expectPiiActivation`. Fails with the codes
 * `createVault` uses for those steps (`UNSUPPORTED_RUNTIME`,
 * `INVALID_ARGUMENT`, `PII_UNAVAILABLE`, `CORE_FAILURE`,
 * `PII_ACTIVATION_MISMATCH`).
 */
export async function openCapturePlanner(options: CapturePlannerOptions = {}): Promise<CapturePlanner> {
  return openCapturePlannerFor(installedCore, options);
}
