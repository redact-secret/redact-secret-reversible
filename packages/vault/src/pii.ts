/**
 * PII retention and PII option validation helpers.
 *
 * Implements docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md
 * §1 (retention allowlist) and the §3 step-1 shape checks. The activation
 * routine itself (§3 steps 2 to 6) lives in `core-module.ts`.
 * Everything here is shared by the main-thread vault and is written to be
 * reused unchanged by Worker mode (#39): each helper is a pure function of
 * its argument, throws only a fixed, value-free `VaultError`, and never
 * copies or enumerates the core's PII inventory. The only core knowledge is
 * the public `pii_` finding-type prefix and the `selectors=` field of the
 * core's own canonical activation identity.
 */
import { VaultError } from "./errors.js";

/** A finding is a PII finding iff its public type starts with exactly this. */
export const PII_TYPE_PREFIX = "pii_";

/** `CaptureOptions.pii.retain`: 1 to this many entries. */
export const MAX_PII_RETAIN_TYPES = 64;
/** `VaultOptions.pii`: 0 to this many selectors. */
export const MAX_PII_SELECTORS = 64;
/** Longest selector string `VaultOptions.pii` accepts (shape only). */
export const MAX_PII_SELECTOR_LENGTH = 128;
/** Longest `VaultOptions.expectPiiActivation` accepted. */
export const MAX_PII_ACTIVATION_LENGTH = 512;

/**
 * An exact public PII type: the `pii_` prefix, then at least one character
 * from `[a-z0-9_-]`, at most 128 ASCII characters in total.
 */
const PII_TYPE_PATTERN = /^pii_[a-z0-9_-]{1,124}$/;

/** True iff `type` is a PII finding type (prefix check only). */
export function isPiiFindingType(type: string): boolean {
  return type.startsWith(PII_TYPE_PREFIX);
}

function isPlainObject(value: unknown): value is object {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Snapshots an array's elements once, as own data properties only: a getter,
 * a hole, or a proxy trap is never invoked twice, and the result cannot be
 * mutated by the caller afterwards.
 */
function snapshotArray(value: unknown, min: number, max: number): unknown[] {
  if (!Array.isArray(value)) throw new VaultError("INVALID_ARGUMENT");
  const length: unknown = value.length;
  if (typeof length !== "number" || length < min || length > max) {
    throw new VaultError("INVALID_ARGUMENT");
  }
  const out: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined || !("value" in descriptor)) throw new VaultError("INVALID_ARGUMENT");
    out.push(descriptor.value);
  }
  return out;
}

/**
 * Validates `CaptureOptions.pii` (ADR §1). Returns `undefined` when absent,
 * otherwise the de-duplicated set of exact PII types whose `redact` findings
 * may be retained. Fails with a fixed `INVALID_ARGUMENT` when `pii` is not a
 * plain object with exactly the own data key `retain`, when `retain` is not
 * an array of 1 to 64 strings, or when an entry is not an exact public PII
 * type. Unknown but well-formed types are accepted and simply never match.
 */
export function resolvePiiRetention(pii: unknown): ReadonlySet<string> | undefined {
  if (pii === undefined) return undefined;
  if (!isPlainObject(pii)) throw new VaultError("INVALID_ARGUMENT");
  const keys = Reflect.ownKeys(pii);
  if (keys.length !== 1 || keys[0] !== "retain") throw new VaultError("INVALID_ARGUMENT");
  const descriptor = Object.getOwnPropertyDescriptor(pii, "retain");
  if (descriptor === undefined || !("value" in descriptor)) throw new VaultError("INVALID_ARGUMENT");
  const entries = snapshotArray(descriptor.value, 1, MAX_PII_RETAIN_TYPES);
  const retain = new Set<string>();
  for (const entry of entries) {
    if (typeof entry !== "string" || !PII_TYPE_PATTERN.test(entry)) {
      throw new VaultError("INVALID_ARGUMENT");
    }
    retain.add(entry);
  }
  return retain;
}

/**
 * Shape check for `VaultOptions.pii` (ADR §3 step 1): absent, or an array of
 * 0 to 64 strings of 1 to 128 characters. Returns a frozen copy. Selector
 * grammar is the core's to judge (`PII_SELECTOR_*`), not the vault's.
 */
export function resolvePiiSelection(pii: unknown): readonly string[] | undefined {
  if (pii === undefined) return undefined;
  const entries = snapshotArray(pii, 0, MAX_PII_SELECTORS);
  for (const entry of entries) {
    if (typeof entry !== "string" || entry.length === 0 || entry.length > MAX_PII_SELECTOR_LENGTH) {
      throw new VaultError("INVALID_ARGUMENT");
    }
  }
  return Object.freeze(entries as string[]);
}

/** Shape check for `VaultOptions.expectPiiActivation`: absent, or a 1 to 512 character string. */
export function resolveExpectedPiiActivation(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_PII_ACTIVATION_LENGTH) {
    throw new VaultError("INVALID_ARGUMENT");
  }
  return value;
}

/**
 * True iff an observed activation identity has PII detection active: it is
 * not `null` (a core without a PII surface) and its `selectors=` field is
 * present and not `off`. An identity without a readable `selectors=` field
 * counts as inactive (fail closed).
 */
export function isPiiActive(activation: string | null): boolean {
  if (activation === null) return false;
  const field = activation.split(";").find((part) => part.startsWith("selectors="));
  if (field === undefined) return false;
  const selectors = field.slice("selectors=".length);
  return selectors.length > 0 && selectors !== "off";
}
