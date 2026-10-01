/**
 * Shared plumbing of the conformance cases: a seeded generator, synthetic
 * identifiers, assertions with fixed messages, and a per-case bench that
 * builds inputs. Nothing here prints stored bytes.
 */
import { StoreError } from "@redact-secret/vault-contracts";
import type {
  CommitRestoreInput,
  CreateCaptureInput,
  ReadEntriesResult,
  Store,
  StoreCapabilities,
  StoredCapture,
  StoredEntry,
  StoreErrorCode,
  StoreScope,
} from "@redact-secret/vault-contracts";
import { ConformanceFailure, ConformanceSkip } from "./types.js";
import type { ConformanceCase, ConformanceClock, StoreFactory, StoreUnderTest } from "./types.js";

export const HOUR_MS = 60 * 60 * 1000;
export const DAY_MS = 24 * HOUR_MS;

const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";
const HEX = "0123456789abcdef";

/** mulberry32: small, seedable, and good enough to choose operations. Not for keys. */
export class Prng {
  private state: number;

  constructor(seed: number) {
    this.state = seed >>> 0;
  }

  next(): number {
    this.state = (this.state + 0x6d2b79f5) >>> 0;
    let t = this.state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  /** An integer in [0, bound). */
  int(bound: number): number {
    return Math.floor(this.next() * bound);
  }

  chance(probability: number): boolean {
    return this.next() < probability;
  }

  pick<T>(items: readonly T[]): T {
    return at(items, this.int(items.length));
  }

  text(alphabet: string, length: number): string {
    let out = "";
    for (let i = 0; i < length; i += 1) out += alphabet[this.int(alphabet.length)];
    return out;
  }

  bytes(length: number): Uint8Array {
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i += 1) out[i] = this.int(256);
    return out;
  }

  captureId(): string {
    return `cap_${this.text(BASE32, 26)}`;
  }

  entryId(): string {
    return this.text(HEX, 64);
  }
}

export function hashSeed(seed: number, label: string): number {
  let h = (seed ^ 0x811c9dc5) >>> 0;
  for (let i = 0; i < label.length; i += 1) {
    h ^= label.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h;
}

/** A namespace no other case, run, or process will draw. */
export function freshNamespace(): string {
  const random = new Uint8Array(10);
  crypto.getRandomValues(random);
  let suffix = "";
  for (const byte of random) suffix += (HEX[byte >> 4] as string) + (HEX[byte & 15] as string);
  return `conf-${suffix}`;
}

export function at<T>(items: readonly T[], index: number): T {
  const item = items[index];
  if (item === undefined) throw new ConformanceFailure("harness: index out of range");
  return item;
}

/** A description safe to print: enum-like strings, numbers, and shapes. Never bytes or free text. */
export function describe(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) return "undefined";
  if (typeof value === "string") return /^[A-Za-z0-9 :_.,|/-]{0,64}$/.test(value) ? `"${value}"` : "a string";
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (value instanceof Uint8Array) return `bytes(${value.byteLength})`;
  if (Array.isArray(value)) return `array(${value.length})`;
  if (value instanceof StoreError) return `StoreError ${value.code}`;
  if (value instanceof Error) return `a thrown ${describe(value.name)}`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    if (typeof record.outcome === "string") {
      return typeof record.reason === "string"
        ? `${describe(record.outcome)} (${describe(record.reason)})`
        : describe(record.outcome);
    }
    if (typeof record.state === "string") return `state ${describe(record.state)}`;
    return "an object";
  }
  return typeof value;
}

export function fail(what: string): never {
  throw new ConformanceFailure(what);
}

export function check(condition: boolean, what: string): asserts condition {
  if (!condition) fail(what);
}

export function equal(actual: unknown, expected: unknown, what: string): void {
  if (actual !== expected) fail(`${what}: expected ${describe(expected)}, got ${describe(actual)}`);
}

export function outcome(result: unknown, expected: string, what: string): void {
  const actual = (result as { outcome?: unknown } | null)?.outcome;
  if (actual !== expected) fail(`${what}: expected outcome ${describe(expected)}, got ${describe(result)}`);
}

export function rejected(result: unknown, reasons: string | readonly string[], what: string): void {
  const allowed = typeof reasons === "string" ? [reasons] : reasons;
  const record = result as { outcome?: unknown; reason?: unknown } | null;
  if (record?.outcome !== "rejected" || typeof record.reason !== "string" || !allowed.includes(record.reason)) {
    fail(`${what}: expected rejection ${describe(allowed.join("|"))}, got ${describe(result)}`);
  }
}

export async function throwsStoreError(
  call: () => Promise<unknown>,
  codes: StoreErrorCode | readonly StoreErrorCode[],
  what: string,
): Promise<void> {
  const allowed = typeof codes === "string" ? [codes] : codes;
  let result: unknown;
  try {
    result = await call();
  } catch (error) {
    if (!(error instanceof StoreError)) fail(`${what}: expected a StoreError, got ${describe(error)}`);
    if (!allowed.includes(error.code)) {
      fail(`${what}: expected ${describe(allowed.join("|"))}, got ${describe(error)}`);
    }
    if ("cause" in error && (error as { cause?: unknown }).cause !== undefined) {
      fail(`${what}: a StoreError must not carry a cause`);
    }
    return;
  }
  fail(`${what}: expected ${describe(allowed.join("|"))} to be thrown, got ${describe(result)}`);
}

export function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += (HEX[byte >> 4] as string) + (HEX[byte & 15] as string);
  return out;
}

/** A writable deep copy shape, for building deliberately wrong inputs. */
export type Draft<T> = T extends Uint8Array
  ? Uint8Array
  : T extends readonly (infer U)[]
    ? Draft<U>[]
    : T extends object
      ? { -readonly [K in keyof T]: Draft<T[K]> }
      : T;

export function draft<T>(value: T): Draft<T> {
  if (value instanceof Uint8Array) return new Uint8Array(value) as Draft<T>;
  if (Array.isArray(value)) return value.map((item) => draft(item)) as Draft<T>;
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) out[key] = draft(item);
    return out as Draft<T>;
  }
  return value as Draft<T>;
}

/** Copies `value` and applies `change` to the copy. */
export function altered<T>(value: T, change: (copy: Draft<T>) => void): T {
  const copy = draft(value);
  change(copy);
  return copy as T;
}

export interface CaptureHandle {
  readonly scope: StoreScope;
  readonly captureId: string;
  readonly entryIds: readonly string[];
  readonly input: CreateCaptureInput;
}

export interface CaptureOptions {
  readonly scope?: StoreScope;
  readonly entries?: number;
  readonly maxUses?: number | readonly number[];
  readonly lifetimeMs?: number;
  readonly epoch?: number;
  readonly captureId?: string;
  readonly entryIds?: readonly string[];
  readonly sessionTag?: string | null;
  readonly envelopeBytes?: number;
}

export interface UseSpec {
  readonly capture: CaptureHandle;
  /** Index into the capture's entries. Default 0. */
  readonly entry?: number;
  /** Default 1. */
  readonly count?: number;
}

/** Everything one case needs: the store under test, a private namespace, and input builders. */
export class Bench {
  readonly store: Store;
  readonly second: Store;
  readonly clock: ConformanceClock | null;
  readonly sut: StoreUnderTest;
  readonly caps: StoreCapabilities;
  readonly rng: Prng;
  readonly seed: number;
  readonly namespace: string;
  readonly otherNamespace: string;
  readonly tenantA: StoreScope;
  readonly tenantB: StoreScope;
  private attempts = 0;

  constructor(sut: StoreUnderTest, seed: number) {
    this.sut = sut;
    this.store = sut.store;
    this.second = sut.secondStore ?? sut.store;
    this.clock = sut.clock;
    this.caps = sut.store.capabilities();
    this.seed = seed;
    this.rng = new Prng(seed);
    this.namespace = freshNamespace();
    this.otherNamespace = freshNamespace();
    this.tenantA = { namespace: this.namespace, tenant: "tenant-acme-synthetic" };
    this.tenantB = { namespace: this.namespace, tenant: "tenant-globex-synthetic" };
  }

  /** The harness's reading of the store's clock: exact with a controllable clock, an estimate otherwise. */
  now(): number {
    return this.clock === null ? Date.now() : this.clock.now();
  }

  get skew(): number {
    return this.caps.maxClockSkewMs;
  }

  timeTravel(): ConformanceClock {
    if (this.clock === null) {
      throw new ConformanceSkip("the factory supplies no controllable store clock (clock: null)");
    }
    return this.clock;
  }

  attemptId(): string {
    this.attempts += 1;
    return `attempt-synthetic-${this.attempts}-${this.rng.text(BASE32, 8)}`;
  }

  digest(): Uint8Array {
    return this.rng.bytes(32);
  }

  async serving(epoch = 1, namespace = this.namespace): Promise<void> {
    outcome(await this.store.initializeNamespace({ namespace, epoch }), "initialized", "initializeNamespace of a fresh namespace");
  }

  captureInput(options: CaptureOptions = {}): CreateCaptureInput {
    const now = this.now();
    const count = options.entryIds?.length ?? options.entries ?? 1;
    const entries = [];
    for (let i = 0; i < count; i += 1) {
      const maxUses = typeof options.maxUses === "number" ? options.maxUses : (options.maxUses?.[i] ?? 1);
      entries.push({
        entryId: options.entryIds?.[i] ?? this.rng.entryId(),
        maxUses,
        envelope: this.rng.bytes(options.envelopeBytes ?? 24),
      });
    }
    return {
      scope: options.scope ?? this.tenantA,
      epoch: options.epoch ?? 1,
      now,
      capture: {
        captureId: options.captureId ?? this.rng.captureId(),
        sessionTag: options.sessionTag ?? null,
        createdAt: now,
        expiresAt: now + (options.lifetimeMs ?? HOUR_MS),
        lookupVersion: 1,
        keyRef: "synthetic-key:v1",
        wrappedKey: this.rng.bytes(40),
      },
      entries,
    };
  }

  handle(input: CreateCaptureInput): CaptureHandle {
    return {
      scope: input.scope,
      captureId: input.capture.captureId,
      entryIds: input.entries.map((entry) => entry.entryId),
      input,
    };
  }

  async create(options: CaptureOptions = {}): Promise<CaptureHandle> {
    const input = this.captureInput(options);
    outcome(await this.store.createCapture(input), "created", "createCapture of a new capture");
    return this.handle(input);
  }

  /**
   * A capture that is already expired on the store's clock. With a
   * controllable clock the clock is moved past a normal lifetime; without
   * one the capture is created with an expiry just behind the store's clock.
   */
  async createExpired(options: CaptureOptions = {}): Promise<CaptureHandle> {
    if (this.clock !== null) {
      const handle = await this.create(options);
      this.clock.set(handle.input.capture.expiresAt);
      return handle;
    }
    const back = Math.min(1000, this.skew);
    if (back < 100) {
      throw new ConformanceSkip("without a controllable clock this case needs maxClockSkewMs of at least 100");
    }
    const input = altered(this.captureInput(options), (copy) => {
      copy.capture.createdAt = copy.now - back;
      copy.capture.expiresAt = copy.now - back + 1;
    });
    outcome(await this.store.createCapture(input), "created", "createCapture of a capture that is already expired");
    return this.handle(input);
  }

  async read(scope: StoreScope, entryIds: readonly string[]): Promise<ReadEntriesResult> {
    return this.store.readEntries({ scope, entryIds });
  }

  async entry(handle: CaptureHandle, index = 0): Promise<StoredEntry> {
    const entryId = at(handle.entryIds, index);
    const result = await this.read(handle.scope, [entryId]);
    const found = result.entries.find((entry) => entry.entryId === entryId);
    if (found === undefined) fail("readEntries: an entry that was created and not deleted must be returned");
    return found;
  }

  async capture(handle: CaptureHandle): Promise<StoredCapture> {
    const found = (await this.store.readCaptures({ scope: handle.scope, captureIds: [handle.captureId] })).find(
      (capture) => capture.captureId === handle.captureId,
    );
    if (found === undefined) fail("readCaptures: a capture row that exists must be returned");
    return found;
  }

  /** A commit input built, as a server would, from a fresh read of the named entries. */
  async commitInput(specs: readonly UseSpec[], scope: StoreScope = this.tenantA): Promise<CommitRestoreInput> {
    const entryIds = specs.map((spec) => at(spec.capture.entryIds, spec.entry ?? 0));
    const result = await this.read(scope, entryIds);
    return this.commitFromRead(result, specs, scope);
  }

  commitFromRead(result: ReadEntriesResult, specs: readonly UseSpec[], scope: StoreScope = this.tenantA): CommitRestoreInput {
    const captures = new Map<string, { captureId: string; generation: number }>();
    let latest = 0;
    const uses = specs.map((spec) => {
      const entryId = at(spec.capture.entryIds, spec.entry ?? 0);
      const entry = result.entries.find((candidate) => candidate.entryId === entryId);
      const capture = result.captures.find((candidate) => candidate.captureId === spec.capture.captureId);
      if (entry === undefined || capture === undefined) {
        fail("readEntries: an entry that was created and not deleted must be returned with its capture");
      }
      captures.set(capture.captureId, { captureId: capture.captureId, generation: capture.generation });
      latest = Math.max(latest, capture.expiresAt);
      return {
        entryId,
        captureId: capture.captureId,
        count: spec.count ?? 1,
        lifecycleRevision: entry.lifecycleRevision,
        ciphertextRevision: entry.ciphertextRevision,
      };
    });
    return {
      scope,
      epoch: result.recovery.epoch === 0 ? 1 : result.recovery.epoch,
      now: this.now(),
      attempt: { attemptId: this.attemptId(), requestDigest: this.digest() },
      receiptExpiresAt: latest + this.skew + HOUR_MS,
      captures: [...captures.values()],
      uses,
    };
  }

  /** An opaque digest of what the store returns for these captures. Compared, never printed. */
  async fingerprint(handles: readonly CaptureHandle[]): Promise<string> {
    const parts: unknown[] = [await this.store.recoveryState({ namespace: this.namespace })];
    for (const handle of handles) {
      const captures = await this.store.readCaptures({ scope: handle.scope, captureIds: [handle.captureId] });
      const entries = await this.read(handle.scope, handle.entryIds);
      parts.push(
        captures.map((capture) => ({ ...capture, wrappedKey: toHex(capture.wrappedKey) })),
        [...entries.entries]
          .sort((a, b) => (a.entryId < b.entryId ? -1 : 1))
          .map((entry) => ({ ...entry, envelope: toHex(entry.envelope) })),
      );
    }
    return JSON.stringify(parts);
  }
}

export type CaseBody = (bench: Bench) => Promise<void>;

/** Builds cases that each get a fresh `StoreUnderTest` and a private namespace. */
export function caseBuilder(
  factory: StoreFactory,
  seed: number,
  cases: ConformanceCase[],
): (group: string, name: string, body: CaseBody) => void {
  return (group, name, body) => {
    const fullName = `${group}: ${name}`;
    cases.push({
      name: fullName,
      group,
      async run() {
        const sut = await factory();
        try {
          const caseSeed = hashSeed(seed, fullName);
          try {
            await body(new Bench(sut, caseSeed));
          } catch (error) {
            if (error instanceof ConformanceSkip) throw error;
            if (error instanceof ConformanceFailure) {
              throw new ConformanceFailure(`${fullName}: ${error.message} [seed ${seed}]`);
            }
            // An unexpected exception. Its message may be a driver's; only its shape is reported.
            throw new ConformanceFailure(`${fullName}: unexpected ${describe(error)} [seed ${seed}]`);
          }
        } finally {
          if (sut.dispose !== undefined) await sut.dispose();
        }
      },
    });
  };
}
