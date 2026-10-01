/**
 * `createFaultyStore`: a `Store` wrapper that injects failures by operation
 * and call index, for testing how a caller behaves when a store is
 * unavailable, ambiguous, slow, leaky, skewed, or lying.
 *
 * It injects faults; it does not check the caller. All injected text is
 * synthetic.
 */
import { StoreError } from "@redact-secret/vault-contracts";
import type { Store, StoreCallOptions, StoreCapabilities } from "@redact-secret/vault-contracts";

export type StoreOperation = Exclude<keyof Store, "capabilities">;

const OPERATIONS: readonly StoreOperation[] = [
  "createCapture",
  "readEntries",
  "readCaptures",
  "commitRestore",
  "revokeCapture",
  "inspectAttempt",
  "replaceCaptureKey",
  "deleteCiphertext",
  "sweepExpired",
  "recoveryState",
  "initializeNamespace",
  "quarantine",
  "invalidateRecovered",
];

/**
 * A marker that appears in every foreign error this wrapper throws. A caller
 * that sanitizes errors correctly never lets it reach a message, an audit
 * event, or a log. It is not a credential.
 */
export const SYNTHETIC_SECRET_MARKER = "SYNTHETIC-NOT-A-SECRET-0000";

const FOREIGN_MESSAGE = `synthetic driver failure at db.invalid: credential=${SYNTHETIC_SECRET_MARKER}`;
const FOREIGN_CAPTURE_ID = "cap_foreignforeignforeignforei";
const FOREIGN_ENTRY_ID = "f".repeat(64);

export type MalformedShape =
  /** Any operation: a result whose fields have the wrong types. */
  | "wrong-types"
  /** Any operation: `null`. */
  | "null"
  /** readEntries, readCaptures: one extra row of a capture nobody asked for. */
  | "foreign-entry"
  /** readEntries: the first entry claims another capture. */
  | "mismatched-capture"
  /** readEntries: entries are returned without their captures. */
  | "missing-capture"
  /** readEntries: the first entry is returned twice. */
  | "duplicate-entry"
  /** readEntries, readCaptures: every lifecycleRevision and generation is one too high. */
  | "revision-lie"
  /** readEntries: every entry claims `used` 0. */
  | "budget-lie";

export type Fault =
  /** Throws STORE_UNAVAILABLE without calling the inner store: no effect. */
  | { readonly kind: "unavailable" }
  /**
   * Throws STORE_AMBIGUOUS. With `applied: true` the inner store is called
   * first and its response is lost; with `applied: false` it is not called.
   */
  | { readonly kind: "ambiguous"; readonly applied: boolean }
  /** Waits before and/or after calling the inner store. */
  | { readonly kind: "delay"; readonly beforeMs?: number; readonly afterMs?: number }
  /**
   * Throws an `Error` that is not a `StoreError` and carries
   * `SYNTHETIC_SECRET_MARKER` in its message, a property, and its `cause`.
   * With `when: "after"` the inner store is called first.
   */
  | { readonly kind: "foreign-error"; readonly when: "before" | "after" }
  /** Calls the inner store and returns a corrupted version of its result. */
  | { readonly kind: "malformed"; readonly shape: MalformedShape }
  /** Shifts the input's `now` by `shiftMs` before calling the inner store. */
  | { readonly kind: "clock-skew"; readonly shiftMs: number }
  /** Returns `result` as is. With `delegate: false` the inner store is not called. */
  | { readonly kind: "result"; readonly result: unknown; readonly delegate: boolean };

export interface FaultRule {
  readonly operation: StoreOperation;
  /** Zero-based index among the calls of `operation`. Omitted: every call. */
  readonly call?: number;
  readonly fault: Fault;
}

export interface FaultPlan {
  readonly rules?: readonly FaultRule[];
  /** How a delay waits. Default: `setTimeout`. */
  readonly sleep?: (ms: number) => Promise<void>;
  /** Fields that replace the inner store's declared capabilities, to model an adapter that misdeclares itself. */
  readonly capabilities?: Readonly<Record<string, unknown>>;
}

export interface FaultLogEntry {
  readonly operation: StoreOperation;
  readonly call: number;
  readonly faults: readonly Fault["kind"][];
}

export interface FaultControl {
  /** How many times `operation` was called on the wrapper. */
  calls(operation: StoreOperation): number;
  /** Every call so far, in order, with the faults applied to it. */
  log(): readonly FaultLogEntry[];
  /** Adds a rule. Call indexes keep counting from the wrapper's creation. */
  add(rule: FaultRule): void;
  /** Removes every rule. Call counts and the log are kept. */
  clear(): void;
}

export type FaultyStore = Store & { readonly faults: FaultControl };

const READ_SHAPES: Readonly<Record<MalformedShape, readonly StoreOperation[] | "any">> = {
  "wrong-types": "any",
  null: "any",
  "foreign-entry": ["readEntries", "readCaptures"],
  "mismatched-capture": ["readEntries"],
  "missing-capture": ["readEntries"],
  "duplicate-entry": ["readEntries"],
  "revision-lie": ["readEntries", "readCaptures"],
  "budget-lie": ["readEntries"],
};

function checkRule(rule: FaultRule): void {
  if (typeof rule !== "object" || rule === null || !OPERATIONS.includes(rule.operation)) {
    throw new TypeError("createFaultyStore: a rule names an unknown operation.");
  }
  if (rule.call !== undefined && (!Number.isSafeInteger(rule.call) || rule.call < 0)) {
    throw new TypeError("createFaultyStore: a rule's call index must be a non-negative integer.");
  }
  const fault = rule.fault;
  if (typeof fault !== "object" || fault === null) throw new TypeError("createFaultyStore: a rule has no fault.");
  switch (fault.kind) {
    case "unavailable":
    case "ambiguous":
    case "delay":
    case "foreign-error":
    case "clock-skew":
    case "result":
      return;
    case "malformed": {
      const allowed = READ_SHAPES[fault.shape];
      if (allowed === undefined || (allowed !== "any" && !allowed.includes(rule.operation))) {
        throw new TypeError("createFaultyStore: this malformed shape does not apply to this operation.");
      }
      return;
    }
    default:
      throw new TypeError("createFaultyStore: a rule has an unknown fault kind.");
  }
}

function foreignError(): Error {
  const error = new Error(FOREIGN_MESSAGE, { cause: new Error(FOREIGN_MESSAGE) });
  error.name = "SyntheticDriverError";
  (error as Error & { detail?: string }).detail = SYNTHETIC_SECRET_MARKER;
  return error;
}

function shifted(input: unknown, shiftMs: number): unknown {
  if (typeof input !== "object" || input === null) return input;
  const now = (input as { now?: unknown }).now;
  return typeof now === "number" ? { ...input, now: now + shiftMs } : input;
}

function malformed(shape: MalformedShape, result: unknown): unknown {
  if (shape === "null") return null;
  if (shape === "wrong-types") {
    return { outcome: 42, reason: {}, state: 7, epoch: "1", recovery: "serving", entries: "not-an-array", captures: null, requestDigest: "not-bytes" };
  }
  const foreignCapture = {
    captureId: FOREIGN_CAPTURE_ID,
    state: "live",
    generation: 1,
    keyRevision: 1,
    epoch: 1,
    sessionTag: null,
    createdAt: 0,
    expiresAt: Number.MAX_SAFE_INTEGER,
    keyRef: "synthetic-foreign-key",
    wrappedKey: new Uint8Array(40),
  };
  if (Array.isArray(result)) {
    // readCaptures
    const captures = result as Record<string, unknown>[];
    if (shape === "foreign-entry") return [...captures, foreignCapture];
    return captures.map((capture) => ({ ...capture, generation: Number(capture.generation) + 1 }));
  }
  const read = result as { recovery: unknown; entries: Record<string, unknown>[]; captures: Record<string, unknown>[] };
  const first = read.entries[0];
  switch (shape) {
    case "foreign-entry":
      return {
        recovery: read.recovery,
        entries: [
          ...read.entries,
          {
            entryId: FOREIGN_ENTRY_ID,
            captureId: FOREIGN_CAPTURE_ID,
            maxUses: 1000,
            used: 0,
            lifecycleRevision: 1,
            ciphertextRevision: 1,
            envelope: new Uint8Array(24),
          },
        ],
        captures: [...read.captures, foreignCapture],
      };
    case "mismatched-capture":
      return {
        ...read,
        entries: first === undefined ? [] : [{ ...first, captureId: FOREIGN_CAPTURE_ID }, ...read.entries.slice(1)],
      };
    case "missing-capture":
      return { ...read, captures: [] };
    case "duplicate-entry":
      return { ...read, entries: first === undefined ? [] : [first, ...read.entries] };
    case "revision-lie":
      return {
        recovery: read.recovery,
        entries: read.entries.map((entry) => ({ ...entry, lifecycleRevision: Number(entry.lifecycleRevision) + 1 })),
        captures: read.captures.map((capture) => ({ ...capture, generation: Number(capture.generation) + 1 })),
      };
    case "budget-lie":
      return { ...read, entries: read.entries.map((entry) => ({ ...entry, used: 0 })) };
  }
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * Wraps `inner`. Rules that match a call are applied together: every
 * `clock-skew` and `delay` rule, and the first rule of any other kind.
 */
export function createFaultyStore(inner: Store, plan: FaultPlan = {}): FaultyStore {
  const rules: FaultRule[] = [];
  for (const rule of plan.rules ?? []) {
    checkRule(rule);
    rules.push(rule);
  }
  const sleep = plan.sleep ?? defaultSleep;
  const counts = new Map<StoreOperation, number>();
  const log: FaultLogEntry[] = [];

  async function invoke(operation: StoreOperation, input: unknown, options: StoreCallOptions | undefined): Promise<unknown> {
    const call = counts.get(operation) ?? 0;
    counts.set(operation, call + 1);
    const matching = rules.filter((rule) => rule.operation === operation && (rule.call === undefined || rule.call === call));
    log.push({ operation, call, faults: matching.map((rule) => rule.fault.kind) });
    let argument = input;
    let terminal: Fault | undefined;
    const delays: Extract<Fault, { kind: "delay" }>[] = [];
    for (const { fault } of matching) {
      if (fault.kind === "clock-skew") argument = shifted(argument, fault.shiftMs);
      else if (fault.kind === "delay") delays.push(fault);
      else if (terminal === undefined) terminal = fault;
    }
    for (const delay of delays) if (delay.beforeMs !== undefined) await sleep(delay.beforeMs);
    if (terminal?.kind === "unavailable") throw new StoreError("STORE_UNAVAILABLE");
    if (terminal?.kind === "ambiguous" && !terminal.applied) throw new StoreError("STORE_AMBIGUOUS");
    if (terminal?.kind === "foreign-error" && terminal.when === "before") throw foreignError();
    let result: unknown;
    if (!(terminal?.kind === "result" && !terminal.delegate)) {
      result = await (inner[operation] as (input: unknown, options?: StoreCallOptions) => Promise<unknown>)(argument, options);
    }
    for (const delay of delays) if (delay.afterMs !== undefined) await sleep(delay.afterMs);
    if (terminal === undefined) return result;
    switch (terminal.kind) {
      case "ambiguous":
        throw new StoreError("STORE_AMBIGUOUS");
      case "foreign-error":
        throw foreignError();
      case "malformed":
        return malformed(terminal.shape, result);
      case "result":
        return terminal.result;
      default:
        return result;
    }
  }

  const bind =
    <K extends StoreOperation>(operation: K): Store[K] =>
    ((input: unknown, options?: StoreCallOptions) => invoke(operation, input, options)) as Store[K];

  const faults: FaultControl = {
    calls: (operation) => counts.get(operation) ?? 0,
    log: () => [...log],
    add(rule) {
      checkRule(rule);
      rules.push(rule);
    },
    clear() {
      rules.length = 0;
    },
  };

  return {
    capabilities: () =>
      plan.capabilities === undefined
        ? inner.capabilities()
        : ({ ...inner.capabilities(), ...plan.capabilities } as unknown as StoreCapabilities),
    createCapture: bind("createCapture"),
    readEntries: bind("readEntries"),
    readCaptures: bind("readCaptures"),
    commitRestore: bind("commitRestore"),
    revokeCapture: bind("revokeCapture"),
    inspectAttempt: bind("inspectAttempt"),
    replaceCaptureKey: bind("replaceCaptureKey"),
    deleteCiphertext: bind("deleteCiphertext"),
    sweepExpired: bind("sweepExpired"),
    recoveryState: bind("recoveryState"),
    initializeNamespace: bind("initializeNamespace"),
    quarantine: bind("quarantine"),
    invalidateRecovered: bind("invalidateRecovered"),
    faults,
  };
}
