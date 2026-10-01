import type { KeyProvider, Store } from "@redact-secret/vault-contracts";

/** One conformance case. `run` resolves on a pass, and rejects with `ConformanceSkip` or a failure. */
export interface ConformanceCase {
  readonly name: string;
  readonly group: string;
  run(): Promise<void>;
}

/** Thrown by a case that cannot run against this factory. It is a skip with a reason, never a pass. */
export class ConformanceSkip extends Error {
  readonly reason: string;

  constructor(reason: string) {
    super(`Skipped: ${reason}`);
    this.name = "ConformanceSkip";
    this.reason = reason;
  }
}

/** Thrown when a store or provider did not behave as the specification requires. */
export class ConformanceFailure extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConformanceFailure";
  }
}

/** A handle on the clock the store under test judges expiry and skew with. */
export interface ConformanceClock {
  /** The store clock's current reading, in milliseconds. */
  now(): number;
  /** Moves the store's clock forward by `ms`. */
  advance(ms: number): void;
  /** Sets the store's clock to `ms`. */
  set(ms: number): void;
}

export interface InterleaveRequest<T> {
  /** The operation of `primary` whose transaction is to be held open. */
  readonly operation: "commitRestore" | "createCapture";
  /**
   * Starts exactly one call of `operation` on the store under test and
   * resolves with its result. The adapter calls it once.
   */
  readonly primary: () => Promise<T>;
  /**
   * The competing work. The adapter calls it once, with a store handle on a
   * second connection, at the moment the primary call has made its reads and
   * checks and has not yet committed.
   */
  readonly concurrent: (second: Store) => Promise<void>;
}

/**
 * Holds one transaction open while another runs (specification §5.2).
 *
 * The implementation starts `primary()`, suspends that call after its reads
 * and checks and before its commit, starts `concurrent(second)`, and lets the
 * primary call continue once `concurrent` has either settled or is known to be
 * blocked by the primary's locks. It resolves with what `primary()` resolved
 * with, or rejects with what it rejected with, after both have settled.
 *
 * A store that locks will block `concurrent` until the primary commits; an
 * optimistic store will let it commit and then abort the primary. The harness
 * observes which settled first and accepts either order; what it never
 * accepts is a primary call that succeeds after the competing call was
 * acknowledged.
 */
export type Interleave = <T>(request: InterleaveRequest<T>) => Promise<T>;

export interface StoreUnderTest {
  readonly store: Store;
  /**
   * Control over the store's own clock, or `null` when the harness cannot
   * move it (a real database). With `null`, the harness uses `Date.now()` as
   * its estimate of the store clock and reports every time-travel case as
   * skipped.
   */
  readonly clock: ConformanceClock | null;
  /**
   * A second handle on the same authoritative state, on its own connection.
   * When present, concurrent cases spread their calls over both.
   */
  readonly secondStore?: Store;
  /** Without it, the §5.2 two-connection schedules are reported as skipped. */
  readonly interleave?: Interleave;
  /** Called once when the case ends, whatever its outcome. */
  readonly dispose?: () => Promise<void>;
}

/**
 * Called once per case. It may return a new store each time or handles on
 * one shared database: every case works in namespaces it draws at random and
 * never touches another namespace.
 */
export type StoreFactory = () => Promise<StoreUnderTest>;

export interface StoreConformanceOptions {
  /** Seed of every pseudo-random choice. Printed by a failing case. Default 20261001. */
  readonly seed?: number;
  /** Calls issued together by a concurrency case. Default 100. */
  readonly parallelism?: number;
  /** Operations per model sequence. Default 400. */
  readonly modelSteps?: number;
  /** Model sequences per variant. Default 4. */
  readonly modelSequences?: number;
}

export interface KeyProviderScope {
  readonly namespaces: readonly string[];
  readonly tenants: readonly string[];
}

export interface KeyProviderUnderTest {
  readonly provider: KeyProvider;
  /**
   * Makes a new wrapping key version active and the previous one
   * decrypt-only. Without it, rotation cases are reported as skipped.
   */
  readonly rotate?: () => Promise<void>;
  /**
   * Retires the wrapping key version `keyRef` names. Without it, retirement
   * cases are reported as skipped.
   */
  readonly retire?: (keyRef: string) => Promise<void>;
  readonly dispose?: () => Promise<void>;
}

/**
 * Called once per case. The provider it returns must serve exactly the
 * namespaces in `scope.namespaces`. A provider that can also restrict tenants
 * restricts them to `scope.tenants`; one that cannot ignores that list.
 */
export type KeyProviderFactory = (request: { readonly scope: KeyProviderScope }) => Promise<KeyProviderUnderTest>;

export type CaseStatus = "passed" | "failed" | "skipped";

export interface CaseResult {
  readonly name: string;
  readonly group: string;
  readonly status: CaseStatus;
  /** The skip reason, or the failure's message. */
  readonly detail?: string;
}

/** The subset of a test runner's `test` function that `runWithNodeTest` uses. */
export type TestFunction = (
  name: string,
  fn: (context: { skip(message?: string): void }) => Promise<void>,
) => unknown;
