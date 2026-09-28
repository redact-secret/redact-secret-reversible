import type { PlaceholderFormatter, SecretFinding, SecretPolicy } from "@redact-secret/core";

import type { DenialReason, VaultErrorCode } from "./errors.js";

/**
 * Bounds on everything a vault retains or processes. Every field is a
 * positive integer; omitted fields take {@link DEFAULT_LIMITS}.
 */
export interface VaultLimits {
  /** Live restorable entries across all captures. */
  readonly maxEntries: number;
  /** UTF-8 bytes of retained original values across all captures. */
  readonly maxRetainedBytes: number;
  /** UTF-8 bytes of any one retained value. */
  readonly maxValueBytes: number;
  /** Lifetime of each entry, measured from its capture. */
  readonly entryTtlMs: number;
  /** Lifetime of the vault itself; after it, every call fails `DISPOSED`. */
  readonly vaultTtlMs: number;
  /** UTF-8 bytes of one capture input (also passed to the core). */
  readonly maxInputBytes: number;
  /** Findings in one capture input (also passed to the core). */
  readonly maxFindings: number;
  /** Fields in one restore request. */
  readonly maxRestoreFields: number;
  /** UTF-8 bytes of one restore field. */
  readonly maxRestoreFieldBytes: number;
  /** Upper bound a capture may request for `maxUses`. */
  readonly maxUsesPerEntry: number;
}

/**
 * A destination an application allows a capture's values to be restored into:
 * one sink identifier and the exact field paths within it. Chosen by
 * application code at capture time, never by model output.
 */
export interface ReleaseGrant {
  readonly sink: string;
  readonly paths: readonly string[];
}

/** What a page-local release policy sees for one entry at restore time. */
export interface ReleaseRequest {
  readonly captureId: string;
  readonly sink: string;
  readonly path: string;
  /** Core finding type of the retained value. Descriptive only. */
  readonly type: string;
  /** Occurrences of this entry in this path. */
  readonly occurrences: number;
  /** Occurrences of this entry across every field of the request. */
  readonly totalOccurrences: number;
  /** Uses already consumed before this request. */
  readonly used: number;
}

/**
 * Page-local release policy, evaluated at every restore for every entry and
 * path. Only a literal `true` allows. It runs in the same trust boundary as
 * the rest of the page and is not multi-user authorization.
 */
export type ReleasePolicy = (request: ReleaseRequest) => boolean;

export interface AuditEvent {
  readonly operation: "capture" | "restore" | "revoke" | "dispose";
  readonly outcome: "committed" | "denied" | "failed";
  readonly at: number;
  readonly code?: VaultErrorCode;
  readonly reason?: DenialReason;
  /** Entries created (capture), consumed (restore), or removed (revoke/dispose). */
  readonly entries?: number;
  readonly sink?: string;
  readonly fields?: number;
}

/** Receives safe metadata only. Exceptions it throws are swallowed. */
export type AuditHook = (event: AuditEvent) => void;

export interface VaultOptions {
  readonly limits?: Partial<VaultLimits>;
  readonly releasePolicy?: ReleasePolicy;
  readonly onAudit?: AuditHook;
  /**
   * Millisecond clock, for tests and controlled environments. The default is
   * the later of `Date.now()` and a `performance.now()` timeline anchored at
   * creation, so neither a backwards system-clock change nor system sleep
   * extends a TTL. An injected
   * clock is trusted: the vault never lets *observed* time go backwards (a
   * decrease is treated as no change), but it cannot detect a clock that runs
   * slow. A clock that throws or returns a non-finite value
   * fails the call with `INVALID_ARGUMENT`.
   */
  readonly now?: () => number;
  /**
   * PII selectors, forwarded verbatim (as a copied array) to the core's
   * `initialize({ pii })`. `[]` is an explicit "PII off". Omit to adopt the
   * activation the application already established: on a core with a PII
   * surface the vault then calls no initializer, and fails `CORE_FAILURE`
   * with `coreCode: "NOT_INITIALIZED"` when nobody initialized the core.
   * Shape: 0 to 64 strings of 1 to 128 characters; the core judges selector
   * grammar (`PII_SELECTOR_*`). On a core without a PII surface (beta.9),
   * a non-empty array fails `PII_UNAVAILABLE` and `[]` equals omission.
   */
  readonly pii?: readonly string[];
  /**
   * Optional exact canonical activation identity the application expects,
   * compared byte-for-byte with the core's `piiActivation()` after
   * initialization or adoption. A difference fails `PII_ACTIVATION_MISMATCH`.
   * 1 to 512 characters. On a core without a PII surface it fails
   * `PII_UNAVAILABLE`.
   */
  readonly expectPiiActivation?: string;
}

/** Exact public PII finding types whose `redact` findings may be retained. */
export interface PiiRetention {
  /**
   * Non-empty (1 to 64 entries). Each entry is an exact public PII type
   * (`pii_…`, at most 128 ASCII characters from `[a-z0-9_-]`). No wildcards,
   * prefixes, or selectors. Duplicates are ignored. Unknown but well-formed
   * names are accepted and simply never match: the vault does not know the
   * core's inventory.
   */
  readonly retain: readonly string[];
}

export interface CaptureOptions {
  /** Where values from this capture may be restored. Required, non-empty. */
  readonly release: readonly ReleaseGrant[];
  /** Occurrences each entry may be restored, in total. Default 1. */
  readonly maxUses?: number;
  /**
   * What to do when the core leaves `warn` or `allow` findings as plaintext
   * in the output. `"reject"` (default) fails the capture; `"pass-through"`
   * returns the text and reports the count in `passedThrough`.
   */
  readonly unredacted?: "reject" | "pass-through";
  /** Core policy. Omit for the core's built-in policy. */
  readonly policy?: SecretPolicy;
  /** Core declarative ruleset. */
  readonly ruleset?: Uint8Array | string;
  /**
   * Which `redact` findings to retain. Default: all non-PII findings. An
   * ineligible finding is still replaced, with a display placeholder that
   * cannot be restored. For a PII finding (type starting `pii_`) this is
   * consulted only after `pii.retain` allowlists its exact type: it can
   * narrow the PII allowlist, never widen it, and is not called for a PII
   * finding outside the allowlist.
   */
  readonly eligible?: (finding: SecretFinding) => boolean;
  /**
   * PII retention opt-in. Omit to retain no PII finding: every `redact`
   * finding whose type starts `pii_` is then replaced by a non-restorable
   * display placeholder and counted in `unrestorable`. Supplying it while the
   * vault's observed activation is `null` or has `selectors=off` fails
   * `PII_UNAVAILABLE`.
   */
  readonly pii?: PiiRetention;
  /** Display placeholder for ineligible findings. Default `<SECRET_n>`. */
  readonly displayFormatter?: PlaceholderFormatter;
}

export interface IssuedToken {
  readonly token: string;
  /** Core finding type. Descriptive; grants nothing. */
  readonly type: string;
}

export interface CaptureResult {
  readonly captureId: string;
  /** Redacted text, safe to send only as far as `passedThrough` allows. */
  readonly text: string;
  readonly tokens: readonly IssuedToken[];
  /** `warn`/`allow` findings left as plaintext in `text`. */
  readonly passedThrough: number;
  /** Distinct core finding types among `passedThrough`, sorted. */
  readonly passedThroughTypes: readonly string[];
  /** `redact` findings replaced by a non-restorable display placeholder. */
  readonly unrestorable: number;
  readonly expiresAt: number;
}

export interface RestoreRequest {
  /** The application-chosen destination. */
  readonly sink: string;
  /**
   * The captures this output may draw from, by `captureId`. Required and
   * non-empty: a token issued by any other capture in the same vault is
   * denied (`source`), even when that capture granted the same sink and path.
   */
  readonly captures: readonly string[];
  /** Field path → text that may contain issued tokens. */
  readonly fields: Readonly<Record<string, string>>;
}

export interface RestoreResult {
  /** The same paths as the request, with issued tokens replaced. */
  readonly fields: Readonly<Record<string, string>>;
  /** Token occurrences replaced. */
  readonly restored: number;
}

export interface VaultStats {
  readonly entries: number;
  readonly retainedBytes: number;
  readonly captures: number;
  readonly disposed: boolean;
  readonly expiresAt: number;
}

export interface Vault {
  /**
   * The core's canonical PII activation identity observed at `createVault`,
   * or `null` when the installed core has no PII surface (beta.9). Fixed for
   * the vault's lifetime because activation is one-shot per realm.
   */
  readonly piiActivation: string | null;
  capture(input: string, options: CaptureOptions): CaptureResult;
  restore(request: RestoreRequest): RestoreResult;
  /** Removes every entry of one capture. Returns the number removed. */
  revoke(captureId: string): number;
  dispose(): void;
  stats(): VaultStats;
}
