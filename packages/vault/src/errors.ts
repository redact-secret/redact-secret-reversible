/**
 * The single sanitized error type this package throws.
 *
 * Every message is a fixed string chosen by `code`. No error carries input
 * text, a matched value, an issued token, a restored value, a field path, or
 * the message of an exception thrown by a consumer callback. `cause` is never
 * set, so a structured logger cannot walk into a payload-bearing error.
 */
export type VaultErrorCode =
  | "INVALID_ARGUMENT"
  | "UNSUPPORTED_RUNTIME"
  | "CORE_FAILURE"
  | "BLOCKED_FINDING"
  | "UNREDACTED_FINDINGS"
  | "TOKEN_LITERAL_IN_INPUT"
  | "LIMIT_EXCEEDED"
  | "TOKEN_GENERATION_FAILED"
  | "INVARIANT_VIOLATION"
  | "RESTORE_DENIED"
  | "BUSY"
  | "DISPOSED"
  | "WORKER_PROTOCOL_VIOLATION"
  | "WORKER_UNAVAILABLE"
  | "PII_UNAVAILABLE"
  | "PII_ACTIVATION_MISMATCH";

const MESSAGES: Readonly<Record<VaultErrorCode, string>> = Object.freeze({
  INVALID_ARGUMENT: "The vault operation received an invalid argument.",
  UNSUPPORTED_RUNTIME: "This runtime lacks a required primitive for the vault.",
  CORE_FAILURE: "The redaction core rejected the operation.",
  BLOCKED_FINDING: "The input contains a finding whose policy action is block.",
  UNREDACTED_FINDINGS:
    "The input contains warn or allow findings that would remain in the output.",
  TOKEN_LITERAL_IN_INPUT: "The input already contains token-like text.",
  LIMIT_EXCEEDED: "The operation exceeds a configured vault limit.",
  TOKEN_GENERATION_FAILED: "The vault could not issue a token.",
  INVARIANT_VIOLATION: "The vault rejected an inconsistent intermediate result.",
  RESTORE_DENIED: "The restore request was denied.",
  BUSY: "The vault is already running an operation.",
  DISPOSED: "The vault has been disposed or has expired.",
  WORKER_PROTOCOL_VIOLATION:
    "A Worker-mode message did not match the validated protocol and was rejected.",
  WORKER_UNAVAILABLE: "The vault Worker did not respond, errored, or was terminated.",
  PII_UNAVAILABLE:
    "PII options were supplied, but the redaction core has no PII support or PII detection is not active.",
  PII_ACTIVATION_MISMATCH: "The redaction core's PII activation differs from the expected activation.",
});

/** Every fixed error code, derived from {@link MESSAGES} so the two cannot drift. */
export const VAULT_ERROR_CODES: readonly VaultErrorCode[] = Object.freeze(
  Object.keys(MESSAGES) as VaultErrorCode[],
);

/**
 * Why a restore was denied. Carried on {@link VaultError.reason} and on audit
 * events. The reason distinguishes failure classes for the application; it
 * never identifies which token, value, or field failed.
 */
export type DenialReason =
  | "invalid-request"
  | "malformed-token"
  | "unknown-token"
  | "source"
  | "expired"
  | "sink-or-path"
  | "budget"
  | "policy";

export class VaultError extends Error {
  readonly code: VaultErrorCode;
  /** Set only for `CORE_FAILURE`: the core's own fixed error code. */
  readonly coreCode: string | undefined;
  /** Set only for `RESTORE_DENIED`. */
  readonly reason: DenialReason | undefined;

  constructor(
    code: VaultErrorCode,
    detail: { coreCode?: string | undefined; reason?: DenialReason | undefined } = {},
  ) {
    super(MESSAGES[code]);
    this.name = "VaultError";
    this.code = code;
    this.coreCode = detail.coreCode;
    this.reason = detail.reason;
  }
}

/** The core's error codes are fixed identifiers; anything else is dropped. */
export function coreCodeOf(thrown: unknown): string | undefined {
  if (typeof thrown !== "object" || thrown === null) return undefined;
  const code = (thrown as { code?: unknown }).code;
  return typeof code === "string" && /^[A-Z_]{1,40}$/.test(code) ? code : undefined;
}
