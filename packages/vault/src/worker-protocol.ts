/**
 * Validated message protocol between a main-thread client and a dedicated
 * Worker that owns an in-memory vault instance (issue #14).
 *
 * Every message carries a fixed `kind` discriminator and protocol version.
 * Both {@link parseRequest} and {@link parseResponse} reject, rather than
 * coerce, anything that does not match one of the shapes below exactly:
 * wrong `kind`, wrong or missing `v`, an unrecognized `op`, a wrong field
 * type, or an object carrying keys outside the exact allowed set for its
 * message (including `__proto__`/`constructor`/`prototype`, which are
 * rejected unconditionally). There is no operation for bulk export, dumping
 * entries, or listing tokens: the protocol only ever carries the same
 * `capture` / `restore` / `revoke` / `stats` / `dispose` surface the
 * in-memory {@link Vault} exposes.
 *
 * This module has no side effects: it never sends or receives a Worker
 * message itself, and never touches `self` or `Worker`. Both the host
 * (worker-host.ts) and the client (worker-client.ts) import it, so their
 * understanding of the protocol cannot drift apart.
 */
import { VaultError, VAULT_ERROR_CODES, type DenialReason, type VaultErrorCode } from "./errors.js";
import type { CaptureOptions, CaptureResult, RestoreRequest, RestoreResult, VaultStats } from "./types.js";

export const PROTOCOL_VERSION = 1;

/**
 * Capture options a Worker-mode caller may supply. `policy`, `eligible`, and
 * `displayFormatter` are functions: the structured-clone algorithm the
 * Worker message-passing API uses cannot carry a function across the thread
 * boundary, and even if it could, running main-thread-supplied code inside
 * the Worker would defeat the isolation this mode exists to provide. A
 * request that includes one of them is rejected explicitly and
 * synchronously before anything is sent (see `buildCaptureRequest`); it is
 * never dropped or ignored silently.
 */
export type WorkerCaptureOptions = Pick<CaptureOptions, "release" | "maxUses" | "unredacted" | "ruleset">;

const CAPTURE_OPTION_KEYS = ["release", "maxUses", "unredacted", "ruleset"] as const;

export type VaultWorkerOp = "capture" | "restore" | "revoke" | "stats" | "dispose";
/** `"unknown"` appears only on a response when the host could not determine which op a malformed request named. */
export type VaultWorkerResponseOp = VaultWorkerOp | "unknown";

export type VaultWorkerRequest =
  | {
      readonly kind: "vault-request";
      readonly v: 1;
      readonly id: string;
      readonly op: "capture";
      readonly input: string;
      readonly options: WorkerCaptureOptions;
    }
  | {
      readonly kind: "vault-request";
      readonly v: 1;
      readonly id: string;
      readonly op: "restore";
      readonly request: RestoreRequest;
    }
  | {
      readonly kind: "vault-request";
      readonly v: 1;
      readonly id: string;
      readonly op: "revoke";
      readonly captureId: string;
    }
  | { readonly kind: "vault-request"; readonly v: 1; readonly id: string; readonly op: "stats" }
  | { readonly kind: "vault-request"; readonly v: 1; readonly id: string; readonly op: "dispose" };

export interface VaultWorkerErrorInfo {
  readonly code: VaultErrorCode;
  readonly coreCode?: string;
  readonly reason?: DenialReason;
}

export type VaultWorkerResult = CaptureResult | RestoreResult | VaultStats | number | null;

export type VaultWorkerResponse =
  | { readonly kind: "vault-ready"; readonly v: 1 }
  | { readonly kind: "vault-init-failed"; readonly v: 1; readonly code: VaultErrorCode; readonly coreCode?: string }
  | {
      readonly kind: "vault-response";
      readonly v: 1;
      readonly id: string;
      readonly op: VaultWorkerResponseOp;
      readonly ok: true;
      readonly result: VaultWorkerResult;
    }
  | {
      readonly kind: "vault-response";
      readonly v: 1;
      readonly id: string;
      readonly op: VaultWorkerResponseOp;
      readonly ok: false;
      readonly error: VaultWorkerErrorInfo;
    };

export type ParseResult<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly id: string | undefined };

const ERROR_CODES = new Set<string>(VAULT_ERROR_CODES);
const REQUEST_OPS = new Set<string>(["capture", "restore", "revoke", "stats", "dispose"]);
const RESPONSE_OPS = new Set<string>([...REQUEST_OPS, "unknown"]);
/** Never a legitimate key, regardless of what a schema's allowed list says. */
const POISON_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = Object.keys(value);
  for (const key of keys) {
    if (POISON_KEYS.has(key)) return false;
    if (!allowed.includes(key)) return false;
  }
  return true;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 128;
}

function isVaultErrorCode(value: unknown): value is VaultErrorCode {
  return typeof value === "string" && ERROR_CODES.has(value);
}

function isRequestOp(value: unknown): value is VaultWorkerOp {
  return typeof value === "string" && REQUEST_OPS.has(value);
}

function isResponseOp(value: unknown): value is VaultWorkerResponseOp {
  return typeof value === "string" && RESPONSE_OPS.has(value);
}

/** Best-effort correlation id for a message that otherwise fails validation. Never trusted beyond that. */
function looseId(value: unknown): string | undefined {
  if (!isPlainObject(value)) return undefined;
  return isNonEmptyString(value.id) ? value.id : undefined;
}

/** Validated by the Worker host. Rejects anything that is not exactly one of the five known operations. */
export function parseRequest(data: unknown): ParseResult<VaultWorkerRequest> {
  if (!isPlainObject(data)) return { ok: false, id: undefined };
  const id = looseId(data);
  if (data.kind !== "vault-request" || data.v !== PROTOCOL_VERSION) return { ok: false, id };
  if (!isNonEmptyString(data.id)) return { ok: false, id: undefined };
  if (!isRequestOp(data.op)) return { ok: false, id: data.id };

  switch (data.op) {
    case "capture": {
      if (!hasOnlyKeys(data, ["kind", "v", "id", "op", "input", "options"])) return { ok: false, id: data.id };
      if (typeof data.input !== "string") return { ok: false, id: data.id };
      const options = data.options;
      if (!isPlainObject(options) || !hasOnlyKeys(options, CAPTURE_OPTION_KEYS)) return { ok: false, id: data.id };
      return {
        ok: true,
        value: {
          kind: "vault-request",
          v: 1,
          id: data.id,
          op: "capture",
          input: data.input,
          options: options as WorkerCaptureOptions,
        },
      };
    }
    case "restore": {
      if (!hasOnlyKeys(data, ["kind", "v", "id", "op", "request"])) return { ok: false, id: data.id };
      if (!isPlainObject(data.request)) return { ok: false, id: data.id };
      return {
        ok: true,
        value: {
          kind: "vault-request",
          v: 1,
          id: data.id,
          op: "restore",
          request: data.request as unknown as RestoreRequest,
        },
      };
    }
    case "revoke": {
      if (!hasOnlyKeys(data, ["kind", "v", "id", "op", "captureId"])) return { ok: false, id: data.id };
      if (typeof data.captureId !== "string") return { ok: false, id: data.id };
      return { ok: true, value: { kind: "vault-request", v: 1, id: data.id, op: "revoke", captureId: data.captureId } };
    }
    case "stats":
    case "dispose": {
      if (!hasOnlyKeys(data, ["kind", "v", "id", "op"])) return { ok: false, id: data.id };
      return { ok: true, value: { kind: "vault-request", v: 1, id: data.id, op: data.op } };
    }
  }
}

/** Validated by the main-thread client against whatever the Worker sends back. */
export function parseResponse(data: unknown): ParseResult<VaultWorkerResponse> {
  if (!isPlainObject(data)) return { ok: false, id: undefined };

  if (data.kind === "vault-ready") {
    if (!hasOnlyKeys(data, ["kind", "v"]) || data.v !== PROTOCOL_VERSION) return { ok: false, id: undefined };
    return { ok: true, value: { kind: "vault-ready", v: 1 } };
  }

  if (data.kind === "vault-init-failed") {
    if (!hasOnlyKeys(data, ["kind", "v", "code", "coreCode"]) || data.v !== PROTOCOL_VERSION) {
      return { ok: false, id: undefined };
    }
    if (!isVaultErrorCode(data.code)) return { ok: false, id: undefined };
    if (data.coreCode !== undefined && typeof data.coreCode !== "string") return { ok: false, id: undefined };
    return {
      ok: true,
      value: { kind: "vault-init-failed", v: 1, code: data.code, ...(data.coreCode === undefined ? {} : { coreCode: data.coreCode }) },
    };
  }

  if (data.kind === "vault-response") {
    const id = looseId(data);
    if (data.v !== PROTOCOL_VERSION || !isNonEmptyString(data.id)) return { ok: false, id };
    if (!isResponseOp(data.op)) return { ok: false, id: data.id };
    if (data.ok === true) {
      if (!hasOnlyKeys(data, ["kind", "v", "id", "op", "ok", "result"])) return { ok: false, id: data.id };
      return {
        ok: true,
        value: { kind: "vault-response", v: 1, id: data.id, op: data.op, ok: true, result: data.result as VaultWorkerResult },
      };
    }
    if (data.ok === false) {
      if (!hasOnlyKeys(data, ["kind", "v", "id", "op", "ok", "error"])) return { ok: false, id: data.id };
      const error = data.error;
      if (!isPlainObject(error) || !hasOnlyKeys(error, ["code", "coreCode", "reason"])) return { ok: false, id: data.id };
      if (!isVaultErrorCode(error.code)) return { ok: false, id: data.id };
      if (error.coreCode !== undefined && typeof error.coreCode !== "string") return { ok: false, id: data.id };
      if (error.reason !== undefined && typeof error.reason !== "string") return { ok: false, id: data.id };
      return {
        ok: true,
        value: {
          kind: "vault-response",
          v: 1,
          id: data.id,
          op: data.op,
          ok: false,
          error: {
            code: error.code,
            ...(error.coreCode === undefined ? {} : { coreCode: error.coreCode }),
            ...(error.reason === undefined ? {} : { reason: error.reason as DenialReason }),
          },
        },
      };
    }
    return { ok: false, id: data.id };
  }

  return { ok: false, id: looseId(data) };
}

// --- Client-side request builders -------------------------------------
//
// Each builder validates its own arguments before constructing a message and
// throws the same fixed VaultError the in-process vault would, so a caller
// cannot smuggle a non-cloneable value (or an unsupported option) into an
// outgoing message. Nothing here is sent; the caller still owns that step.

export function buildCaptureRequest(id: string, input: string, options: WorkerCaptureOptions): VaultWorkerRequest {
  if (typeof input !== "string") throw new VaultError("INVALID_ARGUMENT");
  if (!isPlainObject(options) || !hasOnlyKeys(options, CAPTURE_OPTION_KEYS)) {
    throw new VaultError("INVALID_ARGUMENT");
  }
  return { kind: "vault-request", v: PROTOCOL_VERSION, id, op: "capture", input, options };
}

export function buildRestoreRequest(id: string, request: RestoreRequest): VaultWorkerRequest {
  if (!isPlainObject(request)) throw new VaultError("INVALID_ARGUMENT");
  return { kind: "vault-request", v: PROTOCOL_VERSION, id, op: "restore", request };
}

export function buildRevokeRequest(id: string, captureId: string): VaultWorkerRequest {
  if (typeof captureId !== "string") throw new VaultError("INVALID_ARGUMENT");
  return { kind: "vault-request", v: PROTOCOL_VERSION, id, op: "revoke", captureId };
}

export function buildStatsRequest(id: string): VaultWorkerRequest {
  return { kind: "vault-request", v: PROTOCOL_VERSION, id, op: "stats" };
}

export function buildDisposeRequest(id: string): VaultWorkerRequest {
  return { kind: "vault-request", v: PROTOCOL_VERSION, id, op: "dispose" };
}
