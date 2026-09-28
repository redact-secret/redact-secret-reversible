/**
 * The Worker-side half of optional Worker mode (issue #14): owns an
 * `InMemoryVault` instance in a closure private to this module and this
 * Worker's global scope. Nothing here ever assigns the vault, an entry, or a
 * retained value to `self`, a global, or any value reachable from a posted
 * message; the only way in or out is the validated protocol in
 * `worker-protocol.js`.
 *
 * This does not make the caller trusted. The threat model this satisfies is
 * "ordinary main-thread code cannot reach the mapping directly" (structural
 * isolation across a thread boundary), not "a compromised main thread cannot
 * call restore" — it still can, through the same protocol a legitimate
 * caller uses. See docs/specs/in-memory-security.md section 5.
 */
import type { DetectedSecretFinding, PolicyContext, SecretAction, SecretPolicy } from "@redact-secret/core";

import { VaultError, type VaultErrorCode } from "./errors.js";
import { createVault } from "./vault.js";
import type { Vault, VaultOptions } from "./types.js";
import { parseRequest, PROTOCOL_VERSION, type VaultWorkerRequest, type VaultWorkerResponse } from "./worker-protocol.js";

/** The minimal surface this module needs from a Worker global scope or a `MessagePort`. */
export interface VaultWorkerTarget {
  postMessage(message: unknown): void;
  addEventListener(type: "message", listener: (event: { readonly data: unknown }) => void): void;
}

/**
 * `VaultOptions`, including `pii` and `expectPiiActivation`, with exactly the
 * main-thread `createVault` semantics inside this Worker realm
 * (docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md
 * §3 "Worker mode"): the selection is forwarded only when the Worker script
 * passes one; otherwise the vault adopts the activation the Worker script
 * established itself. The page cannot set either option: no request message
 * carries them.
 */
export interface VaultWorkerHostOptions extends VaultOptions {
  /** Message target. Defaults to `globalThis`, which is the Worker's own scope inside a real dedicated Worker. Overridable for tests. */
  readonly target?: VaultWorkerTarget;
  /**
   * Core policy for every capture this Worker serves (#59; PII ADR addendum
   * of 2026-09-28). The Worker script owns it, as it owns `pii`: no request
   * message carries policy data, so the page cannot see, send, replace, or
   * weaken it. Same semantics as the main-thread `CaptureOptions.policy`: it
   * replaces the core's built-in policy for every finding, and a `redact` it
   * assigns to a PII finding is still not restorable unless the capture's
   * `pii.retain` names that exact type. Must be an object with a callable
   * `evaluate`, checked once at start (otherwise `vault-init-failed` with
   * `INVALID_ARGUMENT`); that `evaluate` is pinned for the host's lifetime.
   */
  readonly policy?: SecretPolicy;
}

function errorCode(thrown: unknown): { code: VaultErrorCode; coreCode: string | undefined } {
  if (thrown instanceof VaultError) return { code: thrown.code, coreCode: thrown.coreCode };
  return { code: "CORE_FAILURE", coreCode: undefined };
}

/**
 * Checks the Worker script's policy once and pins its `evaluate`, so a later
 * change to that object cannot swap it out. The check is the core's own
 * (an object with a callable `evaluate`), and also refuses `null`. Fails
 * with a fixed, value-free `INVALID_ARGUMENT`.
 */
function resolveHostPolicy(policy: unknown): SecretPolicy | undefined {
  if (policy === undefined) return undefined;
  if (typeof policy !== "object" || policy === null) throw new VaultError("INVALID_ARGUMENT");
  let evaluate: unknown;
  try {
    evaluate = (policy as { evaluate?: unknown }).evaluate;
  } catch {
    throw new VaultError("INVALID_ARGUMENT");
  }
  if (typeof evaluate !== "function") throw new VaultError("INVALID_ARGUMENT");
  const pinned = evaluate as SecretPolicy["evaluate"];
  return Object.freeze({
    evaluate: (finding: DetectedSecretFinding, context: PolicyContext): SecretAction =>
      pinned.call(policy, finding, context),
  });
}

function dispatch(vault: Vault, policy: SecretPolicy | undefined, request: VaultWorkerRequest): unknown {
  switch (request.op) {
    case "capture":
      // A page's options never carry `policy` (parseRequest rejects the key),
      // so the only policy a Worker-mode capture runs is the Worker script's.
      return vault.capture(request.input, policy === undefined ? request.options : { ...request.options, policy });
    case "restore":
      return vault.restore(request.request);
    case "revoke":
      return vault.revoke(request.captureId);
    case "stats":
      return vault.stats();
    case "dispose":
      vault.dispose();
      return null;
  }
}

/**
 * Creates the in-memory vault inside this Worker and starts listening for
 * validated protocol messages. Resolves once the listener is installed.
 *
 * If `policy` is invalid, or vault creation itself fails (for example the
 * core's WASM artifact could not compile under the Worker's CSP), this posts an explicit
 * `vault-init-failed` message and returns without installing a listener —
 * there is no main-thread fallback and no partially-initialized vault left
 * reachable by any later message.
 */
export async function startVaultWorkerHost(options: VaultWorkerHostOptions = {}): Promise<void> {
  const { target: providedTarget, policy: providedPolicy, ...vaultOptions } = options;
  const target: VaultWorkerTarget = providedTarget ?? (globalThis as unknown as VaultWorkerTarget);

  let policy: SecretPolicy | undefined;
  let vault: Vault;
  try {
    // Checked before the core is touched: an invalid policy fails init
    // without activating anything in this realm.
    policy = resolveHostPolicy(providedPolicy);
    vault = await createVault(vaultOptions);
  } catch (thrown) {
    const { code, coreCode } = errorCode(thrown);
    const failed: VaultWorkerResponse = {
      kind: "vault-init-failed",
      v: PROTOCOL_VERSION,
      code,
      ...(coreCode === undefined ? {} : { coreCode }),
    };
    target.postMessage(failed);
    return;
  }

  // The observed identity only; the vault fixed it at creation and it cannot
  // change. Nothing about the Worker script's policy is sent.
  const ready: VaultWorkerResponse = { kind: "vault-ready", v: PROTOCOL_VERSION, piiActivation: vault.piiActivation };
  target.postMessage(ready);

  target.addEventListener("message", (event) => {
    const parsed = parseRequest(event.data);
    if (!parsed.ok) {
      // A message that does not match the protocol never reaches the vault.
      // Without a valid id there is no caller to answer; that is a fail-closed
      // drop, not a crash and not a silently-accepted operation.
      if (parsed.id !== undefined) {
        const violation: VaultWorkerResponse = {
          kind: "vault-response",
          v: PROTOCOL_VERSION,
          id: parsed.id,
          op: "unknown",
          ok: false,
          error: { code: "WORKER_PROTOCOL_VIOLATION" },
        };
        target.postMessage(violation);
      }
      return;
    }

    const request = parsed.value;
    try {
      const result = dispatch(vault, policy, request);
      const response: VaultWorkerResponse = {
        kind: "vault-response",
        v: PROTOCOL_VERSION,
        id: request.id,
        op: request.op,
        ok: true,
        result: result as never,
      };
      target.postMessage(response);
    } catch (thrown) {
      const err = thrown instanceof VaultError ? thrown : new VaultError("INVARIANT_VIOLATION");
      const response: VaultWorkerResponse = {
        kind: "vault-response",
        v: PROTOCOL_VERSION,
        id: request.id,
        op: request.op,
        ok: false,
        error: {
          code: err.code,
          ...(err.coreCode === undefined ? {} : { coreCode: err.coreCode }),
          ...(err.reason === undefined ? {} : { reason: err.reason }),
        },
      };
      target.postMessage(response);
    }
  });
}
