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
import { VaultError, type VaultErrorCode } from "./errors.js";
import { createVault } from "./vault.js";
import type { Vault, VaultOptions } from "./types.js";
import { parseRequest, type VaultWorkerRequest, type VaultWorkerResponse } from "./worker-protocol.js";

/** The minimal surface this module needs from a Worker global scope or a `MessagePort`. */
export interface VaultWorkerTarget {
  postMessage(message: unknown): void;
  addEventListener(type: "message", listener: (event: { readonly data: unknown }) => void): void;
}

export interface VaultWorkerHostOptions extends VaultOptions {
  /** Message target. Defaults to `globalThis`, which is the Worker's own scope inside a real dedicated Worker. Overridable for tests. */
  readonly target?: VaultWorkerTarget;
}

function errorCode(thrown: unknown): { code: VaultErrorCode; coreCode: string | undefined } {
  if (thrown instanceof VaultError) return { code: thrown.code, coreCode: thrown.coreCode };
  return { code: "CORE_FAILURE", coreCode: undefined };
}

function dispatch(vault: Vault, request: VaultWorkerRequest): unknown {
  switch (request.op) {
    case "capture":
      return vault.capture(request.input, request.options);
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
 * If vault creation itself fails (for example the core's WASM artifact could
 * not compile under the Worker's CSP), this posts an explicit
 * `vault-init-failed` message and returns without installing a listener —
 * there is no main-thread fallback and no partially-initialized vault left
 * reachable by any later message.
 */
export async function startVaultWorkerHost(options: VaultWorkerHostOptions = {}): Promise<void> {
  const { target: providedTarget, ...vaultOptions } = options;
  const target: VaultWorkerTarget = providedTarget ?? (globalThis as unknown as VaultWorkerTarget);

  let vault: Vault;
  try {
    vault = await createVault(vaultOptions);
  } catch (thrown) {
    const { code, coreCode } = errorCode(thrown);
    const failed: VaultWorkerResponse = { kind: "vault-init-failed", v: 1, code, ...(coreCode === undefined ? {} : { coreCode }) };
    target.postMessage(failed);
    return;
  }

  const ready: VaultWorkerResponse = { kind: "vault-ready", v: 1 };
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
          v: 1,
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
      const result = dispatch(vault, request);
      const response: VaultWorkerResponse = {
        kind: "vault-response",
        v: 1,
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
        v: 1,
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
