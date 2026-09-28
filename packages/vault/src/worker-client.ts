/**
 * The main-thread half of optional Worker mode (issue #14): a small
 * asynchronous RPC client that talks to a Worker running
 * `startVaultWorkerHost` (see worker-host.ts) through the validated protocol
 * in worker-protocol.ts. It never holds the mapping itself and never gains
 * `postMessage`-independent access to it.
 *
 * `WorkerVault` deliberately does **not** implement the synchronous `Vault`
 * interface the main-thread package exposes: every call here is a message
 * round trip, so every method returns a `Promise`. This is a visible,
 * intentional difference, not a hidden capability change — see
 * docs/specs/in-memory-security.md section 5 and the Worker-mode ADR.
 */
import { VaultError } from "./errors.js";
import type { CaptureResult, RestoreRequest, RestoreResult, VaultStats } from "./types.js";
import {
  buildCaptureRequest,
  buildDisposeRequest,
  buildRestoreRequest,
  buildRevokeRequest,
  buildStatsRequest,
  parseResponse,
  type VaultWorkerRequest,
  type WorkerCaptureOptions,
} from "./worker-protocol.js";

export type { WorkerCaptureOptions } from "./worker-protocol.js";

/** The minimal surface this client needs from a `Worker` (or a `MessagePort`). */
export interface VaultWorkerPort {
  postMessage(message: unknown): void;
  addEventListener(type: "message", listener: (event: { readonly data: unknown }) => void): void;
  addEventListener(type: "error", listener: (event: unknown) => void): void;
  addEventListener(type: "messageerror", listener: (event: unknown) => void): void;
  terminate?(): void;
}

/** Worker-mode mirror of `Vault`. Every operation is an asynchronous round trip to the Worker that owns the mapping. */
export interface WorkerVault {
  capture(input: string, options: WorkerCaptureOptions): Promise<CaptureResult>;
  restore(request: RestoreRequest): Promise<RestoreResult>;
  /** Removes every entry of one capture. Resolves to the number removed. */
  revoke(captureId: string): Promise<number>;
  stats(): Promise<VaultStats>;
  /** Disposes the Worker-held vault. Every later call fails `DISPOSED` without a round trip. */
  dispose(): Promise<void>;
  /** Terminates the underlying Worker immediately. Every pending and future call fails `WORKER_UNAVAILABLE`. */
  terminate(): void;
}

export interface CreateWorkerVaultOptions {
  /** Milliseconds to wait for the Worker to become ready, or for a reply to any one call. Default 15000. */
  readonly timeoutMs?: number;
}

interface Waiter {
  readonly resolve: (value: unknown) => void;
  readonly reject: (error: unknown) => void;
  readonly timer: ReturnType<typeof setTimeout>;
}

/**
 * Starts talking to `worker` and resolves once it announces readiness.
 *
 * This never falls back to an in-process vault. If the Worker fails to
 * initialize, errors, or does not answer within `timeoutMs`, the returned
 * promise rejects with a `VaultError` (`WORKER_UNAVAILABLE`, or whatever
 * fixed code the Worker's own vault creation failed with) — the caller must
 * make an explicit, separate choice about what to do next.
 */
export function createWorkerVault(worker: VaultWorkerPort, options: CreateWorkerVaultOptions = {}): Promise<WorkerVault> {
  const timeoutMs = options.timeoutMs ?? 15_000;
  if (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    return Promise.reject(new VaultError("INVALID_ARGUMENT"));
  }

  return new Promise<WorkerVault>((resolveReady, rejectReady) => {
    let readySettled = false;
    let disposed = false;
    let terminated = false;
    let nextId = 0;
    const pending = new Map<string, Waiter>();

    const readyTimer = setTimeout(() => {
      if (!readySettled) {
        readySettled = true;
        rejectReady(new VaultError("WORKER_UNAVAILABLE"));
      }
    }, timeoutMs);

    const failAllPending = (err: VaultError): void => {
      for (const waiter of pending.values()) {
        clearTimeout(waiter.timer);
        waiter.reject(err);
      }
      pending.clear();
    };

    worker.addEventListener("message", (event) => {
      const parsed = parseResponse(event.data);
      if (!parsed.ok) {
        // Never coerced into a result. If we can identify which caller this
        // was meant for, that caller's promise rejects explicitly; a message
        // we cannot correlate is dropped, not guessed at.
        if (parsed.id !== undefined) {
          const waiter = pending.get(parsed.id);
          if (waiter !== undefined) {
            pending.delete(parsed.id);
            clearTimeout(waiter.timer);
            waiter.reject(new VaultError("WORKER_PROTOCOL_VIOLATION"));
          }
        }
        return;
      }

      const message = parsed.value;
      if (message.kind === "vault-ready") {
        if (!readySettled) {
          readySettled = true;
          clearTimeout(readyTimer);
          resolveReady(makeVault());
        }
        return;
      }
      if (message.kind === "vault-init-failed") {
        if (!readySettled) {
          readySettled = true;
          clearTimeout(readyTimer);
          rejectReady(new VaultError(message.code, message.coreCode === undefined ? {} : { coreCode: message.coreCode }));
        }
        return;
      }

      const waiter = pending.get(message.id);
      if (waiter === undefined) return; // no matching caller: drop, never fabricate a result
      pending.delete(message.id);
      clearTimeout(waiter.timer);
      if (message.ok) {
        waiter.resolve(message.result);
      } else {
        waiter.reject(
          new VaultError(message.error.code, { coreCode: message.error.coreCode, reason: message.error.reason }),
        );
      }
    });

    worker.addEventListener("error", () => {
      const err = new VaultError("WORKER_UNAVAILABLE");
      if (!readySettled) {
        readySettled = true;
        clearTimeout(readyTimer);
        rejectReady(err);
      }
      terminated = true;
      failAllPending(err);
    });

    worker.addEventListener("messageerror", () => {
      // A message failed structured-clone deserialization on the way in.
      // Its meaning cannot be recovered; cancel what we can identify as
      // affected rather than guess.
      failAllPending(new VaultError("WORKER_PROTOCOL_VIOLATION"));
    });

    function send<T>(build: (id: string) => VaultWorkerRequest): Promise<T> {
      if (disposed) return Promise.reject(new VaultError("DISPOSED"));
      if (terminated) return Promise.reject(new VaultError("WORKER_UNAVAILABLE"));
      const id = `wreq_${(nextId += 1)}`;
      // May throw synchronously (e.g. INVALID_ARGUMENT) before anything is sent.
      const request = build(id);
      return new Promise<T>((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new VaultError("WORKER_UNAVAILABLE"));
        }, timeoutMs);
        pending.set(id, { resolve: resolve as (value: unknown) => void, reject, timer });
        worker.postMessage(request);
      });
    }

    function makeVault(): WorkerVault {
      return {
        capture: (input, captureOptions) => send((id) => buildCaptureRequest(id, input, captureOptions)),
        restore: (request) => send((id) => buildRestoreRequest(id, request)),
        revoke: (captureId) => send((id) => buildRevokeRequest(id, captureId)),
        stats: () => send((id) => buildStatsRequest(id)),
        dispose: () =>
          send<null>((id) => buildDisposeRequest(id)).then(() => {
            disposed = true;
          }),
        terminate: () => {
          if (terminated) return;
          terminated = true;
          if (typeof worker.terminate === "function") worker.terminate();
          failAllPending(new VaultError("WORKER_UNAVAILABLE"));
        },
      };
    }
  });
}
