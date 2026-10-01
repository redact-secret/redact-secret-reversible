# Worker mode

Run [`@redact-secret/vault`](../../packages/vault/README.md) inside a dedicated Worker, so the mapping is not reachable by direct main-thread object access. Optional, browser only.

**Main-thread and Worker guarantees are different. Do not conflate them.** Worker mode is optional, opted into explicitly, and never an implicit upgrade over main-thread use — importing `"@redact-secret/vault"` alone never gains Worker capability.

```ts
// main thread
import { createWorkerVault, VaultError } from "@redact-secret/vault/worker";

const worker = new Worker(new URL("./vault-worker.js", import.meta.url), { type: "module" });
const vault = await createWorkerVault(worker); // rejects explicitly; never falls back to a main-thread vault

const captured = await vault.capture(userText, { release: [{ sink: "draft-reply", paths: ["body"] }] });
// ... same flow as the main-thread example above, but every call returns a Promise ...
await vault.dispose();
```

```ts
// vault-worker.js — runs inside the dedicated Worker
import { startVaultWorkerHost } from "@redact-secret/vault/worker/host";
startVaultWorkerHost({ pii: [] }); // PII off in this Worker realm; see PII findings
```

What changes from main-thread mode:

- **Where the mapping lives.** The vault instance and every retained entry live in a closure private to the Worker's own module scope, not reachable by direct main-thread object access. The only interface is a validated message protocol: an out-of-protocol request (unrecognized operation, wrong shape, an unexpected key, a `__proto__`-bearing payload) is rejected explicitly (`WORKER_PROTOCOL_VIOLATION`), never silently ignored or coerced.
- **What it does not add.** A dedicated Worker is not an authentication boundary. Code that already has a reference to the `Worker` (for example a compromised same-page script) can still call `capture`/`restore` through the same protocol a legitimate caller uses, and can still observe whatever that protocol legitimately returns. Worker mode narrows *accidental* main-thread reach to the mapping; it does not defend against a main thread that is already compromised. See the [Worker-mode ADR](../decisions/qualify-dedicated-worker-mode.md)'s guarantee boundary.
- **The API shape.** `WorkerVault` mirrors `capture`/`restore`/`revoke`/`stats`/`dispose`, but every call returns a `Promise` — it is a message round trip, not an in-process call. `createWorkerVault(worker, { timeoutMs? })` never falls back to a main-thread vault: if the Worker fails to start, errors, or does not answer in time, the promise rejects with a fixed `VaultError`. Call `vault.terminate()` to stop the underlying Worker immediately.
- **Capture options.** `policy`, `eligible`, and `displayFormatter` are functions and cannot cross the message boundary (and running main-thread-supplied code inside the Worker would defeat the isolation this mode exists to provide). Worker-mode `capture` accepts only `release`, `maxUses`, `unredacted`, `ruleset`, and the PII retention allowlist `pii` (see [PII findings](pii.md)); passing one of the unsupported options throws `INVALID_ARGUMENT` synchronously, before anything is sent. A core policy for Worker captures belongs to the Worker script instead: see [Worker-script policy](#worker-script-policy).
- **CSP.** The Worker's own script response needs the same `'wasm-unsafe-eval'` the main thread needs (it is not inherited from the page), plus a `worker-src` directive that allows creating it, plus — under `require-trusted-types-for 'script'` — a Trusted Types policy for the `new Worker(url)` sink. See the [worker qualification record](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/research/qualification-worker-mode.md) for the exact policy used in qualification.

## PII in a Worker

The main-thread rules are in the [PII guide](pii.md).

**In Worker mode** ([#39](https://github.com/redact-secret/redact-secret-vault/issues/39)) the Worker is its own realm with its own core, so the Worker script owns its activation, not the page:

- `startVaultWorkerHost({ pii, expectPiiActivation })` behaves exactly like `createVault` inside the Worker realm, including adoption when the Worker script awaited the core's `initialize(...)` itself. A conflict surfaces as `createWorkerVault` rejecting with `CORE_FAILURE` / `coreCode: "PII_ACTIVATION_CONFLICT"`.
- The page cannot choose or change the Worker's selection. No message the page can send carries selectors; a request that tries is rejected with `WORKER_PROTOCOL_VIOLATION`.
- `workerVault.piiActivation` is the identity the Worker observed (`null` without PII support). `createWorkerVault(worker, { expectPiiActivation })` compares it byte-for-byte and rejects with `PII_ACTIVATION_MISMATCH` on any difference, including `null`. It returns no vault then; terminate the Worker yourself.
- `workerVault.capture(input, { pii: { retain: [...] } })` takes the same retention allowlist as the main thread. The client validates it before sending (`INVALID_ARGUMENT`), and the Worker validates it again on its own.
- The page cannot send a `policy` or `eligible`. To redact warn-level PII in a Worker, give the Worker script's host a policy (below). Without one, a Worker capture containing warn-level PII can only reject (`UNREDACTED_FINDINGS`) or use `unredacted: "pass-through"`.

```ts
// vault-worker.js — PII on for this Worker realm only
import { startVaultWorkerHost } from "@redact-secret/vault/worker/host";
startVaultWorkerHost({ pii: ["pii"] });
```

## Worker-script policy

The Worker script can own a core policy for every capture in its Worker ([#59](https://github.com/redact-secret/redact-secret-vault/issues/59), [decision addendum](../decisions/decide-pii-retention-and-activation-ownership.md#addendum-2026-09-28-worker-script-owned-core-policy-59)):

```ts
// vault-worker.js — the application writes this file; the page cannot change it
import { startVaultWorkerHost } from "@redact-secret/vault/worker/host";

startVaultWorkerHost({
  pii: ["pii"],
  // Redact every finding the core reports, including Medium/Low PII the core
  // would otherwise mark `warn` (for example `telephone=…` → pii_global_phone).
  policy: { evaluate: () => "redact" },
});
```

```ts
// main thread: no policy here; the Worker script's applies
const plain = await vault.capture("telephone=555-2345", { release });
// plain.unrestorable === 1: replaced, not restorable
const kept = await vault.capture("telephone=555-2345", { release, pii: { retain: ["pii_global_phone"] } });
// kept.tokens[0].type === "pii_global_phone": restorable under the grant
```

- **Same semantics as the main-thread `policy`.** It replaces the core's built-in policy for every finding, credentials included. The core exports no default policy to fall back to, so return an action for every finding: `redact` unless you mean otherwise.
- **PII retention is unchanged.** A PII finding the policy maps to `redact` is replaced by a placeholder that cannot be restored, unless the capture's `pii.retain` names its exact type. `block` still rejects the capture with `BLOCKED_FINDING`; a `warn` or `allow` still goes through the `unredacted` gate.
- **The page cannot see or change it.** No message carries policy data, the page-side `policy` option still throws `INVALID_ARGUMENT`, and `vault-ready` says nothing about the policy.
- **Checked at start.** `policy` must be an object with a callable `evaluate`. Otherwise the host reports `vault-init-failed` and `createWorkerVault` rejects with `INVALID_ARGUMENT`, before the Worker's core is initialized. `evaluate` is read once at start; replacing it on your object later has no effect.
- **Failures.** A policy that throws, or returns anything other than `redact`, `block`, `warn`, or `allow`, fails that capture exactly as on the main thread: `CORE_FAILURE` with `coreCode` `POLICY_FAILURE` or `INVALID_POLICY_ACTION` (core beta.10). Nothing is committed and the Worker keeps serving.
- **No override count.** The vault sees only the final actions, so audit events do not say which findings the policy changed. The vault does not run a second scan to find out; count inside `evaluate` if you need that.

## API

`createWorkerVault(worker, options?) → Promise<WorkerVault>` from `"@redact-secret/vault/worker"`. `worker` is a `Worker` (or a `MessagePort`); `options.timeoutMs` (default 15000) bounds the initial handshake and each call; `options.expectPiiActivation` (1 to 512 characters) must equal the Worker's reported identity, or the promise rejects with `PII_ACTIVATION_MISMATCH`. Never falls back to a main-thread vault: rejects with a `VaultError` if the Worker fails to start, errors, or times out, and with `WORKER_PROTOCOL_VIOLATION` if the Worker speaks another protocol version. `VaultError` is exported from this entry too.

`startVaultWorkerHost(options?) → Promise<void>` from `"@redact-secret/vault/worker/host"`, run inside the Worker. `options` extends `VaultOptions` (`limits`, `releasePolicy`, `onAudit`, `now`, `pii`, `expectPiiActivation`) plus an optional `policy` (a core `SecretPolicy` applied to every capture in this Worker; see [Worker-script policy](#worker-script-policy)) and an optional `target` (defaults to the Worker's own global scope; overridable for tests).

`WorkerVault`: `piiActivation` (`string | null`, read-only), `capture(input, options) → Promise<CaptureResult>` (`options` is `release`, `maxUses`, `unredacted`, `ruleset`, `pii` only — no `policy`, `eligible`, or `displayFormatter`), `restore(request) → Promise<RestoreResult>`, `revoke(captureId) → Promise<number>`, `stats() → Promise<VaultStats>`, `dispose() → Promise<void>`, and `terminate()` (synchronous; stops the Worker immediately).
