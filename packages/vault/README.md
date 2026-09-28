# @redact-secret/vault

**Alpha.** An opt-in, bounded, in-memory vault for [`@redact-secret/core`](https://www.npmjs.com/package/@redact-secret/core). It replaces detected secrets with random tokens before text leaves your code, for example to an LLM. Later it puts the original values back, but only into fields your application names in advance.

```bash
npm install @redact-secret/vault@alpha @redact-secret/core@0.1.0-beta.9
```

## Supported, and not

| Runtime | Status in 0.1.0-alpha.1 |
| --- | --- |
| Node.js 20, 22, 24 (core native addon or its WebAssembly fallback) | Qualified: Linux x64, macOS arm64 |
| Browser main thread, bundled, with a CSP allowing `'wasm-unsafe-eval'` | Qualified: Chromium, Firefox, WebKit (versions in the [qualification record](https://github.com/redact-secret/redact-secret-reversible/blob/main/docs/research/qualification-0.1.0-alpha.1.md)) |
| Optional dedicated-Worker mode (`@redact-secret/vault/worker`), same three browser engines, CSP allowing `'wasm-unsafe-eval'` and `worker-src` | **Qualified, opt-in, separately from main-thread mode** — see [Worker mode](#worker-mode) and the [worker qualification record](https://github.com/redact-secret/redact-secret-reversible/blob/main/docs/research/qualification-worker-mode.md) ([#14](https://github.com/redact-secret/redact-secret-reversible/issues/14)) |
| `@redact-secret/core` | `0.1.0-beta.9` exactly (peer dependency) |
| `SharedWorker`, a Service Worker, or Node.js `worker_threads` | **Not supported** |
| Multi-user or multi-tenant server authorization | **Not supported**. This package does not know users or tenants ([#15](https://github.com/redact-secret/redact-secret-reversible/issues/15)) |
| Persistence, Python, streaming, free-text `restore(text)` | **Not supported** |

## Usage

```ts
import { createVault, VaultError } from "@redact-secret/vault";

// One vault per user task or session. Nothing is retained until you call capture.
const vault = await createVault({ limits: { entryTtlMs: 5 * 60_000 } });

try {
  const userText = "Please rotate ghp_SYNTHETICxREVOKEDxTESTx0000000000000 today";

  const captured = vault.capture(userText, {
    // Where these values may come back: this sink, these exact field paths.
    release: [{ sink: "draft-reply", paths: ["body"] }],
  });
  // captured.text: "Please rotate <rsv_…> today"
  // captured.passedThrough === 0, guaranteed under the default unredacted: "reject".

  const modelReply = await callModel(captured.text); // your code; sees only tokens

  let body: string;
  try {
    const { fields } = vault.restore({
      sink: "draft-reply",
      captures: [captured.captureId], // only this conversation's values
      fields: { body: modelReply },
    });
    body = fields.body;
  } catch (error) {
    if (!(error instanceof VaultError) || error.code !== "RESTORE_DENIED") throw error;
    body = modelReply; // denied: keep the redacted text, do not retry with a wider grant
  }
  render(body); // your code owns safe rendering of plaintext
} finally {
  vault.dispose();
}
```

## What the vault enforces

- **Explicit capture.** `createVault` and `capture` are the only ways to retain anything. Importing the package retains nothing.
- **Core action gate.** Any `block` finding fails the capture (`BLOCKED_FINDING`) with no output and no mapping. `warn` and `allow` findings stay as plaintext in the core's output, so by default the capture fails (`UNREDACTED_FINDINGS`). With `unredacted: "pass-through"` it returns the text and reports the count in `passedThrough`.
- **Tokens.** Each retained occurrence gets its own `<rsv_…>` token with 128 bits from `crypto.getRandomValues`. The type beside it is descriptive only. Input that already contains `rsv_` is refused (`TOKEN_LITERAL_IN_INPUT`), so no literal can be mistaken for an issued token.
- **Restoration into granted fields only.** You pass one `sink`, the `captures` the output may draw from, and a map of `path → text`. Every token in every field must come from one of those captures in this vault, be unexpired, be granted for that sink and exact path, and fit within its use budget (`maxUses`, default 1). Your optional `releasePolicy` must also return `true`. One failure denies the whole request, with no plaintext and no budget consumed. A token altered while its `rsv_` marker survives (case, truncation, whitespace, invisible format characters) is denied rather than ignored. An alteration that destroys the marker, such as a look-alike letter or another invisible mark (for example U+034F or a variation selector), leaves ordinary text that is returned unrestored; no value is released.
- **Bounds.** Entries, retained bytes, bytes per value, input bytes, findings, entry TTL, vault lifetime, restore fields, and bytes per field are all bounded. See `DEFAULT_LIMITS` and `LIMIT_CEILINGS`. Expiry is checked on every call; no timers run.
- **Lifecycle.** `revoke(captureId)` removes a capture's unused entries. `dispose()` clears everything, is idempotent, and makes later calls fail with `DISPOSED`.
- **Sanitized diagnostics.** Errors carry a fixed message, a `code`, and only a core error code or coarse denial `reason`. They never carry input, values, tokens, or paths, and never a `cause`. `onAudit` receives frozen events with operation, outcome, code, reason, counts, sink, and time only. `stats()` returns counts. There is no export, dump, or iteration API. The vault never logs, stores to disk or browser storage, or makes network calls.
- **Re-entrancy.** A callback that calls back into the vault during an operation gets `BUSY`.

## What it does not protect against

- **Code in your page or process.** Same-page scripts, XSS, compromised dependencies, and extensions can read the input before capture, call `restore`, or read its result. The vault shares their trust boundary.
- **Relocation within a grant.** A model can move a valid token within a granted field, or into another path you granted for the same capture. Grant the narrowest paths. Keep `maxUses: 1`.
- **Other users.** A vault shared across users or tenants will restore one user's value into another's granted field if you list both captures. Use one vault per user task. Server authorization is future work.
- **Denial reasons.** `reason` tells your code which check failed, and so whether a token is live. Do not forward it to the model or to end users.
- **Inspection tools.** Browser DevTools and debuggers can display private fields; `console.log(vault)` in a DevTools session can show retained values.
- **Undetected secrets.** The core does not detect every secret. Treat `text` as "known findings removed", not "safe to send".
- **Memory erasure.** Values are JavaScript strings; revoke and dispose drop references but cannot zeroize memory.
- **Plaintext after return.** Once `restore` returns, rendering, logging, and forwarding are your responsibility.

See the [threat model](https://github.com/redact-secret/redact-secret-reversible/blob/main/docs/specs/threat-model.md) for each mode's boundary and alternatives.

## Worker mode

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
startVaultWorkerHost();
```

What changes from main-thread mode:

- **Where the mapping lives.** The vault instance and every retained entry live in a closure private to the Worker's own module scope, not reachable by direct main-thread object access. The only interface is a validated message protocol: an out-of-protocol request (unrecognized operation, wrong shape, an unexpected key, a `__proto__`-bearing payload) is rejected explicitly (`WORKER_PROTOCOL_VIOLATION`), never silently ignored or coerced.
- **What it does not add.** A dedicated Worker is not an authentication boundary. Code that already has a reference to the `Worker` (for example a compromised same-page script) can still call `capture`/`restore` through the same protocol a legitimate caller uses, and can still observe whatever that protocol legitimately returns. Worker mode narrows *accidental* main-thread reach to the mapping; it does not defend against a main thread that is already compromised. See the [Worker-mode ADR](https://github.com/redact-secret/redact-secret-reversible/blob/main/docs/decisions/2026-09-27-qualify-dedicated-worker-mode.md)'s guarantee boundary.
- **The API shape.** `WorkerVault` mirrors `capture`/`restore`/`revoke`/`stats`/`dispose`, but every call returns a `Promise` — it is a message round trip, not an in-process call. `createWorkerVault(worker, { timeoutMs? })` never falls back to a main-thread vault: if the Worker fails to start, errors, or does not answer in time, the promise rejects with a fixed `VaultError`. Call `vault.terminate()` to stop the underlying Worker immediately.
- **Capture options.** `policy`, `eligible`, and `displayFormatter` are functions and cannot cross the message boundary (and running main-thread-supplied code inside the Worker would defeat the isolation this mode exists to provide). Worker-mode `capture` accepts only `release`, `maxUses`, `unredacted`, and `ruleset`; passing one of the unsupported options throws `INVALID_ARGUMENT` synchronously, before anything is sent.
- **CSP.** The Worker's own script response needs the same `'wasm-unsafe-eval'` the main thread needs (it is not inherited from the page), plus a `worker-src` directive that allows creating it, plus — under `require-trusted-types-for 'script'` — a Trusted Types policy for the `new Worker(url)` sink. See the [worker qualification record](https://github.com/redact-secret/redact-secret-reversible/blob/main/docs/research/qualification-worker-mode.md) for the exact policy used in qualification.

## Multi-turn conversations

Capture only the new user turn. Earlier turns are already redacted, so send the stored redacted history plus the new capture's `text`, and do not re-capture history: tokens in the input are refused (`TOKEN_LITERAL_IN_INPUT`), so nothing restored is scanned twice. At restore time, list the captures of this conversation in `captures`. Do not restore history in order to re-capture it.

If a capture fails with `UNREDACTED_FINDINGS`, the input contains values the core chose to leave visible (`warn`/`allow`). Prefer adjusting the core `policy` to `redact` those types over `unredacted: "pass-through"`. If you do pass them through, check `passedThroughTypes` before sending.

## PII findings

The pinned core (`0.1.0-beta.9`) has no PII detection. A later core adds opt-in PII detection, whose finding types start with `pii_`. The vault detects that support at runtime, never by version. The rules below are implemented and tested against a local build of the `0.1.0-beta.10` candidate, which is not on npm. See the [decision record](https://github.com/redact-secret/redact-secret-reversible/blob/main/docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md).

- **Your application owns PII activation.** In the core, PII activation applies to the whole process or page and can be set only once. The vault never chooses a selection for you. Pass `createVault({ pii: [...] })` and the vault forwards your selectors to the core's `initialize({ pii })` as given. `pii: []` means PII off. Omit `pii` and the vault adopts whatever your application already set with the core's own `initialize`, and calls no initializer itself. If nothing initialized the core, `createVault()` fails with `CORE_FAILURE` / `coreCode: "NOT_INITIALIZED"` rather than silently locking PII off. Fix it with `createVault({ pii: [] })`, or by awaiting the core's `initialize(...)` first. A different selection than the one already active fails with `CORE_FAILURE` / `coreCode: "PII_ACTIVATION_CONFLICT"`, and the active selection is left unchanged.
- **Observed activation.** `vault.piiActivation` is the core's canonical activation identity, or `null` on a core without PII support. Pass `expectPiiActivation` to require an exact identity. Any difference fails with `PII_ACTIVATION_MISMATCH`.
- **PII is never retained by default.** A `redact` finding whose type starts `pii_` is replaced by a display placeholder that cannot be restored, and counted in `unrestorable`. To retain a type, name it exactly in `capture(input, { pii: { retain: ["pii_global_iban"] } })`. `eligible` is consulted only for allowlisted PII types. It can narrow the allowlist but cannot widen it, so an allow-all `eligible` retains no PII. Retained PII uses the same grants, `maxUses`, TTLs, and limits as any other entry.
- **Warn-level PII still fails the capture.** Medium- and Low-confidence PII defaults to the core's `warn` action, so such a capture fails with `UNREDACTED_FINDINGS` unless you map those types to `redact` with a core `policy` or choose `unredacted: "pass-through"`.
- **Fail closed on the pinned core.** With a core that lacks PII support, a non-empty `pii`, any `expectPiiActivation`, or a capture's `pii` option fails with `PII_UNAVAILABLE` before the core is called. `pii: []` is accepted and equals omission. A capture's `pii` option also fails `PII_UNAVAILABLE` when the observed activation has `selectors=off`.

Worker mode does not accept PII options yet ([#39](https://github.com/redact-secret/redact-secret-reversible/issues/39)).

## API

`createVault(options?) → Promise<Vault>`. Options: `limits` (partial `VaultLimits`), `releasePolicy(request) → boolean`, `onAudit(event)`, `now() → ms` (for tests; the default clock is monotonic), `pii` (core PII selectors, 0 to 64 strings of 1 to 128 characters, forwarded as given), and `expectPiiActivation` (1 to 512 characters). Rejects with `UNSUPPORTED_RUNTIME` without `crypto.getRandomValues`, with `CORE_FAILURE` if the core cannot initialize (for example, a CSP without `'wasm-unsafe-eval'`) or rejects the PII selection (`coreCode` `PII_ACTIVATION_CONFLICT`, `PII_SELECTOR_INVALID`, `PII_SELECTOR_UNSUPPORTED`, `PII_SELECTOR_UNAVAILABLE`, or `NOT_INITIALIZED`), and with `PII_UNAVAILABLE` or `PII_ACTIVATION_MISMATCH` as described under [PII findings](#pii-findings).

`vault.piiActivation → string | null`. The core's PII activation identity observed at creation. It is `null` on a core without PII support.

`vault.capture(input, options) → CaptureResult`. Options: `release` (required), `maxUses`, `unredacted` (`"reject"` | `"pass-through"`), `policy` and `ruleset` (passed to the core), `eligible(finding)`, `displayFormatter`, `pii: { retain }` (1 to 64 exact `pii_…` types, each at most 128 characters from `[a-z0-9_-]`; no wildcards). Result: `captureId`, `text`, `tokens[{ token, type }]`, `passedThrough`, `passedThroughTypes`, `unrestorable`, `expiresAt`. A core limit failure (for example, too many findings) surfaces as `CORE_FAILURE` with the core's `coreCode`.

`vault.restore({ sink, captures, fields }) → { fields, restored }`. Returns the same paths with issued tokens replaced; throws `RESTORE_DENIED` with `reason` of `invalid-request`, `malformed-token`, `unknown-token`, `source`, `expired`, `sink-or-path`, `budget`, or `policy`. `releasePolicy` receives `captureId`, `sink`, `path`, `type`, `occurrences` (in this path), `totalOccurrences` (in the whole request), and `used`.

`vault.revoke(captureId) → number`, `vault.dispose()`, `vault.stats()`.

Error codes: `INVALID_ARGUMENT`, `UNSUPPORTED_RUNTIME`, `CORE_FAILURE`, `BLOCKED_FINDING`, `UNREDACTED_FINDINGS`, `TOKEN_LITERAL_IN_INPUT`, `LIMIT_EXCEEDED`, `TOKEN_GENERATION_FAILED`, `INVARIANT_VIOLATION`, `RESTORE_DENIED`, `BUSY`, `DISPOSED`, `PII_UNAVAILABLE` (a PII option on a core without PII support, or capture retention while PII detection is off), `PII_ACTIVATION_MISMATCH` (the observed activation differs from `expectPiiActivation`). Worker mode ([#14](https://github.com/redact-secret/redact-secret-reversible/issues/14)) also uses `WORKER_PROTOCOL_VIOLATION` (a message did not match the validated protocol) and `WORKER_UNAVAILABLE` (the Worker did not respond, errored, or was terminated).

### Worker mode API

`createWorkerVault(worker, options?) → Promise<WorkerVault>` from `"@redact-secret/vault/worker"`. `worker` is a `Worker` (or a `MessagePort`); `options.timeoutMs` (default 15000) bounds the initial handshake and each call. Never falls back to a main-thread vault: rejects with a `VaultError` if the Worker fails to start, errors, or times out.

`startVaultWorkerHost(options?) → Promise<void>` from `"@redact-secret/vault/worker/host"`, run inside the Worker. `options` extends `VaultOptions` (`limits`, `releasePolicy`, `onAudit`, `now`) plus an optional `target` (defaults to the Worker's own global scope; overridable for tests).

`WorkerVault`: `capture(input, options) → Promise<CaptureResult>` (`options` is `release`, `maxUses`, `unredacted`, `ruleset` only — no `policy`, `eligible`, or `displayFormatter`), `restore(request) → Promise<RestoreResult>`, `revoke(captureId) → Promise<number>`, `stats() → Promise<VaultStats>`, `dispose() → Promise<void>`, and `terminate()` (synchronous; stops the Worker immediately).

## Security reports

Report vulnerabilities privately through [GitHub security advisories](https://github.com/redact-secret/redact-secret-reversible/security/advisories/new). Never include live credentials. See [SECURITY.md](https://github.com/redact-secret/redact-secret-reversible/blob/main/SECURITY.md).

## License

MIT
