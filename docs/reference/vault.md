# `@redact-secret/vault` reference

Runtime support, guarantees, limits, and the full API of [`@redact-secret/vault`](../../packages/vault/README.md). Start with the package README for the five-minute path. Related guides: [Worker mode](../guides/worker-mode.md), [PII](../guides/pii.md).

## Supported, and not

| Runtime | Status in 0.1.0-beta.4 |
| --- | --- |
| Node.js 20, 22, 24 (core native addon or its WebAssembly fallback) | Qualified: Linux x64, macOS arm64 |
| Browser main thread, bundled, with a CSP allowing `'wasm-unsafe-eval'` | Qualified: Chromium, Firefox, WebKit (versions in the [alpha.1 qualification record](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/research/qualification-0.1.0-alpha.1.md); PII off and on in the [beta.10 qualification record](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/research/qualification-core-0.1.0-beta.10.md)) |
| Optional dedicated-Worker mode (`@redact-secret/vault/worker`), same three browser engines, CSP allowing `'wasm-unsafe-eval'` and `worker-src` | **Qualified, opt-in, separately from main-thread mode** — see [Worker mode](../guides/worker-mode.md) and the [worker qualification record](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/research/qualification-worker-mode.md) ([#14](https://github.com/redact-secret/redact-secret-vault/issues/14)) |
| `@redact-secret/core` | `0.1.0-beta.12` exactly (peer dependency; `0.1.0-beta.2` pinned `0.1.0-beta.11`, `0.1.0-alpha.2` through `0.1.0-beta.1` pinned `0.1.0-beta.10`, `0.1.0-alpha.1` pinned `0.1.0-beta.9`, and without PII support) |
| `SharedWorker`, a Service Worker, or Node.js `worker_threads` | **Not supported** |
| Multi-user or multi-tenant server authorization | **Not supported**. This package does not know users or tenants. Use [`@redact-secret/vault-server`](../../packages/vault-server/README.md) for principal and tenant authorization |
| Persistence, Python, streaming, free-text `restore(text)` | **Not supported** |

## What the vault enforces

- **Explicit capture.** `createVault` and `capture` are the only ways to retain anything. Importing the package retains nothing.
- **Core action gate.** Any `block` finding fails the capture (`BLOCKED_FINDING`) with no output and no mapping. `warn` and `allow` findings stay as plaintext in the core's output, so by default the capture fails (`UNREDACTED_FINDINGS`). With `unredacted: "pass-through"` it returns the text and reports the count in `passedThrough`.
- **Tokens.** Each retained occurrence gets its own `<rsv_…>` token with 128 bits from `crypto.getRandomValues`. The type beside it is descriptive only. Input that already contains `rsv_` is refused (`TOKEN_LITERAL_IN_INPUT`), so no literal can be mistaken for an issued token.
- **Restoration into granted fields only.** You pass one `sink`, the `captures` the output may draw from, and a map of `path → text`. Every token in every field must come from one of those captures in this vault, be unexpired, be granted for that sink and exact path, and fit within its use budget (`maxUses`, default 1). Your optional `releasePolicy` must also return `true`. One failure denies the whole request, with no plaintext and no budget consumed. A token altered while its `rsv_` marker survives (case, truncation, whitespace, invisible format characters) is denied rather than ignored. An alteration that destroys the marker, such as a look-alike letter or another invisible mark (for example U+034F or a variation selector), leaves ordinary text that is returned unrestored; no value is released.
- **Bounds.** Entries, retained bytes, bytes per value, input bytes, findings, entry TTL, vault lifetime, restore fields, and bytes per field are all bounded. See `DEFAULT_LIMITS` and `LIMIT_CEILINGS`. Expiry is checked on every call; no timers run. The vault checks `maxInputBytes` itself (`LIMIT_EXCEEDED`). `maxFindings` is passed to the core as its finding limit, so too many findings fail the whole capture with `CORE_FAILURE` / `coreCode: "FINDING_LIMIT_EXCEEDED"` and commit nothing. Every finding the core returns counts toward it, including PII findings that are not retained or are passed through, so enabling PII can make an input that fit before exceed the limit.
- **Lifecycle.** `revoke(captureId)` removes a capture's unused entries. `dispose()` clears everything, is idempotent, and makes later calls fail with `DISPOSED`.
- **Sanitized diagnostics.** Errors carry a fixed message, a `code`, and only a core error code or coarse denial `reason`. They never carry input, values, tokens, or paths, and never a `cause`. `onAudit` receives frozen events with operation, outcome, code, reason, counts, sink, and time only. `stats()` returns counts. There is no export, dump, or iteration API. The vault never logs, stores to disk or browser storage, or makes network calls.
- **Re-entrancy.** A callback that calls back into the vault during an operation gets `BUSY`.

## What it does not protect against

- **Code in your page or process.** Same-page scripts, XSS, compromised dependencies, and extensions can read the input before capture, call `restore`, or read its result. The vault shares their trust boundary.
- **Relocation within a grant.** A model can move a valid token within a granted field, or into another path you granted for the same capture. Grant the narrowest paths. Keep `maxUses: 1`.
- **Other users.** A vault shared across users or tenants will restore one user's value into another's granted field if you list both captures. Use one vault per user task, or [`@redact-secret/vault-server`](../../packages/vault-server/README.md) for principal and tenant checks.
- **Denial reasons.** `reason` tells your code which check failed, and so whether a token is live. Do not forward it to the model or to end users.
- **Inspection tools.** Browser DevTools and debuggers can display private fields; `console.log(vault)` in a DevTools session can show retained values.
- **Undetected secrets.** The core does not detect every secret. Treat `text` as "known findings removed", not "safe to send".
- **Memory erasure.** Values are JavaScript strings; revoke and dispose drop references but cannot zeroize memory.
- **Plaintext after return.** Once `restore` returns, rendering, logging, and forwarding are your responsibility.

See the [threat model](../specs/threat-model.md) for each mode's boundary and alternatives.

## API

`createVault(options?) → Promise<Vault>`. Options: `limits` (partial `VaultLimits`), `releasePolicy(request) → boolean`, `onAudit(event)`, `now() → ms` (for tests; the default clock is monotonic), `pii` (core PII selectors, 0 to 64 strings of 1 to 128 characters, forwarded as given), and `expectPiiActivation` (1 to 512 characters). Rejects with `UNSUPPORTED_RUNTIME` without `crypto.getRandomValues`, with `CORE_FAILURE` if the core cannot initialize (for example, a CSP without `'wasm-unsafe-eval'`) or rejects the PII selection (`coreCode` `PII_ACTIVATION_CONFLICT`, `PII_SELECTOR_INVALID`, `PII_SELECTOR_UNSUPPORTED`, `PII_SELECTOR_UNAVAILABLE`, or `NOT_INITIALIZED`), and with `PII_UNAVAILABLE` or `PII_ACTIVATION_MISMATCH` as described under [PII findings](../guides/pii.md).

`vault.piiActivation → string | null`. The core's PII activation identity observed at creation. It is `null` on a core without PII support.

`vault.capture(input, options) → CaptureResult`. Options: `release` (required), `maxUses`, `unredacted` (`"reject"` | `"pass-through"`), `policy` and `ruleset` (passed to the core), `eligible(finding)`, `displayFormatter`, `pii: { retain }` (1 to 64 exact `pii_…` types, each at most 128 characters from `[a-z0-9_-]`; no wildcards). Result: `captureId`, `text`, `tokens[{ token, type }]`, `passedThrough`, `passedThroughTypes`, `unrestorable`, `expiresAt`. A core limit failure (for example, too many findings) surfaces as `CORE_FAILURE` with the core's `coreCode`.

`displayFormatter(finding, context)` labels the `redact` findings the vault does not retain. A label that contains the `rsv_` token marker, or a formatter that throws, fails the capture with `CORE_FAILURE` / `coreCode: "PLACEHOLDER_FAILURE"`; an empty label fails with `coreCode: "INVALID_PLACEHOLDER"`. The core (beta.10) also rejects a label that reproduces the matched text of any finding in the same input, including a `warn` or `allow` finding left as plaintext under `unredacted: "pass-through"`. That fails the whole capture with `CORE_FAILURE` / `coreCode: "INVALID_PLACEHOLDER"`: no text, no tokens, nothing committed, and the error and audit event carry no value. Use fixed labels that cannot look like input, such as `[REDACTED]` or the finding type.

`vault.restore({ sink, captures, fields }) → { fields, restored }`. Returns the same paths with issued tokens replaced; throws `RESTORE_DENIED` with `reason` of `invalid-request`, `malformed-token`, `unknown-token`, `source`, `expired`, `sink-or-path`, `budget`, or `policy`. `releasePolicy` receives `captureId`, `sink`, `path`, `type`, `occurrences` (in this path), `totalOccurrences` (in the whole request), and `used`.

`vault.revoke(captureId) → number`, `vault.dispose()`, `vault.stats()`.

Error codes: `INVALID_ARGUMENT`, `UNSUPPORTED_RUNTIME`, `CORE_FAILURE`, `BLOCKED_FINDING`, `UNREDACTED_FINDINGS`, `TOKEN_LITERAL_IN_INPUT`, `LIMIT_EXCEEDED`, `TOKEN_GENERATION_FAILED`, `INVARIANT_VIOLATION`, `RESTORE_DENIED`, `BUSY`, `DISPOSED`, `PII_UNAVAILABLE` (a PII option on a core without PII support, or capture retention while PII detection is off), `PII_ACTIVATION_MISMATCH` (the observed activation differs from `expectPiiActivation`). Worker mode ([#14](https://github.com/redact-secret/redact-secret-vault/issues/14)) also uses `WORKER_PROTOCOL_VIOLATION` (a message did not match the validated protocol) and `WORKER_UNAVAILABLE` (the Worker did not respond, errored, or was terminated).

The Worker entry points are in the [Worker mode guide](../guides/worker-mode.md#api).

## Internal entry points

`@redact-secret/vault/internal/capture-plan` exists for `@redact-secret/vault-server`, which pins the exact vault version it was built with. It is not a supported public API and has no stability guarantee: it can change or disappear in any release. It is exported under the `node` condition only and is not re-exported from the package root or the Worker entry points.

The module holds the part of a capture that comes before anything is retained: argument validation, the core scan, the action gate, the PII allowlist, `eligible`, limits, token issuance, and output validation. It returns the redacted text and, for each retained finding, the token, the type, and the range of the finding in the input. It returns no retained value, since the caller slices the input it already holds, and it reads no vault. Tokens come from the platform CSPRNG inside the module; no caller supplies a random source.
