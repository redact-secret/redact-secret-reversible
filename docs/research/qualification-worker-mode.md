# Qualification record: optional dedicated-Worker mode

**Status:** executed evidence, 2026-09-27. Additional to, and does not replace or modify, the [0.1.0-alpha.1 qualification record](qualification-0.1.0-alpha.1.md): every number in that record is unchanged by this addition.
**Issue:** [#14](https://github.com/redact-secret/redact-secret-vault/issues/14) (depends on [#12](https://github.com/redact-secret/redact-secret-vault/issues/12), [#13](https://github.com/redact-secret/redact-secret-vault/issues/13)). **Decision:** [Worker-mode ADR](../decisions/2026-09-27-qualify-dedicated-worker-mode.md).

## Pinned core artifact

Same as alpha.1: `@redact-secret/core@0.1.0-beta.9` (peer dependency, single supported version). Worker mode adds no new dependency; the Worker's own realm loads the same core package the main thread would, independently, inside the Worker.

## Method

1. `npm pack` the vault (same tarball the main-thread and Node.js qualification runs use — one build, three runners). Install it and the pinned core into a throwaway consumer project **outside** the repository.
2. Build a production Vite bundle of a consumer page that creates a real dedicated Worker (`new Worker(new URL("./worker-entry.js", import.meta.url), { type: "module" })`) running `startVaultWorkerHost()` from the packed `@redact-secret/vault/worker/host` entry, and drives it from the page through `createWorkerVault()` from the packed `@redact-secret/vault/worker` entry.
3. Serve it with a strict CSP applied to *every* response in a navigation — the document, the worker script, and the worker's own WebAssembly fetch — since a dedicated Worker's effective CSP comes from its own script response headers, not from the creating document's query string:
   `Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types default; worker-src 'self'`.
   A `"default"` Trusted Types policy (that performs no rewriting, only satisfies the sink's type check) is required because `new Worker(url)` is its own Trusted Types sink, distinct from the `<script src>` sink the main-thread qualification exercises.
4. Run the portable Worker suite (`packages/vault/test/worker-suite.js`) through Playwright in Chromium, Firefox, and WebKit. It exercises capture/restore parity, client-side rejection of a non-cloneable capture option before any message is sent, and five hostile-main-thread cases sent directly to the raw `Worker` (bypassing the safe client wrapper): an unrecognized operation, a wrong `kind`, an unexpected extra key, a `__proto__`-bearing payload, and a non-object message — each asserted to be rejected explicitly (`WORKER_PROTOCOL_VIOLATION`) with the Worker still serving legitimate requests afterward, plus a check that no fixture value leaks into a protocol-violation reply.
5. Two negative controls, run as separate page loads against the same server: (a) `worker-src 'none'` — Worker creation must fail closed, and `createWorkerVault` must reject explicitly rather than fall back to an in-process vault; (b) the Worker is created but its CSP omits `'wasm-unsafe-eval'` — vault creation inside the Worker must fail closed with the same `CORE_FAILURE`/`INITIALIZATION_FAILED` the main-thread negative control already reports.
6. The runner adds 4 browser-specific checks on top of the suite's own 11 (no CSP violations, the `.wasm` asset was actually requested, and the two negative controls above), for 15 total.

All values are synthetic, drawn from the same `conformance/v1/corpus.json` fixtures the main-thread and Node.js suites use.

## Results

Reproduced locally (macOS arm64) on this branch, prior to the CI run linked from the pull request that introduced this file.

| Runtime | Platform | Result | `worker-src 'none'` control | No-WASM-in-Worker control |
| --- | --- | --- | --- | --- |
| Chromium 153.0.8010.12 (Playwright) | darwin-arm64 (local), linux-x64 (CI) | 15/15 | `WORKER_UNAVAILABLE`, rejected | `CORE_FAILURE`/`INITIALIZATION_FAILED`, rejected |
| Firefox 155.0 (Playwright) | darwin-arm64 (local), linux-x64 (CI) | 15/15 | `WORKER_UNAVAILABLE`, rejected | `CORE_FAILURE`/`INITIALIZATION_FAILED`, rejected |
| WebKit 26.6 (Playwright) | darwin-arm64 (local), linux-x64 (CI) | 15/15 | `WORKER_UNAVAILABLE`, rejected | `CORE_FAILURE`/`INITIALIZATION_FAILED`, rejected |

The main-thread suite (`qualification/browser.mjs`) and the Node.js suite (`qualification/node.mjs`) were re-run on the same commit and remain 65/65 and 61/61 respectively (see the [alpha.1 record](qualification-0.1.0-alpha.1.md)): Worker mode's addition does not change either.

Firefox and WebKit do not implement Trusted Types; the `trusted-types default` directive is simply unsupported and ignored there, which is the documented, spec-correct behavior for an unsupported CSP directive — it is not a gap this qualification papers over, since the `worker-src`/WASM-CSP controls that matter for the failure-mode claim are standard CSP, supported everywhere tested.

## Protocol v2: PII activation and retention (#39)

**Status:** executed evidence, 2026-09-28, still against the pinned `0.1.0-beta.9`. The table above is the #14 run and is left as recorded.

[#39](https://github.com/redact-secret/redact-secret-vault/issues/39) implements §3 "Worker mode" of the [PII retention and activation ADR](../decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md):

- `PROTOCOL_VERSION` is `2`. A version-1 request is answered with `WORKER_PROTOCOL_VIOLATION`, and a version-1 or incomplete `vault-ready` makes `createWorkerVault` reject with `WORKER_PROTOCOL_VIOLATION` instead of waiting for the timeout. Unknown keys are still rejected everywhere.
- `vault-ready` carries `piiActivation: string | null`, the identity the Worker realm's vault observed. `vault-init-failed` still carries only `code` and `coreCode`.
- `startVaultWorkerHost({ pii, expectPiiActivation })` has the main-thread `createVault` semantics inside the Worker realm, adoption included. No request carries selectors, so the page cannot choose or change the Worker's activation.
- `createWorkerVault(worker, { expectPiiActivation })` compares the ready identity byte-for-byte and rejects with `PII_ACTIVATION_MISMATCH`. `WorkerVault.piiActivation` exposes it.
- Capture options gain `pii: { retain }`. The client validates it under ADR §1 before sending (`INVALID_ARGUMENT`). The host validates it again on its own, accepts only the key `retain`, and rebuilds a fresh `{ retain }` object. Malformed retention sent straight to the Worker is a `WORKER_PROTOCOL_VIOLATION`.

What `qualify:worker` adds (the existing hostile cases now send `v: 2`, so they still test the shape they name rather than the version check):

- Suite cases (11 → 16): a version-1 request is rejected; the ready identity agrees with the page core's PII surface (`null` on beta.9); invalid `pii` retention throws synchronously and sends nothing; capture retention fails closed with `PII_UNAVAILABLE` when PII is not active; and five selector-smuggling messages (a `pii` or `expectPiiActivation` key on a request, a selector array or `selectors` key in `options.pii`, and an `initialize` op) are rejected while the Worker keeps serving.
- Runner controls (4 → 6): a second Worker entry calls `startVaultWorkerHost({ pii: ["pii"] })`. It must fail closed with `PII_UNAVAILABLE` on a core without a PII surface, and report an active identity on a PII-capable core. A page passing an impossible `expectPiiActivation` must be rejected with `PII_ACTIVATION_MISMATCH`.

| Runtime | Result |
| --- | --- |
| Chromium 153.0.8010.12 (Playwright), darwin-arm64 local | 22/22 |
| Firefox 155.0 (Playwright), darwin-arm64 local | 22/22 |
| WebKit 26.6 (Playwright), darwin-arm64 local | 22/22 |

Protocol and activation cases that do not need a browser are in `packages/vault/test/worker-pii.test.mjs` (fake core, one Node.js process per Worker realm) and `worker-pii-core.test.mjs` (real installed core; PII-on cases skip with a stated reason on beta.9). Against a local build of the `0.1.0-beta.10` candidate, which is not on npm, the six PII-on cases of `worker-pii-core.test.mjs` pass. **Browser qualification of Worker mode against beta.10 itself is [#42](https://github.com/redact-secret/redact-secret-vault/issues/42), recorded in the [beta.10 qualification record](qualification-core-0.1.0-beta.10.md).** Note for #42: on a PII-capable core the default Worker entry (`startVaultWorkerHost()` with no `pii`) fails with `CORE_FAILURE`/`NOT_INITIALIZED` by design, so the runner needs `pii: []` or a Worker script that initializes the core first.

## What this does and does not establish

- **Establishes:** for the exact versions above, Worker mode's message protocol rejects every tested out-of-protocol request explicitly without disrupting legitimate use; a compromised main thread cannot reach the Worker-held mapping other than through that protocol; Worker creation and Worker-internal vault initialization each fail closed, with no main-thread fallback, when their respective CSP requirement is not met; and none of this changes what the main-thread and Node.js modes already established.
- **Does not establish:** `SharedWorker`, a Service Worker, or Node.js `worker_threads` (none are claimed supported); branded Chrome/Edge/Safari on real devices or Windows/Linux-arm64 (same caveat as the alpha.1 record — Playwright engine builds were used); resistance to a main thread that is already compromised calling the *legitimate* protocol (by design, out of scope — see the ADR's guarantee boundary); server authorization; persistence; memory erasure.

## Reproduce

```bash
npm ci
npm run check:boundaries
npx playwright install chromium firefox webkit
npm run qualify:worker        # BROWSERS=chromium,firefox,webkit
```

Reports are written to `.qualification/reports/worker-<engine>-<version>.json`.
