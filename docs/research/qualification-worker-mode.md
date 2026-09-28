# Qualification record: optional dedicated-Worker mode

**Status:** executed evidence, 2026-09-27. Additional to, and does not replace or modify, the [0.1.0-alpha.1 qualification record](qualification-0.1.0-alpha.1.md): every number in that record is unchanged by this addition.
**Issue:** [#14](https://github.com/redact-secret/redact-secret-reversible/issues/14) (depends on [#12](https://github.com/redact-secret/redact-secret-reversible/issues/12), [#13](https://github.com/redact-secret/redact-secret-reversible/issues/13)). **Decision:** [Worker-mode ADR](../decisions/2026-09-27-qualify-dedicated-worker-mode.md).

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
