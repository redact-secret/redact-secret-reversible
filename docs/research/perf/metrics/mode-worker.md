# `mode-worker`: dedicated Worker ÷ main thread (B5, [#79](https://github.com/redact-secret/redact-secret-vault/issues/79))

Status: **current**, PII off, Chromium only. File: `bench/browser/worker-boundary.mjs`.

```bash
npm run build && node bench/browser/worker-boundary.mjs [--quick] [--out file] [--iterations N] [--warmup N]
```

## Why a separate script

Worker mode is browser-only: `@redact-secret/vault/worker` talks to `/worker/host` over a real dedicated `Worker`, and Node's `worker_threads` is not a supported port. The harness runs metrics in-process in Node.js, so this is not a `bench/metrics/` file and is not part of `bench`, `bench:smoke`, or `bench:compare`. It writes the same `redact-secret-vault/bench-result@1` result (kind `run`, metric id `mode-worker`) through the harness's `writeResult`, so it is schema-validated and leak-checked. Default output: `.bench-results/worker-boundary-<time>.json`.

When Playwright or its Chromium is not installed, the result records the metric as `skipped` and the script exits 0. A/B against a published version is not implemented for this mode.

## How it runs

The script bundles a small page with Vite from the workspace build. The app lives in the gitignored `.bench-cache/worker-boundary/` and is deleted afterwards, so bare imports resolve to the workspace packages and the repository's pinned core. It is served from localhost with COOP/COEP headers, so the page is cross-origin isolated and Chromium's `performance.now()` has 5 µs resolution instead of 100 µs. The page initializes the core with PII off and creates a main-thread vault. The Worker script calls `startVaultWorkerHost({ pii: [] })`. The page returns timing numbers only. The recorded core artifact is the one the page ran (`wasm`), not Node's.

Per iteration, in alternating order, the same operation runs on both vaults, each on its own fresh capture:

| Measurement | One sample |
| --- | --- |
| `rtt.main` / `rtt.worker` | `stats()`: the smallest request, so the message round-trip floor |
| `capture.*` | capture of `capture1k` |
| `restore.*` | restore of `restore64` over a fresh capture |
| `revoke.*` | revoke of a 4-entry capture |
| `<op>.boundary_ms` | `worker − main` of the same iteration |
| `<op>.ratio` | p50 worker ÷ p50 main, only where main p50 ≥ 0.05 ms (10 timer ticks) |

`rtt` and `revoke` have no ratio: the main-thread call takes under a microsecond, below the timer's resolution. Their `boundary_ms` is the figure.

## Figures

Local, one full run (1000 iterations after 200):

`[pii=off corpus-v1 candidate vault@0.1.0-alpha.3 core@0.1.0-beta.10/wasm node@22.16.0 darwin-arm64]` (Apple M4), Chromium 153 headless, cross-origin isolated

| Op | main p50 | worker p50 | boundary p50 (p95) | ratio |
| --- | --- | --- | --- | --- |
| rtt (`stats`) | < 0.005 ms | 0.015 ms | 0.015 ms (0.020) | — |
| capture | 0.245 ms | 0.260 ms | 0.015 ms (0.045) | 1.06 |
| restore (64 fields) | 0.060 ms | 0.080 ms | 0.020 ms (0.035) | 1.33 |
| revoke | < 0.005 ms | 0.010 ms | 0.010 ms (0.020) | — |

A Worker round trip costs about 10 to 20 µs per call, whatever the operation. The whole script takes about 3 seconds in full mode, including the Vite build.
