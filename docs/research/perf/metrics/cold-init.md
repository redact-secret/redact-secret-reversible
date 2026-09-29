# `cold-init` and `cold-init-browser`: cold `createVault()` (B8, [#82](https://github.com/redact-secret/redact-secret-vault/issues/82))

Status: **current**, PII off and on, Node.js and Chromium.

Source: `bench/metrics/cold-init.mjs` (Node.js) and `bench/metrics/cold-init-browser.mjs` (Chromium), with `bench/metrics/support/distribution.mjs` locating each side's package directories.

## What one sample times

Each sample is a fresh realm that has never loaded the core or the vault:

1. `import` the side's core, then `core.initialize({ pii })` for the run's PII mode. This loads the native addon (Node.js) or fetches and compiles the WebAssembly (browser). → `core_ms`
2. `import` the side's vault, then `await createVault()`. → `vault_ms`

| Measurement | Runtime | Gating |
| --- | --- | --- |
| `cold_init.total_ms` | Node.js | informational (includes the core) |
| `cold_init.core_ms` | Node.js | informational (moves with the pinned core) |
| `cold_init.vault_ms` | Node.js | **yes**: the vault's own cold start |
| `cold_init.process_ms` | Node.js, measured by the parent from spawn to exit, including Node.js startup | informational |
| `cold_init.browser.total_ms` | Chromium | informational |
| `cold_init.browser.core_ms` | Chromium | informational |
| `cold_init.browser.vault_ms` | Chromium | **yes** |

Gating latency uses the epic's rule: warn when the ratio of medians exceeds 1.10 and the bootstrap CI lies above 1.0.

**Node.js.** One child process per sample (`node --input-type=module -e …`), run one at a time. Times use `performance.now()` inside the child from before the first import. The child receives only the two entry URLs and the PII selectors, creates an empty vault, and prints three numbers, the core artifact, and the vault's PII activation. The parent fails the metric if the artifact or activation differ from the harness's own side, so the child measures the same core build in the same mode.

**Chromium.** A production Vite build per side (the vault and core resolved from that side's install, the WebAssembly emitted as a separate asset) under `.bench-cache/b8/`, served from `127.0.0.1` with `cache-control: no-store`. Each sample is a new browser context (no HTTP or compiled-code cache) and a new page. Chromium coarsens `performance.now()` to 0.1 ms without cross-origin isolation; `vault_ms` is about 4 ms, so that resolution is well below the 10% warn ratio. Each page must report the `wasm` artifact and the harness's PII activation.

**Cold, not cold-disk.** One untimed spawn (or page) per `run()` call absorbs first-touch file-cache and code-signing cost, which made the first sample about 5× slower in local runs. The OS file cache is warm; the process, module graph, and core are cold.

**Counts.** Per `run()` call: 20 spawns (quick: 3); 15 pages and one Chromium launch (quick: 3). `bench/compare.mjs` calls `run()` once per round per side, so a full compare pools 200 Node.js and 150 Chromium samples per side.

## Skipping the browser

`cold-init-browser` is **skipped**, not failed, when playwright's Chromium is not installed (`npx playwright install chromium`) or `BENCH_SKIP_BROWSER=1` is set. Only Chromium is measured: the issue asks for one engine. Firefox and WebKit would reuse the same page build.

## Runtime

A full `bench:compare` of `dist-size`, `cold-init`, and `cold-init-browser` takes about 36 s on an Apple M4 (about 45 ms per Node.js spawn, 45 ms per Chromium page, 0.3 s per Chromium launch). Quick: about 8 s including the first baseline install.

## Figures

`[pii=off corpus-v1 rounds=10x1000 node@22.16.0 darwin-arm64 local]` candidate `vault@0.1.0-alpha.3 (workspace@cacd734e7544) core@0.1.0-beta.10/addon` vs baseline `vault@0.1.0-alpha.3 (npm) core@0.1.0-beta.10/addon`; Chromium 153.0.8010.12 (wasm):

| Measurement | Candidate p50 / p95 (ms) | Baseline p50 / p95 (ms) | Ratio [95% CI] |
| --- | --- | --- | --- |
| `cold_init.vault_ms` | 2.96 / 5.39 | 2.94 / 5.47 | 1.006 [0.980, 1.053] |
| `cold_init.core_ms` | 7.16 / 12.09 | 7.37 / 13.65 | 0.973 [0.945, 0.994] |
| `cold_init.total_ms` | 10.14 / 17.81 | 10.32 / 18.83 | 0.982 [0.950, 1.004] |
| `cold_init.process_ms` | 34.14 / 53.36 | 34.62 / 57.24 | 0.986 [0.959, 1.032] |
| `cold_init.browser.vault_ms` | 3.90 / 4.60 | 3.80 / 4.20 | 1.026 [1.000, 1.066] |
| `cold_init.browser.core_ms` | 6.70 / 10.81 | 6.70 / 10.86 | 1.000 [0.971, 1.030] |
| `cold_init.browser.total_ms` | 10.70 / 12.81 | 10.55 / 13.20 | 1.014 [0.986, 1.047] |

The candidate and baseline hold the same vault source, so this is effectively an A/A run: every gating ratio is within ±3%.
