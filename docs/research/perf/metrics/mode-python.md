# `mode-python`: Python ÷ JS (B5, [#79](https://github.com/redact-secret/redact-secret-vault/issues/79))

Status: **current**, PII off, workspace candidate only, never gating. Files: `bench/metrics/mode-python.mjs` and `bench/python/mode_python_driver.py`.

## Pair

`packages/vault-py` (`redact-secret-vault`) implements the server authority contract in Python, and detects through `NodeCoreBridge`, which keeps one long-lived Node.js process per bridge ([#89](https://github.com/redact-secret/redact-secret-vault/issues/89); before that, one process per scan). Its JS counterpart is `@redact-secret/vault-server` in-process, so the pair is Python `InMemoryVaultServer` ÷ JS `createServerVault`, same input, same always-allow resolver and policy.

## How it runs

`run()` times the JS side in-process (`ctx.iterations`), then starts one `python` process on the driver with `PYTHONPATH=packages/vault-py/src`. No install is needed, and an installed copy is never the one measured. The bridge uses the Node.js running the benchmark (`process.execPath`) and the repository's `node_modules` core. The driver returns timing samples only.

Interpreter: `$BENCH_PYTHON`, else `.venv/bin/python` at the repository root or in `packages/vault-py`, else `python3` on `PATH`. The metric is **skipped**, never failed, when no interpreter is found, Python is older than 3.10, or the package does not import. It is also skipped on a published side, so `bench:compare` reports it as skipped.

Python iterations are capped because each iteration starts one bridge process: 30 after 3 warmup in full mode, 5 after 1 in quick mode, or fewer when `--iterations`/`--warmup` are lower. The Python server uses `revocation_tombstone_ttl_ms: 1` and the JS server `revocationMemoryMs: 0`, for the reason given in [mode-server.md](mode-server.md).

## Measurements

Per Python iteration, in rotating order:

| Measurement | One sample |
| --- | --- |
| `python.node_spawn` | `subprocess.run([node, "-e", ""])`: a bare Node.js start and exit |
| `python.bridge.start` | a new `NodeCoreBridge`'s first `scan("")`: spawn, bridge script, core load and initialize, paid once per bridge process (closing it is not timed) |
| `python.bridge.scan_empty` | `NodeCoreBridge.scan("")` on the long-lived bridge: one request round trip, no scan work |
| `python.bridge.scan` | `NodeCoreBridge.scan(capture1k)` on the long-lived bridge |
| `python.capture` | `InMemoryVaultServer.capture(capture1k)` (one bridge scan plus Python staging) |
| `python.restore` | `InMemoryVaultServer.restore` of `restore64` (no subprocess) |
| `python.bridge.startup_ms` | `start − node_spawn`, paired per iteration |
| `python.bridge.scan_work_ms` | `scan − scan_empty`, paired per iteration |
| `python.capture.native_ms` | `capture − scan`, paired per iteration |
| `js.core_scan`, `js.server.capture`, `js.server.restore` | the same work in-process in Node.js |
| `capture.ratio`, `scan.ratio`, `restore.ratio` | p50 Python ÷ p50 JS |
| `capture.roundtrip_share` | p50 `bridge.scan_empty` ÷ p50 `python.capture` |
| `bridge.start_in_scans` | p50 `bridge.start` ÷ p50 `bridge.scan`: how many scans one process start costs |

Process start is reported apart from the per-scan cost, as #79 and #89 ask. The long-lived bridge is started once, untimed, before warmup; every step except `bridge.start` runs on it. `capture.spawn_share` (a bridge `scan("")` ÷ a capture, when every scan was a spawn) was replaced by `capture.roundtrip_share` in #89.

## Figures

### Long-lived bridge (#89)

Local, one full run (30 Python iterations after 3, 1000 JS after 200), on a machine running other benchmarks at the same time, so indicative only:

`[pii=off corpus-v1 candidate vault@0.1.0-alpha.3 core@0.1.0-beta.10/addon node@22.16.0 darwin-arm64]` (Apple M4), Python 3.14.7

| | p50 |
| --- | --- |
| bare `node` spawn from Python | 22.9 ms |
| new bridge's first `scan("")` (spawn + core load/init, once per process) | 31.9 ms |
| bridge `scan("")` (round trip) | 0.155 ms |
| bridge `scan(capture1k)` | 0.283 ms |
| Python `capture` | 0.602 ms |
| JS `vault-server` capture | 0.147 ms |
| JS `core.scan` | 0.121 ms |
| Python `restore` (64 fields) | 0.582 ms |
| JS `vault-server` restore | 0.135 ms |

Ratios: capture ≈ 4.1× (was ≈ 208× in the figures below, and 252× in a run of the old bridge right before this change on the same loaded machine), scan ≈ 2.3×, restore ≈ 4.3×. One process start costs about 113 scans. About half of a Python capture is the bridge scan (0.28 ms, 0.16 ms of it the pipe round trip); the rest is Python's own staging (`capture.native_ms` p50 0.34 ms).

### One process per scan (before #89)

Local, one full run (30 Python iterations after 3, 1000 JS after 200):

`[pii=off corpus-v1 candidate vault@0.1.0-alpha.3 core@0.1.0-beta.10/addon node@22.16.0 darwin-arm64]` (Apple M4), Python 3.14.7

| | p50 |
| --- | --- |
| bare `node` spawn from Python | 24.6 ms |
| bridge `scan("")` (spawn + core load/init) | 36.2 ms |
| bridge `scan(capture1k)` | 36.3 ms |
| Python `capture` | 35.8 ms |
| JS `vault-server` capture | 0.172 ms |
| JS `core.scan` | 0.140 ms |
| Python `restore` (64 fields) | 0.664 ms |
| JS `vault-server` restore | 0.152 ms |

Ratios: capture ≈ 208×, scan ≈ 259×, restore ≈ 4.4×. Spawn share of a Python capture ≈ 1.0: essentially all of a Python capture is process spawn (~25 ms) and bridge/core startup (~11 ms). Restore, which never leaves Python, is within a small constant of JS.

The metric takes a few seconds in full mode and under 2 seconds in quick mode.
