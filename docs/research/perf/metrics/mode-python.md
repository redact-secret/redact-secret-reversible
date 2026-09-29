# `mode-python`: Python ÷ JS (B5, [#79](https://github.com/redact-secret/redact-secret-vault/issues/79))

Status: **current**, PII off, workspace candidate only, never gating. Files: `bench/metrics/mode-python.mjs` and `bench/python/mode_python_driver.py`.

## Pair

`packages/vault-py` (`redact-secret-vault`) implements the server authority contract in Python, and detects through `NodeCoreBridge`, which spawns one Node.js process per scan (`core_client.py`, `subprocess.run`). Its JS counterpart is `@redact-secret/vault-server` in-process, so the pair is Python `InMemoryVaultServer` ÷ JS `createServerVault`, same input, same always-allow resolver and policy.

## How it runs

`run()` times the JS side in-process (`ctx.iterations`), then starts one `python` process on the driver with `PYTHONPATH=packages/vault-py/src`. No install is needed, and an installed copy is never the one measured. The bridge uses the Node.js running the benchmark (`process.execPath`) and the repository's `node_modules` core. The driver returns timing samples only.

Interpreter: `$BENCH_PYTHON`, else `.venv/bin/python` at the repository root or in `packages/vault-py`, else `python3` on `PATH`. The metric is **skipped**, never failed, when no interpreter is found, Python is older than 3.10, or the package does not import. It is also skipped on a published side, so `bench:compare` reports it as skipped.

Python iterations are capped because each scan is a process spawn: 30 after 3 warmup in full mode, 5 after 1 in quick mode, or fewer when `--iterations`/`--warmup` are lower. The Python server uses `revocation_tombstone_ttl_ms: 1` and the JS server `revocationMemoryMs: 0`, for the reason given in [mode-server.md](mode-server.md).

## Measurements

Per Python iteration, in rotating order:

| Measurement | One sample |
| --- | --- |
| `python.node_spawn` | `subprocess.run([node, "-e", ""])`: a bare Node.js start and exit |
| `python.bridge.scan_empty` | `NodeCoreBridge.scan("")`: spawn, bridge script, core load and initialize, no scan work |
| `python.bridge.scan` | `NodeCoreBridge.scan(capture1k)` |
| `python.capture` | `InMemoryVaultServer.capture(capture1k)` (one bridge scan plus Python staging) |
| `python.restore` | `InMemoryVaultServer.restore` of `restore64` (no subprocess) |
| `python.bridge.startup_ms` | `scan_empty − node_spawn`, paired per iteration |
| `python.bridge.scan_work_ms` | `scan − scan_empty`, paired per iteration |
| `python.capture.native_ms` | `capture − scan`, paired per iteration |
| `js.core_scan`, `js.server.capture`, `js.server.restore` | the same work in-process in Node.js |
| `capture.ratio`, `scan.ratio`, `restore.ratio` | p50 Python ÷ p50 JS |
| `capture.spawn_share` | p50 `bridge.scan_empty` ÷ p50 `python.capture` |

Spawn plus bridge startup is reported apart from scan time, as #79 asks. The scan itself (~0.1 to 0.6 ms) is smaller than the jitter of a process spawn (several ms at p95), so `scan_work_ms` and `native_ms` are only good to about ±1 ms at p50. The robust reading is `spawn_share`.

## Figures

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

The metric takes about 7 seconds in full mode and under 2 seconds in quick mode.
