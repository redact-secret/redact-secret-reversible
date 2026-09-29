# `entry-scaling`: capture and restore cost by retained entry count (B4)

Status: **current** with PII off. Tracking issue: [#78](https://github.com/redact-secret/redact-secret-vault/issues/78), epic [#74](https://github.com/redact-secret/redact-secret-vault/issues/74). Implementation: `bench/metrics/entry-scaling.mjs`.

## Why

`#sweep` in `packages/vault/src/vault.ts` copies and walks the whole entry map on every capture and restore, so per-operation cost is expected to grow linearly with the number of entries the vault already holds. This metric draws that curve and reports its slope, so an optimization (or a regression) is judged by the slope, not by a single point.

## What is measured

| Measurement | What one sample times | Gating in A/B |
| --- | --- | --- |
| `capture.at-<n>` | One `vault.capture` of `capture1k` (1 KiB, 4 findings, all retained) on a vault holding n − 4 entries, so it ends at n | no (moves with the core) |
| `capture.core_ms.at-<n>` | The core's scan and redact of the same input, paired and order-alternated as in B3 | no |
| `capture.vault_overhead_ms.at-<n>` | `capture − core_ms` of the same iteration | yes |
| `restore.at-<n>` | One `vault.restore` of `restore64` (64 fields, 16 occurrences per token) over a fresh `capture1k` capture | yes |
| `capture.vault_overhead_ms.ms_per_1k_entries`, `restore.ms_per_1k_entries` | Least-squares slope of the per-size p50 against n, in ms per 1000 entries | no (informational) |
| `capture.vault_overhead_ms.loglog_exponent`, `restore.loglog_exponent` | log(p50 ratio) ÷ log(n ratio) between the two largest sizes; ≈1 is O(n), ≈0 is flat | no (informational) |

Sizes: 256 (default `maxEntries`), 10 000, and 100 000 (`LIMIT_CEILINGS.maxEntries`). Quick mode: 256 and 2048. Each size uses its own vault with `maxEntries` = n and `maxRetainedBytes` at its ceiling; other limits are defaults.

Iterations per size are a share of the run's counts: 1, 0.3, and 0.1 of `--iterations`/`--warmup` for 256, 10 000, and 100 000 (quick: 1 and 0.5), with at least 10 iterations. Full mode is 1000/300/100 iterations.

Each iteration's capture is revoked (untimed), and each restore consumes its four entries' whole budget, so the fill level is the same for every sample. Every iteration checks its outcome and the vault's `stats().entries`.

## Input

Operations use `corpus-v1` (`capture1k`, `restore64`), unchanged. The fill is generated inside the metric, deterministically, and never returned: lines `key AKIASYNTHETIC<7 base-36 chars> retired`, one distinct synthetic AWS-key-shaped value each, which the pinned core (0.1.0-beta.10) detects as `aws_access_key_id` with action `redact` (checked by `bench/test/entry-scaling.test.mjs`).

The fill is built once per size per `run()` from captures of 250 values each. Filling with one-finding captures would be O(N²) because of the sweep, and very large captures are also slow: the core's own scan and redact grow faster than linearly in findings per input (about 7 ms at 250 findings, 140 ms at 2000). With 250 per capture, a 100 000-entry fill takes about 4–5 seconds on an Apple M4.

## Reference figures

`[pii=off corpus-v1 candidate vault@0.1.0-alpha.3 core@0.1.0-beta.10/addon node@22.16.0 darwin-arm64]`, Apple M4, full mode, one run:

| n | capture p50 | vault overhead p50 | restore p50 |
| --- | --- | --- | --- |
| 256 | 0.149 ms | 0.023 ms | 0.065 ms |
| 10 000 | 0.302 ms | 0.175 ms | 0.235 ms |
| 100 000 | 4.47 ms | 4.31 ms | 7.19 ms |

Slopes: capture overhead 0.044 ms per 1000 entries, restore 0.074 ms per 1000 entries; log-log exponents between 10 000 and 100 000 of 1.39 (capture overhead) and 1.48 (restore). The cost is at least linear in retained entries, confirming the sweep is the per-operation O(n) term; the exponent above 1 at 100 000 is consistent with the sweep's per-call copy of the whole map (allocation and GC pressure grow with it). Absolute figures are only comparable within one result file.

The whole metric takes about 8 seconds in full mode with `npm run bench -- --metrics entry-scaling`, most of it the 100 000-entry fill and its 100 iterations. `bench:compare` runs it once per round per side (20 times at the default 10 rounds), so a full compare of this metric alone took 3.5 minutes on the same machine (all 16 comparisons `ok` in an A/A-equivalent run against 0.1.0-alpha.3).

## Limits

- In `bench:compare`, a deterministic measurement is compared from each side's first round only, so the slope ratios there are single-round figures (0.81–0.95 in the run above, with identical vault code on both sides). Judge a change by the per-size `vault_overhead_ms` and `restore` ratios, which pool all rounds, and by the slopes of a full `npm run bench` on each side. Pooling slopes across rounds would need a change to `bench/lib/compare.mjs`.
- PII on is not measured: the operations use `capture1k` as in B3.
