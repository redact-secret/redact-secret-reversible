# `entry-memory`: heap per retained entry and reclaim after revoke and dispose (B6)

Status: **current** with PII off. Tracking issue: [#80](https://github.com/redact-secret/redact-secret-vault/issues/80), epic [#74](https://github.com/redact-secret/redact-secret-vault/issues/74). Implementation: `bench/metrics/entry-memory.mjs`. Runs in `npm run bench` and `npm run bench:compare`.

## Why

The vault claims bounded memory: entries count against `maxEntries` and `maxRetainedBytes`, and `revoke()` and `dispose()` drop them. `retainedBytes` counts only value bytes. This metric measures what an entry really costs on the V8 heap, and whether that heap comes back once the entries are revoked or the vault is disposed.

## How

Each size runs in a fresh child process, `node --expose-gc`, so `gc()` is available, the heap starts clean, and the harness's own flags and heap history do not matter. The child imports the side's core and vault from their package directories, the same way B8's `cold-init` does (`bench/metrics/support/distribution.mjs`), so a baseline side measures the published packages. It also checks that the core artifact and the vault's PII activation match the harness's.

"Heap" is `process.memoryUsage().heapUsed` after two forced full GCs. One cycle at N entries:

1. `createVault({ limits: { maxEntries: N, maxRetainedBytes: ceiling } })`, then heap `h0`.
2. Fill to N entries with B4's deterministic fill (`fillInput`, 250 synthetic AWS-key-shaped values per capture). All results are dropped except the capture ids. Then heap `h1`.
3. Either revoke every capture, or `dispose()`. The vault object stays referenced, because the claim is that a disposed vault a caller still holds keeps nothing alive. Then heap `h2`.

Revoke and dispose each get their own vault. Each child runs one untimed warm-up cycle, then 7 cycles per path (3 in quick mode), and reports medians.

| Measurement | Value | Gating |
| --- | --- | --- |
| `heap.bytes_per_entry.at-<n>` | (h1 − h0) ÷ n, bytes | no |
| `heap.per_retained_byte.at-<n>` | (h1 − h0) ÷ `stats().retainedBytes` | no |
| `heap.unreclaimed_ratio.revoke.at-<n>` | (h2 − h0) ÷ (h1 − h0) after revoking every capture; 0 = all returned, 1 = none | no |
| `heap.unreclaimed_ratio.dispose.at-<n>` | the same after `dispose()` | **yes at 10 000**, threshold `max: 0.1`; no at 256 |

Sizes: 256 (default `maxEntries`) and 10 000, in both full and quick mode.

## Threshold: non-reclaiming vault

If more than 10% of the fill's heap growth is still live after `dispose()` and two full GCs at 10 000 entries, the metric fails. `npm run bench` then exits non-zero and `bench:compare` marks the comparison `fail`. At 10 000 entries the growth is about 3.3 MB, and after-GC noise is a few KiB, so 10% sits far above the noise and far below a real leak. A vault whose `dispose()` kept its entries would read about 1.0; this was checked by running a patched copy of the child that holds the vault's contents instead of disposing, which read 0.9996 (not committed). At 256 entries the growth is about 90 KiB and the same few KiB of noise are 5–10% of it, so the 256 dispose figure is reported without a threshold. The revoke path is informational: revoke-all leaves an empty but live vault, and the bounded-memory claim concerns `dispose()`.

## Why deterministic, and the compare caveat

The result schema allows `unit: "ms"` only for latency samples, so these are deterministic-kind values in `bytes` and `ratio`. `bench:compare` compares deterministic values from round 0 only. The median over 7 cycles inside that one child is what makes a single round usable. Every round still runs `run()` (two children, about 4 s per call), so a full compare spends most of its time on rounds that are not compared.

## Reference figures

`[pii=off corpus-v1 candidate vault@0.1.0-alpha.3 core@0.1.0-beta.10/addon node@22.16.0 (V8 12.4) darwin-arm64]`, Apple M4, full mode, three consecutive runs. Another benchmark was running on the same machine at the time, so treat the figures as indicative.

| n | bytes per entry | heap ÷ retained value bytes | unreclaimed after revoke | unreclaimed after dispose |
| --- | --- | --- | --- | --- |
| 256 | 346–351 | 17.3–17.6 | 0.058–0.075 | 0.063–0.094 |
| 10 000 | 330.9 | 16.54 | 0.0018 | 0.0017 |

Each fill value is 20 bytes, so `retainedBytes` is 20 per entry, while the heap cost is about 330 bytes per entry. That covers the value, the token, the entry record, and its map and capture-set slots. `maxRetainedBytes` therefore bounds heap only up to a per-entry factor. For short values the heap is set by `maxEntries`, about 3.3 MB per 10 000 entries on this build. After `dispose()` more than 99.8% of the growth is reclaimed at 10 000 entries. The 256-entry remainder is the same absolute few KiB of noise.

Run times on the same machine: `npm run bench -- --metrics entry-memory` about 4 s (quick about 2 s). `npm run bench:compare -- --metrics entry-memory` about 90 s at the default 10 rounds (quick about 18 s). The first compare adds the baseline install. In an A/A-equivalent compare against the published 0.1.0-alpha.3, all 8 comparisons were `ok`: 1.000 at 10 000 entries, and 0.82–1.02 on the noisy 256-entry reclaim ratios.

## Limits

- `heapUsed` is the V8 heap only. Native memory held by the core addon, and `ArrayBuffer` backing stores, are not included. The vault retains strings, so its entries live on the V8 heap.
- Figures depend on the V8 version (string and hash-table layout); compare only within one result file.
- PII off only; the fill is AWS-key-shaped values, so PII mode would not change what the vault retains.
