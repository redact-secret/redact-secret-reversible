# `mode-server`: vault-server ÷ vault (B5, [#79](https://github.com/redact-secret/redact-secret-vault/issues/79))

Status: **current**, PII off. File: `bench/metrics/mode-server.mjs`. Runs in `npm run bench` and `npm run bench:compare`; skipped on a side without `@redact-secret/vault-server` (before `0.1.0-alpha.2`).

## What one sample times

Each iteration runs the same operation on a plain `createVault()` vault and on a `createServerVault()` server, back to back in alternating order, each on its own fresh capture. Setup (the captures a restore or revoke needs) and cleanup are untimed.

| Measurement | One sample | Input |
| --- | --- | --- |
| `capture.vault` / `capture.server` | `vault.capture` / `await server.capture` | `capture1k` (1 KiB, 4 findings) |
| `restore.vault` / `restore.server` | one restore of 64 fields, one token occurrence each | `restore64` over a fresh `capture1k` capture |
| `revoke.vault` / `revoke.server` | revoke of a 4-entry capture | `capture1k` |
| `<op>.boundary_ms` | `server − vault` of the same iteration | |
| `<op>.ratio` | p50 server ÷ p50 vault (deterministic, per side and round; `bench:compare` reports the median over rounds) | |

The server's resolver returns a constant principal and its policy always allows, so `boundary_ms` is the server's own floor: the FIFO queue hop, principal resolution, one policy call per token occurrence (each raced against its timeout), and the metadata shadow checks. An application's own resolver and policy cost comes on top.

## Why `revocationMemoryMs: 0`

With the default (the entry TTL), every revoke leaves a tombstone, and before #87 every server call swept the tombstone map in O(recently revoked captures) (since #87 it visits only expired tombstones). The per-call cost then grows with the number of earlier iterations: in a full run (about 3,600 revokes on one server) the p50 capture boundary went from ~0.002 ms to ~0.08 ms and the revoke boundary from ~0.001 ms to ~0.24 ms. That is a scaling property for B4/B7 to measure, not the per-call boundary, so this metric forgets revoked captures at once.

## Gating

`restore.boundary_ms` and `revoke.boundary_ms` gate in A/B. Everything else is informational: the per-side totals move with the core and the vault (already gated by `op-latency`), the ratios are deterministic per-round values, and the capture boundary's median is within timer noise of zero.

## Figures

Local, not for comparison across machines. Full mode (1000 iterations after 200 warmup), one run:

`[pii=off corpus-v1 candidate vault@0.1.0-alpha.3 core@0.1.0-beta.10/addon node@22.16.0 darwin-arm64]` (Apple M4)

| Op | vault p50 | server p50 | boundary p50 | ratio |
| --- | --- | --- | --- | --- |
| capture | 0.180 ms | 0.182 ms | 0.002 ms | 1.01 |
| restore (64 fields) | 0.071 ms | 0.153 ms | 0.081 ms | 2.15 |
| revoke | 0.0005 ms | 0.0014 ms | 0.0010 ms | 3.09 |

The metric takes about 2 seconds in full mode.
