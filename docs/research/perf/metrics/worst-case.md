# `worst-case`: cost at the configured limits and on denial (B7)

Status: **current** with PII off. Tracking issue: [#81](https://github.com/redact-secret/redact-secret-vault/issues/81), epic [#74](https://github.com/redact-secret/redact-secret-vault/issues/74). Implementation: `bench/metrics/worst-case.mjs`.

## Why

The vault's limits are its DoS defense. What an input at, or just past, a limit costs is the guarantee an application actually gets, not the 1 KiB median of B3. This metric measures capture at the limit edges and at the configured ceilings, the cost of each restore denial against a committed restore of the same shape, and the vault-server's revocation-memory growth that B5 found.

## What is measured

### 1. Capture at the default limits

Each case is paired with the core's own scan and redact of the same input, as in B3, and reports `<name>`, `<name>.core_ms`, and `<name>.vault_overhead_ms`.

| Measurement | Input | Retained | Samples (full / quick) | Gating |
| --- | --- | --- | --- | --- |
| `capture.default.input-1MiB` | exactly `maxInputBytes` (1 MiB), 4 findings | 4 | 10 / 3 | overhead only |
| `capture.default.findings-1024` | exactly `maxFindings` (1024) findings packed into 33 KiB | 256 (`maxEntries`, via `eligible`) | 30 / 5 | overhead only |
| `capture.default.worst-1024f-1MiB` | 1024 findings spread through 1 MiB (standard tier and quick: 128 KiB, named `worst-1024f-128KiB`) | 256 | 3 / 2 | no |

The third shape is the slowest capture the defaults accept. The core's scan and redact each cost about a·bytes + b·findings·bytes, so the two edges together cost far more than either alone.

Rejected captures, one `vault.capture` that must fail with the named error:

| Measurement | Input | Outcome | Gating |
| --- | --- | --- | --- |
| `capture.reject.input-over` | 1 MiB + 1 byte | `LIMIT_EXCEEDED` before the core runs | yes |
| `capture.reject.findings-over` | 1 MiB packed with 31 775 findings | `CORE_FAILURE` / `FINDING_LIMIT_EXCEEDED` | no (core) |
| `capture.reject.entries-over` | 1024 findings, all retained | `LIMIT_EXCEEDED` on `maxEntries`, after the full scan | no (core) |

### 2. Capture at the configured ceilings

On a vault with `LIMIT_CEILINGS` for `maxInputBytes` (64 MiB), `maxFindings` (50 000), `maxEntries` (100 000), and `maxRetainedBytes` (64 MiB). One paired sample per side per process, reported as deterministic values `capture.ceiling.<shape>.ms`, `.core_ms`, `.vault_overhead_ms` (non-gating):

- `input-64MiB` (standard tier and quick: `input-4MiB`): exactly 64 MiB, 4 findings.
- `findings-4096` (standard tier and quick: `findings-2048`): packed into 132 KiB, all retained.

Later rounds of the same side in one process reuse the round-0 sample instead of paying for it again, so `bench:compare`'s median over rounds of these values is the round-0 sample.

The findings ceiling itself is not run: extrapolating from the model below, 50 000 findings take about a minute of core time in 1 MiB and about an hour in 64 MiB. Instead the run fits core_ms ≈ a·MiB + b·findings·MiB from the two default-limit shapes and reports:

| Measurement | Meaning |
| --- | --- |
| `capture.model.core_ms_per_mib` | a, from `input-1MiB` |
| `capture.model.core_ms_per_finding_mib` | b, from `worst-1024f-1MiB` after subtracting a |
| `capture.model.check_ratio` | measured ÷ predicted core_ms for the `findings-4096` ceiling case, which the fit did not use |
| `capture.extrapolated.core_ms.50000f-1MiB` | predicted core_ms, 50 000 findings in 1 MiB (the default input limit with the findings ceiling) |
| `capture.extrapolated.core_ms.50000f-64MiB` | predicted core_ms at every ceiling |

These last two are extrapolations, not measurements, and are labeled so in `params` (`extrapolated: true`).

### 3. Restore denials

Every case uses the committed-restore shape of B3: `restore64` over a fresh `capture1k` capture (64 fields, 16 occurrences per token, 4 entries). Each denial is placed as late as its reason allows, in `field_63`, so the figure is the most preflight work a denied request of this shape can cause. Samples: 500 after 100 warmup (quick: 50 after 10). Every iteration checks the denial reason.

| Reason | How it is reached |
| --- | --- |
| `invalid-request` | `field_63` is not a string (after 63 fields are snapshotted) |
| `malformed-token` | the token in `field_63` is upper-cased: a marker without a valid token |
| `unknown-token` | the token in `field_63` has its last character changed: well-formed, never issued |
| `source` | `captures` names another capture |
| `expired` | the fake clock is advanced by the entry TTL before the restore |
| `sink-or-path` | the capture granted every path except `field_63` |
| `budget` | the capture allowed 15 uses per entry, the request uses 16 |
| `policy` | a release policy that refuses only `field_63` (vault: `releasePolicy`; server: `{ allow: false, reason: "policy" }`) |

Plain vault: `restore.committed`, `restore.denied.<reason>`, and `restore.committed.policy` (the same vault with a release policy that allows all) as the baseline for `restore.denied.policy`.

vault-server: `server.restore.committed` and `server.restore.denied.<reason>` for the reasons above plus `unauthenticated` (the resolver throws), `revoked` (`field_63` holds a token of a second capture revoked in setup), `tenant-mismatch` (a `tenant` override), `missing-purpose` (empty purpose), and `policy-evaluation-error` (the policy throws on `field_63`). The resolver and policy are otherwise the cheapest conformant ones, as in B5.

Largest request at the defaults: 64 fields of exactly 1 MiB (`maxRestoreFieldBytes`), one token at the end of each: `restore.max-size.committed`, `restore.max-size.denied.malformed-token` (a broken marker at the end of the last field), and the same two on the server. 6 samples after 1 warmup (quick: 3). Non-gating.

Denial and committed restores gate in A/B; the max-size cases do not.

### 4. vault-server revocation memory

With the default `revocationMemoryMs` (the entry TTL, 10 minutes), every revoked capture leaves a tombstone that every capture, restore, and revoke sweeps (since #87, only the expired ones are visited). `server.<op>.revoked-<n>` times one call with n tombstones alive, for n = 0, 1000, 10 000 (quick: 0, 250); `server.<op>.ms_per_1k_revoked` is the least-squares slope of the medians. All non-gating.

The sweep cost depends on how many tombstones are alive, not on the memory length, so the level is held at exactly n with a rolling window on a fake clock: one revoke per 1 ms and `revocationMemoryMs` = n ms. With the default memory, n is the number of captures revoked in the last 10 minutes. The fill is n one-finding captures, each revoked. Timed captures are consumed by a restore (which leaves no tombstone) instead of revoked; each timed revoke first advances the clock one step, so the oldest tombstone ages out and the level is n − 1 before and n after. Every iteration checks `stats().revokedCaptures`. (The server's clock is monotonic, so the level cannot be held by moving time backwards.)

## Tiers and compare rounds

The full-size worst capture (about 13 s per call with its paired core sample) and the two ceiling samples (about 20 s) are too slow to repeat in every `bench:compare` round, so they run only in the extended tier (`npm run bench`'s default, or `--tier extended`). The standard tier (`bench:compare`'s default) uses the quick shapes for them: 1024 findings in 128 KiB, a 4 MiB input, and 2048 findings. Everything else is the same in both tiers. The model is fitted from whichever worst shape ran, so `capture.model.*` and the extrapolations are comparable only within one tier.

The metric also sets `compareRounds = 4`: a standard-tier call still takes about 20 s on an Apple M4, and its heavy capture cases take several samples per call, so four interleaved rounds per side keep a full compare within a CI job.

## Input

`corpus-v1` is unchanged (`capture1k`, `restore64`). The large inputs are generated in the metric, deterministically, and never returned: lines `key AKIASYNTHETIC<7 base-36 chars> retired` (the B4 fill value, detected as `aws_access_key_id` / `redact`) and a fixed English filler sentence with no digits or key-like words. `bench/test/worst-case.test.mjs` checks the exact sizes and that the pinned core finds exactly the planted values and nothing in the filler; every iteration of the metric checks its finding, entry, or error outcome.

## Reference figures

`[pii=off corpus-v1 candidate vault@0.1.0-alpha.3 core@0.1.0-beta.10/addon node@22.16.0 darwin-arm64]`, Apple M4, full mode, one run, while another benchmark ran on the same machine (load average 5–7): indicative only.

Capture at the default limits (p50):

| Case | capture | core_ms | vault_overhead_ms |
| --- | --- | --- | --- |
| `input-1MiB` (4 findings) | 112 ms | 107 ms | 3.8 ms |
| `findings-1024` (33 KiB, 256 retained) | 63 ms | 42 ms | 21 ms |
| `worst-1024f-1MiB` (256 retained) | 1.88 s | 1.26 s | 0.62 s |
| `reject.input-over` | 2.0 ms | | |
| `reject.findings-over` (31 775 findings) | 113 ms | | |
| `reject.entries-over` | 24 ms | | |

Capture at the ceilings (one sample each): `input-64MiB` 8.4 s (core 7.7 s); `findings-4096` 1.06 s (core 0.66 s, overhead 0.40 s). Model: a = 107 ms per MiB, b = 1.12 ms per finding·MiB, check ratio 1.09 on `findings-4096`. Extrapolated core_ms: 50 000 findings in 1 MiB ≈ 56 s; 50 000 findings in 64 MiB ≈ 1 hour.

Restore denials (p50, 64 fields, denial in `field_63`):

| Reason | vault | vault-server |
| --- | --- | --- |
| committed | 0.067 ms | 0.159 ms |
| invalid-request | 0.029 | 0.037 |
| unauthenticated | | 0.030 |
| malformed-token | 0.045 | 0.052 |
| unknown-token | 0.046 | 0.055 |
| revoked | | 0.052 |
| source | 0.047 | 0.052 |
| tenant-mismatch | | 0.051 |
| expired | 0.048 | 0.057 |
| sink-or-path | 0.047 | 0.054 |
| missing-purpose | | 0.054 |
| budget | 0.048 | 0.053 |
| policy | 0.050 (committed with policy 0.075) | 0.094 |
| policy-evaluation-error | | 0.105 |
| max-size committed (64 × 1 MiB) | 131 ms | 245 ms |
| max-size malformed-token | 106 ms | 119 ms |

vault-server revocation memory (p50):

| Tombstones alive | capture | restore | revoke |
| --- | --- | --- | --- |
| 0 | 0.19 ms | 0.013 ms | 0.002 ms |
| 1000 | 0.27 ms | 0.076 ms | 0.075 ms |
| 10 000 | 0.94 ms | 0.72 ms | 0.61 ms |

Slopes: 0.075 (capture), 0.071 (restore), 0.060 (revoke) ms per 1000 tombstones.

Run time: `npm run bench -- --metrics worst-case` takes about 57 s in full mode (extended tier; about 20 s of it the two ceiling samples) and 8 s in quick mode. A full `bench:compare -- --metrics worst-case` with the extended shapes and all 10 rounds per side took 17.4 minutes on the loaded machine, before the standard tier and `compareRounds = 4` existed. It was A/A-equivalent: identical vault code on both sides, all 63 comparisons `ok` or `improved`, 0 warn, 0 fail. The `improved` verdicts (ratios 0.77–0.89) came from load drift during the run.

## Findings

- **Denials cost less than a committed restore.** Every denial is cheaper than the committed restore of the same shape (vault about 0.03–0.05 ms against 0.067 ms; server 0.03–0.10 ms against 0.16 ms), even when placed in the last field. The preflight rejects before any substitution or budget change, so a flood of denied requests costs no more per request than legitimate traffic. The policy reasons are the most expensive denials because the policy runs once per (entry, path) before the refusal.
- **The worst capture at the defaults is about 2 seconds, and a third of it is the vault.** 1024 findings spread through 1 MiB take about 1.3 s in the core and another 0.6 s in the vault. The vault's share grows with retained entries × output length (4 entries in 1 MiB: 3.8 ms; 256 entries in 33 KiB: 21 ms; 256 in 1 MiB: 0.62 s; 4096 in 132 KiB: 0.40 s). The likely cause, not yet profiled: capture validates each staged token with two `text.indexOf` calls over the whole redacted text (`#capture`, "Validate the output"), which is O(entries × bytes). The single 64 MiB sample's overhead ranged from 12 ms to 0.64 s between runs, which is noise on a difference of two 8 s figures. A single pass over the output that counts each token would make this linear. This is a candidate vault optimization, not a bug.
- **The core is super-linear in findings × bytes.** Scan and redact each cost about 1.1 ms per finding·MiB on top of about 107 ms per MiB. The default `maxFindings` (1024) keeps the worst case near 2 s. Raising `maxFindings` toward its ceiling makes a 1 MiB input able to cost about a minute of core time, and all ceilings together about an hour. Over-limit input is cheap to refuse: `input-over` is refused in 2 ms before the core runs, and an input with too many findings is refused by the core in about the time of one linear scan (113 ms for 1 MiB), not after the quadratic part.
- **vault-server revocation memory is linear, about 0.06–0.075 ms per 1000 recently revoked captures per call.** At the default memory (10 minutes), a service revoking 10 captures a second holds 6000 tombstones, adding about 0.4 ms to every capture, restore, and revoke. These figures predate #87: every call then copied both tombstone maps (`#sweepTombstones`). #87 sweeps in insertion (time) order and stops at the first live tombstone, so the cost is now O(expired); after the change, the same curve measured flat (10 000 tombstones: capture 0.23 ms, restore 0.014 ms, revoke 0.003 ms; indicative, machine under other load).

## Limits

- PII off only. The PII detectors could change the core's cost on these shapes; that is not measured here.
- The heavy capture cases have few samples (3 to 30 per run), so their p95/p99 are rough; `bench:compare` pools 10 rounds. The ceiling cases are single samples, so their `vault_overhead_ms` (a difference of two multi-second figures) can be negative on a loaded machine.
- The model and the extrapolations assume core cost stays a·bytes + b·findings·bytes beyond the measured range. `check_ratio` tests that on one point outside the fit; it is an order-of-magnitude guide, not a bound.
- Restore ceilings (`maxRestoreFields` 10 000, `maxRestoreFieldBytes` 64 MiB) are not run: a request is bounded by its own size, which the application controls, and the max-size case shows the cost per request byte.
