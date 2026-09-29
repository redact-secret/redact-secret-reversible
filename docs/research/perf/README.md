# Vault performance measurement

Status: **current** for the harness, corpus, and result schema ([#75](https://github.com/redact-secret/redact-secret-vault/issues/75)), the A/B runner ([#76](https://github.com/redact-secret/redact-secret-vault/issues/76)), and every metric below (B3–B8, [#77](https://github.com/redact-secret/redact-secret-vault/issues/77)–[#82](https://github.com/redact-secret/redact-secret-vault/issues/82)). The plan is tracked in the epic [#74](https://github.com/redact-secret/redact-secret-vault/issues/74).

This measures **vault overhead**: capture, restore, lifecycle, mode boundaries, memory, and distribution cost. Detection accuracy and detector speed belong to [redact-secret-benchmarks](https://github.com/redact-secret/redact-secret-benchmarks), not here.

## Running

```bash
npm ci
npm run bench:smoke                      # quick mode, PII off; well under a minute
npm run bench                            # full iteration counts, PII off
npm run bench -- --pii on                # PII on (a separate process: activation is one-shot)
npm run bench -- --metrics op-latency    # only the named metric(s), comma-separated
npm run bench -- --out results.json      # default: .bench-results/run-pii-<mode>-<time>.json
npm run bench -- --tier standard         # skip the extended-only shapes (see Tiers)
npm run bench:worker                     # Worker ÷ main thread in Chromium (a separate script, not a metric)
BENCH_SKIP_BROWSER=1 npm run bench       # skip cold-init-browser without trying to launch Chromium
```

`--iterations N` and `--warmup N` override the counts. Every script builds the workspace packages first. Results under `.bench-results/` are gitignored. Nothing is uploaded anywhere from a local run.

The Chromium measurements (`cold-init-browser`, `bench:worker`) need Playwright's Chromium (`npx playwright install chromium`). Without it they are recorded as `skipped` and the run still succeeds. `BENCH_SKIP_BROWSER=1` skips `cold-init-browser` without probing for a browser at all.

**Tiers.** `--tier standard|extended` selects shapes. The extended tier adds what is too slow to repeat in every compare round: `entry-scaling` at 100 000 retained entries, and `worst-case`'s full-size worst capture (1024 findings in 1 MiB) and ceiling samples (64 MiB input, 4096 findings). The standard tier uses smaller shapes for these (`entry-scaling` at 256 and 10 000; `worst-case` with 1024 findings in 128 KiB, a 4 MiB input, and 2048 findings) and is otherwise identical. `bench` defaults to `extended` and `bench:compare` to `standard`. Every result records its tier in `mode.tier`, and the console tag says `standard` when it applies. Figures from different tiers are not compared: the shapes, and so some measurement names, differ.

Each run prints one line per measurement, always with its mode and environment, for example:

```
[pii=off corpus-v1 candidate vault@0.1.0-alpha.3 core@0.1.0-beta.10/addon node@22.16.0 darwin-arm64 quick] op-latency capture.total p50=…ms p95=…ms p99=…ms n=20
```

## A/B against a published version

Status: **current** ([#76](https://github.com/redact-secret/redact-secret-vault/issues/76)).

```bash
npm run bench:compare                                  # candidate vs bench/baseline.json (0.1.0-alpha.3)
npm run bench:compare -- --baseline 0.1.0-alpha.2      # any exact published version
npm run bench:compare:smoke                            # quick: 4 rounds x 50 iterations
npm run bench:compare -- --rounds 20 --fail-on-warn
npm run bench:compare -- --tier extended               # adds the ceiling and 100 000-entry shapes (much slower)
```

`bench/compare.mjs` loads two sides in one Node.js process:

- **candidate**: the workspace build (`packages/*/dist`) with the core installed at the repository root, recorded with its git commit.
- **baseline**: the exact published `@redact-secret/vault` and, when that version exists, `@redact-secret/vault-server`, with the exact core that version pins as its peer. They are installed into `.bench-cache/vault-<version>/` (gitignored) with `npm install --ignore-scripts`. The root `package.json` and lockfile are never touched. Only exact versions are accepted. The resolved tarball URL and integrity of each baseline package, from that directory's lockfile, are recorded in the result. A cache that already matches is reused offline.

Each side's vault uses its own core instance, initialized for the run's PII mode. Before measuring, the harness proves each vault resolves the core it initialized: `createVault()` without `pii` only succeeds on an initialized core.

**Interleaving.** Each round runs every metric once per side, alternating which side runs first (candidate first in even rounds, baseline first in odd), so drift over the job lands on both sides. Default: 10 rounds of 1000 iterations after 200 warmup per side per round (quick: 4 × 50 after 10). A full `op-latency` comparison takes about 40 seconds on an Apple M4.

A metric can cap its rounds with `export const compareRounds = N` when more rounds would repeat expensive work without adding information. The metric then runs only rounds 0 to N−1, still alternating, and the result records `rounds` on that metric's entry:

| Metric | `compareRounds` | Why |
| --- | --- | --- |
| `dist-size` | 1 | byte counts, identical in every round |
| `entry-memory` | 3 | each call is already a median of 7 cycles in a fresh child (about 4 s) |
| `worst-case` | 4 | about 20 s per call in the standard tier; the heavy cases sample several times per call |
| every other metric | all rounds | |

**Ratios and CI.** For each latency measurement the result carries both sides' pooled summaries and the ratio of medians candidate÷baseline, with a 95% percentile bootstrap CI (2000 resamples, fixed seed). Each resample draws rounds with replacement, the same rounds for both sides, and then samples within each drawn round, so between-round drift widens the interval instead of being ignored. On a laptop, that drift dominates: A/A intervals of ±10–15% are normal, and a 10% change is only reliably flagged on a quiet machine or with more rounds.

A deterministic measurement (sizes, heap figures, slopes, per-call ratios, single ceiling samples) is aggregated as the **median of its per-round values** on each side, and its ratio is the ratio of those medians. The CI fields repeat the ratio; there is no resampling for these. Earlier, only round 0 was compared, so a slope ratio was a single-round figure (0.81–0.95 in an A/A run) and every later round's work on it was wasted; the same A/A comparison now reads 0.98–1.02.

**Run time.** `bench:compare` prints each metric's wall time (`<metric>: ok, N round(s), S s`; console only, never in the result). A full standard-tier compare of every metric with Chromium installed, on an Apple M4 with Node.js 22 under background load (load average 5–13 on 10 cores), against the published 0.1.0-alpha.3:

| PII | Total | Per metric |
| --- | --- | --- |
| off | 8.5 min | `worst-case` 298 s (4 rounds), `entry-scaling` 62 s, `mode-server` 48 s, `op-latency` 26 s, `entry-memory` 24 s (3 rounds), `cold-init-browser` 23 s, `cold-init` 19 s, `mode-python` 7 s (candidate only, then skipped), `dist-size` 2 s (1 round) |
| on | 1.3 min | `cold-init-browser` 26 s, `op-latency` 26 s, `cold-init` 21 s, `dist-size` 2 s; the PII-off-only metrics are skipped |

The same PII-off comparison with every round of every metric and the extended shapes added up to about 24 minutes on a similarly loaded machine (from the per-metric figures in `metrics/*.md`: `worst-case` alone 17.4 min, `entry-scaling` 3.5 min, `entry-memory` 90 s). Run as one job per PII mode in parallel, the PII-off job sets the length. The extended tier adds roughly 20 × 6 s for `entry-scaling` at 100 000 entries, 8 × 13 s for `worst-case`'s full-size worst capture, and two single ceiling samples per side of about 10 s each.

**Verdicts.**

| Verdict | When |
| --- | --- |
| `warn` | latency ratio > 1.10 and CI lower bound > 1.0 |
| `improved` | CI upper bound < 1.0 |
| `fail` | a deterministic measurement exceeds its `threshold` (`max` on the value, `maxRatio` on the ratio) |
| `inconclusive` | no ratio (a zero baseline) |
| `ok` | otherwise |

A measurement a metric marks `gating: false` is compared and reported but never counts toward the outcome: `capture` and `capture.core_ms` move with the pinned core, so `capture.vault_overhead_ms` is the release signal for capture. The command exits 1 on a gating `fail` or a failed metric, and on a gating `warn` only with `--fail-on-warn`. Quick-run ratios are smoke output, not evidence.

If the two sides use different cores (version or artifact), the run says so; compare vault overhead, not totals.

**Versions.** `0.1.0-alpha.2` and `0.1.0-alpha.3` work as baselines. `0.1.0-alpha.1` is out of scope: it pins core `0.1.0-beta.9`, and `0.1.0-alpha.2` changed `createVault` initialization (`pii: []` or an initialized core), so its figures would mix a core change and an API change. Retro-measuring it is not attempted.

## What is measured, and what is only input

| | Measured | Input (held fixed) |
| --- | --- | --- |
| What varies | The vault packages under test (`@redact-secret/vault`, `@redact-secret/vault-server`) | The corpus, the core version each side pins, Node.js, the machine |
| Reported as | p50, p95, p99, mean, min, max, and sample count per operation; ratios candidate÷baseline for A/B | Recorded next to every figure, never varied inside one result |

Inputs are the minimum size that exercises each metric: a 1 KiB input with four findings is enough to exercise every capture code path (scan, gate, staging, token issue, redact, validation, commit), and 64 fields is the default `maxRestoreFields`. Scaling with size or entry count is a separate metric (B4), not a reason to enlarge every input.

## Comparability rules

From the epic ([#74](https://github.com/redact-secret/redact-secret-vault/issues/74)):

- **Ratios, not absolute times across runs.** The candidate and the previous published version run interleaved in the same job on the same machine. An absolute figure is only compared with figures from the same result file.
- **Fixed, versioned, synthetic-only corpus.** `corpus-v1` is pinned by a SHA-256 of its generated bytes. A corpus change bumps the version (`bench/corpus/v2/`) and is never mixed with earlier figures.
- **Every figure carries its environment.** Each result records the core version and artifact (addon or wasm) per side, the Node.js and V8 versions, OS, architecture, CPU model and count, memory, runner (`local`, `ci`, or `github-actions/<os>/<arch>/<image>`), PII mode, corpus version and digest, and whether it was a quick run. A figure without its mode is not reported.
- **Regression rule.** A ratio above 1.10 whose bootstrap confidence interval excludes 1.0 is a warning. Deterministic metrics (package size) fail on their threshold.
- **Quick runs are smoke tests.** `--quick` checks that every metric runs and produces a valid result. Its figures are not for comparison.

## Corpus (`bench/corpus/v1`)

Generated from fixed seeds by `bench/corpus/v1/index.mjs`; `loadCorpus()` refuses to return it if its digest differs from `CORPUS_SHA256`.

| Item | Shape | Findings with the pinned core (0.1.0-beta.10) |
| --- | --- | --- |
| `capture1k` | 1024 bytes of ASCII filler with four credential-shaped values | PII off and on: 4 (`github_token`, `aws_access_key_id`, `bearer_token`, `connection_string_password`), all `redact` |
| `capture1kPii` | 1024 bytes with the same four values plus two IBANs | PII off: 4. PII on: 6 (adds two `pii_global_iban`), all `redact` |
| `restore64` | 64 field templates (`field_00`…`field_63`), each holding one token slot of a `capture1k` capture | 16 occurrences per token, the default `maxUsesPerEntry` |

Every credential-shaped value contains `SYNTHETIC` and was never a live credential. The IBANs are the examples published in IBAN documentation. `bench/test/corpus.test.mjs` checks that the pinned core finds exactly these values and nothing else, with PII off and on.

## Result schema (`redact-secret-vault/bench-result@1`)

Defined and validated in `bench/lib/schema.mjs`. A result has `schema`, `kind` (`run` or `compare`), `createdAt`, `mode` (`pii`, `quick`, `iterations`, `warmup`, `rounds`), `corpus` (`version`, `sha256`), `environment`, `sides` (package versions, core artifact, and PII activation per side; `resolved` and `integrity` for published packages), and `metrics`, each with `id`, `issue`, `title`, `status` (`ok`, `skipped`, `failed`), an optional short `reason`, and `measurements`. A latency measurement carries `n`, `p50`, `p95`, `p99`, `mean`, `min`, and `max` in milliseconds; a deterministic one carries a `value` and optional `threshold`. Measurement objects are closed: unknown keys are schema errors, so raw samples, inputs, and outputs cannot be written.

**No values in results.** Every result is validated and then checked by `bench/lib/leak-guard.mjs` before it is written. It is refused if it contains any corpus value, an issued-token marker (`rsv_`), or the `SYNTHETIC` marker. A metric that throws is recorded as `failed` with only its error code or name, since an arbitrary error message is not known to be value-free.

## Metrics

Every metric is one file in `bench/metrics/`, discovered by `bench`, `bench:smoke`, `bench:compare`, and `bench:compare:smoke`. The Worker boundary is a separate script because it runs in Chromium.

| Metric | Issue | PII modes | Extended tier only | Details |
| --- | --- | --- | --- | --- |
| `op-latency`: capture, restore, revoke; capture split into core and vault overhead | B3, [#77](https://github.com/redact-secret/redact-secret-vault/issues/77) | off, on | | below |
| `entry-scaling`: capture and restore by retained entry count, and the slope | B4, [#78](https://github.com/redact-secret/redact-secret-vault/issues/78) | off | 100 000 entries | [metrics/entry-scaling.md](metrics/entry-scaling.md) |
| `mode-server`: vault-server ÷ vault | B5, [#79](https://github.com/redact-secret/redact-secret-vault/issues/79) | off | | [metrics/mode-server.md](metrics/mode-server.md) |
| `mode-python`: Python bridge ÷ JS, candidate only | B5, [#79](https://github.com/redact-secret/redact-secret-vault/issues/79) | off | | [metrics/mode-python.md](metrics/mode-python.md) |
| `mode-worker`: dedicated Worker ÷ main thread; `npm run bench:worker` (`bench/browser/worker-boundary.mjs`), candidate only, not in `bench:compare` | B5, [#79](https://github.com/redact-secret/redact-secret-vault/issues/79) | off | | [metrics/mode-worker.md](metrics/mode-worker.md) |
| `entry-memory`: heap per entry, reclaim after revoke and dispose | B6, [#80](https://github.com/redact-secret/redact-secret-vault/issues/80) | off | | [metrics/entry-memory.md](metrics/entry-memory.md) |
| `worst-case`: capture at the limits and ceilings, restore denials, server revocation memory | B7, [#81](https://github.com/redact-secret/redact-secret-vault/issues/81) | off | full-size worst capture and ceiling shapes | [metrics/worst-case.md](metrics/worst-case.md) |
| `dist-size`: npm tarball, unpacked, and browser bundle size | B8, [#82](https://github.com/redact-secret/redact-secret-vault/issues/82) | off, on | | [metrics/dist-size.md](metrics/dist-size.md) |
| `cold-init`: cold `createVault()` in a fresh Node.js process | B8, [#82](https://github.com/redact-secret/redact-secret-vault/issues/82) | off, on | | [metrics/cold-init.md](metrics/cold-init.md) |
| `cold-init-browser`: cold `createVault()` in a fresh Chromium page | B8, [#82](https://github.com/redact-secret/redact-secret-vault/issues/82) | off, on | | [metrics/cold-init.md](metrics/cold-init.md) |

### `op-latency`: operation latency (B3, [#77](https://github.com/redact-secret/redact-secret-vault/issues/77))

Status: **current** with PII off and on.

| Measurement | What one sample times | Input |
| --- | --- | --- |
| `capture` | One `vault.capture` | PII off: `capture1k` (1 KiB, 4 findings, all retained). PII on: `capture1kPii` (6 findings, all retained; the two IBANs through `pii: { retain: ["pii_global_iban"] }`) |
| `capture.core_ms` | What capture asks of the core on the same input: `core.scan` then `core.redact` with the vault's default limits | same |
| `capture.vault_overhead_ms` | `capture − capture.core_ms` of the same iteration | same |
| `restore` | One `vault.restore` of 64 fields, one token occurrence each (16 per entry) | `restore64` over a fresh `capture1k` capture |
| `revoke` | One `vault.revoke` of a capture holding 4 entries | `capture1k` |

`core_ms` and the whole capture run back to back in alternating order within each iteration, so their difference is paired. Every operation runs on a vault holding no other entries: setup (a capture for restore and revoke) and cleanup (revoking the iteration's capture) are untimed. Each iteration checks its own outcome (findings, restored occurrences, revoked entries), so a denial or a changed detection fails the metric instead of timing an error path. Release-over-release comparison of capture uses `capture.vault_overhead_ms`, because each release pins its own exact core.

With `--pii on` (a separate process), capture uses `capture1kPii` and retains the IBANs, so all six findings become entries and the core runs its PII detectors. Restore and revoke use `capture1k` in both modes: neither calls the core, so their PII-on figures show that an active PII surface adds nothing to them. The inputs per mode are `CAPTURE_INPUTS` in `bench/metrics/op-latency.mjs`.

Default counts: 1000 iterations after 200 warmup (quick: 50 after 10). On an Apple M4 with Node.js 22 the whole metric takes under a second.

## Adding a metric

Add one file, `bench/metrics/<id>.mjs`. The runner discovers it; there is no registry to edit.

```js
export const id = "<id>";          // must equal the file name
export const issue = 78;           // tracking issue
export const title = "Scaling by retained entry count";
export const piiModes = ["off", "on"]; // optional, this is the default

export async function run(ctx) {
  const vault = await ctx.vault.createVault({ limits: { maxEntries: 4096 } }); // never pass `pii`
  try {
    const samples = await ctx.sample({ iterations: ctx.iterations, warmup: ctx.warmup, op: () => { /* ... */ } });
    return [{ name: "capture.at-4096", kind: "latency", unit: "ms", samples, params: { entries: 4096 } }];
  } finally {
    vault.dispose();
  }
}
```

- Use the packages from `ctx` (`ctx.vault`, `ctx.vaultServer`, `ctx.core`), never `import "@redact-secret/..."`: the A/B runner injects a different side's packages. `ctx.vaultServer` may be `null` for a published version without it; call `ctx.skip("reason")` when a metric does not apply.
- Use only the packages' public API.
- The harness owns PII activation: create vaults without `pii` so they adopt it. `ctx.pii.mode` is `"off"` or `"on"`.
- `run(ctx)` must be repeatable: the A/B runner calls it once per round per side. Create and dispose everything it uses. If one call is already an aggregate (a median over child processes) or deterministic, set `export const compareRounds = N` instead of repeating it every round.
- Anything too slow to repeat every compare round belongs to the extended tier: branch on `ctx.tier` (`"standard"` or `"extended"`) and use a smaller shape in standard.
- Return numbers only. `params` holds sizes, counts, and short labels.
- Inputs: see the next section.

### Inputs: the corpus and generated inputs

Two kinds of input are allowed, and each is versioned by what defines it:

- **Corpus items** (`ctx.corpus`): fixed text shared across metrics, versioned by the corpus (`corpus-v1`, pinned by its SHA-256). Changing or adding a corpus item is a corpus version bump (`bench/corpus/v2/`), and figures from different corpus versions are never compared.
- **Generated inputs**: large or parametric inputs a metric builds deterministically in its own file (the synthetic AWS-key fill in `entry-scaling`, reused by `entry-memory` and `worst-case`, and `worst-case`'s filler and limit-sized inputs). They are versioned by that metric file. A generator must be deterministic (no clock, no unseeded randomness), use only unmistakably synthetic values, and have a test that the pinned core finds exactly the planted values. Changing a generator's output is treated like a corpus bump **for the metrics that use it**: say so in the commit and the metric's doc, and do not compare those metrics across results from before and after the change. Both sides of a compare run the same metric file, so one compare result is always self-consistent; the rule matters when reading figures across archives.

Use a corpus item when an input is small and shared; generate it when it is large, sized from the packages' limits, or used by one metric only.

## Files

| Path | Role |
| --- | --- |
| `bench/run.mjs` | One side (the workspace build), one PII mode, writes a result |
| `bench/compare.mjs`, `bench/lib/compare.mjs` | Interleaved A/B, per-round aggregation, ratios, CI, verdicts |
| `bench/browser/worker-boundary.mjs` | `mode-worker` in Chromium (`npm run bench:worker`) |
| `bench/lib/published.mjs`, `bench/baseline.json` | Installing a published baseline into `.bench-cache/`; the default baseline version |
| `bench/lib/timing.mjs` | `process.hrtime.bigint()` timing, warmup, fixed iterations, paired sampling |
| `bench/lib/stats.mjs` | Percentiles and the bootstrap CI for ratios |
| `bench/lib/env.mjs` | Environment capture |
| `bench/lib/sides.mjs` | Loading and activating the packages under test |
| `bench/lib/harness.mjs` | Metric discovery, `ctx`, tiers, result assembly and writing |
| `bench/lib/schema.mjs`, `bench/lib/leak-guard.mjs` | Result validation and the no-values check |
| `bench/corpus/v1/` | `corpus-v1` |
| `bench/metrics/` | One file per metric (`bench/metrics/support/` holds shared helpers) |
| `bench/test/` | `npm run test:bench` (also part of `npm test`) |
