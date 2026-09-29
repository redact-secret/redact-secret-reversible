# Vault performance measurement

Status: **current** for the harness, corpus, and result schema ([#75](https://github.com/redact-secret/redact-secret-vault/issues/75)). The rest of the plan is tracked in the epic [#74](https://github.com/redact-secret/redact-secret-vault/issues/74).

This measures **vault overhead**: capture, restore, lifecycle, mode boundaries, memory, and distribution cost. Detection accuracy and detector speed belong to [redact-secret-benchmarks](https://github.com/redact-secret/redact-secret-benchmarks), not here.

## Running

```bash
npm ci
npm run bench:smoke                      # quick mode, PII off; well under a minute
npm run bench                            # full iteration counts, PII off
npm run bench -- --pii on                # PII on (a separate process: activation is one-shot)
npm run bench -- --metrics op-latency    # only the named metric(s), comma-separated
npm run bench -- --out results.json      # default: .bench-results/run-pii-<mode>-<time>.json
```

`--iterations N` and `--warmup N` override the counts. Every script builds the workspace packages first. Results under `.bench-results/` are gitignored. Nothing is uploaded anywhere.

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
```

`bench/compare.mjs` loads two sides in one Node.js process:

- **candidate**: the workspace build (`packages/*/dist`) with the core installed at the repository root, recorded with its git commit.
- **baseline**: the exact published `@redact-secret/vault` and, when that version exists, `@redact-secret/vault-server`, with the exact core that version pins as its peer. They are installed into `.bench-cache/vault-<version>/` (gitignored) with `npm install --ignore-scripts`. The root `package.json` and lockfile are never touched. Only exact versions are accepted. The resolved tarball URL and integrity of each baseline package, from that directory's lockfile, are recorded in the result. A cache that already matches is reused offline.

Each side's vault uses its own core instance, initialized for the run's PII mode. Before measuring, the harness proves each vault resolves the core it initialized: `createVault()` without `pii` only succeeds on an initialized core.

**Interleaving.** Each round runs every metric once per side, alternating which side runs first (candidate first in even rounds, baseline first in odd), so drift over the job lands on both sides. Default: 10 rounds of 1000 iterations after 200 warmup per side per round (quick: 4 × 50 after 10). A full `op-latency` comparison takes about 40 seconds on an Apple M4.

**Ratios and CI.** For each measurement the result carries both sides' pooled summaries and the ratio of medians candidate÷baseline, with a 95% percentile bootstrap CI (2000 resamples, fixed seed). Each resample draws rounds with replacement, the same rounds for both sides, and then samples within each drawn round, so between-round drift widens the interval instead of being ignored. On a laptop, that drift dominates: A/A intervals of ±10–15% are normal, and a 10% change is only reliably flagged on a quiet machine or with more rounds.

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

### `op-latency`: operation latency (B3, [#77](https://github.com/redact-secret/redact-secret-vault/issues/77))

Status: **current** with PII off. PII on is **planned** under the same issue.

| Measurement | What one sample times | Input |
| --- | --- | --- |
| `capture` | One `vault.capture` | `capture1k` (1 KiB, 4 findings, all retained) |
| `capture.core_ms` | What capture asks of the core on the same input: `core.scan` then `core.redact` with the vault's default limits | same |
| `capture.vault_overhead_ms` | `capture − capture.core_ms` of the same iteration | same |
| `restore` | One `vault.restore` of 64 fields, one token occurrence each (16 per entry) | `restore64` over a fresh `capture1k` capture |
| `revoke` | One `vault.revoke` of a capture holding 4 entries | `capture1k` |

`core_ms` and the whole capture run back to back in alternating order within each iteration, so their difference is paired. Every operation runs on a vault holding no other entries: setup (a capture for restore and revoke) and cleanup (revoking the iteration's capture) are untimed. Each iteration checks its own outcome (findings, restored occurrences, revoked entries), so a denial or a changed detection fails the metric instead of timing an error path. Release-over-release comparison of capture uses `capture.vault_overhead_ms`, because each release pins its own exact core.

Measuring PII on is one entry in `CAPTURE_INPUTS` in `bench/metrics/op-latency.mjs` (`capture1kPii` with `pii: { retain: ["pii_global_iban"] }`), run with `--pii on`.

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
- `run(ctx)` must be repeatable: the A/B runner calls it once per round per side. Create and dispose everything it uses.
- Return numbers only. `params` holds sizes, counts, and short labels.
- Take inputs from `ctx.corpus`. A new input is a corpus version bump.

## Files

| Path | Role |
| --- | --- |
| `bench/run.mjs` | One side (the workspace build), one PII mode, writes a result |
| `bench/compare.mjs`, `bench/lib/compare.mjs` | Interleaved A/B, ratios, CI, verdicts |
| `bench/lib/published.mjs`, `bench/baseline.json` | Installing a published baseline into `.bench-cache/`; the default baseline version |
| `bench/lib/timing.mjs` | `process.hrtime.bigint()` timing, warmup, fixed iterations, paired sampling |
| `bench/lib/stats.mjs` | Percentiles and the bootstrap CI for ratios |
| `bench/lib/env.mjs` | Environment capture |
| `bench/lib/sides.mjs` | Loading and activating the packages under test |
| `bench/lib/harness.mjs` | Metric discovery, `ctx`, result assembly and writing |
| `bench/lib/schema.mjs`, `bench/lib/leak-guard.mjs` | Result validation and the no-values check |
| `bench/corpus/v1/` | `corpus-v1` |
| `bench/metrics/` | One file per metric |
| `bench/test/` | `npm run test:bench` (also part of `npm test`) |
