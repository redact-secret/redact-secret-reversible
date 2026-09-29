# `dist-size`: distribution size (B8, [#82](https://github.com/redact-secret/redact-secret-vault/issues/82))

Status: **current**, PII off and on (sizes do not depend on the mode; the metric runs in both so either job carries the gate).

Source: `bench/metrics/dist-size.mjs`, with `bench/metrics/support/distribution.mjs` locating each side's package directories.

## Measurements

All are deterministic byte (or file) counts. `<pkg>` is `vault` or `vault-server`.

| Measurement | What it counts | Gate |
| --- | --- | --- |
| `pack.<pkg>.tarball_bytes` | Size of the tarball `npm pack --dry-run --json --ignore-scripts` would publish | `maxRatio` 1.10 |
| `pack.<pkg>.unpacked_bytes` | Sum of the packed files' sizes | `maxRatio` 1.10 |
| `pack.<pkg>.files` | Packed file count | informational |
| `bundle.vault.min_bytes` | Minified browser bundle of `export { createVault } from "@redact-secret/vault"`, core external | informational |
| `bundle.vault.gzip_bytes` | The same bundle, gzip level 9, summed per emitted chunk | `maxRatio` 1.10 |
| `core.core.{tarball,unpacked}_bytes` | The pinned `@redact-secret/core` package | informational |
| `core.wasm.{tarball,unpacked}_bytes` | Its `@redact-secret/wasm` dependency | informational |

**Where each side's packages come from.** The candidate packs `packages/vault` and `packages/vault-server` (built `dist/`, `README.md`, `LICENSE`, per each package's `files`). The baseline re-packs its install in `.bench-cache/vault-<version>/node_modules/@redact-secret/*` with the same local npm, rather than using the registry tarball, because the tarball's gzip bytes depend on the npm that packed it. For `0.1.0-alpha.3` the re-packed `unpacked_bytes` equals the registry's `dist.unpackedSize` (129229 for vault, 58537 for vault-server). Each directory's `package.json` version is checked against the side's recorded versions.

**Bundle.** A production Vite build (the repository's `vite` devDependency, default minifier, `target: es2022`) with `@redact-secret/core` external, so the figure is vault code only; the build fails the metric if any core or wasm module ends up in a chunk. The build is not written to disk.

**Core excluded from the vault's figures.** The core is a peer dependency that each release pins exactly, so its size is not the vault's. It is reported under `core.` with `gating: false`. The native addon packages (`@redact-secret/node-<platform>`) are platform-specific and are not reported.

## Thresholds

`maxRatio: 1.10` (candidate÷baseline, checked by `bench/compare.mjs`) on the tarball, unpacked, and gzip-bundle sizes. A single `bench/run.mjs` has no baseline and so never fails on size.

- 1.10 is the epic's regression ratio ([#74](https://github.com/redact-secret/redact-secret-vault/issues/74)). Byte counts carry no noise, so there is no confidence interval: any crossing is a real change.
- At today's sizes 10% is about 3.6 KB of vault tarball, 13 KB unpacked, and 0.5 KB of gzip bundle. A few percent per release passes; a release that grows the vault by more than 10% fails and has to be accepted on purpose (by releasing against it knowingly, or by raising the ratio in this file with a reason) instead of drifting upward unnoticed.
- `README.md` is part of the tarball, so a large documentation change can move `pack.*`. That is a real download-size change and is left in.
- Minified bytes and file counts move with the gated figures and are informational.

## Runtime

Measured once per side per process and cached, and the metric sets `compareRounds = 1`: byte counts are identical in every round, so `bench:compare` runs it once per side. Two `npm pack --dry-run` calls per package side (about 0.4 s each) and one Vite build (about 0.1 s). A full `bench:compare` of the B8 metrics takes about 36 s on an Apple M4, almost all of it `cold-init` and `cold-init-browser`.

## Figures

`[pii=off corpus-v1 rounds=10x1000 node@22.16.0 darwin-arm64 local]` candidate `vault@0.1.0-alpha.3 (workspace@cacd734e7544) core@0.1.0-beta.10/addon` vs baseline `vault@0.1.0-alpha.3 (npm) core@0.1.0-beta.10/addon`:

| Measurement | Candidate | Baseline | Ratio |
| --- | ---: | ---: | ---: |
| `pack.vault.tarball_bytes` | 35990 | 35991 | 1.000 |
| `pack.vault.unpacked_bytes` | 129121 | 129229 | 0.999 |
| `pack.vault.files` | 23 | 23 | 1.000 |
| `pack.vault-server.tarball_bytes` | 16906 | 16898 | 1.000 |
| `pack.vault-server.unpacked_bytes` | 58580 | 58537 | 1.001 |
| `bundle.vault.min_bytes` | 14229 | 14225 | 1.000 |
| `bundle.vault.gzip_bytes` | 4983 | 4980 | 1.001 |
| `core.core.tarball_bytes` | 40560 | 40560 | 1.000 |
| `core.wasm.tarball_bytes` | 569273 | 569273 | 1.000 |
