# Releasing

Each package is versioned independently of the core. Every release pins an exact tested core version.

1. Merge to `main` with the `ci` workflow green: boundaries (including `check:persistence-boundaries`), Node.js 20/22/24 on Linux and macOS (addon and WASM fallback), the `vault-server` and `persistence` jobs on the same matrix, `postgres 17`, `sqlite` on Node.js 20/22/24 on Linux and macOS, and real-browser qualification in Chromium, Firefox, and WebKit. See [Persistence packages](#persistence-packages) for the checks a release that includes them needs.
2. Bump the `version` in `packages/vault/package.json` and, when it ships in the same release, `packages/vault-server/package.json` (including its exact `@redact-secret/vault` dependency), and merge that to `main`. `npm pack --dry-run -w @redact-secret/vault` (or the `boundaries` job below) confirms the vault's packed file list stays exactly `LICENSE`, `README.md`, `package.json`, and `dist/*.js`/`*.d.ts`.

   Then run the `bench` workflow by hand on that commit (Actions → bench → Run workflow, from `main`; defaults: baseline from `bench/baseline.json`, both PII modes, standard tier) and read its result before tagging. See [Performance check](#performance-check) for the rule.
3. Tag the merged commit `v<version>` and push the tag (`git tag v<version> && git push origin v<version>`). This triggers `.github/workflows/release.yml`, which re-runs `check:boundaries`, the `@redact-secret/vault-server` test suite, the persistence checks, `@redact-secret/store-postgres` against PostgreSQL 17, `@redact-secret/store-sqlite` on real SQLite files, and the Node and browser qualification against that commit. Its `publish` job then runs `npm publish --provenance` for `@redact-secret/vault-contracts`, `@redact-secret/vault`, the other persistence packages, and last `@redact-secret/vault-server`, each with its own `publishConfig` dist-tag (`beta` for vault and vault-server, `alpha` for the persistence packages; see [Persistence packages](#persistence-packages)). One tag publishes every package whose version is new, in dependency order, because the vault-server depends on exact vault and vault-contracts versions; the vault-server step refuses to publish when that vault version is not on the registry, after retrying for about 5 minutes because a just-published version can 404 briefly while npm processes it. The workflow never publishes with the `latest` dist-tag; step 6 moves it. Each package's step checks `npm view <package>@<version>` first, so re-pushing a tag, re-running the workflow, or tagging a release that bumps only one package publishes only what is missing instead of failing on a double publish. The same workflow can be run by hand from a specific ref with `workflow_dispatch` (e.g. to retry after a transient failure). The same run also publishes the Python distribution to PyPI when its version is new; see [Python](#python).
4. Once the workflow's `publish` job succeeds, create a GitHub pre-release for the `v<version>` tag summarizing the tested matrix and limitations.
5. Verify: `npm view @redact-secret/vault dist-tags` and `npm view @redact-secret/vault-server dist-tags` (and each persistence package that was published; see [Persistence packages](#persistence-packages) for their registry check), then a clean install of the published packages with the pinned core, a `node` import, and a browser load, all against the *registry* tarball rather than the working tree. Set `VAULT_SPEC=@redact-secret/vault@<version>` and run `npm run qualify:node` and `npm run qualify:browser`; `qualification/lib.mjs`'s `packVault()` returns that spec directly instead of building and packing the local source, so both qualification runners install the published package. Record the results in the qualification record (for `0.1.0-alpha.2`: [registry verification](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-core-0.1.0-beta.10.md#registry-verification-010-alpha2)).

6. After verification passes, move `latest` to the new version for each published package (`npm dist-tag add <package>@<version> latest`; see [the `latest` dist-tag](#the-latest-dist-tag)), then confirm with `npm view <package> dist-tags`.
7. Archive the performance result and move the baseline: commit `docs/research/perf/<version>.json` from the tag's `bench` run, link it from its `CHANGELOG.md` entry and the pre-release notes, and bump `bench/baseline.json` to `<version>` in the same change. See [Performance check](#performance-check).

## Persistence packages

**Registry state (2026-10-02, after `v0.1.0-beta.4`).** All nine npm packages of this repository are published. `@redact-secret/vault` and `@redact-secret/vault-server` `0.1.0-beta.4` came from `release.yml` run [36996502364](https://github.com/redact-secret/redact-secret-vault/actions/runs/36996502364) (tag `v0.1.0-beta.4` at `b77d8cb`) with provenance attestations. `@redact-secret/vault-contracts`, `vault-crypto`, `vault-conformance`, `store-memory`, `store-postgres`, `store-sqlite`, and `key-provider-aws-kms` are each at `0.1.0-alpha.1`, published by hand by the maintainer under the `alpha` dist-tag on 2026-10-02 (10:28 to 10:31 UTC, per the registry's `time` field) before the workflow published the two `beta.4` packages, without provenance (see [First publish of each new package](#first-publish-of-each-new-package)). `@redact-secret/store-memory` and `@redact-secret/store-sqlite` each also list a version `0.0.0-stage` on the registry (published 10:29 UTC, no dist-tag, not deprecated); the agent did not publish it and does not know its content. There is no `key-provider-local` package: the local key provider is the `@redact-secret/vault-crypto/local-key-provider` entry. The dist-tags are in [the `latest` dist-tag](#the-latest-dist-tag), the verification results in the [persistence qualification record](docs/research/qualification-persistence-0.1.0-alpha.1.md#9-registry-verification).

### Publish order

The `publish` job of `release.yml` runs these steps in this order. Each is a separate step, and a failed step stops the job: no later step runs.

1. `node scripts/publish-workspace.mjs vault-contracts`. Everything else depends on it at an exact version.
2. `@redact-secret/vault` (the existing resolve, already-published, and publish steps).
3. `node scripts/publish-workspace.mjs vault-crypto vault-conformance store-memory store-postgres store-sqlite key-provider-aws-kms`, in that order.
4. `@redact-secret/vault-server` (the existing steps; it waits up to about 5 minutes for its exact `@redact-secret/vault` version to be visible).

`scripts/publish-workspace.mjs` takes package directory names and, for each in the order given:

- refuses to continue unless `publishConfig.tag` is an explicit dist-tag other than `latest`;
- skips the package when `<name>@<version>` is already on the registry, so a re-run or a re-pushed tag publishes only what is missing;
- waits for every exact `@redact-secret/*` runtime dependency to be visible on the registry (20 attempts, 15 seconds apart), and exits 1 if one never appears;
- runs `npm publish -w <name> --provenance --tag <publishConfig.tag>`.

It never uses a token, never moves `latest`, and exits at the first failure. `PUBLISH_DRY_RUN=1` adds `--dry-run` to the publish command; the registry lookups still run.

### Checks required before publishing

The `publish` job needs all of these jobs of the same `release.yml` run to pass:

| Job | Runs |
| --- | --- |
| `boundaries` | `npm run check:boundaries` |
| `node` | `npm run qualify:node` |
| `vault-server` | `npm run test:vault-server` (the in-memory and persistent server suites) |
| `persistence` | `npm run test:persistence`, `npm run check:persistence-boundaries`, `npm run qualify:persistence` (packed tarballs in clean projects; over `store-memory` and a temporary SQLite file, and over PostgreSQL only when a database is configured; also installs `store-sqlite` alone and checks that it loads no driver and refuses to start without one the application passes; it installs no `better-sqlite3`, and runs the SQLite flow over `node:sqlite` where the Node.js has a new enough one) |
| `postgres` | `npm run test:postgres` against a `postgres:17` service container, as a serving role that is not a superuser |
| `sqlite` | `npm run install:sqlite-driver` (the only step that installs `better-sqlite3` and runs its install script; the job has `contents: read` only), then `npm run test:sqlite` on Node.js 22 (Linux), over `better-sqlite3` and over `node:sqlite`: the shared conformance suite and the process, kill, and backup tests on real SQLite files. The `ci` workflow runs the same on Node.js 20 (`better-sqlite3` only), 22, and 24, Linux and macOS, and adds `npm run qualify:persistence` with `RSV_QUALIFY_BETTER_SQLITE3=1`. No workflow simulates power loss |
| `browser` | `npm run qualify:browser` |

Not run by any workflow: a power-loss simulation of the SQLite store (it has not been run at all; see its [qualification record](docs/research/qualification-store-sqlite-0.1.0-alpha.1.md)), the PostgreSQL topology scenarios (restart, failover, backup; `npm run qualify -w @redact-secret/store-postgres`, which needs Docker), the real AWS KMS suite, and the server mutation table (`node packages/vault-server/test/persistent/mutation-controls.mjs`). Run them by hand before a release that changes the store, the KMS provider, or the persistent server, and record the result in the [qualification record](docs/research/qualification-persistence-0.1.0-alpha.1.md) or its successor.

On `main`, the `ci` workflow runs the `persistence` and `sqlite` matrices and `postgres 17` on every pull request. As of 2026-10-01 the branch protection's required status checks are `boundaries`, `browser`, the six `node` jobs, and `sast`; the `persistence`, `sqlite`, `vault-server`, and `postgres 17` jobs are not in that list, so a maintainer reads them before merging until they are added in the repository settings.

### First publish of each new package

npm trusted publishing can be configured only for a package that already exists (see [Provenance](#provenance)). So the first version of each new package is published by hand by a maintainer, exactly as `@redact-secret/vault@0.1.0-alpha.1` and `@redact-secret/vault-server@0.1.0-alpha.2` were, and carries no provenance attestation. The seven packages of the persistence line went through this procedure before `v0.1.0-beta.4`; it applies again to any package added later. For each package, in this order — `vault-contracts`, `vault-crypto`, `vault-conformance`, `store-memory`, `store-postgres`, `store-sqlite`, `key-provider-aws-kms`:

1. From a clean checkout of the commit to be tagged, with `ci` green on it: `npm ci && npm run build`. Then `npm run readme:pin`, so the README you publish links to the release tag ([README links](#readme-links)); run `npm run readme:restore` when you are done.
2. `npm publish -w @redact-secret/<package> --tag alpha`, authenticated as a maintainer of the `@redact-secret` scope (web 2FA, or a granular token limited to that package). No `--provenance`: it is not available outside the workflow.
3. `npm view @redact-secret/<package> dist-tags`. For `@redact-secret/vault-server`'s first publish the registry pointed `latest` as well as `alpha` at the new version; expect the same and leave it.
4. On npmjs.com: the package → Settings → Trusted Publisher → add a GitHub Actions publisher for repository `redact-secret/redact-secret-vault`, workflow `release.yml`, environment none.
5. Revoke the token or login session used for step 2.

Then push the tag (step 3 of the procedure above). For `v0.1.0-beta.4` the workflow found the seven `0.1.0-alpha.1` versions on the registry, skipped them, and published `@redact-secret/vault` and `@redact-secret/vault-server` `0.1.0-beta.4` with provenance. The first version of a new package that carries provenance is therefore its second version.

**Until that is done for a package, the workflow fails closed.** (For the seven existing packages it was done before `v0.1.0-beta.4`.) What happens depends on how far the manual steps got. There is no token fallback in either case.

| Registry state when the tag is pushed | Result of the `publish` job |
| --- | --- |
| `@redact-secret/vault-contracts` not on npm | Step 1 above fails at `npm publish` (no trusted publisher; when this happened for `v0.1.0-alpha.2` the error was `PUT 404`). The job stops. **Nothing is published**, `@redact-secret/vault` and `@redact-secret/vault-server` included, because their steps come after it |
| `vault-contracts` published by hand, another persistence package not | Step 1 skips. Step 2 publishes `@redact-secret/vault`. Step 3 fails at the first package that is not on npm. The job stops, and **`@redact-secret/vault-server` is not published**: its steps come after step 3. The registry then has the new vault without its vault-server until the missing packages are published by hand and the workflow is re-run, which skips what exists and publishes the rest |
| Every package published by hand, trusted publishers not yet configured | Steps 1 and 3 skip everything. `@redact-secret/vault` and `@redact-secret/vault-server` publish. The missing trusted publishers surface at the next version of a new package |

The Python job chain (`python`, `python-dist`, `pypi-publish`) does not depend on the npm `publish` job and is not affected.

Never move a tag once any package has been published from it.

### Dist-tags

- `alpha` for the seven persistence packages (`publishConfig.tag` in each manifest).
- `beta` for `@redact-secret/vault` and `@redact-secret/vault-server`.
- `latest` is never set by the workflow: both the vault steps and `publish-workspace.mjs` refuse a `publishConfig.tag` of `latest`. On `@redact-secret/vault-server`'s first publish the registry set `latest` as well as the named tag, so expect a new package's first version to become its `latest`. Moving it afterwards is the manual step 6.

### Verifying the published persistence packages

`VAULT_SPEC` (step 5) covers `@redact-secret/vault` only: `qualification/lib.mjs`'s `packVault()` returns it instead of a local tarball, so `qualify:node` and `qualify:browser` install the registry package.

Nothing equivalent exists for the persistence packages. `qualification/persistence-consumer.mjs` (`npm run qualify:persistence`) always builds and packs the working tree; it reads no variable that points it at the registry. The variables it does read are `QUALIFICATION_DIR` (work directory) and `RSV_PG_ADMIN_URL` with `RSV_PG_APP_URL` (a disposable database; without both it runs over `store-memory` only and says so). So a pass of `qualify:persistence` is evidence about the tagged commit, not about the registry tarballs.

Until a registry mode exists, verify by hand, in a new directory outside any checkout:

```bash
npm view @redact-secret/vault-contracts dist-tags   # and each other package
mkdir /tmp/rsv-verify-persistence && cd /tmp/rsv-verify-persistence && npm init -y
npm install --save-exact @redact-secret/vault-server@<version> @redact-secret/vault@<version> \
  @redact-secret/core@<pinned core> @redact-secret/vault-contracts@<version> @redact-secret/vault-crypto@<version> \
  @redact-secret/store-memory@<version> @redact-secret/store-postgres@<version> pg@8.23.1 \
  @redact-secret/store-sqlite@<version>
node --input-type=module -e 'await import("@redact-secret/vault-server/persistent"); await import("@redact-secret/vault-crypto/local-key-provider"); await import("@redact-secret/store-postgres"); await import("@redact-secret/store-sqlite"); console.log("ok")'
npm audit signatures   # provenance, for versions the workflow published
```

Then run the consumer script's persistent flow (`exercise` in `qualification/persistence-consumer.mjs`) in that directory, and record what was run in the qualification record. A version published by hand has a registry signature and no provenance attestation.

## README links

A README on the registry stays as it was published, so a link to `main` in it would show a reader of an old version the documentation of a newer one. `release.yml` therefore runs `node scripts/pin-readme-links.mjs pin` after the build and before the first publish ([#138](https://github.com/redact-secret/redact-secret-vault/issues/138)). In every `packages/*/README.md` it rewrites:

- `https://github.com/redact-secret/redact-secret-vault/blob/main/...` and `/tree/main/...` to the release tag;
- relative links (`../../docs/...`) to absolute links at the release tag, because the registry does not resolve them.

The tag is `v<version of @redact-secret/vault>`, the tag the workflow runs from. Links to an exact commit, to issues, and to other sites are left alone. The committed READMEs keep their `main` and relative links; only the packed copy changes.

It is a step of the workflow and not a `prepack` script because package manifests carry no lifecycle script (`check:boundaries`). For a publish by hand, run `npm run readme:pin` before and `npm run readme:restore` after. A link pinned before the tag is pushed resolves once it is. `npm run test:scripts` covers the rewrite and a packed tarball. The Python README is not rewritten: it links to `main` with absolute URLs.

## Performance check

The `bench` workflow (`.github/workflows/bench.yml`, [#83](https://github.com/redact-secret/redact-secret-vault/issues/83)) compares the release candidate with the previous published version (`bench/baseline.json`), interleaved on one runner, once with PII off and once with PII on. It runs on every `v*` tag push, next to `release.yml`, and by hand with `workflow_dispatch` (step 2). It is not a required check and does not block `release.yml`; the maintainer applies the rule below. Details: [docs/research/perf/README.md](docs/research/perf/README.md).

**Regression rule** (from the epic [#74](https://github.com/redact-secret/redact-secret-vault/issues/74)):

- **Latency: warn.** A gating latency measurement whose ratio candidate÷baseline is above 1.10 **and** whose 95% bootstrap CI excludes 1.0 (lower bound above 1.0) is a `warn`. The workflow job stays green. Every such warning must be explained in the release notes (the GitHub pre-release) or in the version-bump PR: the cause, or a re-run showing it was runner noise. An unexplained warning means the release is not ready.
- **Deterministic: fail.** A deterministic measurement over its threshold (package and bundle size above 1.10× the baseline, or the vault's heap not reclaimed after `dispose()`) is a `fail`, and so is a metric that errors. The job fails. Do not tag until it is fixed, or until the threshold is changed on purpose in a reviewed change that says why.
- Non-gating measurements (for example `capture` totals and `core_ms`, which move with the pinned core) are reported and never decide the outcome.

**Where results go.** Each run uploads its compare results (`bench-pii-off`, `bench-pii-on`) and the archive built from them (`bench-archive`). For every release, commit the tag run's `docs/research/perf/<version>.json` (`gh run download <run-id> -n bench-archive`, or `npm run bench:archive -- <compare results>`) and link it from the release's `CHANGELOG.md` entry. The first archive is written for the first release after this check existed; none is back-filled for earlier versions.

**Stating figures.** A performance figure quoted anywhere (release notes, CHANGELOG, PR) always states its PII mode, corpus version (`corpus-v1`), tier (`standard` in CI), and runner (`github-actions/Linux/X64/<image>` for the workflow), and is a ratio against the named baseline version, not an absolute time from another run.

**After the release.** Bump `bench/baseline.json` to the version just published (step 7), so the next release is compared against this one.

### Release 0.1.0-beta.4: bench result

Tag run [36996502332](https://github.com/redact-secret/redact-secret-vault/actions/runs/36996502332), archived in [docs/research/perf/0.1.0-beta.4.json](docs/research/perf/0.1.0-beta.4.json). Figures are ratios of the `0.1.0-beta.4` workspace build (`b77d8cb`) over the published `0.1.0-beta.3` baseline, corpus `corpus-v1`, tier `standard`, runner `github-actions/Linux/X64/ubuntu24/20260927.320.1`, Node 22.23.3, 10 rounds. The `compare` jobs for PII off and PII on both failed; `archive` succeeded.

- **Fail, both PII modes (explained, threshold unchanged).** `dist-size pack.vault-server.tarball_bytes` 1.971 (17 471 to 34 432 bytes) and `pack.vault-server.unpacked_bytes` 2.366 (60 027 to 142 118 bytes), against the 1.10 limit. Cause: the new opt-in `@redact-secret/vault-server/persistent` entry ([#109](https://github.com/redact-secret/redact-secret-vault/issues/109)) and the `/policies` entry ([#134](https://github.com/redact-secret/redact-secret-vault/issues/134)). Comparing the packed tarballs of the two published versions, `dist/persistent/*` adds 8 files, 79 696 bytes (`server.js` alone is 62 606), `dist/policies.*` adds 2 files, 4 754 bytes, and `errors.*`, `types.d.ts`, `server-vault.js`, and `package.json` (new exports and the `vault-contracts` dependency) add 3 078 bytes, less 5 437 bytes from the shorter README: +82 091 bytes in all. The tarball holds only `dist`, `README.md`, `LICENSE`, `package.json`; no tests, source maps, fixtures, or docs shipped. The measurement is deterministic, so a re-run cannot change it (re-runs below gave the same 1.971 and 2.366). A 1.10 limit cannot hold when a package gains a whole profile, and the baseline moves to `0.1.0-beta.4` in this change, so the next release is compared against it. The threshold is left at 1.10. Proposal for review: keep it, and for a release that adds a documented entry point record the explained fail here, as above.
- **Warn, PII off only (not reproduced).** `op-latency revoke` 1.103, 95% CI [1.070, 1.116]; PII on: 1.006, [0.995, 1.023]. Two re-runs of `bench` by hand on the `v0.1.0-beta.4` ref with baseline `0.1.0-beta.3`, PII off, standard tier: run [37000886112](https://github.com/redact-secret/redact-secret-vault/actions/runs/37000886112) gave 0.957 [0.937, 0.978] and run [37001234382](https://github.com/redact-secret/redact-secret-vault/actions/runs/37001234382) gave 1.063 [1.043, 1.082]; neither warned, and run 37001234382 had no other warning. The runs landed on different CPU models (EPYC 9V74, 9V45, 7763), and the ratio ranges from 0.957 to 1.103 across the three PII-off runs. The revoke code is unchanged between the tags (`git diff v0.1.0-beta.3 v0.1.0-beta.4 -- packages/vault/src` touches the capture plan and `errors.ts`; `vault.ts` changes there only move capture logic into the plan, and `revoke` itself is not edited). Verdict: not reproduced and not traced to a code change; the spread between runs is as large as the warning, so it is recorded as runner variation shown by the re-runs, with a possible small real effect of the capture-plan change on the entries `revoke` removes not excluded (run 37001234382 sat 6% above 1.0 with a CI above 1.0). The release is not held for it.
- The `worker-boundary` result from the tag run is in the run's `bench-pii-off` artifact only; it is not archived.

## Release history

| Tag | Package | How it was published | Provenance |
| --- | --- | --- | --- |
| `v0.1.0-alpha.1` (2026-09-27) | `@redact-secret/vault@0.1.0-alpha.1` | Manually, from a maintainer machine with a granular access token | None |
| `v0.1.0-alpha.2` (2026-09-28, `8b30ae5`) | `@redact-secret/vault@0.1.0-alpha.2` | `release.yml` run [36410617284](https://github.com/redact-secret/redact-secret-vault/actions/runs/36410617284), npm trusted publishing | SLSA provenance (sigstore log index 2981833072) |
| `v0.1.0-alpha.2` (2026-09-28) | `@redact-secret/vault-server@0.1.0-alpha.2` (first publish) | Manually, from a maintainer machine (npm web 2FA) | None |
| `v0.1.0-alpha.3` (2026-09-28, `bd01c06`) | `@redact-secret/vault@0.1.0-alpha.3`, `@redact-secret/vault-server@0.1.0-alpha.3` | `release.yml` run [36438298743](https://github.com/redact-secret/redact-secret-vault/actions/runs/36438298743), npm trusted publishing; the vault-server dependency check retried 9 times (about 2.5 minutes) before the vault version was visible | SLSA provenance on both; `npm audit signatures` verified both |
| `v0.1.0-beta.1` (2026-09-29, `9212e4d`) | `@redact-secret/vault@0.1.0-beta.1`, `@redact-secret/vault-server@0.1.0-beta.1`, `redact-secret-vault@0.1.0b1` (PyPI) | `release.yml` run [36589858908](https://github.com/redact-secret/redact-secret-vault/actions/runs/36589858908), npm trusted publishing (dist-tag `beta`) and PyPI trusted publishing; the vault-server version took about 6 minutes to appear on the registry after `npm publish` | SLSA provenance on both npm packages (`npm audit signatures` verified); PEP 740 attestations on the wheel and sdist (`pypi-attestations verify pypi` OK) |
| `v0.1.0-beta.2` (2026-09-29, `3462d8e`) | `@redact-secret/vault@0.1.0-beta.2`, `@redact-secret/vault-server@0.1.0-beta.2`, `redact-secret-vault@0.1.0b2` (PyPI) | `release.yml` run [36619621473](https://github.com/redact-secret/redact-secret-vault/actions/runs/36619621473), npm trusted publishing (dist-tag `beta`) and PyPI trusted publishing | SLSA provenance on both npm packages (`npm audit signatures` verified); PEP 740 attestations on the wheel (`pypi-attestations verify pypi` OK) |
| `v0.1.0-beta.3` (2026-10-01, `b526492`) | `@redact-secret/vault@0.1.0-beta.3`, `@redact-secret/vault-server@0.1.0-beta.3`, `redact-secret-vault@0.1.0b3` (PyPI) | `release.yml` run [36879552785](https://github.com/redact-secret/redact-secret-vault/actions/runs/36879552785), npm trusted publishing (dist-tag `beta`) and PyPI trusted publishing; the vault-server version took several minutes to appear on the registry | SLSA provenance on both npm packages (`npm audit signatures` verified); PEP 740 attestations on the wheel and sdist (provenance endpoint HTTP 200 for both) |
| `v0.1.0-beta.4` (2026-10-02, `b77d8cb`) | `@redact-secret/vault@0.1.0-beta.4`, `@redact-secret/vault-server@0.1.0-beta.4`; `redact-secret-vault` stays at `0.1.0b3` on PyPI (no Python bump) | `release.yml` run [36996502364](https://github.com/redact-secret/redact-secret-vault/actions/runs/36996502364), npm trusted publishing (dist-tag `beta`); the seven persistence packages were already on the registry and were skipped | SLSA provenance on both packages (`npm audit signatures`: 42 packages verified in the clean install of the registry packages) |
| No tag (2026-10-02, 10:28 to 10:31 UTC, before `v0.1.0-beta.4` was published) | `@redact-secret/vault-contracts`, `vault-crypto`, `vault-conformance`, `store-memory`, `store-postgres`, `store-sqlite`, `key-provider-aws-kms`, each `0.1.0-alpha.1` | Manually, by the maintainer (dist-tag `alpha`; the registry also set `latest`) | None |

For `v0.1.0-alpha.2`, the tag was first pushed at `9f3524d`. That run's publish failed with `PUT 404` because no trusted publisher was configured yet. After the maintainer configured it and [#54](https://github.com/redact-secret/redact-secret-vault/pull/54) pointed the packages' `repository` URLs at the renamed repository, the still-unpublished tag was moved to `8b30ae5` and the release workflow published. Never move a tag once any package has been published from it.

## Provenance

`0.1.0-alpha.1` was published manually because npm trusted publishing can be configured only for a package that already exists. The same constraint made the first `@redact-secret/vault-server` publish (`0.1.0-alpha.2`) manual. Neither carries an npm provenance attestation. The same constraint applied to each of the seven persistence packages: their `0.1.0-alpha.1` versions were published by hand, with a registry signature and no provenance attestation. See [First publish of each new package](#first-publish-of-each-new-package).

`.github/workflows/release.yml` (added for [#24](https://github.com/redact-secret/redact-secret-vault/issues/24), extended to the vault-server for [#55](https://github.com/redact-secret/redact-secret-vault/issues/55)) publishes releases from GitHub Actions through npm trusted publishing (OIDC): the `publish` job requests an `id-token` (granted only to that job) and runs `npm publish --provenance` for each package, with no npm token in the workflow. These steps are manual, on npmjs.com, and are **not** done by this workflow:

- **Configure a trusted publisher for each package.** On npmjs.com, open the package → Settings → Trusted Publisher, and add a GitHub Actions publisher for repository `redact-secret/redact-secret-vault` (renamed from `redact-secret-reversible`; the publisher must name the current repository), workflow `release.yml`, environment none.
  - `@redact-secret/vault`: configured; it published `0.1.0-alpha.2` through `0.1.0-beta.4`.
  - `@redact-secret/vault-server`: configured; it published `0.1.0-alpha.3` through `0.1.0-beta.4`.
  - `@redact-secret/vault-contracts`, `@redact-secret/vault-crypto`, `@redact-secret/vault-conformance`, `@redact-secret/store-memory`, `@redact-secret/store-postgres`, `@redact-secret/store-sqlite`, `@redact-secret/key-provider-aws-kms`: configured by the maintainer on npmjs.com, **not verified by the agent that wrote this record**: the repository has no way to check it, and the npm CLI used here (11.4.1) has no command that lists a package's trusted publishers. The first version of each of these packages that the workflow publishes (`0.1.0-alpha.2` or later) is the first test of it.
- **Revoke the manual publish credentials.** A tagged release has now published through OIDC, so revoke the granular access token used for `0.1.0-alpha.1` (npmjs.com → Access Tokens → revoke it, or, if it is still needed for something else, remove its publish permission on `@redact-secret/vault`). Also revoke any token or login session created on the maintainer machine for the manual `@redact-secret/vault-server@0.1.0-alpha.2` publish.
- **Optionally, require trusted publishing.** Once both packages publish through OIDC, set each package's publishing access on npmjs.com to disallow tokens, so a leaked token cannot publish.

## The `latest` dist-tag

The release workflow publishes only under each package's `publishConfig.tag` (`beta` today) and refuses to publish with `latest` (see `release.yml`'s "Resolve version and dist-tag" steps). Moving `latest` is a separate, deliberate maintainer step (step 6 above), done only after the registry verification passes:

```bash
npm dist-tag add @redact-secret/vault@<version> latest
npm dist-tag add @redact-secret/vault-server@<version> latest
```

npm allows moving `latest` to any published version, prerelease included; what it refuses is deleting a package's `latest` tag. So a bare `npm install @redact-secret/vault` installs whatever `latest` names, and leaving `latest` on an older alpha is a real hazard: until 2026-09-28 it pointed at `@redact-secret/vault@0.1.0-alpha.1`, which peers core beta.9 and conflicts with core beta.10.

Current tags (2026-10-02, after `0.1.0-beta.4`, read with `npm view <package> dist-tags --prefer-online`):

- `@redact-secret/vault`: `latest` and `beta` → `0.1.0-beta.4`; `alpha` → `0.1.0-alpha.3`.
- `@redact-secret/vault-server`: `latest` and `beta` → `0.1.0-beta.4`; `alpha` → `0.1.0-alpha.3`.
- The seven persistence packages (`vault-contracts`, `vault-crypto`, `vault-conformance`, `store-memory`, `store-postgres`, `store-sqlite`, `key-provider-aws-kms`): `alpha` and `latest` → `0.1.0-alpha.1`. The registry set `latest` on each first publish, as expected for a new package; the workflow never sets it and the maintainer left it. `vault` moved to `0.1.0-beta.4` first, and `vault-server` followed later the same day, so the moves are separate observations.

For the first stable release, either keep this manual step or change each package's `publishConfig.tag` to `latest` and deliberately relax the workflow guard in the same reviewed change.

## Python

`redact-secret-vault` (Python, [packages/vault-py](packages/vault-py/README.md)) is published to PyPI by the same `.github/workflows/release.yml`, through PyPI trusted publishing (OIDC). No PyPI API token is stored in the repository. The distribution was named `redact-secret-vault-server` until [#56](https://github.com/redact-secret/redact-secret-vault/issues/56); that name was never published. `0.1.0a2` was never published either. `0.1.0a3` is the first version to go to PyPI.

### Procedure

1. Bump `version` in `packages/vault-py/pyproject.toml` and `__version__` in `packages/vault-py/src/redact_secret_vault/__init__.py` (PEP 440, e.g. `0.1.0a3` for the npm `0.1.0-alpha.3` line) and merge to `main` with `ci` green.
2. The same `v<version>` tag push (step 3 above), or a `workflow_dispatch` run of `release.yml` from `main`, publishes the Python distribution when its version is not on PyPI yet. The Python chain does not depend on the npm jobs, and they do not depend on it:
   - `python` re-runs `ruff check` and `pytest` on Python 3.12 against that commit (the `ci` workflow covers 3.10, 3.12, and 3.13).
   - `python-dist` builds the sdist and wheel with a pinned `build`, fails unless the wheel contains `redact_secret_vault/boundary/core_bridge.mjs` and both files carry the `pyproject.toml` version (`scripts/verify-python-dist.py`). It then runs an install smoke test: it installs the wheel into a virtualenv under `$RUNNER_TEMP`, outside the checkout, and installs `@redact-secret/core` into a separate directory with `npm ci --ignore-scripts` from `scripts/python-wheel-smoke/package-lock.json`, whose core version must equal the wheel's `PINNED_CORE_VERSION`. `scripts/smoke-python-wheel.py` then checks that `NodeCoreBridge()` without a location fails with `BRIDGE_CORE_NOT_FOUND` and that `NodeCoreBridge(node_modules=...)` finds a synthetic `github_token`. Last, it runs `twine check --strict` and uploads `dist/` as the `python-dist` artifact. When the core pin changes, update that lockfile in the same change (`npm install --package-lock-only` in `scripts/python-wheel-smoke`), and regenerate the bridge's integrity pin with `python3 scripts/core-integrity.py write` (it downloads the published tarballs, checks their sha512 against `package-lock.json`, and rewrites `packages/vault-py/src/redact_secret_vault/_core_pin.py`); `ci` runs `scripts/core-integrity.py check --fetch --installed node_modules` and fails if `PINNED_CORE_VERSION`, `package.json`, either lockfile, or the pin disagree. The smoke test installs the core the way a consumer does, so it also exercises the pin on the runner's platform.
   - `pypi-publish` is the only job with `id-token: write`. It resolves the version from `pyproject.toml` and checks `https://pypi.org/pypi/redact-secret-vault/<version>/json`: HTTP 200 skips the upload (so a re-pushed tag or re-run is a no-op), 404 proceeds, and anything else fails the job. It then downloads the artifact and uploads it with `pypa/gh-action-pypi-publish`, which also uploads PEP 740 attestations by default.
3. Because the Python version is independent of the npm versions, a tag that bumps only the npm packages publishes nothing new to PyPI, and a Python-only bump can ship from a `workflow_dispatch` run on `main` without a new tag.

### Trusted publisher

The maintainer registered a PyPI **pending publisher**: project `redact-secret-vault`, repository `redact-secret/redact-secret-vault`, workflow `release.yml`, environment (Any). PyPI turns it into a normal trusted publisher for the project on the first successful upload. A pending publisher does not reserve the name, so the first publish should happen soon after this workflow lands.

`pypi-publish` sets no GitHub `environment:`, which the (Any) publisher accepts. To gate uploads behind a GitHub environment later, add the environment to the job **and** update the PyPI publisher to name it in the same change; otherwise the OIDC exchange is rejected.

### First publish

After this workflow merges, the maintainer runs `release.yml` once via `workflow_dispatch` on `main`. The npm packages are already at `0.1.0-alpha.3` on the registry, so their publish steps skip; only `redact-secret-vault` `0.1.0a3` is uploaded. Afterwards, confirm on pypi.org that the pending publisher became a trusted publisher for the project, and record the run in the release history above.

### Verification

In a fresh virtual environment, not this repository's:

```bash
python3 -m venv /tmp/rsv-verify && . /tmp/rsv-verify/bin/activate
pip index versions redact-secret-vault --pre
pip install --no-cache-dir "redact-secret-vault==<version>"
python -c "import redact_secret_vault as m; print(m.__version__)"
python -c "import importlib.resources as r; print(r.files('redact_secret_vault').joinpath('boundary/core_bridge.mjs').is_file())"
mkdir -p /tmp/rsv-verify-core && npm install --prefix /tmp/rsv-verify-core --ignore-scripts @redact-secret/core@<PINNED_CORE_VERSION>
SMOKE_NODE_MODULES=/tmp/rsv-verify-core/node_modules python scripts/smoke-python-wheel.py  # from a checkout
```

To check the PEP 740 attestations, fetch them from PyPI's integrity API, or verify them against this repository with [`pypi-attestations`](https://pypi.org/project/pypi-attestations/):

```bash
curl -fsS "https://pypi.org/integrity/redact-secret-vault/<version>/redact_secret_vault-<version>-py3-none-any.whl/provenance"
uvx pypi-attestations verify pypi --repository https://github.com/redact-secret/redact-secret-vault "pypi:redact_secret_vault-<version>-py3-none-any.whl"
uvx pypi-attestations verify pypi --repository https://github.com/redact-secret/redact-secret-vault "pypi:redact_secret_vault-<version>.tar.gz"
```

The PyPI project page's "Verified details" should also show `redact-secret/redact-secret-vault` and `release.yml`.
