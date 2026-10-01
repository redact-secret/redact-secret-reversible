# Releasing

Each package is versioned independently of the core. Every release pins an exact tested core version.

1. Merge to `main` with the `ci` workflow green: boundaries, Node.js 20/22/24 on Linux and macOS (addon and WASM fallback), and real-browser qualification in Chromium, Firefox, and WebKit.
2. Bump the `version` in `packages/vault/package.json` and, when it ships in the same release, `packages/vault-server/package.json` (including its exact `@redact-secret/vault` dependency), and merge that to `main`. `npm pack --dry-run -w @redact-secret/vault` (or the `boundaries` job below) confirms the vault's packed file list stays exactly `LICENSE`, `README.md`, `package.json`, and `dist/*.js`/`*.d.ts`.

   Then run the `bench` workflow by hand on that commit (Actions → bench → Run workflow, from `main`; defaults: baseline from `bench/baseline.json`, both PII modes, standard tier) and read its result before tagging. See [Performance check](#performance-check) for the rule.
3. Tag the merged commit `v<version>` and push the tag (`git tag v<version> && git push origin v<version>`). This triggers `.github/workflows/release.yml`, which re-runs `check:boundaries`, the `@redact-secret/vault-server` test suite, and the Node and browser qualification against that commit. Its `publish` job then runs `npm publish --provenance` for `@redact-secret/vault` and, after it, `@redact-secret/vault-server`, each with its own `publishConfig` dist-tag (`beta` today). One tag publishes both packages, vault first, because the vault-server depends on an exact vault version; the vault-server step refuses to publish when that vault version is not on the registry, after retrying for about 5 minutes because a just-published version can 404 briefly while npm processes it. The workflow never publishes with the `latest` dist-tag; step 6 moves it. Each package's step checks `npm view <package>@<version>` first, so re-pushing a tag, re-running the workflow, or tagging a release that bumps only one package publishes only what is missing instead of failing on a double publish. The same workflow can be run by hand from a specific ref with `workflow_dispatch` (e.g. to retry after a transient failure). The same run also publishes the Python distribution to PyPI when its version is new; see [Python](#python).
4. Once the workflow's `publish` job succeeds, create a GitHub pre-release for the `v<version>` tag summarizing the tested matrix and limitations.
5. Verify: `npm view @redact-secret/vault dist-tags` and `npm view @redact-secret/vault-server dist-tags`, then a clean install of the published packages with the pinned core, a `node` import, and a browser load, all against the *registry* tarball rather than the working tree. Set `VAULT_SPEC=@redact-secret/vault@<version>` and run `npm run qualify:node` and `npm run qualify:browser`; `qualification/lib.mjs`'s `packVault()` returns that spec directly instead of building and packing the local source, so both qualification runners install the published package. Record the results in the qualification record (for `0.1.0-alpha.2`: [registry verification](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-core-0.1.0-beta.10.md#registry-verification-010-alpha2)).

6. After verification passes, move `latest` to the new version for each published package (`npm dist-tag add <package>@<version> latest`; see [the `latest` dist-tag](#the-latest-dist-tag)), then confirm with `npm view <package> dist-tags`.
7. Archive the performance result and move the baseline: commit `docs/research/perf/<version>.json` from the tag's `bench` run, link it from its `CHANGELOG.md` entry and the pre-release notes, and bump `bench/baseline.json` to `<version>` in the same change. See [Performance check](#performance-check).

## Performance check

The `bench` workflow (`.github/workflows/bench.yml`, [#83](https://github.com/redact-secret/redact-secret-vault/issues/83)) compares the release candidate with the previous published version (`bench/baseline.json`), interleaved on one runner, once with PII off and once with PII on. It runs on every `v*` tag push, next to `release.yml`, and by hand with `workflow_dispatch` (step 2). It is not a required check and does not block `release.yml`; the maintainer applies the rule below. Details: [docs/research/perf/README.md](docs/research/perf/README.md).

**Regression rule** (from the epic [#74](https://github.com/redact-secret/redact-secret-vault/issues/74)):

- **Latency: warn.** A gating latency measurement whose ratio candidate÷baseline is above 1.10 **and** whose 95% bootstrap CI excludes 1.0 (lower bound above 1.0) is a `warn`. The workflow job stays green. Every such warning must be explained in the release notes (the GitHub pre-release) or in the version-bump PR: the cause, or a re-run showing it was runner noise. An unexplained warning means the release is not ready.
- **Deterministic: fail.** A deterministic measurement over its threshold (package and bundle size above 1.10× the baseline, or the vault's heap not reclaimed after `dispose()`) is a `fail`, and so is a metric that errors. The job fails. Do not tag until it is fixed, or until the threshold is changed on purpose in a reviewed change that says why.
- Non-gating measurements (for example `capture` totals and `core_ms`, which move with the pinned core) are reported and never decide the outcome.

**Where results go.** Each run uploads its compare results (`bench-pii-off`, `bench-pii-on`) and the archive built from them (`bench-archive`). For every release, commit the tag run's `docs/research/perf/<version>.json` (`gh run download <run-id> -n bench-archive`, or `npm run bench:archive -- <compare results>`) and link it from the release's `CHANGELOG.md` entry. The first archive is written for the first release after this check existed; none is back-filled for earlier versions.

**Stating figures.** A performance figure quoted anywhere (release notes, CHANGELOG, PR) always states its PII mode, corpus version (`corpus-v1`), tier (`standard` in CI), and runner (`github-actions/Linux/X64/<image>` for the workflow), and is a ratio against the named baseline version, not an absolute time from another run.

**After the release.** Bump `bench/baseline.json` to the version just published (step 7), so the next release is compared against this one.

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

For `v0.1.0-alpha.2`, the tag was first pushed at `9f3524d`. That run's publish failed with `PUT 404` because no trusted publisher was configured yet. After the maintainer configured it and [#54](https://github.com/redact-secret/redact-secret-vault/pull/54) pointed the packages' `repository` URLs at the renamed repository, the still-unpublished tag was moved to `8b30ae5` and the release workflow published. Never move a tag once any package has been published from it.

## Provenance

`0.1.0-alpha.1` was published manually because npm trusted publishing can be configured only for a package that already exists. The same constraint made the first `@redact-secret/vault-server` publish (`0.1.0-alpha.2`) manual. Neither carries an npm provenance attestation.

`.github/workflows/release.yml` (added for [#24](https://github.com/redact-secret/redact-secret-vault/issues/24), extended to the vault-server for [#55](https://github.com/redact-secret/redact-secret-vault/issues/55)) publishes releases from GitHub Actions through npm trusted publishing (OIDC): the `publish` job requests an `id-token` (granted only to that job) and runs `npm publish --provenance` for each package, with no npm token in the workflow. These steps are manual, on npmjs.com, and are **not** done by this workflow:

- **Configure a trusted publisher for each package.** On npmjs.com, open the package → Settings → Trusted Publisher, and add a GitHub Actions publisher for repository `redact-secret/redact-secret-vault` (renamed from `redact-secret-reversible`; the publisher must name the current repository), workflow `release.yml`, environment none.
  - `@redact-secret/vault`: configured; it published `0.1.0-alpha.2` and `0.1.0-alpha.3`.
  - `@redact-secret/vault-server`: configured; it published `0.1.0-alpha.3`.
- **Revoke the manual publish credentials.** A tagged release has now published through OIDC, so revoke the granular access token used for `0.1.0-alpha.1` (npmjs.com → Access Tokens → revoke it, or, if it is still needed for something else, remove its publish permission on `@redact-secret/vault`). Also revoke any token or login session created on the maintainer machine for the manual `@redact-secret/vault-server@0.1.0-alpha.2` publish.
- **Optionally, require trusted publishing.** Once both packages publish through OIDC, set each package's publishing access on npmjs.com to disallow tokens, so a leaked token cannot publish.

## The `latest` dist-tag

The release workflow publishes only under each package's `publishConfig.tag` (`beta` today) and refuses to publish with `latest` (see `release.yml`'s "Resolve version and dist-tag" steps). Moving `latest` is a separate, deliberate maintainer step (step 6 above), done only after the registry verification passes:

```bash
npm dist-tag add @redact-secret/vault@<version> latest
npm dist-tag add @redact-secret/vault-server@<version> latest
```

npm allows moving `latest` to any published version, prerelease included; what it refuses is deleting a package's `latest` tag. So a bare `npm install @redact-secret/vault` installs whatever `latest` names, and leaving `latest` on an older alpha is a real hazard: until 2026-09-28 it pointed at `@redact-secret/vault@0.1.0-alpha.1`, which peers core beta.9 and conflicts with core beta.10.

Current tags (2026-10-01, after `0.1.0-beta.3`):

- `@redact-secret/vault`: `latest` and `beta` → `0.1.0-beta.3`; `alpha` → `0.1.0-alpha.3`.
- `@redact-secret/vault-server`: `latest` and `beta` → `0.1.0-beta.3`; `alpha` → `0.1.0-alpha.3`.

For the first stable release, either keep this manual step or change each package's `publishConfig.tag` to `latest` and deliberately relax the workflow guard in the same reviewed change.

## Python

`redact-secret-vault` (Python, [packages/vault-py](packages/vault-py/README.md)) is published to PyPI by the same `.github/workflows/release.yml`, through PyPI trusted publishing (OIDC). No PyPI API token is stored in the repository. The distribution was named `redact-secret-vault-server` until [#56](https://github.com/redact-secret/redact-secret-vault/issues/56); that name was never published. `0.1.0a2` was never published either. `0.1.0a3` is the first version to go to PyPI.

### Procedure

1. Bump `version` in `packages/vault-py/pyproject.toml` and `__version__` in `packages/vault-py/src/redact_secret_vault/__init__.py` (PEP 440, e.g. `0.1.0a3` for the npm `0.1.0-alpha.3` line) and merge to `main` with `ci` green.
2. The same `v<version>` tag push (step 3 above), or a `workflow_dispatch` run of `release.yml` from `main`, publishes the Python distribution when its version is not on PyPI yet. The Python chain does not depend on the npm jobs, and they do not depend on it:
   - `python` re-runs `ruff check` and `pytest` on Python 3.12 against that commit (the `ci` workflow covers 3.10, 3.12, and 3.13).
   - `python-dist` builds the sdist and wheel with a pinned `build`, fails unless the wheel contains `redact_secret_vault/boundary/core_bridge.mjs` and both files carry the `pyproject.toml` version (`scripts/verify-python-dist.py`). It then runs an install smoke test: it installs the wheel into a virtualenv under `$RUNNER_TEMP`, outside the checkout, and installs `@redact-secret/core` into a separate directory with `npm ci --ignore-scripts` from `scripts/python-wheel-smoke/package-lock.json`, whose core version must equal the wheel's `PINNED_CORE_VERSION`. `scripts/smoke-python-wheel.py` then checks that `NodeCoreBridge()` without a location fails with `BRIDGE_CORE_NOT_FOUND` and that `NodeCoreBridge(node_modules=...)` finds a synthetic `github_token`. Last, it runs `twine check --strict` and uploads `dist/` as the `python-dist` artifact. When the core pin changes, update that lockfile in the same change (`npm install --package-lock-only` in `scripts/python-wheel-smoke`).
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
