# Releasing

Each package is versioned independently of the core. Every release pins an exact tested core version.

1. Merge to `main` with the `ci` workflow green: boundaries, Node.js 20/22/24 on Linux and macOS (addon and WASM fallback), and real-browser qualification in Chromium, Firefox, and WebKit.
2. Bump the `version` in `packages/vault/package.json` and, when it ships in the same release, `packages/vault-server/package.json` (including its exact `@redact-secret/vault` dependency), and merge that to `main`. `npm pack --dry-run -w @redact-secret/vault` (or the `boundaries` job below) confirms the vault's packed file list stays exactly `LICENSE`, `README.md`, `package.json`, and `dist/*.js`/`*.d.ts`.
3. Tag the merged commit `v<version>` and push the tag (`git tag v<version> && git push origin v<version>`). This triggers `.github/workflows/release.yml`, which re-runs `check:boundaries`, the `@redact-secret/vault-server` test suite, and the Node and browser qualification against that commit. Its `publish` job then runs `npm publish --provenance` for `@redact-secret/vault` and, after it, `@redact-secret/vault-server`, each with its own `publishConfig` dist-tag (`alpha` today). One tag publishes both packages, vault first, because the vault-server depends on an exact vault version; the vault-server step refuses to publish when that vault version is not on the registry, after retrying for about 5 minutes because a just-published version can 404 briefly while npm processes it. Pre-releases never take the `latest` dist-tag. Each package's step checks `npm view <package>@<version>` first, so re-pushing a tag, re-running the workflow, or tagging a release that bumps only one package publishes only what is missing instead of failing on a double publish. The same workflow can be run by hand from a specific ref with `workflow_dispatch` (e.g. to retry after a transient failure).
4. Once the workflow's `publish` job succeeds, create a GitHub pre-release for the `v<version>` tag summarizing the tested matrix and limitations.
5. Verify: `npm view @redact-secret/vault dist-tags` and `npm view @redact-secret/vault-server dist-tags`, then a clean install of the published packages with the pinned core, a `node` import, and a browser load, all against the *registry* tarball rather than the working tree. Set `VAULT_SPEC=@redact-secret/vault@<version>` and run `npm run qualify:node` and `npm run qualify:browser`; `qualification/lib.mjs`'s `packVault()` returns that spec directly instead of building and packing the local source, so both qualification runners install the published package. Record the results in the qualification record (for `0.1.0-alpha.2`: [registry verification](docs/research/qualification-core-0.1.0-beta.10.md#registry-verification-010-alpha2)).

## Release history

| Tag | Package | How it was published | Provenance |
| --- | --- | --- | --- |
| `v0.1.0-alpha.1` (2026-09-27) | `@redact-secret/vault@0.1.0-alpha.1` | Manually, from a maintainer machine with a granular access token | None |
| `v0.1.0-alpha.2` (2026-09-28, `8b30ae5`) | `@redact-secret/vault@0.1.0-alpha.2` | `release.yml` run [36410617284](https://github.com/redact-secret/redact-secret-vault/actions/runs/36410617284), npm trusted publishing | SLSA provenance (sigstore log index 2981833072) |
| `v0.1.0-alpha.2` (2026-09-28) | `@redact-secret/vault-server@0.1.0-alpha.2` (first publish) | Manually, from a maintainer machine (npm web 2FA) | None |

For `v0.1.0-alpha.2`, the tag was first pushed at `9f3524d`. That run's publish failed with `PUT 404` because no trusted publisher was configured yet. After the maintainer configured it and [#54](https://github.com/redact-secret/redact-secret-vault/pull/54) pointed the packages' `repository` URLs at the renamed repository, the still-unpublished tag was moved to `8b30ae5` and the release workflow published. Never move a tag once any package has been published from it.

## Provenance

`0.1.0-alpha.1` was published manually because npm trusted publishing can be configured only for a package that already exists. The same constraint made the first `@redact-secret/vault-server` publish (`0.1.0-alpha.2`) manual. Neither carries an npm provenance attestation.

`.github/workflows/release.yml` (added for [#24](https://github.com/redact-secret/redact-secret-vault/issues/24), extended to the vault-server for [#55](https://github.com/redact-secret/redact-secret-vault/issues/55)) publishes releases from GitHub Actions through npm trusted publishing (OIDC): the `publish` job requests an `id-token` (granted only to that job) and runs `npm publish --provenance` for each package, with no npm token in the workflow. These steps are manual, on npmjs.com, and are **not** done by this workflow:

- **Configure a trusted publisher for each package.** On npmjs.com, open the package → Settings → Trusted Publisher, and add a GitHub Actions publisher for repository `redact-secret/redact-secret-vault` (renamed from `redact-secret-reversible`; the publisher must name the current repository), workflow `release.yml`, environment none.
  - `@redact-secret/vault`: configured; it published `0.1.0-alpha.2`.
  - `@redact-secret/vault-server`: **still to configure.** Until it is, the workflow's vault-server publish step fails with an auth error for the next version (expected; it does not fall back to a token). The vault publish earlier in the same run is unaffected, and once the publisher exists, a `workflow_dispatch` rerun on the tag publishes only the missing package.
- **Revoke the manual publish credentials.** A tagged release has now published through OIDC, so revoke the granular access token used for `0.1.0-alpha.1` (npmjs.com → Access Tokens → revoke it, or, if it is still needed for something else, remove its publish permission on `@redact-secret/vault`). Also revoke any token or login session created on the maintainer machine for the manual `@redact-secret/vault-server@0.1.0-alpha.2` publish.
- **Optionally, require trusted publishing.** Once both packages publish through OIDC, set each package's publishing access on npmjs.com to disallow tokens, so a leaked token cannot publish.

## The `latest` dist-tag

The registry auto-assigns `latest` to a package's first published version, and npm refuses to delete a package's last remaining `latest`-tagged version. This is npm registry behavior, not something in this repo's control. Until the first stable release, `latest` points at a prerelease on both packages, and that's expected:

- `@redact-secret/vault`: `latest` → `0.1.0-alpha.1` (peers core beta.9), `alpha` → `0.1.0-alpha.2`.
- `@redact-secret/vault-server`: `latest` and `alpha` → `0.1.0-alpha.2`.

`latest` moves with the first stable publish (the first `x.y.z` version with no `-alpha`/`-beta` suffix), but only if that release is published with the `latest` tag. This workflow always publishes with each package's `publishConfig.tag` (currently `alpha`) and errors out rather than publish if that is ever `latest` (see `release.yml`'s "Resolve version and dist-tag" steps). So cutting the first stable release means changing `publishConfig.tag` from `alpha` to `latest` in each package's `package.json` (step 2, before tagging) and deliberately relaxing that guard in the same reviewed change; otherwise the stable version would publish under the `alpha` tag and `latest` would stay pinned to the last prerelease.

## Python (not yet published)

`redact-secret-vault` (Python, [packages/vault-py](packages/vault-py/README.md)) has never been uploaded to PyPI or any other index; it installs only from this repository. **No publish workflow exists for it yet.** `release.yml` publishes only the npm packages and never builds or uploads a Python distribution. It was named `redact-secret-vault-server` until [#56](https://github.com/redact-secret/redact-secret-vault/issues/56); that name was never published.

The intended setup is PyPI trusted publishing (OIDC), mirroring the npm packages, so no PyPI API token is ever stored in the repository. Because the project does not exist on PyPI yet, it has to start from a **pending publisher**, which PyPI turns into a normal trusted publisher on the first successful upload. This is manual, on pypi.org, and has not been done:

- On pypi.org, open Account settings → Publishing → "Add a new pending publisher" → GitHub, with:
  - PyPI project name: `redact-secret-vault`
  - Owner: `redact-secret`
  - Repository name: `redact-secret-vault`
  - Workflow name: the future Python publish workflow's file name (for example `release-python.yml`; it must match the file that is eventually added)
  - Environment name: `pypi`
- Create a GitHub environment named `pypi` in the repository settings, restricted to release tags, so only a reviewed tag can reach the upload job.
- A pending publisher does not reserve the name. Anyone can register `redact-secret-vault` on PyPI until the first upload, so the first publish should follow soon after the pending publisher is created.

Adding the workflow is separate, reviewed work. It should build the sdist and wheel, run the Python tests against the built wheel, and upload with `pypa/gh-action-pypi-publish` from a job that alone holds `id-token: write` and runs in the `pypi` environment. Until that lands, the Python version in `pyproject.toml` (`0.1.0a2`) is a repository version only.
