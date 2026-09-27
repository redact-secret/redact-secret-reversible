# Releasing

Each package is versioned independently of the core. Every release pins an exact tested core version.

1. Merge to `main` with the `ci` workflow green: boundaries, Node.js 20/22/24 on Linux and macOS (addon and WASM fallback), and real-browser qualification in Chromium, Firefox, and WebKit.
2. Bump `packages/vault/package.json`'s `version` and merge that to `main`. `npm pack --dry-run -w @redact-secret/vault` (or the `boundaries` job below) confirms the packed file list stays exactly `LICENSE`, `README.md`, `package.json`, and `dist/*.js`/`*.d.ts`.
3. Tag the merged commit `v<version>` and push the tag (`git tag v<version> && git push origin v<version>`). This triggers `.github/workflows/release.yml`, which re-runs `check:boundaries` and the Node and browser qualification against that commit, then runs `npm publish --provenance` with the package's `publishConfig` dist-tag (`alpha` today). Pre-releases never take the `latest` dist-tag, and the `publish` job checks `npm view @redact-secret/vault@<version>` first, so re-pushing a tag or re-running the workflow on an already-published version is a no-op rather than a failed double-publish. The same workflow can be run by hand from a specific ref with `workflow_dispatch` (e.g. to retry after a transient failure).
4. Once the workflow's `publish` job succeeds, create a GitHub pre-release for the `v<version>` tag summarizing the tested matrix and limitations.
5. Verify: `npm view @redact-secret/vault dist-tags`, then a clean install of `@redact-secret/vault@<version>` with the pinned core, a `node` import, and a browser load — all against the *registry* tarball rather than the working tree. Set `VAULT_SPEC=@redact-secret/vault@<version>` and run `npm run qualify:node` and `npm run qualify:browser`; `qualification/lib.mjs`'s `packVault()` returns that spec directly instead of building and packing the local source, so both qualification runners install the published package. (For `0.1.0-alpha.1` this was done ad hoc from a maintainer machine; it's scriptable from the repo now.)

## Provenance

`0.1.0-alpha.1` was published manually from a maintainer machine with a granular access token, because npm trusted publishing can be configured only for a package that already exists. It carries **no** npm provenance attestation.

`.github/workflows/release.yml` (added for [#24](https://github.com/redact-secret/redact-secret-reversible/issues/24)) publishes later releases from GitHub Actions through npm trusted publishing (OIDC): the `publish` job requests an `id-token` (granted only to that job) and runs `npm publish --provenance`, with no npm token in the workflow. Two steps remain manual, on npmjs.com, and are **not** done by this workflow:

- **Configure the trusted publisher.** On npmjs.com, open `@redact-secret/vault` → Settings → Trusted Publisher, and add a GitHub Actions publisher for `redact-secret/redact-secret-reversible`, workflow `.github/workflows/release.yml`, environment none. Until this is configured, the `publish` job's `npm publish` fails with an auth error (expected — it does not fall back to a token).
- **Revoke or scope down the manual publish token** used for `0.1.0-alpha.1` once a tagged release has published successfully through OIDC. On npmjs.com: Access Tokens → find the granular token used for the alpha.1 publish → revoke it (or, if it's still needed for something else, remove its publish permission on `@redact-secret/vault`).

## The `latest` dist-tag

The registry auto-assigned `latest` to `0.1.0-alpha.1` because it was the only version at the time, and npm refuses to delete a package's last remaining `latest`-tagged version. This is npm registry behavior, not something in this repo's control: until the first stable release, `npm view @redact-secret/vault dist-tags` will keep showing `latest` pointing at a prerelease, and that's expected.

`latest` moves with the first stable publish (the first `x.y.z` version with no `-alpha`/`-beta` suffix) — but only if that release is published with the `latest` tag. This workflow always publishes with the version's `publishConfig.tag` from `packages/vault/package.json` (currently `alpha`, and it errors out rather than publish if that's ever `latest` by accident — see `release.yml`'s "Resolve version and dist-tag" step). So as part of cutting the first stable release, change `packages/vault/package.json`'s `publishConfig.tag` from `alpha` to `latest` (step 2, before tagging) — otherwise the stable version would publish under the `alpha` tag and `latest` would stay pinned to the last prerelease.
