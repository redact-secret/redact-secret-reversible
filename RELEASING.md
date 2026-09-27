# Releasing

Each package is versioned independently of the core. Every release pins an exact tested core version.

1. Merge to `main` with the `ci` workflow green: boundaries, Node.js 20/22/24 on Linux and macOS (addon and WASM fallback), and real-browser qualification in Chromium, Firefox, and WebKit.
2. From the merged commit, run `npm ci && npm run check:boundaries && npm pack --dry-run -w @redact-secret/vault`. Inspect the file list: `LICENSE`, `README.md`, `package.json`, and `dist/*.js`/`*.d.ts` only.
3. Publish with the package's `publishConfig` (`access: public`, `tag: alpha`). Pre-releases never take the `latest` dist-tag.
4. Tag the published commit `v<version>` and create a GitHub pre-release summarizing the tested matrix and limitations.
5. Verify: `npm view @redact-secret/vault dist-tags`, a clean install of `@redact-secret/vault@<version>` with the pinned core, `node` import, and a browser load through `npm run qualify:browser` against the registry tarball.

## Provenance

`0.1.0-alpha.1` was published manually from a maintainer machine with a granular access token, because npm trusted publishing can be configured only for a package that already exists. It carries **no** npm provenance attestation. Later releases should publish from GitHub Actions through npm trusted publishing (OIDC) with `npm publish --provenance` once a trusted publisher is configured for `@redact-secret/vault` on npmjs.com. Tracked in [#22](https://github.com/redact-secret/redact-secret-reversible/issues/22).
