# Qualification record: @redact-secret/vault 0.1.0-alpha.1

**Status:** executed evidence, 2026-09-27. Supersedes the [beta.8 proof of concept](verification-2026-09-27.md) as current compatibility evidence; that record remains as history.
**Issues:** [#8](https://github.com/redact-secret/redact-secret-vault/issues/8) (real-browser core integration), [#12](https://github.com/redact-secret/redact-secret-vault/issues/12)/[#13](https://github.com/redact-secret/redact-secret-vault/issues/13) (conformance on Node and browser), [#22](https://github.com/redact-secret/redact-secret-vault/issues/22) (compatibility matrix).

## Pinned core artifact

| Package | Version | npm integrity |
| --- | --- | --- |
| `@redact-secret/core` | `0.1.0-beta.9` (npm dist-tag `beta`) | `sha512-NvC+uWR0Q0GaPPUdMAIBHFg8nw/O1NsLI3enoYg4Tu5GICjfeS8D4jUE9jZhx+WIRxxm/Ue5u0Osd+cVD7m9/w==` |
| `@redact-secret/wasm` | `0.1.0-beta.9` (core dependency) | `sha512-Fpv0Q84OASJJoO84OcFG2Yfy4Hq0b2R5u0rKL1rqAplnz9slWpXhaUeBiQjUsDdap0P6v5OAob/GOoAq0wlNdw==` |

The vault declares `peerDependencies: { "@redact-secret/core": "0.1.0-beta.9" }`. The supported range is that single version, so both range endpoints are the same tested artifact. The vault imports only the core's public root export (`initialize`, `scan`, `redact`, `defaultPlaceholderFormatter`); the packed-artifact boundary check enforces this. The core's `latest` dist-tag still points at `0.1.0-beta.8`, which is **not** supported.

## Method

1. `npm pack` the vault. Install the tarball and the pinned core into a throwaway consumer project **outside** the repository, so module resolution cannot reach the workspace's `node_modules`.
2. **Node.js**: run the portable suite (`packages/vault/test/suite.js` with `conformance/v1/corpus.json`) twice. The first run uses the core's native addon. The second removes the installed `@redact-secret/node-*` packages to simulate a failed optional-dependency install, which triggers the core's documented WebAssembly fallback. Each run asserts which artifact `artifact()` reports.
3. **Browsers**: build a production Vite bundle of a consumer page that imports the packed vault and core; the core's `browser` export loads the distributed `.wasm` asset. Serve it with `Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'`. Run the same suite through Playwright. Assert `artifact() === "wasm"`, no CSP violation, and that the `.wasm` asset was fetched. A negative control serves the same page without `'wasm-unsafe-eval'`: the vault must fail closed with `CORE_FAILURE` / `INITIALIZATION_FAILED`.
4. The suite has 61 checks: 39 corpus cases (corpus v1.1.0), 21 runtime checks, and 1 leakage check. The browser runner adds 4 browser-specific checks, for 65. The leakage check fails if any fixture value or issued token appears in any error (message, stack, JSON, own properties), audit event, or console output.
5. Suite sensitivity: nine deliberately broken builds (block ignored, path check removed, budget check removed, expiry check removed, marker check removed, truthy policy accepted, partial commit on formatter failure, token leaked into an error reason) were each caught.

All values are synthetic (for example `ghp_SYNTHETICxREVOKEDxTESTx0000000000000`, `AKIASYNTHETIC0TEST00`).

## Results

CI run [36319904811](https://github.com/redact-secret/redact-secret-vault/actions/runs/36319904811) on commit `7bd9b9b5ff5c1a3126406b9e7639ca2f02b34982`. Reports are uploaded as run artifacts.

| Runtime | Platform | Core artifact | Result | Reuse of findings for a 2nd `redact` |
| --- | --- | --- | --- | --- |
| Node.js 20.20.2 | linux-x64, darwin-arm64 | addon | 61/61 | allowed |
| Node.js 20.20.2 | linux-x64, darwin-arm64 | wasm fallback | 61/61 | `INVALID_FINDINGS` |
| Node.js 22.23.2 | linux-x64, darwin-arm64 | addon | 61/61 | allowed |
| Node.js 22.23.2 | linux-x64, darwin-arm64 | wasm fallback | 61/61 | `INVALID_FINDINGS` |
| Node.js 24.21.0 / 24.20.0 | linux-x64 / darwin-arm64 | addon | 61/61 | allowed |
| Node.js 24.21.0 / 24.20.0 | linux-x64 / darwin-arm64 | wasm fallback | 61/61 | `INVALID_FINDINGS` |
| Chromium 153.0.8010.12 (Playwright headless shell) | linux-x64 (CI), darwin-arm64 (local) | wasm, strict CSP | 65/65 | `INVALID_FINDINGS` |
| Firefox 155.0 (Playwright) | linux-x64 (CI), darwin-arm64 (local) | wasm, strict CSP | 65/65 | `INVALID_FINDINGS` |
| WebKit 26.6 (Playwright) | linux-x64 (CI), darwin-arm64 (local) | wasm, strict CSP | 65/65 | `INVALID_FINDINGS` |

Core action probes are identical in every configuration. `redact` and `block` are replaced, and `warn` and `allow` leave plaintext. The UTF-16 range for a GitHub-token fixture after a leading emoji is `[3, 43)` and selects exactly the match. In all three engines, the no-`'wasm-unsafe-eval'` control failed closed with `CORE_FAILURE` / `INITIALIZATION_FAILED`.

## What this does and does not establish

- **Establishes**, for the exact versions above: the conformance corpus passes against the distributed vault and core in Node.js (both core artifacts) and in three real browser engines under a strict CSP; the action gate matches the core; and vault diagnostics contain no fixture plaintext.
- **Does not establish**: branded Chrome, Edge, or Safari on real devices (Playwright builds of the engines were used); Windows or Linux arm64 Node.js (untested, so unsupported); Worker mode; server authorization; persistence; resistance to same-page script compromise; memory erasure. Those remain unsupported for 0.1.0-alpha.1.

## Reproduce

```bash
npm ci
npm run check:boundaries
npm run qualify:node           # current Node.js; addon and WASM fallback
npx playwright install chromium firefox webkit
npm run qualify:browser        # BROWSERS=chromium,firefox,webkit
```

Reports are written to `.qualification/reports/`.
