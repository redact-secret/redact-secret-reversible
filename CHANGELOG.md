# Changelog

## Unreleased

PII retention and application-owned core PII activation ([#38](https://github.com/redact-secret/redact-secret-reversible/issues/38), per the [decision record](docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md)). The pinned core is still `0.1.0-beta.9`. PII-on behavior is tested against a local build of the `0.1.0-beta.10` candidate, which is not on npm.

- `@redact-secret/vault`: `CaptureOptions.pii: { retain }` is an exact-type allowlist. A `redact` finding whose type starts `pii_` is never retained unless its type is listed. `eligible` can narrow that list but cannot widen it.
- `@redact-secret/vault`: `VaultOptions.pii` (forwarded to the core's `initialize({ pii })`) and `VaultOptions.expectPiiActivation`. `Vault.piiActivation` reports the observed identity, or `null` when the core has no PII support. PII support is detected at runtime from the core's `piiActivation` export.
- `@redact-secret/vault`: new error codes `PII_UNAVAILABLE` and `PII_ACTIVATION_MISMATCH`.
- `@redact-secret/vault-server`: forwards `pii`, `expectPiiActivation`, and capture `pii` to the vault. Adds `ServerVault.piiActivation` and `VaultServerError.coreCode` (the core's code behind a `VAULT_FAILURE` / `CORE_FAILURE`).
- `redact-secret-vault-server` (Python, [#40](https://github.com/redact-secret/redact-secret-reversible/issues/40)): `NodeCoreBridge(pii=..., expected_pii_activation=...)` forwards the selection to the core's `initialize({ pii })` in each bridge process, reports `CoreScanOutcome.pii_activation` (`None` without PII support), and pins the identity across scans (`PII_ACTIVATION_MISMATCH`). `CaptureOptions.pii=PiiRetention(retain=...)` follows the same allowlist rules, with new error codes `PII_UNAVAILABLE` and `PII_ACTIVATION_MISMATCH`; bridge responses are now parsed strictly.
- No behavior change on beta.9 for callers that pass no PII option. Any PII option fails closed with `PII_UNAVAILABLE`, and `pii: []` equals omission.
- **Behavior change once the vault adopts a PII-capable core ([#41](https://github.com/redact-secret/redact-secret-reversible/issues/41)):** `createVault()` without `pii` no longer initializes the core. It adopts the application's activation, and fails with `CORE_FAILURE` / `NOT_INITIALIZED` when nothing initialized the core. Migration: `createVault({ pii: [] })`, or await the core's `initialize(...)` first.
- Worker mode ([#39](https://github.com/redact-secret/redact-secret-reversible/issues/39)) and the Python bridge ([#40](https://github.com/redact-secret/redact-secret-reversible/issues/40)) are not covered yet.

## @redact-secret/vault 0.1.0-alpha.1

First alpha. In-memory, whole-input capture and structured-field restoration for Node.js and browser main-thread runtimes, against `@redact-secret/core@0.1.0-beta.9` exactly.

- `createVault` with bounded entries, retained bytes, value size, input size, findings, entry TTL, vault lifetime, and restore size.
- `capture` gates on core actions (`block` aborts, `warn`/`allow` rejected unless `unredacted: "pass-through"`), issues 128-bit `<rsv_…>` tokens, refuses token-like input literals, and commits only after output validation.
- `restore` into application-granted `sink` + exact `path` pairs, with whole-request preflight, per-entry use budgets (default 1), a page-local `releasePolicy`, and fail-closed handling of altered tokens.
- `revoke`, `dispose`, `stats`, sanitized `VaultError` codes, and safe-metadata audit events.
- Not included: Worker mode, server authorization, persistence, streaming, and free-text restore.
