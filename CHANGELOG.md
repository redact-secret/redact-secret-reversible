# Changelog

## @redact-secret/vault 0.1.0-alpha.1

First alpha. In-memory, whole-input capture and structured-field restoration for Node.js and browser main-thread runtimes, against `@redact-secret/core@0.1.0-beta.9` exactly.

- `createVault` with bounded entries, retained bytes, value size, input size, findings, entry TTL, vault lifetime, and restore size.
- `capture` gates on core actions (`block` aborts, `warn`/`allow` rejected unless `unredacted: "pass-through"`), issues 128-bit `<rsv_…>` tokens, refuses token-like input literals, and commits only after output validation.
- `restore` into application-granted `sink` + exact `path` pairs, with whole-request preflight, per-entry use budgets (default 1), a page-local `releasePolicy`, and fail-closed handling of altered tokens.
- `revoke`, `dispose`, `stats`, sanitized `VaultError` codes, and safe-metadata audit events.
- Not included: Worker mode, server authorization, persistence, streaming, and free-text restore.
