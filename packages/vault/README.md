# @redact-secret/vault

[![npm (beta)](https://img.shields.io/npm/v/@redact-secret/vault/beta?label=npm%20%28beta%29)](https://www.npmjs.com/package/@redact-secret/vault)
[![License: MIT](https://img.shields.io/npm/l/@redact-secret/vault)](https://www.npmjs.com/package/@redact-secret/vault)
[![Node.js](https://img.shields.io/node/v/@redact-secret/vault/beta?label=node%20%28beta%29)](https://www.npmjs.com/package/@redact-secret/vault)
[![CI](https://github.com/redact-secret/redact-secret-vault/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/redact-secret/redact-secret-vault/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/redact-secret/redact-secret-vault/badge)](https://scorecard.dev/viewer/?uri=github.com/redact-secret/redact-secret-vault)

Swap secrets for random tokens before text leaves your code (for example, to an LLM), then put the original values back, but only into fields you named in advance. In-memory, opt-in, built on [`@redact-secret/core`](https://www.npmjs.com/package/@redact-secret/core).

**Beta.** Runs on Node.js 20, 22, 24 and in browsers (main thread, or an optional dedicated Worker).

## Install

```bash
npm install @redact-secret/vault@0.1.0-beta.5
```

npm also installs `@redact-secret/core` at the one version this release works with (an exact peer dependency). If your package manager does not install peers, add `@redact-secret/core@0.1.0-beta.13` yourself.

## Use

```ts
import { createVault, VaultError } from "@redact-secret/vault";

// One vault per user task or session. `pii: []` initializes the core with PII detection off.
const vault = await createVault({ pii: [], limits: { entryTtlMs: 5 * 60_000 } });

try {
  const userText = "Please rotate ghp_SYNTHETICxREVOKEDxTESTx0000000000000 today";

  // 1. Capture. `release` says where these values may come back: this sink, these exact field paths.
  const captured = vault.capture(userText, {
    release: [{ sink: "draft-reply", paths: ["body"] }],
  });
  // captured.text: "Please rotate <rsv_…> today"

  // 2. Send the redacted text. The model sees only tokens.
  const modelReply = await callModel(captured.text); // your code

  // 3. Restore into the granted sink and path.
  let body: string;
  try {
    const { fields } = vault.restore({
      sink: "draft-reply",
      captures: [captured.captureId], // only this conversation's values
      fields: { body: modelReply },
    });
    body = fields.body;
  } catch (error) {
    if (!(error instanceof VaultError) || error.code !== "RESTORE_DENIED") throw error;
    body = modelReply; // denied: keep the redacted text, do not retry with a wider grant
  }
  render(body); // your code owns safe rendering of plaintext
} finally {
  vault.dispose(); // 4. Drop everything.
}
```

That is the whole flow: `createVault` → `capture` → `restore` → `dispose`.

## The rules

- **Grants are fixed at capture.** A value returns only into the `sink` and `paths` you listed in `release`. Grant the narrowest paths.
- **Each token restores once** (`maxUses`, default 1), and every entry expires (`limits.entryTtlMs`).
- **A restore is all or nothing.** One unknown, expired, used-up, or ungranted token denies the whole request with `RESTORE_DENIED` and returns no values.
- **One vault per user.** This package does not know users or tenants. For that, use [`@redact-secret/vault-server`](https://github.com/redact-secret/redact-secret-vault/blob/main/packages/vault-server/README.md).
- **`captured.text` means "known findings removed", not "safe to send".** The core does not detect every secret.

## Common tasks

Runnable versions of these are in [examples](https://github.com/redact-secret/redact-secret-vault/blob/main/examples/README.md), and every error code with its fix is in [troubleshooting](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/guides/troubleshooting.md).

**Multi-turn conversations.** Capture only the new user turn. Earlier turns are already redacted, so send the stored redacted history plus the new capture's `text`. Do not capture text that already contains tokens (it fails with `TOKEN_LITERAL_IN_INPUT`). At restore time, list every capture of the conversation in `captures`.

**A capture fails with `UNREDACTED_FINDINGS`.** The input contains values the core chose to leave visible (`warn` or `allow`). Prefer a core `policy` that maps those types to `redact`. Otherwise pass `unredacted: "pass-through"` and check `passedThroughTypes` before sending.

**A capture fails with `BLOCKED_FINDING`.** The core's policy blocks that value. Nothing was retained and no text is returned.

**`createVault()` fails with `CORE_FAILURE` / `NOT_INITIALIZED`.** Pass `pii: []`, or await the core's own `initialize(...)` first. From `0.1.0-beta.4` the error message says so.

**Revoke early.** `vault.revoke(captured.captureId)` removes a capture's unused entries.

**Detect and restore PII.** Off by default, and never retained unless you name the exact type: see the [PII guide](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/guides/pii.md).

**Keep the mapping off the main thread.** See the [Worker mode guide](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/guides/worker-mode.md).

## API at a glance

| Call | Returns |
| --- | --- |
| `createVault({ pii?, limits?, releasePolicy?, onAudit? })` | `Promise<Vault>` |
| `vault.capture(input, { release, maxUses?, unredacted?, policy?, pii? })` | `{ captureId, text, tokens, passedThrough, unrestorable, expiresAt, … }` |
| `vault.restore({ sink, captures, fields })` | `{ fields, restored }`, or throws `RESTORE_DENIED` |
| `vault.revoke(captureId)` | number of entries removed |
| `vault.stats()` | counts only |
| `vault.dispose()` | clears everything; later calls fail with `DISPOSED` |

Errors are `VaultError` with a fixed message and a `code`. They never carry input, values, or tokens. A `RESTORE_DENIED` also has a `reason`; do not forward it to the model or to end users.

Every option, limit, error code, and guarantee is in the [reference](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/reference/vault.md).

## Not supported

Persistence, streaming, free-text `restore(text)`, `SharedWorker`, Service Workers, and Node.js `worker_threads`. The full table is in the [reference](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/reference/vault.md#supported-and-not).

## What it does not protect against

Code in your own page or process (XSS, a compromised dependency, an extension) can read the input before capture and call `restore` itself. Values are JavaScript strings and cannot be wiped from memory. Read [what the vault enforces and what it does not](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/reference/vault.md#what-the-vault-enforces) and the [threat model](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/specs/threat-model.md) before relying on it.

## More

- [Changelog](https://github.com/redact-secret/redact-secret-vault/blob/main/CHANGELOG.md), including the `0.1.0-alpha.2` change to `createVault()`.
- [Release status](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/status.md): published versions and qualified runtimes.
- Report vulnerabilities privately through [GitHub security advisories](https://github.com/redact-secret/redact-secret-vault/security/advisories/new). Never include live credentials. See [SECURITY.md](https://github.com/redact-secret/redact-secret-vault/blob/main/SECURITY.md).

## License

MIT
