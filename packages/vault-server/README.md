# @redact-secret/vault-server

[`@redact-secret/vault`](https://github.com/redact-secret/redact-secret-vault/blob/main/packages/vault/README.md) for servers with many users: every restore is checked against the caller's identity, tenant, and purpose by a policy you supply.

**Beta.** Node.js 20, 22, 24. In-memory and single-process by default; a [persistent profile](#persistent-profile) is alpha.

## Install

```bash
npm install @redact-secret/vault-server@0.1.0-beta.4
```

npm also installs the matching `@redact-secret/vault` and `@redact-secret/core` (an exact dependency and an exact peer dependency). If your package manager does not install peers, add `@redact-secret/core@0.1.0-beta.12` yourself.

## Use

```ts
import { createServerVault, VaultServerError } from "@redact-secret/vault-server";

const server = await createServerVault({
  // 1. Who is asking? Read YOUR already-authenticated request context.
  //    Throw if it cannot be established. Never return a default principal.
  resolvePrincipal: async (ctx) => ({ id: ctx.userId, tenant: ctx.tenant }),
  // 2. May they? Deny by default: same tenant, and this purpose only.
  policy: (input) =>
    input.tenant === input.source.issuedTenant && input.purpose === "support-reply-purpose-synthetic"
      ? { allow: true }
      : { allow: false, reason: "policy" },
  onAudit: (event) => auditSink.write(event), // no field can carry a restored value
  pii: [], // initializes the core with PII detection off
});

// 3. Capture, and record whose value this is.
const captured = await server.capture(userText, {
  release: [{ sink: "support-ticket-reply-sink-synthetic", paths: ["body"] }],
  issuedTenant: request.tenant,
});

// ... send captured.text to a model; it sees only tokens ...

// 4. Restore, with the request context, a sink, and a purpose.
try {
  const { fields } = await server.restore({
    context: request, // passed to resolvePrincipal
    sink: "support-ticket-reply-sink-synthetic",
    purpose: "support-reply-purpose-synthetic",
    captures: [captured.captureId],
    fields: { body: modelReply },
  });
  render(fields.body);
} catch (error) {
  if (!(error instanceof VaultServerError) || error.code !== "RESTORE_DENIED") throw error;
  render(modelReply); // denied: keep the redacted text
}
```

## The rules

- **You supply two functions.** `resolvePrincipal` turns trusted request context into `{ id, tenant }`. `policy` decides each restore. A throw, a timeout, or a malformed return from either one denies; it never allows.
- **Every restore needs a `purpose`.** An empty one is denied (`missing-purpose`).
- **Tenants are checked before your policy runs.** A token captured for another tenant is denied (`tenant-mismatch`).
- **A restore is all or nothing.** One failing token denies the whole request and returns no values.
- **Calls run one at a time** on each `ServerVault`, in order. A `revoke()` queued before a `restore()` always wins.
- **Single process.** State is in memory. To share captures across processes or survive a restart, see the [persistent profile](#persistent-profile).

## Ready-made policies

From `0.1.0-beta.4`, `@redact-secret/vault-server/policies` has the common rules, so you do not write them by hand:

```ts
import { allOf, allowSameTenantOnly, allowSinkPurposes } from "@redact-secret/vault-server/policies";

const policy = allOf(
  allowSameTenantOnly,
  allowSinkPurposes({ "support-ticket-reply-sink-synthetic": ["support-reply-purpose-synthetic"] }),
);
```

`allOf` needs every policy to allow, and the first denial decides. `denyByDefault` denies everything. Add your own rules as more functions in `allOf`.

## Denial reasons

`error.reason` on a `RESTORE_DENIED`, in the order the checks run:

| Reason | Meaning |
| --- | --- |
| `unauthenticated` | `resolvePrincipal` failed or timed out |
| `malformed-token`, `unknown-token`, `revoked` | The token is altered, not known to this vault, or its capture was recently revoked |
| `source` | The token is not from a capture listed in `captures` |
| `tenant-mismatch` | The caller's tenant is not the capture's `issuedTenant` |
| `expired` | The entry's lifetime passed |
| `sink-or-path` | The capture did not grant this sink and path |
| `missing-purpose` | No `purpose` in the request |
| `budget` | The token was already restored `maxUses` times |
| `policy`, `policy-evaluation-error` | Your policy said no, or failed |

Do not forward the reason to the model or to end users. Causes and fixes for each are in [troubleshooting](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/guides/troubleshooting.md#restoring), and [example 04](https://github.com/redact-secret/redact-secret-vault/blob/main/examples/04-server-two-tenants.mjs) shows three of them.

## API at a glance

| Call | Returns |
| --- | --- |
| `createServerVault({ resolvePrincipal, policy, onAudit?, limits?, pii?, … })` | `Promise<ServerVault>` |
| `server.capture(input, { release, issuedTenant, … })` | the vault's `CaptureResult` |
| `server.restore({ context, sink, purpose, captures, fields })` | `{ fields, restored, principalId, tenant }` |
| `server.revoke(captureId)` | number of entries removed |
| `server.stats()`, `server.dispose()` | counts; idempotent shutdown |

Errors are `VaultServerError` with a `code`: `INVALID_ARGUMENT`, `RESTORE_DENIED`, `VAULT_FAILURE` (with `vaultCode` and, for core failures, `coreCode`), `INVARIANT_VIOLATION`, `DISPOSED`.

Every option, the exact evaluation order, concurrency, audit events, and residual risks are in the [reference](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/reference/vault-server.md). PII works as in `@redact-secret/vault`: see the [PII guide](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/guides/pii.md).

## Persistent profile

**Alpha.** `@redact-secret/vault-server/persistent` lets one process capture and another restore, with ciphertext in a store you inject and keys from a key provider you inject. Importing `@redact-secret/vault-server` loads none of it.

```ts
import { createPersistentServerVault } from "@redact-secret/vault-server/persistent";
```

The [persistent server guide](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/guides/persistent-server.md) has a complete PostgreSQL example, every option, and what to do on each failure.

## Not supported

Browsers, streaming, and free-text `restore(text)`. Python has its own package, [`redact-secret-vault`](https://github.com/redact-secret/redact-secret-vault/blob/main/packages/vault-py/README.md).

## More

- [Changelog](https://github.com/redact-secret/redact-secret-vault/blob/main/CHANGELOG.md) and [release status](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/status.md).
- [Threat model](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/specs/threat-model.md) and the [server authority decision](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/decisions/define-server-authority-interface.md).
- Report vulnerabilities privately through [GitHub security advisories](https://github.com/redact-secret/redact-secret-vault/security/advisories/new). Never include live credentials. See [SECURITY.md](https://github.com/redact-secret/redact-secret-vault/blob/main/SECURITY.md).

## License

MIT
