# Troubleshooting

Find the error code you got, read the cause, apply the fix. Errors never contain your input, a value, or a token, so the code (and for a denied restore, the `reason`) is all there is to go on.

To see what the vault decided without adding logging of your own, pass `onAudit`: each event has the operation, the outcome, and the code or reason, and no value.

## Creating a vault

| You see | Cause | Fix |
| --- | --- | --- |
| `CORE_FAILURE`, `coreCode: "NOT_INITIALIZED"` | Nothing initialized the core | Pass `pii: []` to `createVault` / `createServerVault`, or await the core's `initialize(...)` first |
| `CORE_FAILURE`, `coreCode: "PII_ACTIVATION_CONFLICT"` | The core was already initialized with a different PII selection. It is set once per process or page | Use one selection everywhere, or omit `pii` to adopt the one already set |
| `CORE_FAILURE` in a browser, at creation | The page's Content Security Policy blocks WebAssembly | Allow `'wasm-unsafe-eval'` in `script-src` |
| `PII_UNAVAILABLE` | A PII option was passed, but the core has no PII support or PII detection is off | Turn PII on (`pii: ["pii"]`), or drop the option. See the [PII guide](pii.md) |
| `UNSUPPORTED_RUNTIME` | The runtime has no `crypto.getRandomValues` | Use a [supported runtime](../reference/vault.md#supported-and-not) |
| npm reports a peer dependency conflict on `@redact-secret/core` | Another package, or your own manifest, asks for a different core version | Install the exact core version this release pins. See [release status](../status.md) |

## Capturing

| You see | Cause | Fix |
| --- | --- | --- |
| `UNREDACTED_FINDINGS` | The core found values it would leave visible (`warn` or `allow`). With PII on, Medium- and Low-confidence PII is `warn` by default | Pass a core `policy` that returns `redact` for those types. Or accept them: `unredacted: "pass-through"`, then check `passedThroughTypes` |
| `BLOCKED_FINDING` | The core's policy blocks a value in the input | Nothing is retained and no text is returned. Do not send the input |
| `TOKEN_LITERAL_IN_INPUT` | The input already contains `rsv_`, usually because redacted history was captured again | Capture only the new turn. See [example 02](../../examples/02-multi-turn.mjs) |
| `LIMIT_EXCEEDED` | The input, or the vault, is over a configured limit | Raise the limit in `limits`, up to its ceiling, or use a new vault per task |
| `CORE_FAILURE`, `coreCode: "FINDING_LIMIT_EXCEEDED"` | More findings than `limits.maxFindings`. PII findings count | Raise `maxFindings`, or split the input |
| `CORE_FAILURE`, `coreCode: "INVALID_PLACEHOLDER"` | A `displayFormatter` returned an empty label, or one that repeats text from the input | Return a fixed label such as `[REDACTED]` |
| A PII value comes back as a placeholder that cannot be restored (`unrestorable` is not 0) | PII is never retained unless you name its type | `pii: { retain: ["pii_global_iban"] }` on that capture |

## Restoring

A denied restore throws `RESTORE_DENIED` with a `reason` and returns no values. Keep the redacted text. Do not retry with a wider grant, and do not show the reason to the model or to end users.

| `reason` | Cause | Fix |
| --- | --- | --- |
| `sink-or-path` | The capture's `release` did not list this sink, or this field path | Restore into the sink and path you granted, or grant them at capture |
| `source` | The token belongs to a capture that is not in `captures` | List every capture of the conversation |
| `unknown-token` | The token is not in this vault: it was already restored, its capture was revoked, another vault or process issued it, or the model made it up | Restore each token once; keep one vault for the task. Across processes, use the [persistent profile](persistent-server.md) |
| `budget` | The token was already restored `maxUses` times | Raise `maxUses` at capture if the value must appear more than once |
| `malformed-token` | The model changed a token (case, spacing, truncation) | Ask the model to copy tokens unchanged |
| `expired` | `limits.entryTtlMs` passed | Capture again, or raise the lifetime |
| `invalid-request` | The request is not `{ sink, captures, fields }` with string fields | Fix the request shape |
| `policy` | Your `releasePolicy` / server `policy` said no | Check the policy |

In the in-memory vault a used-up token is removed, so a second restore reads `unknown-token`; the persistent profile keeps the counter and reads `budget`.

**No error, but a token is still in the output.** The model damaged the token's `rsv_` marker, so the vault saw ordinary text. Nothing was released. Treat it as a denial.

### Server only

| `reason` or code | Cause | Fix |
| --- | --- | --- |
| `unauthenticated` | `resolvePrincipal` threw, timed out (`resolverTimeoutMs`, 5 s), or did not return `{ id, tenant }` | Return both fields from trusted request context |
| `tenant-mismatch` | The caller's tenant is not the capture's `issuedTenant` | Pass the owner's tenant as `issuedTenant` at capture |
| `missing-purpose` | The request has no `purpose`, or your policy does not allow it for this sink | Send the purpose your policy expects |
| `revoked` | The capture was revoked | Capture again |
| `policy-evaluation-error` | Your policy threw, timed out (`policyTimeoutMs`, 5 s), or returned something other than `{ allow: true }` or `{ allow: false, reason }` | Fix the policy. A failure never allows |
| `VAULT_FAILURE` | The wrapped vault failed. `vaultCode` is one of the codes above, and `coreCode` is set for a core failure | Look up `vaultCode` in the tables above |

The persistent profile has more outcomes (`COMMIT_AMBIGUOUS`, `RESTORE_CONFLICT`, `STORE_UNAVAILABLE`, …): see [Failures](persistent-server.md#failures).

## After the vault is gone

| You see | Cause | Fix |
| --- | --- | --- |
| `DISPOSED` | `dispose()` was called, or the vault's lifetime passed | Create a new vault |
| `BUSY` | A callback called back into the vault during an operation | Do not call the vault from `policy`, `eligible`, `releasePolicy`, or `onAudit` |

## Python

Run the doctor first. It names the failing part and the fix:

```bash
python -m redact_secret_vault doctor --node-modules /srv/myapp/core/node_modules
```

| You see | Cause | Fix |
| --- | --- | --- |
| `UNSUPPORTED_RUNTIME` when creating `NodeCoreBridge` | No `node` on `PATH` | Install Node.js 20, 22, or 24 |
| `CORE_FAILURE`, `BRIDGE_CORE_NOT_FOUND` | The bridge cannot find `@redact-secret/core` | `npm install` it, then pass `node_modules=` or set `REDACT_SECRET_VAULT_NODE_MODULES` |
| `CORE_FAILURE`, `CORE_VERSION_MISMATCH` | The installed core is not the pinned version | Install exactly the version the doctor names |
| `CORE_FAILURE`, `BRIDGE_TIMEOUT` | A scan ran longer than `timeout_s` (10 s) | Raise `timeout_s`, or send smaller inputs |
| `CORE_FAILURE`, `BRIDGE_CLOSED` | The bridge was closed | Create a new bridge |

More in the [Python reference](../reference/vault-py.md#bridge-process).
