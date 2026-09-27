# @redact-secret/vault

**Alpha.** An opt-in, bounded, in-memory vault for [`@redact-secret/core`](https://www.npmjs.com/package/@redact-secret/core). It replaces detected secrets with random tokens before text leaves your code, for example to an LLM. Later it puts the original values back, but only into fields your application names in advance.

```bash
npm install @redact-secret/vault@alpha @redact-secret/core@0.1.0-beta.9
```

## Supported, and not

| Runtime | Status in 0.1.0-alpha.1 |
| --- | --- |
| Node.js 20, 22, 24 (core native addon or its WebAssembly fallback) | Qualified: Linux x64, macOS arm64 |
| Browser main thread, bundled, with a CSP allowing `'wasm-unsafe-eval'` | Qualified: Chromium, Firefox, WebKit (versions in the [qualification record](https://github.com/redact-secret/redact-secret-reversible/blob/main/docs/research/qualification-0.1.0-alpha.1.md)) |
| `@redact-secret/core` | `0.1.0-beta.9` exactly (peer dependency) |
| Dedicated Web Worker mode | **Not supported** ([#14](https://github.com/redact-secret/redact-secret-reversible/issues/14)) |
| Multi-user or multi-tenant server authorization | **Not supported**. This package does not know users or tenants ([#15](https://github.com/redact-secret/redact-secret-reversible/issues/15)) |
| Persistence, Python, streaming, free-text `restore(text)` | **Not supported** |

## Usage

```ts
import { createVault, VaultError } from "@redact-secret/vault";

// One vault per user task or session. Nothing is retained until you call capture.
const vault = await createVault({ limits: { entryTtlMs: 5 * 60_000 } });

try {
  const userText = "Please rotate ghp_SYNTHETICxREVOKEDxTESTx0000000000000 today";

  const captured = vault.capture(userText, {
    // Where these values may come back: this sink, these exact field paths.
    release: [{ sink: "draft-reply", paths: ["body"] }],
  });
  // captured.text: "Please rotate <rsv_…> today"
  // captured.passedThrough === 0, guaranteed under the default unredacted: "reject".

  const modelReply = await callModel(captured.text); // your code; sees only tokens

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
  vault.dispose();
}
```

## What the vault enforces

- **Explicit capture.** `createVault` and `capture` are the only ways to retain anything. Importing the package retains nothing.
- **Core action gate.** Any `block` finding fails the capture (`BLOCKED_FINDING`) with no output and no mapping. `warn` and `allow` findings stay as plaintext in the core's output, so by default the capture fails (`UNREDACTED_FINDINGS`). With `unredacted: "pass-through"` it returns the text and reports the count in `passedThrough`.
- **Tokens.** Each retained occurrence gets its own `<rsv_…>` token with 128 bits from `crypto.getRandomValues`. The type beside it is descriptive only. Input that already contains `rsv_` is refused (`TOKEN_LITERAL_IN_INPUT`), so no literal can be mistaken for an issued token.
- **Restoration into granted fields only.** You pass one `sink`, the `captures` the output may draw from, and a map of `path → text`. Every token in every field must come from one of those captures in this vault, be unexpired, be granted for that sink and exact path, and fit within its use budget (`maxUses`, default 1). Your optional `releasePolicy` must also return `true`. One failure denies the whole request, with no plaintext and no budget consumed. A token altered while its `rsv_` marker survives (case, truncation, whitespace, invisible format characters) is denied rather than ignored. An alteration that destroys the marker, such as a look-alike letter, leaves ordinary text that is returned unrestored.
- **Bounds.** Entries, retained bytes, bytes per value, input bytes, findings, entry TTL, vault lifetime, restore fields, and bytes per field are all bounded. See `DEFAULT_LIMITS` and `LIMIT_CEILINGS`. Expiry is checked on every call; no timers run.
- **Lifecycle.** `revoke(captureId)` removes a capture's unused entries. `dispose()` clears everything, is idempotent, and makes later calls fail with `DISPOSED`.
- **Sanitized diagnostics.** Errors carry a fixed message, a `code`, and only a core error code or coarse denial `reason`. They never carry input, values, tokens, or paths, and never a `cause`. `onAudit` receives frozen events with operation, outcome, code, reason, counts, sink, and time only. `stats()` returns counts. There is no export, dump, or iteration API. The vault never logs, stores to disk or browser storage, or makes network calls.
- **Re-entrancy.** A callback that calls back into the vault during an operation gets `BUSY`.

## What it does not protect against

- **Code in your page or process.** Same-page scripts, XSS, compromised dependencies, and extensions can read the input before capture, call `restore`, or read its result. The vault shares their trust boundary.
- **Relocation within a grant.** A model can move a valid token within a granted field, or into another path you granted for the same capture. Grant the narrowest paths. Keep `maxUses: 1`.
- **Other users.** A vault shared across users or tenants will restore one user's value into another's granted field if you list both captures. Use one vault per user task. Server authorization is future work.
- **Denial reasons.** `reason` tells your code which check failed, and so whether a token is live. Do not forward it to the model or to end users.
- **Inspection tools.** Browser DevTools and debuggers can display private fields; `console.log(vault)` in a DevTools session can show retained values.
- **Undetected secrets.** The core does not detect every secret. Treat `text` as "known findings removed", not "safe to send".
- **Memory erasure.** Values are JavaScript strings; revoke and dispose drop references but cannot zeroize memory.
- **Plaintext after return.** Once `restore` returns, rendering, logging, and forwarding are your responsibility.

See the [threat model](https://github.com/redact-secret/redact-secret-reversible/blob/main/docs/specs/threat-model.md) for each mode's boundary and alternatives.

## Multi-turn conversations

Capture only the new user turn. Earlier turns are already redacted, so send the stored redacted history plus the new capture's `text`, and do not re-capture history: tokens in the input are refused (`TOKEN_LITERAL_IN_INPUT`), so nothing restored is scanned twice. At restore time, list the captures of this conversation in `captures`. Do not restore history in order to re-capture it.

If a capture fails with `UNREDACTED_FINDINGS`, the input contains values the core chose to leave visible (`warn`/`allow`). Prefer adjusting the core `policy` to `redact` those types over `unredacted: "pass-through"`. If you do pass them through, check `passedThroughTypes` before sending.

## API

`createVault(options?) → Promise<Vault>`. Options: `limits` (partial `VaultLimits`), `releasePolicy(request) → boolean`, `onAudit(event)`, `now() → ms` (for tests; the default clock is monotonic). Rejects with `UNSUPPORTED_RUNTIME` without `crypto.getRandomValues`, and with `CORE_FAILURE` if the core cannot initialize (for example, a CSP without `'wasm-unsafe-eval'`).

`vault.capture(input, options) → CaptureResult`. Options: `release` (required), `maxUses`, `unredacted` (`"reject"` | `"pass-through"`), `policy` and `ruleset` (passed to the core), `eligible(finding)`, `displayFormatter`. Result: `captureId`, `text`, `tokens[{ token, type }]`, `passedThrough`, `passedThroughTypes`, `unrestorable`, `expiresAt`. A core limit failure (for example, too many findings) surfaces as `CORE_FAILURE` with the core's `coreCode`.

`vault.restore({ sink, captures, fields }) → { fields, restored }`. Returns the same paths with issued tokens replaced; throws `RESTORE_DENIED` with `reason` of `invalid-request`, `malformed-token`, `unknown-token`, `source`, `expired`, `sink-or-path`, `budget`, or `policy`. `releasePolicy` receives `captureId`, `sink`, `path`, `type`, `occurrences` (in this path), `totalOccurrences` (in the whole request), and `used`.

`vault.revoke(captureId) → number`, `vault.dispose()`, `vault.stats()`.

Error codes: `INVALID_ARGUMENT`, `UNSUPPORTED_RUNTIME`, `CORE_FAILURE`, `BLOCKED_FINDING`, `UNREDACTED_FINDINGS`, `TOKEN_LITERAL_IN_INPUT`, `LIMIT_EXCEEDED`, `TOKEN_GENERATION_FAILED`, `INVARIANT_VIOLATION`, `RESTORE_DENIED`, `BUSY`, `DISPOSED`.

## Security reports

Report vulnerabilities privately through [GitHub security advisories](https://github.com/redact-secret/redact-secret-reversible/security/advisories/new). Never include live credentials. See [SECURITY.md](https://github.com/redact-secret/redact-secret-reversible/blob/main/SECURITY.md).

## License

MIT
