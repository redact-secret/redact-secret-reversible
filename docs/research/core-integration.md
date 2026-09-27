# Core integration research: whole-input browser vault

**Status:** research snapshot, 2026-09-27. Recheck against an exact supported core release before implementation.
**Question:** Can the reversible product capture eligible originals and issue its own tokens using only the JavaScript core's public API?

## Confirmed public surface

At the inspected core revision, `@redact-secret/core` exports `initialize`, `scan`, `redact`, `scanAndRedact`, a `PlaceholderFormatter` hook, `RANGE_UNIT`, and the finding types. Findings contain action/type/range metadata, never the matched value. JavaScript ranges are half-open UTF-16 code-unit offsets: `input.slice(start, end)` selects the matched span. The formatter receives safe finding metadata and a one-based replacement index, not the original value. The core package supports browser WebAssembly after initialization. [Types](https://github.com/redact-secret/redact-secret/blob/main/packages/javascript/src/types.ts), [runtime](https://github.com/redact-secret/redact-secret/blob/main/packages/javascript/src/runtime.ts), [package guide](https://github.com/redact-secret/redact-secret/blob/main/packages/javascript/README.md).

The core's `redact` replaces both `redact` and `block` actions. `warn` and `allow` spans are left unchanged. A `block` result therefore requires an explicit reversible-side rejection **before any sanitized text or mapping is published**; the presence of a placeholder is not proof that the operation is allowed. A consumer that intends to send no sensitive original to an external model must choose a policy that treats any `warn`/`allow` finding appropriately, or reject the send. Detection is incomplete by design, so even that does not establish universal secrecy. [Core redaction implementation](https://github.com/redact-secret/redact-secret/blob/main/crates/secret-scan-core/src/redact.rs), [package guide](https://github.com/redact-secret/redact-secret/blob/main/packages/javascript/README.md).

The `scan` + `redact` split allows an all-or-nothing check of actions before generating output. However, `redact(input, findings)` requires findings from the *same* input and, in browser WebAssembly, opaque native handles attached to those findings. Do not clone or synthesize them. A custom formatter can issue session-specific tokens without moving token generation into core, but it must preserve the core's placeholder validation (nonempty, bounded length, no reproduced matched value). [Runtime](https://github.com/redact-secret/redact-secret/blob/main/packages/javascript/src/runtime.ts), [core redaction](https://github.com/redact-secret/redact-secret/blob/main/crates/secret-scan-core/src/redact.rs).

## Candidate integration sequence (not yet an API decision)

1. Explicitly create a bounded reversible session; call the public core initializer. Receive the original input inside the trusted browser integration.
2. Call `scan(input, policy, limits)` once. Preflight all findings and outbound policy. A `block` result aborts the whole operation with no mapping or output. Decide explicitly how `warn`/`allow` affect outbound use.
3. Stage eligible values using validated finalized `redact` finding ranges from that same input. Use exact UTF-16 slicing; do not infer ranges from the redacted output or from a formatter callback.
4. Call `redact(input, originalFindings, { placeholderFormatter, limits })`. The formatter associates each replaced finding with a fresh session-bound token, but must not publish the staged map yet. Its callback is invoked for `redact` and `block`; step 2 must have rejected `block` first.
5. Check output and token identity/literal collision rules, then commit the staged mapping and return sanitized text together as one logical operation. On any failure, discard staged references and return no partial result. Avoid emitting output or invoking consumer hooks before commit.

This sequence requires investigation of callback count/order, failed formatter side effects, validated output correspondence, multi-token collision retries, and atomic staging semantics. If public APIs cannot support these properties, propose a *narrow public core extension* in the core repository; do not import private internals or reimplement detection here.

## Security questions that need an experiment or decision

| Question | Evidence needed | Decision gate |
| --- | --- | --- |
| Can a formatter produce an opaque random token without leaking a short matched value? | Synthetic short-value cases; output validation errors; collision retries. | Define token grammar, encoding, and retry bound. |
| Can literal token-like text in original or model output be distinguished from an issued placeholder at the right location? | Adversarial examples with duplicate literals, reordered output, and copied valid tokens. | Define provenance and restore semantics; do not assume regex text matching is enough. |
| Does a `warn`/`allow` action leave plaintext in an outbound payload? | Core action matrix under default/custom policies. | Document safe outbound policy or reject payload. |
| Can `block` or a formatter failure produce a partially committed mapping? | Fault injection during scan, formatter, output validation, and commit. | All-or-nothing capture contract. |
| Are ranges stable for Unicode, zero-width obfuscation, repeated/adjacent findings? | Browser WASM integration with exact original input. | Supported core range and compatibility suite. |
| Is a Worker build feasible under application CSP and asset loading? | Real browser builds with `worker-src`, Worker script CSP, WASM loading. | Qualify Worker separately; never silently fall back. |

Streaming remains out of this whole-input research. Incremental findings use absolute ranges across an input that may no longer be retained; capture/window/cancellation rules require a separate design.

## External references

- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html): deny by default and validate authority at use time (server guarantees need a server authority).
- [MDN `worker-src`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/worker-src) and [Using Web Workers](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers): deployment constraints for a separate Worker mode.
- [MDN `Crypto.getRandomValues()`](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues): cryptographic token randomness.
