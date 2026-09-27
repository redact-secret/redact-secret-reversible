# Browser in-memory vault security specification

**Status:** proposed design requirements; no package or restore API is implemented.
**Scope:** `@redact-secret/vault` in a browser page or a dedicated Web Worker. This specification does not define server authorization or persistent storage.

This document defines the security contract to validate before browser support is claimed. The [architecture](../../ARCHITECTURE.md) and [restore authority decision](../decisions/2026-09-27-restore-authority-and-lifecycle.md) define the repository-wide boundary. The core remains independent and does not retain original values.

## Security objective and limits

The browser vault temporarily retains eligible original spans so the application can restore them at a designated final destination. Its principal benefit is that the application can send redacted text to an external model or service while keeping the mapping in the browser. The application must still decide whether a particular output field may contain restored plaintext.

The vault is inside the trust boundary of the page that receives the original input. It cannot keep an input secret from malicious code that observes that input, invokes an authorized restore, or observes its result. Same-page XSS, compromised dependencies, and third-party scripts may have those capabilities. A dedicated Worker makes its mapping inaccessible through direct main-thread object access, but it is not an authentication boundary: compromised page code can send messages to its Worker and observe returned plaintext. Browser extensions, local device compromise, developer tools, and process-memory inspection are outside the guarantee.

The browser package must not claim multi-user or tenant authorization. Applications needing enforcement across principals or tenants must use a trusted server authority, such as the proposed `vault-server` layer. Encryption with a key available to page code does not resolve same-page script compromise; a non-extractable Web Crypto key prevents export of key material, not authorized use of that key or observation of decrypted results.

## Normative requirements for a supported implementation

“MUST” and “SHOULD” below are proposed release requirements. They do not describe shipped behavior.

### 1. Deliberate retention and minimal scope

- The consumer MUST explicitly create a vault/session and opt in to retaining eligible values. Importing the core or vault package MUST NOT silently create a mapping.
- Each session MUST have a bounded lifetime, entry count, and retained-byte budget. A per-value size limit SHOULD prevent unusually large captures. Limits and default values must be decided and tested before release.
- Capture only finalized original input ranges that the core and application policy mark eligible. A core `block` outcome MUST NOT create a restorable entry. Whole-input capture precedes any separately specified streaming support.
- Plaintext and mapping handles MUST NOT be automatically written to `localStorage`, `sessionStorage`, IndexedDB, Cache API, cookies, URLs, browser history, analytics, logs, traces, serialized framework state, or model context. `sessionStorage` is script-readable storage, not an in-memory vault substitute.
- Session state SHOULD be isolated per browser tab and application task by default. Do not use shared cross-tab channels or Service Workers to hold mappings under this profile. An application that deliberately transfers sensitive material across contexts needs a separate contract.

### 2. Token identity and untrusted output

- Visible core labels such as `<SSN_1>` are display metadata, never mapping keys or proof of authority. A reversible token MUST carry or reference a collision-resistant, unpredictable identity generated with a cryptographic browser random source, and lookup MUST bind it to the issuing session and exact issued entry. Type text is descriptive and MUST NOT determine classification or eligibility.
- Token generation MUST detect collisions with existing entries. Token encoding, escaping, and literal collision behavior in original input and model output must be defined before release; do not replace ordinary text just because it resembles a token.
- The implementation MUST reject unknown, malformed, altered, expired, revoked, or foreign-session tokens without revealing whether a sensitive value exists. Model output and tool arguments are untrusted even when they contain a valid issued token.
- Repeated values may intentionally share an identity only under a documented session/source/type rule. Reuse across unrelated sessions or sources MUST NOT occur implicitly.

### 3. Narrow restoration boundary

- Restoration MUST require an application-designated destination and structural field/path. The application supplies the allowed source-to-destination relationship and purpose; the model cannot assert them. A token alone MUST NOT authorize release.
- The ordinary API SHOULD restore only specified structured fields. An arbitrary-text API, if offered, MUST enforce the same checks and avoid global regex/string replacement over an entire document or DOM.
- Before returning any plaintext, preflight **all** requested replacements against current policy, exact issued tokens, session binding, destination/path, expiry, revocation, and usage limits. One failure MUST reject the whole operation without partial plaintext or budget consumption. Restore and revoke races need deterministic semantics.
- Restored output MUST be returned only to the requesting application integration, which owns safe rendering and onward transmission. The vault cannot control code after the value has been returned.

### 4. Lifecycle and failures

- Expose explicit `dispose`/revoke behavior; invalidate on completion, abort, and timeout according to a documented contract. Application integrations SHOULD dispose on logout, task completion, and component/workflow teardown.
- Expiry MUST be checked during every operation. Timer callbacks and page lifecycle events are best-effort cleanup aids, not the only enforcement mechanism. Tests must cover background tabs, suspended timers, reload, and abrupt termination.
- Invalidate references and clear mutable byte buffers when possible. JavaScript strings, browser internals, copies, garbage collection, and crash artifacts prevent a guarantee that all plaintext bytes are immediately erased. Documentation MUST NOT promise reliable memory zeroization.
- Fail closed on malformed requests, budget exhaustion, storage errors, concurrent operations, and cancellation. Errors and optional audit hooks MUST contain only bounded, non-sensitive outcome metadata, never raw values, token-to-value mappings, input fragments, or restored payloads.

### 5. Optional Worker isolation

A dedicated Worker MAY hold the mapping and perform matching/restore operations behind a small message protocol. Its benefit is reducing direct access to the mapping from ordinary main-thread application code. It does not make the page a trusted caller.

- Validate message shape, operation, size, session state, and allowed paths inside the Worker. Do not expose `dump`, `listSecrets`, or unrestricted export operations.
- Keep original input and restored values out of Worker messages except where the chosen workflow necessarily transfers them. A Worker cannot protect plaintext that was already handled or can later be observed by compromised main-thread code.
- Terminate the Worker on explicit disposal where the Worker is owned by that vault session. Worker lifecycle and failure behavior must be tested separately.
- Worker script delivery and CSP are application/deployment concerns. A fallback to main-thread memory MUST be explicit and accurately documented; do not claim Worker isolation when it is unavailable.

## Application integration requirements

The consumer controls page security and the final sink. Integration guidance SHOULD cover:

- Context-appropriate output encoding or safe DOM APIs; a strict Content Security Policy as an additional layer, Trusted Types where supported, and minimizing third-party scripts.
- Keeping original values and restored results out of telemetry, error reporting, debug consoles, network request logs, hydration payloads, and framework persistence plugins.
- Keeping input and restored output in the browser only when that is the intended data flow. A server request containing the restored value crosses the browser boundary regardless of where the mapping lived.
- Choosing the permitted output paths and recipients in application code. A browser callback is a policy hook within the page; it is not strong authentication against compromised same-page code.

The library should allow these policies to be supplied without imposing an identity provider, browser framework, or encryption vendor.

## Security verification before browser release

The browser qualification suite MUST include at least:

1. Opt-in behavior; no implicit persistence or core-side mapping.
2. Token guessing, forgery, tampering, duplicates, foreign-session replay, and literal token collisions.
3. `block` exclusion; Unicode/range extraction; repeated-value behavior; policy changes between capture and restore.
4. Wrong destination or path, unknown token among valid tokens, all-or-nothing failure, and no budget consumption on rejected operations.
5. Expiry while timers are suspended, abort/dispose, page reload, Worker termination, and concurrent restore/revoke.
6. Limits on bytes, entries, message size, and replacement count; oversized and malformed inputs.
7. No plaintext in error strings, audit payloads, telemetry hooks, snapshots, or fixture output.
8. A same-page hostile-script test demonstrating the **limit** of Worker isolation, so documentation does not claim XSS resistance it cannot provide.

Browser and Worker modes require separate runtime evidence. Passing this suite is a prerequisite to marking the relevant mode supported; it is not a proof of safety against compromised page code.

## References

- [OWASP HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) — script-readable browser storage and Web Worker considerations.
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) and [Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) — application-side defenses.
- [OWASP Third Party JavaScript Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html) — same-page script privileges.
- [MDN: `Crypto.getRandomValues()`](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues), [`CryptoKey.extractable`](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/extractable), and [Using Web Workers](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers) — browser primitive semantics.
