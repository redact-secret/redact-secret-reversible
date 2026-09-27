# Security research foundations for reversible restoration

**Status:** research and design recommendations, 2026-09-27. No implementation is claimed.
**Scope:** browser in-memory vault, server restore authority, optional persistent stores, and shared conformance. This is a source-backed design input, not a compliance certification or an assertion that external standards prescribe this exact API.

Read with the [browser security specification](../specs/in-memory-security.md), [core integration research](core-integration.md), and [executed beta.8 verification](verification-2026-09-27.md).

## Executive findings

1. **Restoration is a release decision, not merely a lookup.** The model can copy or relocate valid tokens; the application must authorize a specific value's release to a specific destination/path at the time of use. OWASP recommends default denial and a permission check on every access; LLM tool outputs are untrusted. The exact source-to-sink contract below is our design inference. [OWASP authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [OWASP LLM prompt injection](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html).
2. **Worker memory changes exposure, not caller authority.** Worker message data is copied/transferred; if the page supplies input and receives plaintext after restoration, a compromised page can observe or request those values. A Worker needs its own response CSP in the usual case, in addition to a page policy that controls `worker-src`. [MDN workers](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers), [MDN worker-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/worker-src), [OWASP third-party JavaScript](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html).
3. **Encryption cannot replace authorization or store transactions.** Authenticated encryption protects stored bytes, while keys, tenant checks, expiry, revocation, usage budgets, and backup retention have separate failure modes. OWASP recommends minimizing sensitive storage and separating keys and data where possible. [OWASP cryptographic storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html), [OWASP key management](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html), [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).
4. **No storage transaction can retract a plaintext value already delivered.** An internal preflight/consume step can be atomic, but a response sent to a browser, tool, callback, or downstream service is outside that transaction. “All or nothing” must name its boundary and failure modes. Redis transactions serialize commands but do not support rollbacks; a backend-specific proof is needed. [Redis transactions](https://redis.io/docs/latest/develop/using-commands/transactions/), [PostgreSQL transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html).

## 1. Assets, attackers, and trust boundaries

| Asset or transition | Threat to research | Required design response |
| --- | --- | --- |
| Original input before redaction | XSS or third-party script reads it before the vault; scanner false negative; `warn`/`allow` passes it through | Never claim protection from a script that receives the input. Explicit outbound policy and actual core action tests. The [beta.8 verification](verification-2026-09-27.md) confirms the action behavior. |
| Session mapping and token identity | Guessing, copied valid token, literal collision, cross-session lookup, exported map | Unpredictable identity, exact issued entry and session binding, limits, no bulk export, and an explicit provenance/ambiguity rule. Randomness alone cannot solve copied-token misuse. |
| Restore request | Model-selected purpose, destination or path; stale policy; wrong tenant | Application-owned sink/path and fresh server authorization against verified principal and tenant. Browser hooks cannot make client code a multi-user authority. |
| Restored result | Logs, analytics, DOM injection, downstream forwarding, malicious recipient | Return only through the approved application boundary; safe rendering and non-payload audit events. Document what the library can no longer control after returning plaintext. |
| Persisted mapping | Database disclosure, ciphertext substitution, key compromise, stale backups, revoked-but-present data | Qualified store: authenticated encryption, key ownership/rotation, metadata integrity, logical expiry/revoke checks, and retention/backup policy. |
| Release artifact | Malicious update or dependency, forged package, unsafe example | Signed/provenanced builds, limited dependencies, compatible core version matrix, and negative examples in docs. [OWASP npm security](https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html). |

## 2. Browser and Worker research

OWASP warns that script-accessible browser storage is exposed by XSS; a dedicated Worker cannot access the caller's DOM but can receive messages and make requests. MDN specifies that messages are normally cloned, so moving a string to a Worker does not erase the main-thread copy. A non-extractable `CryptoKey` prevents key export through `exportKey`/`wrapKey`, but code permitted to call a decrypt operation can still use it and observe decrypted output. These are distinct controls. [OWASP HTML5 security](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html), [MDN workers](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers), [MDN CryptoKey](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/extractable).

**Recommendation:** support a small browser memory profile and, after separate qualification, a Worker-owned profile. Both need the same limited restore semantics. Worker-only selection must fail if Worker delivery or initialization fails; no silent fallback. The Worker deployment guide must cover the page's `worker-src`, the Worker's own CSP response header, WASM asset loading, and strict message validation. A cross-origin sensitive workflow can provide a stronger page separation only if sensitive input and final output do not pass through the less trusted parent.

**Open experiment:** actual browser and Worker execution of the released public API under CSP, including failure to load WASM/Worker, aborted messages, tab suspension, and a hostile main-thread script. WASM executed inside Node is not browser qualification.

## 3. Release authorization and provenance

OWASP's authorization guidance is deny by default and validate permissions for every request. Its multi-tenant guidance requires server-verified tenant context and warns that opaque IDs are not authorization controls. OWASP's LLM guidance treats model-influenced tool arguments as untrusted and recommends least privilege and parameter validation. [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [multi-tenant security](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html), [LLM prompt injection](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html).

**Proposed server decision tuple:** verified principal; tenant; source/session and issued entry; current policy version or fresh evaluation; purpose; sink identity; structural path; expiry/revocation; remaining use budget. Consumer auth and policy implementations are injectable, but these dimensions cannot be silently skipped when a server security claim is made. A browser profile may enforce app-supplied local release rules but must label them as page-local policy, not server-grade authentication.

**Provenance question:** our [beta.8 experiment](verification-2026-09-27.md) produced two indistinguishable token strings after one literal was already present in input. A model can also duplicate or relocate an actual issued token. Token entropy prevents guessing; it cannot prove that a particular occurrence is in its original location. Before publishing a text restore API, decide whether issued tokens carry out-of-band structural handles, whether literal occurrences are escaped/rejected, and how copied tokens in a separately approved path are handled. Reject ambiguity by default. Even a correctly issued token in an approved path releases a value because the application chose that policy; the model must never expand the policy.

**Conformance cases:** wrong tenant, principal, source, sink, path, purpose, policy revision, copied token, valid token in unapproved path, duplicate occurrences, literal collision, expired/revoked token, simultaneous restore/revoke, and reused token beyond budget. Verify both denial and absence of plaintext in errors/audit hooks.

## 4. Persistent storage and atomicity

OWASP favors minimizing sensitive data storage and using authenticated encryption where storage is necessary. If an AES-GCM scheme is chosen, NIST SP 800-38D is the governing primitive reference; nonce/IV uniqueness, authenticated associated metadata, and key lifecycle must be engineered and tested. Do not claim that a ciphertext with a browser-accessible key prevents XSS, and do not force a single KMS or vendor. [OWASP cryptographic storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html), [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).

**Proposed minimum store contract:**

- A stored record binds ciphertext or plaintext to tenant, session, issued entry, source, expiry, revocation state, and use budget. If metadata is separate from ciphertext, prevent metadata/ciphertext substitution; authenticated associated data is one candidate mechanism.
- Every restore checks logical expiry and revocation at use time; background deletion or Redis TTL alone is insufficient as a security decision. Expiration callbacks/events may be delayed. [Redis keyspace notifications](https://redis.io/docs/latest/develop/pubsub/keyspace-notifications/).
- One multi-token restore must validate all requested entries and consistently consume allowed uses without interleaving a revoke or another restore. Define the linearization point and backend guarantee. Redis `MULTI/EXEC` serializes command execution but has no rollback; Lua/Functions have server-side atomic execution, yet a script design must avoid partial effects on error. PostgreSQL `SERIALIZABLE` can abort one concurrent transaction and requires retry handling. [Redis transactions](https://redis.io/docs/latest/develop/using-commands/transactions/), [Redis programmability](https://redis.io/docs/latest/develop/programmability/), [PostgreSQL isolation](https://www.postgresql.org/docs/current/transaction-iso.html).
- Define what “one use” means if the store operation succeeds but the response is lost. Exactly-once delivery to an external sink cannot be guaranteed by the mapping store alone. Choose and document at-most-once, idempotent request keys, or another explicit policy per adapter.
- Revocation prevents future release after its defined commit/linearization point; it cannot undo a prior delivered value. Physical deletion, logs, replicas, snapshots, and backup retention need separate contracts.

This is a portable behavioral contract, not a prescribed database implementation. Each `store-*` adapter must demonstrate it; a consumer-supplied store is qualified with the same conformance suite.

## 5. Audit, test evidence, and supply chain

OWASP logging guidance distinguishes recording security events from exposing sensitive data in event fields. ASVS 5.0's data-protection requirements call for documented controls for retention, encryption, integrity, access, and logging. [OWASP logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), [ASVS 5.0 data-protection documentation](https://cornucopia.owasp.org/taxonomy/asvs-5.0/14-data-protection/01-data-protection-documentation).

**Recommendation:** audit only an outcome code, operation identifier, trusted principal/tenant identifiers where allowed, destination category, and time; document retention and access. Do not log plaintext, ciphertext that serves as a recoverable mapping, raw prompt/response, token-to-value map, or sensitive exceptions. Test that library errors, event hooks, CI fixtures, and benchmarks do not contain original or restored spans. Review examples as part of release: insecure copy-paste integrations are a supply-chain risk even when the library code itself is correct. [OWASP npm security](https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html).

## Recommended decisions before implementation

1. **Highest priority — release policy and token provenance ADR.** Define where an issued token may be restored, who decides that, how literal/copied/reordered tokens are handled, and why a displayed type has no authority. Default-deny ambiguous text.
2. **Highest priority — capture/outbound action ADR.** Define `block` rejection and `warn`/`allow` treatment so a caller cannot mistake sanitized output for a guarantee that all original values were removed.
3. **High priority — transaction boundary ADR.** Specify capture commit, multi-token preflight/consume, revoke races, response loss, and whether usage is at-most-once. Avoid claiming atomic external delivery.
4. **High priority — browser Worker qualification.** Execute real-browser tests under CSP and document the same-page attacker limit.
5. **Before persistence release — encrypted record and store qualification.** Decide key ownership/rotation and deletion/backup semantics, then test at least one concrete backend against the shared race and isolation suite.
6. **Before publication — independent security review and package provenance.** Review public API misuse paths and examples; pin compatible core artifacts and publish exact verification evidence.

## Explicit limits of this research

The cited sources support general security principles and platform/backend behavior. The exact restore tuple, token provenance rules, and proposed store interface are **design inferences for this project** and require adversarial tests. No claim is made that encryption, Worker isolation, random tokens, or a particular database alone makes restoration safe.
