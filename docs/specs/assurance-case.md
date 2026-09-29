# Assurance case

**Status:** current for `@redact-secret/vault` and `@redact-secret/vault-server` `0.1.0-alpha.3`. Persistent stores are out of scope (proposed only).

This document argues why the packages' security requirements are met. It does not restate the evidence; it links to it.

## Claim

A value retained by the vault reappears as plaintext only in a sink and field path the application granted, within the entry's lifetime and use budget, and — with `@redact-secret/vault-server` — only for an authenticated principal of the same tenant with a stated purpose that the application's policy allows. No vault output (error, audit event, stats) discloses a retained value.

## Threat model and trust boundaries

Assets, attacker capabilities, and the trust boundary of every mode (browser main thread, Node.js process, dedicated Worker, single-process server authority) are in the [threat model](threat-model.md). The boundary is the page or process: the vault does not claim to protect against code already inside it. Browser-specific limits are in [in-memory security](in-memory-security.md), and component boundaries in [ARCHITECTURE.md](../../ARCHITECTURE.md).

## Secure design principles

| Principle | How it is applied |
| --- | --- |
| Fail-safe defaults | Nothing is retained until `capture` is called. Unredacted findings are rejected by default (`unredacted: "reject"`). PII is retained only when its exact type is allowlisted. A policy that throws, times out, or returns a malformed decision denies (`policy-evaluation-error`), never allows. Initialization failures fail closed (`CORE_FAILURE`). |
| Complete mediation | Every token occurrence in every restore is checked against the grant (sink, exact path), expiry, revocation, use budget, and, on the server, principal, tenant, purpose, and policy, at the time of the restore. Nothing is cached from an earlier decision. |
| Separation of privilege | Restoration needs both an issued token and an application grant. A token alone, or a visible type label, grants nothing ([decision](../decisions/2026-09-27-decouple-typed-placeholders-from-restoration.md)). |
| Least privilege | Grants name one sink and exact field paths. Entries have a TTL and a per-entry use budget; limits bound entries, bytes, findings, and fields (`DEFAULT_LIMITS` in `packages/vault/src/vault.ts`). |
| Least common mechanism | One vault per session or task; tokens from one vault are unknown to another. Worker mode keeps the mapping in the Worker's private scope. |
| Economy of mechanism | A small public API (`capture`, `restore`, `revoke`, `stats`, `dispose`); detection and policy are delegated to the core rather than reimplemented ([boundary decision](../decisions/2026-09-27-separate-reversible-boundary.md)). |
| Open design | All code, decisions, and the threat model are public. Security relies on 128-bit tokens from the platform CSPRNG and on authorization checks, not on secrecy of the design. |
| Psychological acceptability | Failures are typed errors with fixed codes, so the safe handling (keep the redacted text) is easy to write; the README shows it. |

## Common weaknesses countered

| Weakness | Countermeasure | Evidence |
| --- | --- | --- |
| Information exposure through errors or logs (CWE-209, CWE-532) | Errors, audit events, and stats carry fixed codes and counts only; the vault performs no logging, storage, network, or console use. | Negative tests in `packages/vault/test/suite.js`; packed-artifact checks in `qualification/` |
| Insufficient randomness (CWE-330, CWE-338) | Tokens carry 128 bits from `crypto.getRandomValues` (TypeScript) or `secrets` (Python); capture fails if no CSPRNG exists. | `packages/vault/src/token.ts`, `packages/vault-py/src/redact_secret_vault/token.py` |
| Authorization bypass through a user-controlled key (CWE-639) | A token is a lookup key, never authority; forged, altered, cross-vault, cross-tenant, expired, revoked, and over-budget tokens are denied. | [Conformance corpus](../../conformance/README.md); `packages/vault-server/test/` |
| Prototype pollution and unexpected input (CWE-1321, CWE-20) | Worker messages are validated against exact key allowlists, rejecting `__proto__`, `constructor`, and `prototype`; public functions reject invalid arguments with `INVALID_ARGUMENT`. | `packages/vault/src/worker-protocol.ts`; Worker hostile-page tests |
| Resource exhaustion (CWE-400) | Hard limits on input size, findings, entries, retained bytes, fields, and uses. | `DEFAULT_LIMITS`; limit tests |
| Race conditions (CWE-362) | `vault-server` serializes restore and revoke per instance; a queued revoke denies a later restore. All-or-nothing restore leaves no partial state. | `packages/vault-server/test/` |
| Injection through replacement patterns | Restoration does not interpret `$` patterns in model output. | `packages/vault/test/suite.js` |

## Supporting processes

- Static analysis (OpenGrep with project rules) and Biome lint gate every pull request; see [CONTRIBUTING.md](../../CONTRIBUTING.md).
- Releases are built in CI and published with npm provenance and PyPI attestations; see [SECURITY.md](../../SECURITY.md#verifying-releases).
- Residual risks accepted for each mode are listed in the [threat model](threat-model.md#residual-risks-accepted-for-alpha1).
