---
decision_id: decision-name-vault-packages-and-language-contract
status: accepted
scope: repository
title: Name the portable vault, server authority, and optional stores separately
decided_at: 2026-09-27
---
# Name vault packages and preserve a language-neutral server contract

## Decision

Use `@redact-secret/vault` for the JavaScript portable, opt-in, in-memory vault and `@redact-secret/vault-server` for the JavaScript server authorization layer. Use `@redact-secret/store-*` only for separately qualified optional persistence backends. These are selected names and ownership boundaries, not claims that packages are implemented or published.

A server may use the in-memory vault. Storage mode and execution trust boundary are independent axes: `vault-server` is not an alternative to in-memory storage, and persistence is not a third runtime. A consumer may supply a compatible existing vault or store without adopting a specific vendor implementation.

The server security contract is language-neutral. This repository will hold the normative behavioral contract and shared adversarial cases; JavaScript, Python, Rust, and Go distributions will be individually implemented and qualified as core integration becomes available. Npm package names do not imply a JavaScript-only server product. No detector is reimplemented in this repository, and the core never depends on these packages.

## Rationale

`vault-client` suggests a browser-only product even though an in-memory vault also belongs on a server. `vault-in-memory` paired with `vault-server` misleadingly presents a storage choice and a security boundary as mutually exclusive. A concise `vault` name makes the portable default easy to discover, while `vault-server` advertises additional authority checks.

A single npm-only server implementation would exclude common Python and Go LLM services. A language-neutral contract lets each language integrate with the canonical core without tying all distributions to one release or silently inventing a second detector.

## Package responsibilities

- **Portable vault:** issue unpredictable, session-scoped tokens; capture eligible original spans via the core public API; bound, revoke, and clear mappings; offer explicit final-application restoration under its documented local trust assumptions. Qualify browser, Node.js, and edge runtimes separately. In a browser, same-page scripts can access the vault; this package cannot provide server-grade tenant authorization against compromised page code.
- **Server authority:** bind source provenance and current application-supplied principal, tenant, purpose, destination, and value path; preflight all token occurrences; enforce limits and atomic all-or-nothing restoration. It may use memory or a qualified external store. Model-produced metadata never selects its own authority.
- **Optional stores:** satisfy the mapping lifecycle, isolation, expiry, revocation, and concurrent-use contract. Persistence needs independently reviewed encryption, key ownership, backup, and audit behavior. The interface alone must not be mistaken for a secure implementation.

## Distribution and dependency direction

```text
redact-secret core public API
            ↑
portable vault contract and implementation
            ↑
server authority contract and implementation
            ↔ optional store implementation
```

This describes conceptual dependencies. It does not require Python, Rust, or Go to import JavaScript packages. Every supported language must use its own core integration or a separately specified service boundary, declare supported core versions, and pass the shared security cases plus language-specific runtime tests. The core, adapters, and detection benchmarks have no dependency on this repository.

## Alternatives considered

- `@redact-secret/vault-client`: rejected as the portable vault's name because the vault is not browser-only.
- `@redact-secret/vault-in-memory` paired with `vault-server`: rejected because a server can use in-memory storage; the names describe different dimensions.
- One package bundling server authorization and every backend: rejected because browser bundles would absorb unrelated SDKs and consumers would inherit unused security surfaces.
- One implementation language serving every runtime by assumption: rejected; cross-language behavior needs explicit integration and qualification.

## Consequences and open questions

Browser and server security claims must be documented separately. The intended early work is the portable JavaScript vault and server authorization in JavaScript and Python; sequencing depends on core API and conformance readiness. Rust and Go require their own integration decisions. No store backend, exact language distribution names beyond npm, token syntax, default TTL, or release schedule is fixed here. Before publishing, settle the token collision rules, exact public core dependency, store atomicity, usage budgets, and adversarial conformance corpus.
