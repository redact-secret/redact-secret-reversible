---
decision_id: decision-separate-reversible-boundary
status: accepted
scope: repository
title: Keep reversible restoration outside the side-effect-free core and host adapters
decided_at: 2026-09-27
---
# Keep reversible restoration outside the core and adapters

## Decision

Develop opt-in plaintext retention and restoration in `redact-secret/redact-secret-reversible`, independently versioned from `redact-secret/redact-secret`. Its only product dependency is the core's documented public contract. Neither the core nor `redact-secret-adapters` depends on this repository.

## Rationale

The core's trust contract returns sanitized text and safe metadata without storing matched values. Restoration must capture plaintext, retain a mapping, and enforce a separate authorization decision. Including it in the core would make an optional high-trust behavior part of every runtime and its lockstep qualification. Host adapters sanitize logs, traces, AI context, and MCP boundaries; giving them restore access would confuse outbound safety with authorized reintroduction of plaintext.

## Consequences

- Core users do not install retention code or acquire a recoverable mapping.
- This repository owns its own threat model, release cadence, compatibility range, and security tests.
- The core remains the single detector and redaction authority. This repository must not create a second detector or silently override `block`.
- Benchmark detection claims do not depend on restore functionality; restore security evidence is assessed separately.
- A language-neutral contract is specified in this repository, while runtime packages are added only after qualification. Browser and Node.js vault support, plus JavaScript and Python server support, are intended early targets; no runtime is supported by this design scaffold. See the [package decision](2026-09-27-name-vault-packages-and-language-contract.md).

## Alternatives considered

Putting mapping storage in the core was rejected because it violates its side-effect-free, no-storage boundary. Putting restoration in the adapters repository was rejected because adapters protect outbound sinks and must not expose restored values. A separate detector implementation was rejected because it would drift from the canonical core.

## Open questions

The JavaScript package names are selected in the package decision. The exact core API surface, store interface, token syntax, language-specific distribution names, and first release remain open.
