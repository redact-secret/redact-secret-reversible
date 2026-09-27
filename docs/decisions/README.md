# Decisions

Decision records document durable product and security boundaries. Their status describes a design decision, not an implemented or released feature.

| Record | Status | Question answered |
| --- | --- | --- |
| [Separate the reversible boundary](2026-09-27-separate-reversible-boundary.md) | Accepted | Which repository owns retention and restoration? |
| [Decouple typed placeholders from restoration](2026-09-27-decouple-typed-placeholders-from-restoration.md) | Accepted | Does a typed label carry restore identity or authority? |
| [Define restore authority and lifecycle](2026-09-27-restore-authority-and-lifecycle.md) | Accepted principles; implementation open | Which checks are invariant, and which choices belong to the application? |
| [Name vault packages and preserve a language-neutral server contract](2026-09-27-name-vault-packages-and-language-contract.md) | Accepted names and boundaries; delivery open | How do browser, server, and persistence packages relate across languages? |
| [Bind issued tokens to approved output](2026-09-27-bind-issued-tokens-to-approved-output.md) | Accepted for the in-memory vault; server binding open | How are issued identities, model copies, and destination paths handled? |
| [Gate capture on core actions](2026-09-27-gate-capture-on-core-actions.md) | Accepted for whole-input capture; streaming open | What do `block`, `redact`, `warn`, and `allow` mean for capture and outbound use? |
| [Define restore transaction boundary](2026-09-27-define-restore-transaction-boundary.md) | Accepted for the single-process in-memory vault; stores open | What can be atomic across validation, budgets, revocation, and delivery? |

`@redact-secret/vault` 0.1.0-alpha.1 implements the three records accepted on 2026-09-27 for its in-memory, whole-input scope. Their *Resolved choices* sections fix the token grammar, default use count, limits, and linearization point, and cite the qualification evidence. Still open: server authorization ([#15](https://github.com/redact-secret/redact-secret-reversible/issues/15)), Worker mode ([#14](https://github.com/redact-secret/redact-secret-reversible/issues/14)), persistent-store consistency ([#19](https://github.com/redact-secret/redact-secret-reversible/issues/19)), arbitrary-text restore semantics, streaming, and non-JavaScript threat models. The [threat model](../specs/threat-model.md) states each mode's boundary. See [security research](../research/security-foundations-2026-09-27.md) and the [pre-implementation plan](../plans/pre-implementation.md).
