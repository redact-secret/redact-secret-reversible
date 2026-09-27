# Decisions

Decision records document durable product and security boundaries. Their status describes a design decision, not an implemented or released feature.

| Record | Status | Question answered |
| --- | --- | --- |
| [Separate the reversible boundary](separate-reversible-boundary.md) | Accepted | Which repository owns retention and restoration? |
| [Decouple typed placeholders from restoration](decouple-typed-placeholders-from-restoration.md) | Accepted | Does a typed label carry restore identity or authority? |
| [Define restore authority and lifecycle](restore-authority-and-lifecycle.md) | Accepted principles; implementation open | Which checks are invariant, and which choices belong to the application? |
| [Name vault packages and preserve a language-neutral server contract](name-vault-packages-and-language-contract.md) | Accepted names and boundaries; delivery open | How do browser, server, and persistence packages relate across languages? |
| [Bind issued tokens to approved output](bind-issued-tokens-to-approved-output.md) | Proposed | How are issued identities, model copies, and destination paths handled? |
| [Gate capture on core actions](gate-capture-on-core-actions.md) | Proposed | What do `block`, `redact`, `warn`, and `allow` mean for capture and outbound use? |
| [Define restore transaction boundary](define-restore-transaction-boundary.md) | Proposed | What can be atomic across validation, budgets, revocation, and delivery? |

The package names are selected; implementation and publication are not complete. The three proposed records above state design direction and verification gates; they do not settle token grammar, use-count defaults, or backend consistency. Open design work also includes exact core API compatibility, default limits, arbitrary-text restore semantics, streaming, and language-specific threat models. See [security research](../research/security-foundations-2026-09-27.md) and the [pre-implementation plan](../plans/pre-implementation.md).
