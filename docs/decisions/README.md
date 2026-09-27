# Decisions

Decision records document durable product and security boundaries. Their status describes a design decision, not an implemented or released feature.

| Record | Status | Question answered |
| --- | --- | --- |
| [Separate the reversible boundary](2026-09-27-separate-reversible-boundary.md) | Accepted | Which repository owns retention and restoration? |
| [Decouple typed placeholders from restoration](2026-09-27-decouple-typed-placeholders-from-restoration.md) | Accepted | Does a typed label carry restore identity or authority? |
| [Define restore authority and lifecycle](2026-09-27-restore-authority-and-lifecycle.md) | Accepted principles; implementation open | Which checks are invariant, and which choices belong to the application? |

Open design work before implementation includes token grammar, literal collision behavior, exact core API dependency, eligible `redact` findings, default limits, store atomicity, arbitrary-text restore semantics, streaming, and language-specific threat models.
