# Concepts and boundaries

The core detects and redacts without storing matched plaintext. This repository will opt in to temporarily retaining an original-value mapping so an application can restore an approved value for an approved purpose. Installing or using the core alone must never create a recoverable mapping.

## Repository boundaries

| Repository | Owns | Must not own |
| --- | --- | --- |
| [redact-secret](https://github.com/redact-secret/redact-secret) | Detection, overlap resolution, policy, redaction, safe finding metadata, and placeholder formatting | Restoration storage, restore authorization, or a dependency on this repository |
| **redact-secret-vault** | Opt-in mapping lifecycle, opaque identifiers, restoration checks, and storage/authorization extension points | Detection rules, PII classification, or changes to core policy |
| [redact-secret-adapters](https://github.com/redact-secret/redact-secret-adapters) | Host integrations for logs, traces, AI context, and MCP | Restoration or emitting mapped plaintext to observability |
| [redact-secret-benchmarks](https://github.com/redact-secret/redact-secret-benchmarks) | Detection and support evidence | Treating restoration success as detection accuracy |

Dependency direction is one way: this repository may consume the core's documented public API; the core and adapters must not depend on this repository. Each package releases on its own cadence, independent of the core, and pins one exactly tested core version ([RELEASING.md](../RELEASING.md)). See [Architecture](../ARCHITECTURE.md) and [boundary decision](decisions/separate-reversible-boundary.md).

## Typed placeholders are independent

The core offers a typed formatter using safe finding metadata, such as `<JWT_1>`. Core `0.1.0-beta.10` adds real, opt-in PII finding types, all prefixed `pii_` (for example `pii_global_email`, `pii_global_iban`, `pii_jurisdiction_us_ssn`). A typed display label for one of them, whether the core's `typedPlaceholderFormatter` output (`<PII_JURISDICTION_US_SSN_1>`) or an application label such as `<SSN_1>`, is still a core formatting concern. It grants nothing and does **not** imply that the original value was retained or can be restored.

Restoration needs an issued vault token (`<rsv_…>`, 128 random bits, bound to one vault and capture) plus an application grant for the sink and exact path. A PII value is retained only when the application names its exact type in the capture's PII allowlist (`pii: { retain: [...] }`); every other PII finding is replaced by a display placeholder that cannot be restored. Restoration never infers authority from a visible type name or parses a core display placeholder as proof of ownership. See [typed placeholder decision](decisions/decouple-typed-placeholders-from-restoration.md) and the [PII retention decision](decisions/decide-pii-retention-and-activation-ownership.md).

## Security direction

- Retention is explicit opt-in and limited to a session or consumer-selected store.
- A token alone grants no restore authority. The application supplies identity, tenant, purpose, destination, and authorization policy at the restore boundary.
- Core `block` findings cannot become restorable entries. Other actions require an explicit eligibility decision.
- Expired, revoked, unknown, cross-session, or cross-tenant lookups fail without exposing plaintext in errors, logs, traces, or diagnostics.
- A short-lived in-memory vault is the proposed portable default in both browser and server environments. Browser memory belongs to the page's trust boundary; it does not enforce multi-user server authorization.
- External stores are opt-in and hold ciphertext only: no value, token, grant, or key reaches a store. Keys are injected by the application; the library has no default key and reads none from the environment.
- Every persistent capture expires (24 hours at most). A persistent restore releases a value at most once and never replays it; exactly-once delivery is not provided.
- Deleting ciphertext is not erasure, and a database restored from backup holds authentic but stale state. Encryption does not detect a rollback or a party that can write the database. See the [threat model](specs/threat-model.md#persistent-mappings--implemented-on-main-qualified-for-two-postgresql-profiles).
- No library can guarantee that a managed-runtime string has been wiped from every memory copy.
- Model output, tool arguments, and visible placeholder text cannot authorize their own restoration.

The in-memory vault and the in-memory server implement these for their scope. The persistent items are implemented on `main` and qualified only as the [qualification record](research/qualification-persistence-0.1.0-alpha.1.md) states. The [security decision](decisions/restore-authority-and-lifecycle.md) distinguishes invariants from consumer choices.
