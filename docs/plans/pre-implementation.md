# Pre-implementation design and research plan

**Status:** proposed work sequence. The repository is design-only; the checkboxes are gates, not completed implementation.
**Goal:** establish a testable security contract and explicit alternatives for every material browser, server, and persistence limitation before public APIs are fixed.

The [security research foundations](../research/security-foundations-2026-09-27.md) provide source-backed inputs for the gates below, including the boundary of storage atomicity and external plaintext delivery.

## Deliverables and gates

| Phase | Work and reviewable output | Exit gate |
| --- | --- | --- |
| 1. Assets and threat models | Browser main-thread, Worker, server memory, persistent store: assets, trust boundaries, attackers, data flows, abuse cases, and residual risks. Update [browser security spec](../specs/in-memory-security.md). | Each mode states who can read input/mapping/output and what it cannot promise; alternatives are documented. |
| 2. Core integration proof | Run the [core integration research](../research/core-integration.md) as a browser WASM spike against a pinned core commit/release. Capture exact actions, Unicode ranges, callback behavior, and failures using synthetic values only. | No private imports, detector duplication, `block` retention, or plaintext outbound from `warn`/`allow` by accident. |
| 3. Token and provenance contract | Decide opaque identity, visible grammar, literal collision/escaping, repeated-value reuse, binding to source/session, model-copy/reorder behavior, and exact restoration target. Record an ADR. | A valid-looking string alone cannot cause an unintended substitution; ambiguous output fails closed. |
| 4. Authorization and lifecycle contract | Decide browser sink/path policy hook versus server-enforced principal/tenant/purpose checks; budgets, TTL, revocation, races, and all-or-nothing transaction semantics. Record ADRs. | Negative examples include policy change, replay, foreign session, wrong path, concurrent revoke, and partial store failure. |
| 5. Storage alternatives | Specify in-memory default, consumer-supplied backend interface, and separately qualified persistent encryption/key/backup/isolation behavior; make server memory an ordinary option. | Each mode declares its residual risk and no implicit persistence or downgrade. |
| 6. Adversarial conformance corpus | Language-neutral cases and expected outcomes for capture, restore, expiry, output safety, provenance, Unicode, limits, races, and error leakage. Browser and server runners each verify their guarantees. | Passing evidence for a particular runtime is required before that runtime is called supported. |
| 7. API design and release review | Compare a minimal browser API with native Python/JS server APIs; document ergonomics without hiding policy decisions. Review package dependency graph, security claims, and reporting path. | Exact supported core range, runtime matrix, performance bounds, and documented failure modes exist before implementation/release claims. |

## Priority investigations

1. **Action semantics and outbound leakage:** Core `block` is replaced in output but must abort reversible capture; `warn` and `allow` remain plaintext. Decide an explicit send policy and demonstrate it with the real core.
2. **Issued-token provenance:** Plain text matching of a random token is insufficient to establish that a model-output occurrence is the original placeholder in an approved field. Test copying, reordering, duplication, adversarial surrounding text, and legitimate literal occurrences.
3. **Restore transaction:** Define exactly when usage is consumed and what happens if validation, mapping retrieval, output construction, or final delivery fails. A library can make its own operation atomic, but cannot guarantee what an application does after receiving plaintext.
4. **Browser Worker capability:** Assess CSP, deployment, WASM import, message protocol, and malicious main-thread behavior. Decide whether Worker is a separately opted-in profile and define strict failure if unavailable.
5. **Server/native parity:** Establish a language-neutral security vocabulary; inventory Python core public ranges/actions, then qualify JS/Python independently. Rust/Go follow actual core integration and demand.
6. **Persistent alternatives:** Research store consistency, encryption key ownership, backup and deletion semantics before naming any persistent implementation as secure. A customer-owned KMS/store is an integration choice, not a universal default.

## Decision discipline

- Record **finding**, **inference**, and **proposal** separately. Cite exact core revision or external primary source for facts; measure before setting numeric TTL/token/size defaults.
- Every ADR must name rejected alternatives, residual risk, and a consumer escape hatch that does not weaken mandatory invariant checks.
- A security promise is scoped to a specific runtime and threat model. Where no mode can meet the stated requirement, the API must allow the application to keep redacted text or abort.
- The core and adapters remain independent. No published benchmarks or logs may contain original or restored values.

## Immediate next experiments

- Pinned-core, browser-executed `scan`/preflight/`redact` proof with `redact`, `block`, `warn`, and `allow` synthetic findings.
- Token grammar prototypes evaluated against literal collisions, short matched values, duplicated/reordered model tokens, and cross-session replay.
- Worker-only startup under strict CSP with explicit unsupported outcome; main-thread mode exercised separately.
- Draft an attack-case table before selecting API names or storage backends.

See [Architecture](../../ARCHITECTURE.md) and [Decisions](../decisions/README.md) for currently accepted boundaries. No phase grants approval to make an unsupported security claim.
