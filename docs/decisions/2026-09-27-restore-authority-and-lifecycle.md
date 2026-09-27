---
decision_id: decision-restore-authority-and-lifecycle
status: accepted
scope: repository
title: Bind restoration to application authority and a bounded mapping lifecycle
decided_at: 2026-09-27
---
# Bind restoration to authority and lifecycle

## Decision

Restoration is explicit opt-in. A token alone is never sufficient. At each restore boundary, validate exact issued identity, session and tenant binding, current application authorization, purpose, destination, and mapping validity. Never register a core `block` finding as restorable. Expired, revoked, forged, foreign, or unauthorized lookups fail without plaintext in an error or diagnostic.

The product enforces these invariant checks and provides extension points for the application's authentication, policy, and storage. It does not impose one identity provider, vault, or permitted destination set. A short-lived in-memory vault is the proposed portable default for browser and server. Server-side multi-principal authorization is a separate layer; the browser cannot claim that same guarantee. Persistence is optional and requires its own qualified store contract.

## Rationale

A model or tool may repeat a real token or invent a matching string. Neither can grant itself access. The application knows whether the authenticated caller and destination are allowed to receive a value. Retention itself creates a new asset that requires bounded lifetime and cleanup. A fixed vendor vault would restrict consumers without solving application-level authorization.

## Consequences

- Server restore authorization is evaluated at use time, including after a prior grant or policy change. The application, not model output, establishes principal, source, destination, and structural path; the complete operation must pass before any value is returned.
- A safe structured-field API may guide ordinary usage; an advanced arbitrary-text operation, if added, must preserve the same checks.
- Storage backends must meet a documented expiry, isolation, revocation, and failure contract. Persistent storage additionally needs separately qualified encryption/key/backup behavior.
- Limits on retained bytes, entries, time, and use count must be specified before release.
- Audit hooks and errors carry bounded safe metadata only. Application destinations own the handling of plaintext they explicitly receive.
- Managed-runtime memory cannot be promised to be completely zeroized.

## Alternatives considered

Treating a visible placeholder as a bearer token was rejected because it is copyable and may appear in untrusted output. Reusing the core's `<SECRET_1>` or `<SSN_1>` as a lookup key was rejected because the label is deterministic and can collide. A universal `restore(text)` with no destination or policy context was rejected as an unsafe default.

## Open questions

Specify the exact authorization callback shape, race semantics for revoke versus restore, one-time versus multi-use defaults, store consistency, TTL defaults, and behavior for partial failure or stream cancellation.
