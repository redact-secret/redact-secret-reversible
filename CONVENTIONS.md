# Conventions

## Status language

Use **current** only for implemented and verified behavior, **proposed** for a design under review, and **planned** only when a tracked work item commits to delivery. Do not present the README's proposed API, security properties, runtime support, or package names as shipped functionality.

## Repository boundaries

1. Import only documented public core APIs. Keep the dependency one way: reversible may depend on core; core, adapters, and benchmarks may not depend on reversible.
2. Do not copy detector rules, policy tables, overlap logic, or typed formatter logic into this repository.
3. Never treat a visible placeholder or type label as a bearer capability. Authorize every restore against application-supplied identity, session, tenant, purpose, and destination.
4. Do not turn a core `block` outcome into a restorable entry. Document any other eligibility policy explicitly.
5. Keep logging and tracing integrations redaction-only. A restore feature must not be introduced through adapters.

## Security-sensitive changes

Before changing token identity, value capture, storage, authorization, or restore semantics, update the threat model and relevant decision record. Add negative tests for forged, expired, revoked, cross-session, cross-tenant, and policy-changed requests; include failures and cancellation. Use only unmistakably synthetic or revoked values in tests and documentation. Do not log original or restored values, raw mappings, sensitive exceptions, or raw input in CI output.

Treat memory erasure, encryption-at-rest, one-time use, and exact TTL values as claims requiring an implementation and evidence, not slogans. Prefer small public interfaces with explicit behavior under failure. A consumer's existing vault and identity policy must be injectable without silently weakening invariant checks.

## Documentation and decisions

Keep README concise for consumers, ARCHITECTURE.md for trust boundaries, and `docs/decisions/` for durable choices and rejected alternatives. Each decision records status, scope, consequences, and questions left open. Link to the core's canonical documentation instead of copying its API or detector inventory. Documentation and tests should change with behavior.

## Releases

Publish independently of the core. A supported core version range requires integration tests at both ends. Do not claim browser, Python, Rust, CLI, persistent store, streaming, or host integration support until each is implemented and qualified.
