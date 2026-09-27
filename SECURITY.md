# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities in this repository's packages privately through [GitHub private vulnerability reporting](https://github.com/redact-secret/redact-secret-reversible/security/advisories/new). Do not open a public issue for an undisclosed vulnerability. Never include a live credential: reproduce with unmistakably synthetic values such as `ghp_SYNTHETICxREVOKEDxTESTx0000000000000`.

Detection problems (a secret the core misses or misclassifies) belong to the core project's [advisory channel](https://github.com/redact-secret/redact-secret/security/advisories/new).

## Supported versions

| Package | Version | Security fixes |
| --- | --- | --- |
| `@redact-secret/vault` | `0.1.0-alpha.x` (npm dist-tag `alpha`) | Latest alpha only |

Alpha releases may change their API between versions. Only the runtimes and core version listed in the [qualification record](docs/research/qualification-0.1.0-alpha.1.md) are supported. Worker, server-authority, persistent-store, and non-JavaScript modes are unsupported, and reports about them are treated as design input.

## Scope

In scope: plaintext disclosure through vault errors, audit events, stats, or returned objects; restoration into a sink, path, session, or budget that was not granted; bypass of the core action gate; partial capture or restore state; token predictability or collision; limit bypass.

Out of scope, as documented limits: same-page script compromise, application logging of values it restored, undetected secrets, and memory remanence of JavaScript strings. See the [threat model](docs/specs/threat-model.md).
