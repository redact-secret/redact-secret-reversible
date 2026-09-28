# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities in this repository's packages privately through [GitHub private vulnerability reporting](https://github.com/redact-secret/redact-secret-vault/security/advisories/new). Do not open a public issue for an undisclosed vulnerability. Never include a live credential: reproduce with unmistakably synthetic values such as `ghp_SYNTHETICxREVOKEDxTESTx0000000000000`.

Detection problems (a secret the core misses or misclassifies) belong to the core project's [advisory channel](https://github.com/redact-secret/redact-secret/security/advisories/new).

## Supported versions

| Package | Version | Security fixes |
| --- | --- | --- |
| `@redact-secret/vault` | `0.1.0-alpha.2` (npm dist-tag `alpha`) | Latest alpha only |
| `@redact-secret/vault-server` | `0.1.0-alpha.2` (npm dist-tag `alpha`) | Latest alpha only |
| `@redact-secret/vault` | `0.1.0-alpha.1` (core `0.1.0-beta.9`) | None; upgrade to `0.1.0-alpha.2` |

Alpha releases may change their API between versions. Only the runtimes and core version listed in the [beta.10 qualification record](docs/research/qualification-core-0.1.0-beta.10.md) and the [Worker-mode record](docs/research/qualification-worker-mode.md) are supported: Node.js and browser main-thread use, the optional dedicated-Worker mode, and `@redact-secret/vault-server`'s single-process, in-memory server authority. Persistent-store modes and the unpublished Python package (`redact-secret-vault`) are unsupported, and reports about them are treated as design input.

## Scope

In scope: plaintext disclosure through vault errors, audit events, stats, or returned objects; restoration into a sink, path, session, or budget that was not granted; bypass of the core action gate; partial capture or restore state; token predictability or collision; limit bypass.

Out of scope, as documented limits: same-page script compromise, application logging of values it restored, undetected secrets, and memory remanence of JavaScript strings. See the [threat model](docs/specs/threat-model.md).
