# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities in this repository's packages privately through [GitHub private vulnerability reporting](https://github.com/redact-secret/redact-secret-vault/security/advisories/new). Do not open a public issue for an undisclosed vulnerability. Never include a live credential: reproduce with unmistakably synthetic values such as `ghp_SYNTHETICxREVOKEDxTESTx0000000000000`.

## Response process

- We acknowledge a report within 14 days, usually much sooner, and keep the reporter informed of progress.
- We aim to release a fix for a confirmed vulnerability of medium or higher severity within 60 days of the report.
- Fixes are published as a GitHub security advisory for this repository (with a CVE when one is assigned), and the release notes in [CHANGELOG.md](CHANGELOG.md) identify every publicly known vulnerability fixed in that release by its advisory or CVE identifier.
- Reporters are credited in the advisory unless they ask not to be.

Detection problems (a secret the core misses or misclassifies) belong to the core project's [advisory channel](https://github.com/redact-secret/redact-secret/security/advisories/new).

## Supported versions

| Package | Version | Security fixes |
| --- | --- | --- |
| `@redact-secret/vault` | `0.1.0-beta.3` (npm dist-tag `beta`) | Latest beta only |
| `@redact-secret/vault-server` | `0.1.0-beta.3` (npm dist-tag `beta`) | Latest beta only |
| `@redact-secret/vault`, `@redact-secret/vault-server` | `0.1.0-beta.2` (core `0.1.0-beta.11`) | None; upgrade to `0.1.0-beta.3` |
| `@redact-secret/vault`, `@redact-secret/vault-server` | `0.1.0-beta.1` (core `0.1.0-beta.10`) | None; upgrade to `0.1.0-beta.3` |
| `@redact-secret/vault`, `@redact-secret/vault-server` | `0.1.0-alpha.3` | None; upgrade to `0.1.0-beta.3` |
| `@redact-secret/vault`, `@redact-secret/vault-server` | `0.1.0-alpha.2` | None; upgrade to `0.1.0-beta.3` |
| `@redact-secret/vault` | `0.1.0-alpha.1` (core `0.1.0-beta.9`) | None; upgrade to `0.1.0-beta.3` |

Alpha and beta releases may change their API between versions. Only the runtimes and core version listed in the [beta.10 qualification record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-core-0.1.0-beta.10.md) and the [Worker-mode record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-worker-mode.md) are supported: Node.js and browser main-thread use, the optional dedicated-Worker mode, and `@redact-secret/vault-server`'s single-process, in-memory server authority. Persistent-store modes and the research-grade Python package (`redact-secret-vault`, on PyPI as `0.1.0b1`) are unsupported, and reports about them are treated as design input.

## Verifying releases

Releases are signed with [Sigstore](https://www.sigstore.dev/) keyless signing: the release workflow ([`release.yml`](.github/workflows/release.yml)) publishes from GitHub Actions through OIDC, and the registries record a signed attestation tying each package to this repository, the workflow, and the commit it was built from. There is no long-lived signing key to obtain; the trust root is Sigstore's public-good instance, which the tools below fetch automatically.

- **npm** (`@redact-secret/vault` and `@redact-secret/vault-server` from `0.1.0-alpha.3`, and `@redact-secret/vault@0.1.0-alpha.2`): after installing, run `npm audit signatures`. It verifies the registry signature and the provenance attestation of every installed package. The package page on npmjs.com also shows the provenance, including the source commit and the workflow run.
- **PyPI** (`redact-secret-vault` from `0.1.0a3`, current `0.1.0b3`): each file carries a [PEP 740](https://peps.python.org/pep-0740/) attestation, shown on the file's page on pypi.org. To verify a downloaded file: `pip install pypi-attestations`, then `pypi-attestations verify pypi --repository https://github.com/redact-secret/redact-secret-vault pypi:<file name>`, for example `pypi:redact_secret_vault-0.1.0a3-py3-none-any.whl`.

`@redact-secret/vault@0.1.0-alpha.1` and `@redact-secret/vault-server@0.1.0-alpha.2` were published manually and carry no provenance ([RELEASING.md](RELEASING.md#provenance)). Neither is supported; upgrade.

## Scope

In scope: plaintext disclosure through vault errors, audit events, stats, or returned objects; restoration into a sink, path, session, or budget that was not granted; bypass of the core action gate; partial capture or restore state; token predictability or collision; limit bypass.

Out of scope, as documented limits: same-page script compromise, application logging of values it restored, undetected secrets, and memory remanence of JavaScript strings. See the [threat model](docs/specs/threat-model.md).
