# Redact Secret Vault

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15003/badge)](https://www.bestpractices.dev/projects/15003)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/redact-secret/redact-secret-vault/badge)](https://scorecard.dev/viewer/?uri=github.com/redact-secret/redact-secret-vault)
[![CI](https://github.com/redact-secret/redact-secret-vault/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/redact-secret/redact-secret-vault/actions/workflows/ci.yml)
[![SAST](https://github.com/redact-secret/redact-secret-vault/actions/workflows/sast.yml/badge.svg?branch=main)](https://github.com/redact-secret/redact-secret-vault/actions/workflows/sast.yml)
[![npm: @redact-secret/vault](https://img.shields.io/npm/v/@redact-secret/vault?label=%40redact-secret%2Fvault)](https://www.npmjs.com/package/@redact-secret/vault)
[![npm: @redact-secret/vault-server](https://img.shields.io/npm/v/@redact-secret/vault-server?label=%40redact-secret%2Fvault-server)](https://www.npmjs.com/package/@redact-secret/vault-server)
[![PyPI: redact-secret-vault](https://img.shields.io/pypi/v/redact-secret-vault?label=redact-secret-vault)](https://pypi.org/project/redact-secret-vault/)
[![License: MIT](https://img.shields.io/github/license/redact-secret/redact-secret-vault)](./LICENSE)

Hide secrets from a model, then put them back where you allow it.

[Redact Secret](https://github.com/redact-secret/redact-secret) finds secrets in text and redacts them for good. This repository adds the opt-in way back: `capture` swaps each secret for a random token before the text leaves your code, and `restore` swaps the tokens back, but only into the fields you named in advance.

**Status: beta.** In-memory use is published for JavaScript and Python. Persistence is alpha and published on npm. Python persistence is in the source tree only and is not supported ([qualification record](docs/research/qualification-python-persistence-0.1.0b3.md)). The runtimes and versions each language was run on, and how the two servers differ: [JavaScript and Python matrix](docs/research/js-python-conformance-and-runtime-matrix.md). Details: [release status](docs/status.md).

## Quick start

```bash
npm install @redact-secret/vault@0.1.0-beta.4
```

npm also installs the one `@redact-secret/core` version this release works with.

```ts
import { createVault } from "@redact-secret/vault";

const vault = await createVault({ pii: [] }); // pii: [] = PII detection off

// 1. Capture: say where the values may come back.
const captured = vault.capture("Rotate ghp_SYNTHETICxREVOKEDxTESTx0000000000000 today", {
  release: [{ sink: "reply", paths: ["body"] }],
});
// captured.text === "Rotate <rsv_…> today"

// 2. Send captured.text to the model. It sees only tokens.
const modelReply = `Done: ${captured.text}`;

// 3. Restore: tokens become values again, in the granted sink and path only.
const { fields } = vault.restore({
  sink: "reply",
  captures: [captured.captureId],
  fields: { body: modelReply },
});
// fields.body === "Done: Rotate ghp_SYNTHETICxREVOKEDxTESTx0000000000000 today"

vault.dispose(); // 4. Drop everything when the task ends.
```

Pin the exact version while the packages are beta. More programs you can run as they are: [examples](examples/README.md).

## Which package do I need?

| You are building | Use | Start here |
| --- | --- | --- |
| A browser app, a CLI, or a server handling one user per vault | `@redact-secret/vault` | [README](packages/vault/README.md) |
| A server with many users or tenants | `@redact-secret/vault-server` | [README](packages/vault-server/README.md) |
| A Python server | `redact-secret-vault` (PyPI) | [README](packages/vault-py/README.md) |
| A server whose captures must survive a restart or be restored by another process | `@redact-secret/vault-server/persistent` (alpha) | [Persistent server guide](docs/guides/persistent-server.md) |

The persistent profile is built from smaller packages you only meet in that guide: [`store-postgres`](packages/store-postgres/README.md), [`store-sqlite`](packages/store-sqlite/README.md) (partly qualified, see the [record](docs/research/qualification-store-sqlite-0.1.0-alpha.1.md)), [`store-memory`](packages/store-memory/README.md), [`vault-crypto`](packages/vault-crypto/README.md), [`key-provider-aws-kms`](packages/key-provider-aws-kms/README.md), [`vault-contracts`](packages/vault-contracts/README.md), and [`vault-conformance`](packages/vault-conformance/README.md).

## Five things to know

1. **Nothing is kept unless you call `capture`.** Installing or importing a package retains nothing.
2. **A token is not a permission.** A value comes back only into the `sink` and `paths` the capture granted. On a server, your policy also checks the user, tenant, and purpose on every restore.
3. **A restore is all or nothing.** One bad token denies the whole request and returns no values. Keep the redacted text and do not retry with a wider grant.
4. **Values are short-lived.** Every entry expires, and each token restores once by default.
5. **Redacted does not mean safe.** The core does not detect every secret, and code running in your page or process can read what the vault holds. See the [threat model](docs/specs/threat-model.md).

## Documentation

- Something failed? [Troubleshooting](docs/guides/troubleshooting.md) lists every error code with its fix.
- [Examples](examples/README.md) you can run as they are.
- Guides: [Worker mode](docs/guides/worker-mode.md), [PII findings](docs/guides/pii.md), [persistent server](docs/guides/persistent-server.md).
- Reference: [`vault`](docs/reference/vault.md), [`vault-server`](docs/reference/vault-server.md), [Python](docs/reference/vault-py.md).
- [Release status](docs/status.md) and [changelog](CHANGELOG.md): what is published, and for which runtimes.
- [Concepts and boundaries](docs/concepts.md), [architecture](ARCHITECTURE.md), and [decisions](docs/decisions/README.md): how this repository relates to the core, and why.
- [All documentation](docs/README.md).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CONVENTIONS.md](CONVENTIONS.md). Report security concerns privately through this repository's [security advisories](https://github.com/redact-secret/redact-secret-vault/security/advisories/new) (see [SECURITY.md](SECURITY.md)). Never submit live credentials in a public issue or fixture.

This repository was formerly `redact-secret/redact-secret-reversible`. License: [MIT](LICENSE).
