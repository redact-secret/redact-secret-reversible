# @redact-secret/vault-contracts

[![npm (alpha)](https://img.shields.io/npm/v/@redact-secret/vault-contracts/alpha?label=npm%20%28alpha%29)](https://www.npmjs.com/package/@redact-secret/vault-contracts)
[![License: MIT](https://img.shields.io/npm/l/@redact-secret/vault-contracts)](https://www.npmjs.com/package/@redact-secret/vault-contracts)
[![Node.js](https://img.shields.io/node/v/@redact-secret/vault-contracts/alpha?label=node%20%28alpha%29)](https://www.npmjs.com/package/@redact-secret/vault-contracts)
[![CI](https://github.com/redact-secret/redact-secret-vault/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/redact-secret/redact-secret-vault/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/redact-secret/redact-secret-vault/badge)](https://scorecard.dev/viewer/?uri=github.com/redact-secret/redact-secret-vault)

**Status: alpha.** Types, limits, validators, and error classes shared by a persistent Redact Secret vault server, its crypto layer, store adapters, and key providers.

This package has no runtime dependency and performs no I/O. It contains no detector logic, no cipher, no database driver, and no key-service client. The semantics of everything it names are defined by the [persistent vault specification](../../docs/specs/persistent-vault.md); the types here are transcribed from that document.

It is for authors of a `Store`, a `KeyProvider`, or a `RecordCrypto`. Applications that only use a vault do not need to import it; they start at the [persistent server guide](../../docs/guides/persistent-server.md).

## What it exports

- The contract types of specification §4 and §5: `Store`, `StoreCapabilities`, `KeyProvider`, `RecordCrypto`, and their inputs and results.
- `StoreError`, `KeyProviderError`, `RecordCryptoError`: fixed message per code, no `cause`, no input, key, ciphertext, or driver text.
- `LIMITS`: the hard limits of record format version 1.
- `validate*` functions for every store operation (specification §4.2) and `missingCapabilities`. A store adapter calls them before any write. They protect the store's invariants against a faulty caller; they are not authorization.

Implementing these interfaces does not make an adapter correct or supported. Types cannot show that a transaction is atomic or that a commit is durable. An adapter is supported only for the deployment profile its own qualification record names.
