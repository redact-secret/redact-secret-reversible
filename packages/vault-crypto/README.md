# @redact-secret/vault-crypto

[![npm (alpha)](https://img.shields.io/npm/v/@redact-secret/vault-crypto/alpha?label=npm%20%28alpha%29)](https://www.npmjs.com/package/@redact-secret/vault-crypto)
[![License: MIT](https://img.shields.io/npm/l/@redact-secret/vault-crypto)](https://www.npmjs.com/package/@redact-secret/vault-crypto)
[![Node.js](https://img.shields.io/node/v/@redact-secret/vault-crypto/alpha?label=node%20%28alpha%29)](https://www.npmjs.com/package/@redact-secret/vault-crypto)
[![CI](https://github.com/redact-secret/redact-secret-vault/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/redact-secret/redact-secret-vault/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/redact-secret/redact-secret-vault/badge)](https://scorecard.dev/viewer/?uri=github.com/redact-secret/redact-secret-vault)

**Status: alpha.** The record format of the [persistent vault specification](../../docs/specs/persistent-vault.md) §3, implemented over the platform's WebCrypto: canonical encoding, AES-256-GCM envelope encryption, the request digest and session tag of §7.3 and §3.2, and the local key provider of §6.3.

The persistent server profile of `@redact-secret/vault-server` uses it through the `RecordCrypto` contract. What was tested, and with which stores and providers, is in the [qualification record](../../docs/research/qualification-persistence-0.1.0-alpha.1.md); nothing beyond that record is a support claim. It depends on [`@redact-secret/vault-contracts`](../vault-contracts/README.md) and on nothing else.

## Use

```js
import { createRecordCrypto } from "@redact-secret/vault-crypto";
import { createLocalKeyProvider } from "@redact-secret/vault-crypto/local-key-provider";

const keyProvider = createLocalKeyProvider({
  keys: [
    { id: "2026-10", material, state: "active" },
    { id: "2026-07", material: previous, state: "decrypt-only" },
  ],
  scope: { namespaces: ["support-prod"] },
});
const crypto = createRecordCrypto({ keyProvider });
```

Pass `crypto` to `createPersistentServerVault` ([guide](../../docs/guides/persistent-server.md)). `material` is 32 bytes from your own secret manager: never a literal, and never from this library. To use AWS KMS instead, see [`@redact-secret/key-provider-aws-kms`](../key-provider-aws-kms/README.md).

## What it does

- `createRecordCrypto({ keyProvider, keyTimeoutMs? })` returns a `RecordCrypto` with profile `aes-256-gcm-hkdf-v1`.
  - `sealCapture` asks the provider for one data key per capture, derives one AES-256-GCM key per entry with HKDF-SHA-256, and encrypts each payload under a random 96-bit nonce with the associated data of §3.4. It validates every input, and refuses a duplicate entry, before the provider is called.
  - `openCapture` decodes every envelope, including its version and algorithm, before any key is unwrapped. It returns every payload or throws; there is no partial result. `value` is returned as bytes.
  - `rewrapCaptureKey` passes the stored key to the provider's `rewrapDataKey`.
- Each provider call is bounded by `keyTimeoutMs` (default 5000) and follows the caller's `AbortSignal`. The result is checked for shape and size. Whatever the provider throws, the caller sees a new `KeyProviderError` holding only a code: an error that is not a `KeyProviderError` becomes `KEY_UNAVAILABLE`, and the provider's message, stack, and `cause` are dropped.
- Pure functions, for other implementations and for the test vectors: `deriveEntryId`, `deriveEntryKey`, `encodeAad`, `encodePayload`, `decodePayload`, `encodeEnvelope`, `decodeEnvelope`, and `createDigester` (`requestDigest`, `sessionTag`).
- `@redact-secret/vault-crypto/local-key-provider` exports `createLocalKeyProvider`.

Errors are the contract's `RecordCryptoError` and `KeyProviderError`: a fixed message per code, no `cause`, and no input, key, or ciphertext text.

## What it does not do

- It stores nothing. Envelopes and wrapped keys go to a `Store` the application supplies.
- It authorizes nothing. Principal, tenant, session, sink, path, purpose, expiry, and use budgets are the server's checks. Authentication of a record shows that a key holder wrote it for that binding; it does not show the record is current (specification §9.3).
- It does not hide lengths. A ciphertext is as long as its payload plus 16 bytes.
- It has no cipher of its own. If the runtime has no WebCrypto, construction fails.
- It does not re-encrypt payloads under a new data key. Version 1 of the format has no such operation.

## Local key provider

`material` is 32 bytes, or a non-extractable HKDF `CryptoKey` with the `deriveKey` usage. Bytes are copied and imported as a non-extractable key, so the application can overwrite its own array once the provider exists. `id` is 1 to 64 characters of `[A-Za-z0-9._-]`, and the key reference is `local:<id>`. Exactly one key is `active`. `scope.namespaces` is required; `scope.tenants` is optional and, when given, limits the provider to those tenants.

The application loads the material from its own secret manager and decides when to rotate. The provider does not load, store, or rotate it. It reads no environment variable, has no default key, derives nothing from a passphrase, and keeps no cache of unwrapped keys.

Rotation is the procedure of specification §6.2: construct the provider with the new key `active` and the old one `decrypt-only`, keep the old one for at least 24 hours plus the clock-skew bound, then mark it `retired` or leave it out.

Its limits, as the specification states them:

- The material is in process memory.
- Anyone who obtains the material and a copy of the store can decrypt every capture wrapped under it.
- Every wrapping key derives from one material, so retiring that material makes every capture under it unreadable.
- It offers no per-tenant and no per-capture erasure. Deleting a row from the live store is not erasure either (specification §9).

Whether that is acceptable in production depends on how the deployment's secret manager delivers and protects the material. The [qualification record](../../docs/research/qualification-persistence-0.1.0-alpha.1.md) covers this provider only with synthetic key material generated by the test process, so no deployment's key management is supported yet.

A wrapped key is 61 bytes: `0x01`, a 12-byte random nonce, then the AES-256-GCM ciphertext and tag of the 32-byte data key. The wrapping key is HKDF-SHA-256 of the material with the namespace, tenant, and capture identifier as `info`. The context is bound through that derivation only; no additional data is passed to AES-GCM.

## Memory

The package overwrites the buffers it owns once it is done with them: the data key a provider hands over, each plaintext payload it builds or decrypts, its own copy of injected key material, and a data key that arrives after a call was already abandoned. Entry keys and wrapping keys are derived inside WebCrypto as non-extractable keys and never exist as bytes in this package.

That is best effort. The runtime may have copied any of those buffers, and nothing here can reach such a copy. WebCrypto's internal copy of a key lives until the key object is collected. The `value` bytes that `openCapture` returns belong to the caller, who overwrites them. Once a value is decoded into a JavaScript string it cannot be overwritten.

## Runtime

Tested locally on Node.js 22.16.0 (darwin arm64) with its built-in WebCrypto, and by the repository's `persistence` CI job on Node.js 20, 22, and 24 on Linux and macOS.

Browsers also have WebCrypto. That does not make browser persistence supported: the specification puts browser storage out of scope, and this package has not been run in one.

## Test vectors

`npm test` checks the implementation against [`conformance/persistent/v1/vectors.json`](../../conformance/persistent/v1/README.md) and regenerates the file in memory to confirm the committed copy is current. The data key, nonces, digest key, and wrapping material in that file are fixed public constants for tests only.
