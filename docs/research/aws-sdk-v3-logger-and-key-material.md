# AWS SDK v3 client logger and key material

**Status:** finding for [#145](https://github.com/redact-secret/redact-secret-vault/issues/145), the JavaScript counterpart of the `botocore` `DEBUG` exposure recorded in [section 4.2 of the Python qualification](qualification-python-persistence-0.1.0b3.md#42-g2-interoperation). It supports no claim beyond the versions and calls named here.

## Question

Does a `logger` passed in the configuration of the `KMSClient` handed to `@redact-secret/key-provider-aws-kms` write the plaintext data key, the wrapped key (ciphertext blob), or the key ARN?

## Verdict

- **Plaintext data key: not exposed.** The KMS model marks `Plaintext` sensitive (`PlaintextType`, trait 8 in `@aws-sdk/client-kms` `schemas_0.js`). The SDK's logger middleware (`loggerMiddleware` in `@aws-sdk/core`) passes the command input and output through the command's `FilterSensitiveLog`, which replaces the value with `***SensitiveInformation***`, before calling `logger.info`. On error it logs the filtered input and the error object, with no response body.
- **Key ARN, wrapped key, context digest: exposed** to whatever `logger.info` writes, for `GenerateDataKey` (input `KeyId`, `EncryptionContext`; output `KeyId`, `CiphertextBlob`), `Decrypt`, and `ReEncrypt` (input `KeyId`, `SourceKeyId`, `DestinationKeyId`, `CiphertextBlob`). The wrapped key is ciphertext the store holds anyway, and the ARN is an identifier, so this is a smaller exposure than the Python one, but an application that forwards these records to a sink should know it. The encryption context carries only the digest and a version: no namespace, tenant, or capture identifier appears.
- **`debug` records** from the SDK (credential and region provider lookups, endpoint rule evaluation) carried none of the four values in the run.
- **Without a `logger` in the client config** the SDK writes nothing (`NoOpLogger`).
- **No JavaScript provider change.** The provider logs nothing and the SDK does not log the plaintext, so there is nothing to guard. The exposure of the other fields is documented in the package README.

## Evidence

Versions: `@aws-sdk/client-kms` 3.1144.0 (the exact development pin), Node.js 22. `packages/key-provider-aws-kms/test/sdk-logging.test.mjs` builds the real `KMSClient` with a logger that records every call of every level (`trace`, `debug`, `info`, `warn`, `error`, `log`) and points it at a loopback HTTP server that answers with synthetic bodies; no AWS service, credential, or key is involved. The provider runs `generateDataKey`, `unwrapDataKey`, and `rewrapDataKey` through it. The recorded arguments are rendered as JSON and with `util.inspect`, with byte arrays also rendered as base64, and searched for the data key (base64 and hex), the wrapped key (base64), the ARN, and the caller's identifiers:

| Value | In a logger record |
| --- | --- |
| Data key, base64 or hex | no (replaced by `***SensitiveInformation***`) |
| Wrapped key | yes, at `info` |
| Key ARN | yes, at `info` |
| Namespace, tenant, capture identifier | no |

## Not covered

Custom middleware or a custom `requestHandler` that logs bodies; other SDK versions (the `peerDependencies` range is `^3`); a model change that drops the sensitive trait (the test would fail); `NODE_DEBUG` or proxies outside the SDK. The run used a loopback server, not the real service.
