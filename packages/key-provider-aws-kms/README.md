# @redact-secret/key-provider-aws-kms

[![npm (alpha)](https://img.shields.io/npm/v/@redact-secret/key-provider-aws-kms/alpha?label=npm%20%28alpha%29)](https://www.npmjs.com/package/@redact-secret/key-provider-aws-kms)
[![License: MIT](https://img.shields.io/npm/l/@redact-secret/key-provider-aws-kms)](https://www.npmjs.com/package/@redact-secret/key-provider-aws-kms)
[![Node.js](https://img.shields.io/node/v/@redact-secret/key-provider-aws-kms/alpha?label=node%20%28alpha%29)](https://www.npmjs.com/package/@redact-secret/key-provider-aws-kms)
[![CI](https://github.com/redact-secret/redact-secret-vault/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/redact-secret/redact-secret-vault/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/redact-secret/redact-secret-vault/badge)](https://scorecard.dev/viewer/?uri=github.com/redact-secret/redact-secret-vault)

An optional AWS KMS key provider for the [persistent vault server](../../docs/guides/persistent-server.md). It generates, unwraps, and re-wraps the data keys that encrypt captures. It never sees a captured value.

**Alpha.** Tested against a fake on every run, and once against real KMS (`us-east-1`, Node.js 22, single-Region symmetric keys). Nothing else is qualified: see [what was qualified](../../docs/reference/key-provider-aws-kms.md#what-was-qualified).

## Use

```js
import { KMSClient } from "@aws-sdk/client-kms";
import { createAwsKmsKeyProvider } from "@redact-secret/key-provider-aws-kms";
import { createRecordCrypto } from "@redact-secret/vault-crypto";

const keyProvider = createAwsKmsKeyProvider({
  client: new KMSClient({ region: "us-east-1" }), // yours: region, credentials, retries, timeouts
  keys: [
    { keyArn: "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-4000-8000-000000000000", state: "active" },
    { keyArn: "arn:aws:kms:us-east-1:111122223333:key/11111111-1111-4111-8111-111111111111", state: "decrypt-only" },
  ],
  expected: { region: "us-east-1", accountId: "111122223333" },
  scope: { namespaces: ["support-prod"] }, // and optionally tenants: [...]
});
const crypto = createRecordCrypto({ keyProvider });
```

The account id and key ids above are AWS documentation placeholders, not real resources.

| Option | Meaning |
| --- | --- |
| `client` | Anything with `send(command, { abortSignal })`. A `KMSClient` satisfies it. Required. |
| `keys` | `{ keyArn, state }` with `state` one of `active`, `decrypt-only`, `retired`. Exactly one is `active`. Required. |
| `expected` | `{ region, accountId, partition? }`. Every key ARN must be in it. `partition` defaults to `aws`. Required. |
| `scope` | `{ namespaces, tenants? }`. A context outside it is `KEY_UNAVAILABLE` and reaches no KMS call. Required. |
| `callTimeoutMs` | Upper bound of one KMS call. Default 5000. |
| `cache` | `{ maxEntries, maxAgeMs, perTenantMaxEntries }`. Absent means no cache. See [Cache](../../docs/reference/key-provider-aws-kms.md#cache). |
| `contextLabels` | Static pairs added to the encryption context. See [Context binding](../../docs/reference/key-provider-aws-kms.md#context-binding). |

Pass `crypto` to `createPersistentServerVault`.

## The rules

- **You own the client.** The package constructs no `KMSClient` and reads no environment variable, Region, or credential. It never retries; retries are your client's.
- **Name keys by full key ARN.** Aliases and bare key ids are rejected. Exactly one key is `active`.
- **The serving role needs four actions**: `kms:GenerateDataKey`, `kms:Decrypt`, `kms:ReEncryptFrom`, `kms:ReEncryptTo`. See the [IAM example](../../docs/reference/key-provider-aws-kms.md#iam).
- **To rotate, add a new key.** Make the new ARN `active` and the old one `decrypt-only`, in every process, and keep the old one for at least 24 hours. See [Rotation](../../docs/reference/key-provider-aws-kms.md#rotation).
- **The cache delays revocation.** With `cache` set, disabling a key in KMS takes up to `maxAgeMs` to take effect.
- **A `logger` in your client config sees the ARN and the wrapped key, not the data key.** The SDK marks `Plaintext` sensitive and replaces it before logging; the key ARN, the wrapped key, and the context digest reach `logger.info` ([finding](../../docs/research/aws-sdk-v3-logger-and-key-material.md)). The package itself logs nothing.
- **Deleting rows is not erasure.** A wrapped key in a backup stays decryptable while its KMS key is usable. See [Erasure and its limits](../../docs/reference/key-provider-aws-kms.md#erasure-and-its-limits).

## More

The [reference](../../docs/reference/key-provider-aws-kms.md) covers key references, context binding, IAM, rotation, the cache, every error mapping, what CloudTrail records, erasure, tests, and limits.
