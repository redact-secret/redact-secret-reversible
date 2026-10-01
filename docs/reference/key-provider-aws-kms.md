# `@redact-secret/key-provider-aws-kms` reference

Qualification, key handling, IAM, rotation, cache, and failure behavior of [`@redact-secret/key-provider-aws-kms`](../../packages/key-provider-aws-kms/README.md). Setup and options are in the package README.

## What was qualified

| What | Result |
| --- | --- |
| Mock suite (a hand-written fake of `GenerateDataKey`, `Decrypt`, `ReEncrypt`) | Runs on every `npm test`. It includes the shared `KeyProvider` cases of [`@redact-secret/vault-conformance`](../../packages/vault-conformance/README.md) with no case skipped, with the cache off and on. |
| Real AWS KMS | Run once on 2026-10-01 in `us-east-1`, with `@aws-sdk/client-kms` 3.1144.0 on Node.js 22.16.0, against two symmetric customer managed keys (`SYMMETRIC_DEFAULT`, origin `AWS_KMS`, single-Region) created for the run and scheduled for deletion after it. 23 tests passed, none skipped: the shared conformance cases, the end-to-end cases through `createRecordCrypto`, and the cases listed under [Tests](#tests). |

Not qualified, by any run: Node.js 20 and 24, other Regions and partitions, multi-Region keys, keys with imported material, custom key stores (CloudHSM, external), cross-account use, grants, the IAM condition examples below, real throttling, a real `AccessDeniedException`, and behaviour under a KMS outage. A fake is not KMS; the mock suite shows what the provider does with the answers it is given.

## What the application owns

The package constructs no client, reads no environment variable, resolves no Region, and loads no credential. A test checks that the built files contain none of that. The application constructs the `KMSClient` and so decides the Region, the credential source, the retry count, the endpoint, and the HTTP timeouts. It also owns the key policy, the IAM policy, the choice of keys, and CloudTrail.

The provider calls `client.send` once per operation and never retries. Retries are whatever the client is configured to do, and they happen inside `callTimeoutMs`.

## Keys and key references

- A key is named by its full key ARN. An alias name, an alias ARN, and a bare key id are rejected at construction. An alias can be repointed to another key, and a bare key id leaves the Region and account to the client's configuration; neither names one exact key.
- Every ARN must lie in the Region, account, and partition stated in `expected`. One ARN elsewhere rejects the whole configuration. The provider cannot see the client's Region, so it cannot check that the client agrees with `expected`. A client in another Region gets `KEY_UNAVAILABLE` on every call.
- The key reference stored with a capture is `aws-kms:<keyArn>`.
- `generateDataKey` calls `GenerateDataKey` with `KeySpec: "AES_256"` on the active key.
- `unwrapDataKey` accepts only a reference that names a configured key that is not `retired`; anything else is `KEY_UNAVAILABLE` without a KMS call. It always sends that ARN as `KeyId`. For a symmetric key KMS would otherwise take the key from metadata in the ciphertext blob ([Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html)), which would let a stored row choose the key. It then requires the `KeyId` in the response to equal the requested ARN, or fails `KEY_INTEGRITY`.
- `rewrapDataKey` calls [`ReEncrypt`](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html) with the referenced ARN as `SourceKeyId`, the active ARN as `DestinationKeyId`, and the same context for both. KMS decrypts and encrypts internally; the data key is not returned to the process. The response must name both keys.
- A plaintext data key from KMS is copied into a new array and the SDK's array is overwritten. The SDK and the runtime may have made other copies while decoding the response. This is stated, not solved (specification §6.2).

## Context binding

KMS authenticates an [encryption context](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html) with each ciphertext: decrypting with a different context fails with `InvalidCiphertextException`. The same page states that the context "is not secret and not encrypted" and "appears in plaintext in AWS CloudTrail Logs". The namespace, tenant, and capture identifier are therefore never sent. The provider sends:

```text
"rsv:ctx" = base64url( SHA-256( "rsv-kms-context-v1" 0x00 || lp16(namespace) || lp16(tenant) || lp16(captureId) ) )
"rsv:v"   = "1"
```

`lp16` is a two-byte big-endian length followed by the UTF-8 bytes. Nothing else is sent unless `contextLabels` is set. A wrapped key presented with another namespace, tenant, or capture fails `KEY_INTEGRITY`.

The digest is unkeyed. Because a capture identifier is 128 random bits, a party reading CloudTrail cannot recover or enumerate tenants from it. A party that already knows all three identifiers can compute the digest and recognise that capture's calls in the log.

Consequences for access control:

- An IAM or key policy cannot condition on the tenant, the namespace, or the capture through the encryption context, because none of them is in it. Tenant separation at the KMS level needs a separate key per tenant, each with its own provider and policy (see [Erasure](#erasure-and-its-limits)).
- A policy can condition on the constant pair (`kms:EncryptionContext:rsv:v`), on the set of context keys (`kms:EncryptionContextKeys`), and on any label you add ([condition keys for AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html)).

`contextLabels` is an opt-in for that last case: static pairs such as `{ environment: "prod" }`, the same for every call of one provider. A key is 1 to 63 characters of `[A-Za-z0-9_.-]` starting with a letter; a value is 1 to 128 characters of the same set; at most eight pairs. Two things follow from adding them:

- They appear in clear in CloudTrail for every call. Do not put a tenant, a user, or anything sensitive in a label.
- They are part of the binding. A key wrapped with one set of labels does not unwrap with another set, or with none. Changing labels makes existing captures unreadable; treat a label change like a key change and wait out the 24-hour capture lifetime first.

## IAM

A minimal identity policy for the serving principal, with documentation placeholders. The second key is the previous one, kept for decryption only.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ActiveKey",
      "Effect": "Allow",
      "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:ReEncryptFrom", "kms:ReEncryptTo"],
      "Resource": "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-4000-8000-000000000000",
      "Condition": {
        "StringEquals": { "kms:EncryptionContext:rsv:v": "1" },
        "ForAllValues:StringEquals": { "kms:EncryptionContextKeys": ["rsv:ctx", "rsv:v"] }
      }
    },
    {
      "Sid": "DecryptOnlyKey",
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:ReEncryptFrom"],
      "Resource": "arn:aws:kms:us-east-1:111122223333:key/11111111-1111-4111-8111-111111111111",
      "Condition": {
        "StringEquals": { "kms:EncryptionContext:rsv:v": "1" },
        "ForAllValues:StringEquals": { "kms:EncryptionContextKeys": ["rsv:ctx", "rsv:v"] }
      }
    }
  ]
}
```

- The four actions are everything the provider calls. `kms:ReEncryptFrom` is needed on the key a wrapped key moves from and `kms:ReEncryptTo` on the key it moves to; re-wrapping a key that is already under the active key needs both on that key. Drop both `ReEncrypt` actions if the application never calls `rewrapDataKey`.
- With `contextLabels`, add each label key to the `kms:EncryptionContextKeys` list and, if wanted, a `kms:EncryptionContext:<label>` condition.
- An identity policy takes effect only if the key policy allows the account to delegate to IAM. AWS recommends granting `kms:Decrypt` in the key policy of the particular key rather than broadly in IAM ([Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html)).
- **This example was not exercised.** The qualification run created no policy; its principal had broader permissions. Check the conditions in your account before relying on them.

What the serving principal should not have, in the key policy or anywhere else:

- `kms:*`, or `Resource: "*"` for the actions above.
- `kms:ScheduleKeyDeletion`, `kms:DisableKey`, `kms:PutKeyPolicy`, `kms:CreateGrant`, `kms:ImportKeyMaterial`, `kms:DeleteImportedKeyMaterial`, or any other administrative action. Key administration belongs to a different principal.
- `kms:Encrypt`, `kms:GenerateDataKeyWithoutPlaintext`, or `kms:DescribeKey`. The provider does not call them.

This package says nothing about who may restore a value. That is the application's restore policy, enforced by the server. KMS permissions bound what a compromised server process or a leaked credential can do with a copy of the store.

## Rotation

Two different things are called rotation.

**A new KMS key.** This is the rotation of specification §6.2. Create a new key, give the serving principal the permissions above on it, and deploy a configuration in which the new ARN is `active` and the old one is `decrypt-only`. New captures name the new ARN. Keep the old key `decrypt-only` for at least 24 hours plus the clock skew bound, the longest a capture can live. After that no live capture names it: set it to `retired`, or remove it from the configuration, and then disable or delete it in KMS. `rewrapDataKey` moves one capture's wrapped key to the active key with `ReEncrypt` and does not touch its payloads; this library does not enumerate captures to drive it. Every process must have the old key in its configuration before any process makes the new key active, or it cannot read what the others write.

**AWS automatic or on-demand key rotation.** KMS changes the key material inside one KMS key. The key ARN does not change, KMS keeps every earlier key material and picks the right one when it decrypts, and "You cannot select a particular key material for decrypt operations" ([Rotate AWS KMS keys](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)). For this provider that means:

- The key reference does not change, so the provider cannot tell that the material rotated. A `ReEncrypt` onto the same key re-wraps under the current material.
- The earlier material cannot be retired by itself. KMS deletes key material only when the KMS key is deleted. A wrapped key from before the rotation stays decryptable for as long as the KMS key is usable.
- The same page states that rotation "does not rotate the data keys that the KMS key generated or re-encrypt any data". It is not a response to an exposed data key or an exposed store.

If a requirement says that old wrapping material must become unusable, use a new KMS key.

## Cache

There is no cache unless `cache` is set. Without it, every `unwrapDataKey` is one `Decrypt`.

`cache: { maxEntries, maxAgeMs, perTenantMaxEntries }` keeps unwrapped data keys in process memory.

- An entry is keyed by the key ARN, a SHA-256 digest of the wrapped key, and the context digest. A different context, key reference, or wrapped key is a different entry, and goes to KMS.
- Scope, the key reference, and the caller's signal are checked before the cache is read. A key marked `retired` in the configuration is refused whether or not it was cached.
- Bounds: `maxEntries` in total (at most 10000), `perTenantMaxEntries` per tenant, and `maxAgeMs` per entry (at most 300000, five minutes; construction rejects more). The oldest entry is evicted first. A read does not extend an entry's life.
- An entry is overwritten with zeros when it is evicted, when it ages out, and on `close()`. Callers get copies.
- `generateDataKey` and `rewrapDataKey` are never cached and never read the cache.
- **Revocation delay.** Disabling a key, scheduling its deletion, or removing a permission in KMS does not reach a cached data key until its entry ages out. The delay is `maxAgeMs`. AWS describes the same effect for any data key held in memory ([How unusable KMS keys affect data keys](https://docs.aws.amazon.com/kms/latest/developerguide/unusable-kms-keys.html)). A test shows it against the fake and the real-KMS run showed it against a disabled key. `close()` on every provider instance drops the cache at once; a cache in another process is not reachable from here.
- A cache also means that CloudTrail no longer shows one `Decrypt` per restore.

`stats()` returns counts only: cache entries, tenants, hits, misses, evictions, and the number of calls of each KMS operation.

`close()` overwrites the cache and makes every later call fail `KEY_UNAVAILABLE`. It does not destroy the client, which the application owns.

## Failure semantics

Every failure is a `KeyProviderError` of `@redact-secret/vault-contracts` with the fixed message of its code. It has no `cause` and carries no SDK message, request id, ARN, or account id. The provider reads only the `name` of what the client threw, and the SDK's `$retryable.throttling` flag. KMS error messages contain key ARNs, so they are not passed on.

| Client outcome | Code |
| --- | --- |
| `ThrottlingException`, `LimitExceededException`, `TooManyRequestsException`, `RequestLimitExceeded`, or any error the SDK marks as throttling | `KEY_THROTTLED` |
| `InvalidCiphertextException` (wrong context, tampered or foreign wrapped key) | `KEY_INTEGRITY` |
| A response whose `KeyId` (or `SourceKeyId`) is not the requested ARN, whose plaintext is not 32 bytes, or whose ciphertext is missing or over 4096 bytes | `KEY_INTEGRITY` |
| `DisabledException`, `KMSInvalidStateException` (pending deletion, pending import), `NotFoundException`, `AccessDeniedException`, `KeyUnavailableException`, `IncorrectKeyException` | `KEY_UNAVAILABLE` |
| No answer within `callTimeoutMs`, or the client's own `TimeoutError` | `KEY_TIMEOUT` |
| The caller's `AbortSignal` | `KEY_ABORTED` |
| Anything else, including `KMSInternalException`, `DependencyTimeoutException`, credential and network errors, and a non-object response | `KEY_UNAVAILABLE` |
| A reference that is not a configured, non-retired key; a context out of scope; a closed provider | `KEY_UNAVAILABLE`, without a KMS call |
| An input outside the contract | `KEY_INVALID_ARGUMENT`, without a KMS call |

On a timeout or an abort the provider aborts the signal it passed to `client.send`, and overwrites the plaintext of a response that arrives afterwards. It never tries another key, never falls back to a local key, and never retries.

Key states and their errors are in [Key states of AWS KMS keys](https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html); throttling is in [Throttling AWS KMS requests](https://docs.aws.amazon.com/kms/latest/developerguide/throttling.html). KMS throttles when the request rate exceeds the account's quota for the Region. With the cache off, the load to plan for is one KMS call per capture created and one per capture restored. KMS is [eventually consistent](https://docs.aws.amazon.com/kms/latest/developerguide/accessing-kms.html): a change to a key or policy can take seconds, and in some cases minutes, to be visible.

## What AWS records

The package logs nothing and has no telemetry hook.

AWS KMS writes a CloudTrail event for each call, including failed ones ([Logging AWS KMS API calls with AWS CloudTrail](https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html), [Decrypt entries](https://docs.aws.amazon.com/kms/latest/developerguide/ct-decrypt.html)). An event holds the caller's identity, the time, the source address, the user agent, the operation, the key ARN, the encryption context (the context digest, the version, and any labels), and for a failure the error code and message. The ciphertext and the plaintext are omitted.

Someone who reads the trail therefore sees how many captures were created and restored, when, by which principal, and under which key, and can tell that two calls concerned the same capture. They do not see the namespace, tenant, capture identifier, or any value. If call volume or timing per principal is sensitive in your setting, restrict access to the trail.

## Erasure and its limits

These restate specification §9 for KMS.

- Deleting a capture's rows from the store is not cryptographic erasure. A wrapped data key in a backup, a replica, or a log archive stays decryptable for as long as its KMS key is usable.
- Disabling or deleting a KMS key affects every capture wrapped under it, not one capture and not one tenant.
- Key deletion is not immediate. KMS requires a waiting period of 7 to 30 days, during which the key cannot be used and the deletion can be cancelled; after it the key material is gone and "you can no longer decrypt the data that was encrypted under that KMS key" ([Delete an AWS KMS key](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html)). An erasure statement that rests on key deletion has that completion delay.
- Disabling a key is immediate, subject to eventual consistency and to the cache's revocation delay, and it is reversible. It is not erasure.
- The route to narrower erasure is narrower keys: one KMS key per tenant, or per tenant and period, each with its own provider instance whose `scope.tenants` names that tenant, and a record kept outside the store of which key covered what. The cost is one KMS key per tenant (a monthly charge and a place in the account's key quota), one provider and policy per tenant, routing in the application, and the loss of every capture of that tenant when its key goes. This package does not do the routing.
- With one key per namespace, which is what the example at the top configures, no per-tenant or per-capture erasure exists.

## Tests

```sh
npm run build   # in the repository root: builds the packages the tests import
npm run build -w @redact-secret/key-provider-aws-kms
npm test -w @redact-secret/key-provider-aws-kms
```

- `conformance.test.mjs`: the shared key-provider cases over the fake, cache off and cache on. After each case every command the fake received is checked: digest-only context, full key ARNs, no identifier.
- `provider.test.mjs`: construction (alias, key id, Region, account, partition), key selection, the response `KeyId` check, every error mapping, error hygiene, timeout, abort, close.
- `cache.test.mjs`: off by default, count, age with an injected clock, per-tenant bound, zeroing, and the disabled-key delay.
- `record-crypto.test.mjs`: seal, open, tamper, and rewrap through `createRecordCrypto` of [`@redact-secret/vault-crypto`](../../packages/vault-crypto/README.md).
- `dependency-isolation.test.mjs`: no other workspace package names `@aws-sdk/` in its manifest, source, or build; this package's build imports only `@aws-sdk/client-kms` and `@redact-secret/vault-contracts`.
- `real-kms.integration.test.mjs`: runs only when `RSV_KMS_TEST_KEY_ARN` and `RSV_KMS_TEST_OLD_KEY_ARN` name two symmetric keys in one account and Region, and is reported as skipped with that reason otherwise. The test file constructs `new KMSClient({ region })` with the default credential chain. It needs `kms:GenerateDataKey`, `kms:Decrypt`, `kms:ReEncryptFrom`, and `kms:ReEncryptTo` on both keys, and `kms:DisableKey` and `kms:EnableKey` on the second, which it disables and re-enables. Use keys made for the test. It covers the shared conformance cases; the end-to-end cases; a context mismatch refused by KMS itself; a ciphertext of one key presented with the other key's reference; `ReEncrypt` from one key to the other; a wrong-account ARN rejected at construction and a key id that does not exist; a real timeout and abort; a disabled key, with and without the cache; and per-call latency. It does not provoke throttling.

In the 2026-10-01 run the client-side latency of 91 calls was: `GenerateDataKey` median 31 ms, `Decrypt` 35 ms, `ReEncrypt` 30 ms, from one workstation over the public endpoint, including two calls deliberately abandoned at 1 ms. It is one sample, not a benchmark. `DisableKey` was visible to `Decrypt` in under 200 ms in both runs of that day; AWS documents that it can take longer.

## Limits

- The package depends on WebCrypto for SHA-256 and on the AWS SDK for JavaScript v3. It is tested on Node.js only. Nothing here qualifies a browser or a Worker.
- Multi-Region keys: an `mrk-` key ARN is accepted as syntax and treated as one key in one Region. Decrypting in another Region with a replica is not handled and not tested.
- Custom key stores (CloudHSM, external key store) and keys with imported material are not tested. Their error behaviour differs, and `KMSInvalidStateException` there is a general failure.
- Cross-account use is not tested. Every configured key must be in the one account stated in `expected`; a caller in another account is a matter of the key policy and was not exercised.
- Grants and the IAM condition example were not exercised.
- The context digest is unkeyed (see [Context binding](#context-binding)).
- A hostile or faulty client object runs in the same process. The provider checks what it returns and never passes on what it throws; it cannot contain it.
- The package's `tsconfig.json` sets `skipLibCheck: true`, unlike the other packages. The SDK's type declarations import Node.js types, and this repository builds with `types: []`.
