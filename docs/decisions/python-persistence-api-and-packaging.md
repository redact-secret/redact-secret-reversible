---
decision_id: decision-python-persistence-api-and-packaging
status: accepted
scope: packages/vault-py
title: Decide the Python persistence API shape, packaging, and version floor
proposed_at: 2026-10-01
decided_at: 2026-10-01
---
# Decide the Python persistence API shape, packaging, and version floor

> **Python persistence is not implemented and not supported.** This record fixes how the groundwork issues [#119](https://github.com/redact-secret/redact-secret-vault/issues/119) to [#122](https://github.com/redact-secret/redact-secret-vault/issues/122) are built. It claims nothing about a store, a server profile, or a qualification; those stay with the [plan](../plans/python-persistence-parity.md) and its later issues, and support is stated only by the qualification record of issue [#128](https://github.com/redact-secret/redact-secret-vault/issues/128).

## Context

The plan's [section 9](../plans/python-persistence-parity.md#9-open-questions) left several questions open that the first four handoffs cannot avoid. Each is answered with the recommendation the plan already gives. Where a later measurement can change an answer, the record says what would change it.

## Decisions

1. **One distribution with extras** (plan section 4.1, question 2). `redact-secret-vault` stays the only Python distribution. The base wheel has no `Requires-Dist` without an `extra ==` marker. The extras are `crypto` (`cryptography>=47`), `postgres` (`psycopg>=3.2,<4`), and `aws-kms` (`boto3>=1.43`). Per-module support status is stated in documentation, not by version number. A module moves to its own distribution only when it needs a different release cadence or a second backend of its kind exists, and that would need a new naming decision.
2. **Async-only persistent API** (plan section 3.7, question 1). `Store`, `KeyProvider`, and `RecordCrypto` are `typing.Protocol` classes with `async def` methods. There is no synchronous twin. Pure functions (validators, canonical encoders, digests) are synchronous. A WSGI deployment calls the async API through one long-lived event-loop thread per process.
3. **Python 3.11 floor for the persistent modules** (plan section 6.7, question 3). `requires-python` stays `>=3.10` because the in-memory server keeps its floor. Importing `redact_secret_vault.persistent` on 3.10 raises `ImportError`, and the tests of those modules are not collected on 3.10. 3.11 provides `asyncio.timeout` and exception notes, and 3.10 is at or past the end of its upstream support window.
4. **A bytes-only local key provider has its own profile name** (plan section 3.9, question 6). JavaScript accepts a non-extractable `CryptoKey` for local key material and Python has only bytes in process memory. The Python provider reports the profile `local-bytes-hkdf-aes-256-gcm-v1`, not `local-hkdf-aes-256-gcm-v1`, so a record or a qualification note cannot read as if the stronger handling had been used. The wrapped-key layout is the same, so the two interoperate on bytes.
5. **`KEY_ABORTED` is reserved** (question 8). Python signatures carry no abort signal. A provider raises `KEY_ABORTED` only for a cancellation it started itself. Task cancellation propagates as `asyncio.CancelledError` and is never converted. The local provider never raises it.
6. **The in-memory server is unchanged** (question 7). Its four `raise ... from exc` sites and its code-point identifier limit stay as published. The persistent modules follow the stricter rules (no `__cause__`, no `__context__`, UTF-16 lengths) and do not change the behavior of existing code.
7. **Deterministic test provider lives in the test tree.** It is not in the wheel, and it refuses to construct without the acknowledgement string `test-only`, as in JavaScript.

## `verify_vectors.py`

[`conformance/persistent/v1/verify_vectors.py`](../../conformance/persistent/v1/verify_vectors.py) exists. It rebuilds the `entryId`, session tag, request digest, entry key, AAD, payload, envelope, and local-wrap vectors from the specification with the standard library, checks AES-256-GCM with `cryptography`, and checks that the `negative.open` cases of code `RECORD_INTEGRITY` do not authenticate. It does not decode a negative envelope or payload and does not test any shipped Python code.

It is kept, unchanged, as the independent oracle: it shares no code with either implementation, so a mistaken reading of the specification would have to be made three times. The Python package tests are a separate run: they feed the same `vectors.json` to the code that ships in the wheel, including every negative case.

## Consequences

- The wheel gains modules `persistent`, `crypto`, `stores.postgres`, and `keys.aws_kms`. The last three raise `ImportError` naming the extra when the dependency is missing.
- Python persistence stays "not supported" in every README, status table, and package description until issue #128.
