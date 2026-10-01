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
7. **No thread offloading in the crypto layer** (plan section 3.7, issue [#122](https://github.com/redact-secret/redact-secret-vault/issues/122)). `RecordCrypto` runs HKDF and AES-256-GCM inline in the calling task. See the measurement below. A worker thread cannot be cancelled: `asyncio.to_thread` leaves the thread running after its task is cancelled, so the data key, entry keys, and decrypted payload it holds could not be overwritten on the cancellation path that spec section 7.6 and plan section 3.7 require. The work is also bounded by the store's `max_create_entries` and `max_create_bytes`.
8. **Deterministic test provider lives in the test tree.** It is not in the wheel, and it refuses to construct without the acknowledgement string `test-only`, as in JavaScript.

## Measured seal and open time

`tests/test_crypto_max_capture.py` seals and opens captures at the limits of the format and prints the times with `-s`. Three runs on 2026-10-01, Apple arm64, Darwin 25.5, CPython 3.12.14, `cryptography` 50.0.2, local key provider, one run per process after the first call, median of five repetitions each. Whole-call wall time, including key derivation, nonce draw, and payload encoding or decoding. Not a benchmark claim for any other machine.

| Capture | Seal | Open |
| --- | --- | --- |
| 1 entry of 1 MiB (largest value) | 0.4 ms | 0.4 ms |
| 1024 entries of 1 KiB (most entries) | 17 to 18 ms | 17 ms |
| 1024 entries of 8 KiB (default value limit, 8 MiB) | 19 to 20 ms | 21 ms |
| 64 entries of 1 MiB (64 MiB) | 20 to 22 ms | 20 ms |

The first call in a process was up to about 10 ms slower than these. The cost is dominated by per-entry work (about 16 µs each for the HKDF object, the AES-GCM context, and the encoding), not by the cipher, which is far faster than the interpreter overhead. Inline execution therefore blocks the event loop for at most a few tens of milliseconds on this machine. Decision 7 stands unless a measurement on the target hardware, with the store's real `max_create_bytes`, shows a stall the application cannot accept. A cooperative `await asyncio.sleep(0)` between entries would bound the stall without a thread and keeps the cancellation rule; it is not added until such a measurement asks for it.

## `verify_vectors.py`

[`conformance/persistent/v1/verify_vectors.py`](../../conformance/persistent/v1/verify_vectors.py) exists. It rebuilds the `entryId`, session tag, request digest, entry key, AAD, payload, envelope, and local-wrap vectors from the specification with the standard library, checks AES-256-GCM with `cryptography`, and checks that the `negative.open` cases of code `RECORD_INTEGRITY` do not authenticate. It does not decode a negative envelope or payload and does not test any shipped Python code.

It is kept, unchanged, as the independent oracle: it shares no code with either implementation, so a mistaken reading of the specification would have to be made three times. The Python package tests are a separate run: they feed the same `vectors.json` to the code that ships in the wheel, including every negative case.

## Consequences

- The wheel gains modules `persistent`, `crypto`, `stores.postgres`, and `keys.aws_kms`. The last three raise `ImportError` naming the extra when the dependency is missing.
- Python persistence stays "not supported" in every README, status table, and package description until issue #128.
