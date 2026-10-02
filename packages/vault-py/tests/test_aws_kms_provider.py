"""The AWS KMS key provider (``redact_secret_vault.keys.aws_kms``) against a fake client shaped like ``boto3``.

This file proves the provider's own behavior: the key reference and context digest it shares with the JavaScript
provider, what it sends, what it refuses, what it maps, what it overwrites, and what it never lets out. It runs no
real AWS call. Interoperation with the JavaScript provider against a real key is a separate run
(``tests/aws_kms_interop.py``), recorded in ``docs/research/qualification-python-persistence-0.1.0b3.md``; this file
says nothing about it.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import logging
import pickle
import shutil
import subprocess
import sys
import traceback
import warnings
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("boto3")

from crypto_support import all_zero, track_buffers  # noqa: E402
from kms_support import (  # noqa: E402
    ACCOUNT,
    REGION,
    SDK_REQUEST_ID,
    SDK_TEXT,
    FakeKms,
    FakeSdkError,
    arn_for,
    sdk_error,
)

from redact_secret_vault.keys.aws_kms import (  # noqa: E402
    AWS_KMS_KEY_PROVIDER_PROFILE,
    AwsKmsExpected,
    AwsKmsKey,
    AwsKmsScope,
    DataKeyCacheOptions,
    context_digest,
    create_aws_kms_key_provider,
)
from redact_secret_vault.persistent import KeyContext, KeyProviderError, StoredKey  # noqa: E402

pytestmark = pytest.mark.skipif(sys.version_info < (3, 11), reason="the persistent modules need Python 3.11")

NS = "ns-synthetic"
TENANT = "tenant-acme-synthetic"
OTHER_TENANT = "tenant-globex-synthetic"
CAPTURE_A = "cap_" + "a" * 26
CAPTURE_B = "cap_" + "b" * 26
EXPECTED = AwsKmsExpected(region=REGION, account_id=ACCOUNT)
SCOPE = AwsKmsScope(namespaces=(NS,), tenants=(TENANT, OTHER_TENANT))
REPO = Path(__file__).resolve().parents[3]

#: Computed by the JavaScript provider's ``contextDigest`` (packages/key-provider-aws-kms/dist/context.js).
JS_DIGESTS = [
    (NS, TENANT, CAPTURE_A, "BlFqdWn3UPWuML5pOcRBs371LSwFZetBQLYWsABJ_1Y"),
    (NS, TENANT, CAPTURE_B, "Pa3dyCCPBs93_ZrIjz__E6Dqtf0KNxCvlq33TFcm0_s"),
    (NS, "\U0001f600tenant", CAPTURE_A, "gixTJNd9WixMEgWrQW03fksZIiSOgN0BnnVdyd2JY8c"),
    ("ns:other.2", "t", "cap_" + "z2" * 13, "cqJS4J-J7tn_SbovLHp0nA0dxds-zOJb4zpRzhIiLa8"),
]


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def ctx(capture: str = CAPTURE_A, *, tenant: str = TENANT) -> KeyContext:
    return KeyContext(NS, tenant, capture)


def code_of(coro: Any) -> str:
    captured: KeyProviderError | None = None
    try:
        run(coro)
    except KeyProviderError as thrown:
        captured = thrown
    assert captured is not None, "expected an error"
    assert captured.__cause__ is None and captured.__context__ is None
    assert not hasattr(captured, "__notes__")
    return captured.code


def build(kms: FakeKms, *, active: str | None = None, extra: tuple[AwsKmsKey, ...] = (), **options: Any) -> Any:
    key = active or kms.create_key()
    return create_aws_kms_key_provider(
        client=kms,
        keys=(AwsKmsKey(key, "active"), *extra),
        expected=EXPECTED,
        scope=options.pop("scope", SCOPE),
        **options,
    )


# ------------------------------------------------------------------------ the shared encoding


def test_the_profile_and_the_context_digest_are_the_javascript_ones() -> None:
    assert AWS_KMS_KEY_PROVIDER_PROFILE == "aws-kms-envelope-v1"
    for namespace, tenant, capture, expected in JS_DIGESTS:
        assert context_digest(KeyContext(namespace, tenant, capture)) == expected


@pytest.mark.skipif(shutil.which("node") is None, reason="node is needed to compute the JavaScript digest")
def test_the_context_digest_equals_the_javascript_provider_for_more_contexts_computed_now() -> None:
    dist = REPO / "packages" / "key-provider-aws-kms" / "dist" / "context.js"
    if not dist.is_file():
        pytest.skip("packages/key-provider-aws-kms is not built")
    contexts = [
        (NS, "ténant-中文", "cap_" + "q7" * 13),
        ("ns.with-dots_and:colons", "T" * 256, "cap_" + "m" * 26),
        (NS, "\U0001f600" * 128, "cap_" + "c" * 26),
    ]
    program = (
        "import { pathToFileURL } from 'node:url';"
        f"const m = await import(pathToFileURL({str(dist)!r}).href);"
        "const out = [];"
        "for (const [namespace, tenant, captureId] of JSON.parse(process.argv[1]))"
        " out.push(await m.contextDigest(globalThis.crypto.subtle, { namespace, tenant, captureId }));"
        "console.log(JSON.stringify(out));"
    )
    import json

    done = subprocess.run(
        [shutil.which("node") or "node", "--input-type=module", "-e", program, json.dumps(contexts)],
        capture_output=True,
        text=True,
        check=True,
    )
    for (namespace, tenant, capture), digest in zip(contexts, json.loads(done.stdout), strict=True):
        assert context_digest(KeyContext(namespace, tenant, capture)) == digest


# ----------------------------------------------------------------------------- what is sent


def deep_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (bytes, bytearray)):
        return [bytes(value).hex(), base64.b64encode(bytes(value)).decode()]
    if isinstance(value, dict):
        return [text for key, item in value.items() for text in (*deep_strings(key), *deep_strings(item))]
    if isinstance(value, (list, tuple)):
        return [text for item in value for text in deep_strings(item)]
    return []


def test_a_request_carries_the_digest_and_the_version_and_no_identifier_in_clear() -> None:
    kms = FakeKms()
    old = kms.create_key()
    provider = build(kms, extra=(AwsKmsKey(old, "decrypt-only"),))
    context = ctx(CAPTURE_B, tenant=OTHER_TENANT)

    async def scenario() -> None:
        key = await provider.generate_data_key(context)
        await provider.unwrap_data_key(StoredKey(key.key_ref, key.wrapped_key), context)
        await provider.rewrap_data_key(StoredKey(key.key_ref, key.wrapped_key), context)

    run(scenario())
    digest = context_digest(context)
    assert [name for name, _ in kms.calls] == ["GenerateDataKey", "Decrypt", "ReEncrypt"]
    for name, request in kms.calls:
        contexts = [request[field] for field in request if field.endswith("EncryptionContext")]
        assert contexts and all(item == {"rsv:ctx": digest, "rsv:v": "1"} for item in contexts), name
        text = "\n".join(deep_strings(request))
        for identifier in (NS, OTHER_TENANT, CAPTURE_B):
            assert identifier not in text, f"{identifier} sent in clear to {name}"
    generate, decrypt, re_encrypt = (request for _, request in kms.calls)
    assert generate["KeySpec"] == "AES_256" and generate["KeyId"].startswith("arn:aws:kms:")
    assert decrypt["KeyId"] == generate["KeyId"], "KeyId is always sent: KMS must use the key the reference names"
    assert re_encrypt["SourceKeyId"] == generate["KeyId"] and re_encrypt["DestinationKeyId"] == generate["KeyId"]


def test_context_labels_are_opt_in_part_of_the_binding_and_validated() -> None:
    kms = FakeKms()
    with_label = build(kms, context_labels={"purpose": "synthetic-test"})
    plain_key = kms.create_key()
    plain = create_aws_kms_key_provider(
        client=kms, keys=(AwsKmsKey(plain_key, "active"),), expected=EXPECTED, scope=SCOPE
    )
    key = run(with_label.generate_data_key(ctx()))
    assert kms.calls[0][1]["EncryptionContext"]["purpose"] == "synthetic-test"
    # The same blob, asked for under a provider with other labels: the binding differs, so KMS refuses.
    other = create_aws_kms_key_provider(
        client=kms,
        keys=(AwsKmsKey(key.key_ref.removeprefix("aws-kms:"), "active"),),
        expected=EXPECTED,
        scope=SCOPE,
    )
    assert code_of(other.unwrap_data_key(StoredKey(key.key_ref, key.wrapped_key), ctx())) == "KEY_INTEGRITY"
    del plain
    for bad in (
        {"1bad": "x"},
        {"ok": ""},
        {"ok": "has space"},
        {f"k{i}": "v" for i in range(9)},
        {"rsv:ctx": "x"},
        [1],
    ):
        with pytest.raises(KeyProviderError) as caught:
            build(kms, context_labels=bad)  # type: ignore[arg-type]
        assert caught.value.code == "KEY_INVALID_ARGUMENT"


# ------------------------------------------------------------------------------ round trips


def test_a_data_key_round_trips_and_the_caller_owns_a_buffer_it_can_overwrite() -> None:
    kms = FakeKms()
    provider = build(kms)
    key = run(provider.generate_data_key(ctx()))
    assert type(key.plaintext_key) is bytearray and len(key.plaintext_key) == 32
    assert key.key_ref.startswith("aws-kms:arn:aws:kms:us-east-1:111122223333:key/")
    again = run(provider.unwrap_data_key(StoredKey(key.key_ref, key.wrapped_key), ctx()))
    assert bytes(again) == bytes(key.plaintext_key) == kms.plaintexts[0]
    again[:] = bytes(32)
    assert bytes(key.plaintext_key) == kms.plaintexts[0], "two buffers, not one"
    # A key never generated for this context, or generated for another, does not unwrap.
    assert code_of(provider.unwrap_data_key(StoredKey(key.key_ref, key.wrapped_key), ctx(CAPTURE_B))) == "KEY_INTEGRITY"
    assert (
        code_of(provider.unwrap_data_key(StoredKey(key.key_ref, key.wrapped_key), ctx(tenant=OTHER_TENANT)))
        == "KEY_INTEGRITY"
    )
    assert code_of(provider.unwrap_data_key(StoredKey(key.key_ref, b"\x01" * 40), ctx())) == "KEY_INTEGRITY"


def test_rewrap_moves_a_key_from_a_decrypt_only_key_to_the_active_one_inside_kms() -> None:
    kms = FakeKms()
    old = kms.create_key()
    before = build(kms, active=old)
    key = run(before.generate_data_key(ctx()))
    new = kms.create_key()
    after = build(kms, active=new, extra=(AwsKmsKey(old, "decrypt-only"),))
    moved = run(after.rewrap_data_key(StoredKey(key.key_ref, key.wrapped_key), ctx()))
    assert moved.key_ref == "aws-kms:" + new and moved.wrapped_key != key.wrapped_key
    assert bytes(run(after.unwrap_data_key(moved, ctx()))) == bytes(key.plaintext_key)
    # The data key did not travel: ReEncrypt answered with no plaintext, and no Decrypt was sent for it.
    assert [name for name, _ in kms.calls].count("ReEncrypt") == 1
    # The old key's reference is still served while it is decrypt-only, and not once it is retired.
    assert bytes(run(after.unwrap_data_key(StoredKey(key.key_ref, key.wrapped_key), ctx()))) == bytes(key.plaintext_key)
    retired = build(kms, active=new, extra=(AwsKmsKey(old, "retired"),))
    count = len(kms.calls)
    assert code_of(retired.unwrap_data_key(StoredKey(key.key_ref, key.wrapped_key), ctx())) == "KEY_UNAVAILABLE"
    assert len(kms.calls) == count, "a retired key's reference is refused without a KMS call"


def test_a_reference_to_an_unknown_or_foreign_or_malformed_key_is_unavailable_without_a_kms_call() -> None:
    kms = FakeKms()
    provider = build(kms)
    key = run(provider.generate_data_key(ctx()))
    count = len(kms.calls)
    for ref in (
        "aws-kms:" + arn_for(),
        "aws-kms:" + arn_for(region="eu-west-1"),
        "local:" + key.key_ref.removeprefix("aws-kms:"),
        "aws-kms:alias/some-alias",
        key.key_ref.removeprefix("aws-kms:"),
        "aws-kms:",
        "x",
    ):
        assert code_of(provider.unwrap_data_key(StoredKey(ref, key.wrapped_key), ctx())) == "KEY_UNAVAILABLE", ref
    assert len(kms.calls) == count


def test_a_context_outside_the_scope_is_unavailable_without_a_kms_call() -> None:
    kms = FakeKms()
    provider = build(kms, scope=AwsKmsScope(namespaces=(NS,), tenants=(TENANT,)))
    count = len(kms.calls)
    assert code_of(provider.generate_data_key(KeyContext("other-ns", TENANT, CAPTURE_A))) == "KEY_UNAVAILABLE"
    assert code_of(provider.generate_data_key(ctx(tenant=OTHER_TENANT))) == "KEY_UNAVAILABLE"
    assert len(kms.calls) == count
    assert len(run(provider.generate_data_key(ctx())).plaintext_key) == 32


def test_a_malformed_context_or_stored_key_is_an_invalid_argument() -> None:
    provider = build(FakeKms())
    key = run(provider.generate_data_key(ctx()))
    for bad in (
        KeyContext("bad ns!", TENANT, CAPTURE_A),
        KeyContext(NS, "", CAPTURE_A),
        KeyContext(NS, TENANT, "cap_short"),
        KeyContext(NS, "lone\ud800surrogate", CAPTURE_A),
        None,
        {"namespace": NS},
    ):
        assert code_of(provider.generate_data_key(bad)) == "KEY_INVALID_ARGUMENT"  # type: ignore[arg-type]
    for bad_stored in (
        StoredKey("", key.wrapped_key),
        StoredKey(key.key_ref, b""),
        StoredKey(key.key_ref, b"x" * 4097),
        None,
        "not a stored key",
    ):
        assert code_of(provider.unwrap_data_key(bad_stored, ctx())) == "KEY_INVALID_ARGUMENT"  # type: ignore[arg-type]
        assert code_of(provider.rewrap_data_key(bad_stored, ctx())) == "KEY_INVALID_ARGUMENT"  # type: ignore[arg-type]


# ------------------------------------------------------------------------- error mapping


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (lambda arn: sdk_error("InvalidCiphertextException", arn), "KEY_INTEGRITY"),
        (lambda arn: sdk_error("DisabledException", arn), "KEY_UNAVAILABLE"),
        (lambda arn: sdk_error("KMSInvalidStateException", arn), "KEY_UNAVAILABLE"),
        (lambda arn: sdk_error("NotFoundException", arn), "KEY_UNAVAILABLE"),
        (lambda arn: sdk_error("AccessDeniedException", arn), "KEY_UNAVAILABLE"),
        (lambda arn: sdk_error("KeyUnavailableException", arn), "KEY_UNAVAILABLE"),
        (lambda arn: sdk_error("IncorrectKeyException", arn), "KEY_UNAVAILABLE"),
        (lambda arn: sdk_error("SomethingNew", arn), "KEY_UNAVAILABLE"),
        (lambda arn: sdk_error("ThrottlingException", arn), "KEY_THROTTLED"),
        (lambda arn: sdk_error("LimitExceededException", arn), "KEY_THROTTLED"),
        (lambda arn: sdk_error("TooManyRequestsException", arn), "KEY_THROTTLED"),
        (lambda arn: sdk_error("ClientError", arn, status=429), "KEY_THROTTLED"),
        (lambda arn: sdk_error("ReadTimeoutError", arn), "KEY_TIMEOUT"),
        (lambda arn: sdk_error("ConnectTimeoutError", arn), "KEY_TIMEOUT"),
        (lambda arn: TimeoutError("synthetic"), "KEY_TIMEOUT"),
        (lambda arn: ConnectionResetError("synthetic"), "KEY_UNAVAILABLE"),
        (lambda arn: RuntimeError(SDK_TEXT), "KEY_UNAVAILABLE"),
    ],
)
def test_what_the_client_raised_is_mapped_by_name_and_nothing_else_is_kept(failure: Any, expected: str) -> None:
    kms = FakeKms()
    provider = build(kms)
    key = run(provider.generate_data_key(ctx()))
    stored = StoredKey(key.key_ref, key.wrapped_key)
    kms.next_failure = failure(key.key_ref)
    assert code_of(provider.unwrap_data_key(stored, ctx())) == expected
    kms.next_failure = failure(key.key_ref)
    assert code_of(provider.generate_data_key(ctx())) == expected
    kms.next_failure = failure(key.key_ref)
    assert code_of(provider.rewrap_data_key(stored, ctx())) == expected
    # The next call is unaffected: nothing is cached about a failure.
    assert len(run(provider.unwrap_data_key(stored, ctx()))) == 32


def test_a_disabled_key_fails_unavailable_and_a_re_enabled_key_works_again() -> None:
    kms = FakeKms()
    provider = build(kms)
    key = run(provider.generate_data_key(ctx()))
    arn = key.key_ref.removeprefix("aws-kms:")
    kms.set_state(arn, "Disabled")
    assert code_of(provider.unwrap_data_key(StoredKey(key.key_ref, key.wrapped_key), ctx())) == "KEY_UNAVAILABLE"
    assert code_of(provider.generate_data_key(ctx())) == "KEY_UNAVAILABLE"
    kms.set_state(arn, "Enabled")
    assert len(run(provider.unwrap_data_key(StoredKey(key.key_ref, key.wrapped_key), ctx()))) == 32


def test_a_slow_call_is_a_timeout_and_the_provider_stays_usable() -> None:
    kms = FakeKms()
    provider = build(kms, call_timeout_ms=100)
    kms.delay_s = 0.5
    assert code_of(provider.generate_data_key(ctx())) == "KEY_TIMEOUT"
    kms.delay_s = 0
    assert len(run(provider.generate_data_key(ctx())).plaintext_key) == 32


def test_a_cancelled_caller_gets_the_cancellation_and_the_late_result_is_dropped_quietly() -> None:
    kms = FakeKms()
    provider = build(kms)
    kms.delay_s = 0.4

    async def scenario() -> None:
        task = asyncio.ensure_future(provider.generate_data_key(ctx()))
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        # The worker thread is still running; its result is dropped without a warning or an unretrieved exception.
        await asyncio.sleep(0.6)
        kms.delay_s = 0
        assert len((await provider.generate_data_key(ctx())).plaintext_key) == 32

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        run(scenario())


# -------------------------------------------------------------------- responses out of contract


@pytest.mark.parametrize(
    ("operation", "tamper", "expected"),
    [
        ("generate", lambda r: {**r, "KeyId": arn_for()}, "KEY_INTEGRITY"),
        ("generate", lambda r: {**r, "Plaintext": b"\x01" * 31}, "KEY_INTEGRITY"),
        ("generate", lambda r: {**r, "Plaintext": b"\x01" * 33}, "KEY_INTEGRITY"),
        ("generate", lambda r: {k: v for k, v in r.items() if k != "Plaintext"}, "KEY_INTEGRITY"),
        ("generate", lambda r: {**r, "Plaintext": "text"}, "KEY_INTEGRITY"),
        ("generate", lambda r: {**r, "CiphertextBlob": b""}, "KEY_INTEGRITY"),
        ("generate", lambda r: {**r, "CiphertextBlob": b"\x02" * 4097}, "KEY_INTEGRITY"),
        ("generate", lambda r: {**r, "CiphertextBlob": "text"}, "KEY_INTEGRITY"),
        ("generate", lambda r: None, "KEY_UNAVAILABLE"),
        ("decrypt", lambda r: {**r, "KeyId": arn_for()}, "KEY_INTEGRITY"),
        ("decrypt", lambda r: {**r, "Plaintext": b"\x01" * 16}, "KEY_INTEGRITY"),
        ("decrypt", lambda r: [r], "KEY_UNAVAILABLE"),
        ("re_encrypt", lambda r: {**r, "KeyId": arn_for()}, "KEY_INTEGRITY"),
        ("re_encrypt", lambda r: {**r, "SourceKeyId": arn_for()}, "KEY_INTEGRITY"),
        ("re_encrypt", lambda r: {**r, "CiphertextBlob": b""}, "KEY_INTEGRITY"),
    ],
)
def test_a_response_outside_the_contract_is_an_integrity_failure_and_no_buffer_survives(
    operation: str, tamper: Any, expected: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    kms = FakeKms()
    provider = build(kms)
    key = run(provider.generate_data_key(ctx()))
    stored = StoredKey(key.key_ref, key.wrapped_key)
    created = track_buffers(monkeypatch)
    kms.mutate = lambda name, result: tamper(result) if name == operation else result
    call = {
        "generate": lambda: provider.generate_data_key(ctx()),
        "decrypt": lambda: provider.unwrap_data_key(stored, ctx()),
        "re_encrypt": lambda: provider.rewrap_data_key(stored, ctx()),
    }[operation]
    assert code_of(call()) == expected
    assert all_zero(created), "every buffer the provider allocated is zero after the failure"


def test_buffers_are_zero_after_a_failure_and_the_returned_one_is_the_callers() -> None:
    created: list[bytearray] = []
    kms = FakeKms()
    provider = build(kms)
    with pytest.MonkeyPatch.context() as patch:
        created = track_buffers(patch)
        key = run(provider.generate_data_key(ctx()))
        assert all_zero(created, except_=(key.plaintext_key,))
        assert any(buffer is key.plaintext_key for buffer in created)


# ------------------------------------------------------------------------------- the cache


def build_cached(kms: FakeKms, now: Any, **cache: Any) -> Any:
    options = {"max_entries": 4, "max_age_ms": 1000, "per_tenant_max_entries": 2, **cache}
    return build(kms, cache=DataKeyCacheOptions(now=now, **options))


def test_the_cache_is_off_unless_asked_for_and_every_unwrap_calls_kms() -> None:
    kms = FakeKms()
    provider = build(kms)
    key = run(provider.generate_data_key(ctx()))
    stored = StoredKey(key.key_ref, key.wrapped_key)
    run(provider.unwrap_data_key(stored, ctx()))
    run(provider.unwrap_data_key(stored, ctx()))
    assert [name for name, _ in kms.calls].count("Decrypt") == 2
    stats = provider.stats()
    assert stats.cache_enabled is False and stats.decrypt_calls == 2 and stats.generate_data_key_calls == 1


def test_the_cache_serves_copies_ages_out_and_overwrites_what_it_drops() -> None:
    clock = [0]
    kms = FakeKms()
    provider = build_cached(kms, lambda: clock[0])
    key = run(provider.generate_data_key(ctx()))
    stored = StoredKey(key.key_ref, key.wrapped_key)
    first = run(provider.unwrap_data_key(stored, ctx()))
    second = run(provider.unwrap_data_key(stored, ctx()))
    assert bytes(first) == bytes(second) and first is not second
    assert [name for name, _ in kms.calls].count("Decrypt") == 1
    first[:] = bytes(32)
    third = run(provider.unwrap_data_key(stored, ctx()))
    assert bytes(third) == kms.plaintexts[0], "a caller overwriting its buffer does not touch the cache"
    held = next(iter(provider._cache._entries.values())).key
    assert bytes(held) == kms.plaintexts[0]
    clock[0] = 999
    assert len(run(provider.unwrap_data_key(stored, ctx()))) == 32
    assert [name for name, _ in kms.calls].count("Decrypt") == 1, "still inside the age"
    clock[0] = 1000
    run(provider.unwrap_data_key(stored, ctx()))
    assert [name for name, _ in kms.calls].count("Decrypt") == 2, "at the age it is a miss"
    assert not any(held), "the aged-out entry was overwritten"
    stats = provider.stats()
    assert stats.cache_hits == 3 and stats.cache_misses == 2 and stats.cache_evictions >= 1


def test_the_cache_is_keyed_by_key_blob_and_context_and_a_backwards_clock_expires_it() -> None:
    clock = [500]
    kms = FakeKms()
    provider = build_cached(kms, lambda: clock[0])
    key_a = run(provider.generate_data_key(ctx(CAPTURE_A)))
    key_b = run(provider.generate_data_key(ctx(CAPTURE_B)))
    run(provider.unwrap_data_key(StoredKey(key_a.key_ref, key_a.wrapped_key), ctx(CAPTURE_A)))
    # Another capture's blob, and the same blob under another context, are not served from the first entry.
    run(provider.unwrap_data_key(StoredKey(key_b.key_ref, key_b.wrapped_key), ctx(CAPTURE_B)))
    assert (
        code_of(provider.unwrap_data_key(StoredKey(key_a.key_ref, key_a.wrapped_key), ctx(CAPTURE_B)))
        == "KEY_INTEGRITY"
    )
    before = [name for name, _ in kms.calls].count("Decrypt")
    clock[0] = 400
    run(provider.unwrap_data_key(StoredKey(key_a.key_ref, key_a.wrapped_key), ctx(CAPTURE_A)))
    assert [name for name, _ in kms.calls].count("Decrypt") == before + 1


def test_the_cache_is_bounded_by_entries_and_by_tenant_and_close_overwrites_everything() -> None:
    clock = [0]
    kms = FakeKms()
    provider = build_cached(kms, lambda: clock[0], max_entries=3, per_tenant_max_entries=2)
    keys = []
    for index in range(5):
        capture = "cap_" + chr(ord("a") + index) * 26
        keys.append((capture, run(provider.generate_data_key(ctx(capture)))))
        clock[0] += 1
    for capture, key in keys:
        run(provider.unwrap_data_key(StoredKey(key.key_ref, key.wrapped_key), ctx(capture)))
        clock[0] += 1
    stats = provider.stats()
    assert stats.cache_entries <= 2 and stats.cache_tenants == 1, "one tenant may hold at most two"
    other_capture = "cap_" + "t" * 26
    other = run(provider.generate_data_key(ctx(other_capture, tenant=OTHER_TENANT)))
    run(provider.unwrap_data_key(StoredKey(other.key_ref, other.wrapped_key), ctx(other_capture, tenant=OTHER_TENANT)))
    assert provider.stats().cache_entries <= 3 and provider.stats().cache_tenants == 2
    buffers = [entry.key for entry in provider._cache._entries.values()]
    assert buffers and all(any(buffer) for buffer in buffers)
    provider.close()
    assert not any(any(buffer) for buffer in buffers), "close overwrites every cached key"
    assert provider.stats().closed and provider.stats().cache_entries == 0
    assert code_of(provider.generate_data_key(ctx())) == "KEY_UNAVAILABLE"
    assert (
        code_of(provider.unwrap_data_key(StoredKey(keys[0][1].key_ref, keys[0][1].wrapped_key), ctx(keys[0][0])))
        == "KEY_UNAVAILABLE"
    )


def test_a_cache_option_outside_its_ceilings_is_refused() -> None:
    kms = FakeKms()
    for options in (
        {"max_entries": 0},
        {"max_entries": 10_001},
        {"max_age_ms": 0},
        {"max_age_ms": 300_001},
        {"per_tenant_max_entries": 5},
        {"max_entries": True},
        {"max_age_ms": 1.5},
    ):
        with pytest.raises(KeyProviderError) as caught:
            build_cached(kms, None, **options)
        assert caught.value.code == "KEY_INVALID_ARGUMENT", options


# ------------------------------------------------------------------------- construction


def test_construction_makes_no_call_and_refuses_what_is_not_a_full_arn_in_the_expected_account() -> None:
    kms = FakeKms()
    good = kms.create_key()
    other_account = arn_for(account="999988887777")
    other_region = arn_for(region="us-west-2")
    cases: list[dict[str, Any]] = [
        {"keys": ()},
        {"keys": (AwsKmsKey(good, "decrypt-only"),)},
        {"keys": (AwsKmsKey(good, "active"), AwsKmsKey(arn_for(), "active"))},
        {"keys": (AwsKmsKey(good, "active"), AwsKmsKey(good, "decrypt-only"))},
        {"keys": (AwsKmsKey("alias/my-key", "active"),)},
        {"keys": (AwsKmsKey("1234abcd-12ab-34cd-56ef-1234567890ab", "active"),)},
        {"keys": (AwsKmsKey(other_account, "active"),)},
        {"keys": (AwsKmsKey(other_region, "active"),)},
        {"keys": (AwsKmsKey(good, "active"), AwsKmsKey(other_account, "decrypt-only"))},
        {"keys": (AwsKmsKey(good, "paused"),)},  # type: ignore[arg-type]
        {"keys": [AwsKmsKey(good, "active")]},
        {"keys": (AwsKmsKey(good, "active"),), "scope": AwsKmsScope(namespaces=())},
        {"keys": (AwsKmsKey(good, "active"),), "scope": AwsKmsScope(namespaces=("bad ns",))},
        {"keys": (AwsKmsKey(good, "active"),), "scope": AwsKmsScope(namespaces=(NS,), tenants=())},
        {"keys": (AwsKmsKey(good, "active"),), "scope": None},
        {"keys": (AwsKmsKey(good, "active"),), "expected": AwsKmsExpected("us east", ACCOUNT)},
        {"keys": (AwsKmsKey(good, "active"),), "expected": AwsKmsExpected(REGION, "12345")},
        {"keys": (AwsKmsKey(good, "active"),), "expected": AwsKmsExpected(REGION, "١" * 12)},
        {"keys": (AwsKmsKey(good, "active"),), "expected": None},
        {"keys": (AwsKmsKey(good, "active"),), "call_timeout_ms": 0},
        {"keys": (AwsKmsKey(good, "active"),), "call_timeout_ms": True},
        {"keys": (AwsKmsKey(good, "active"),), "client": object()},
        {"keys": (AwsKmsKey(good, "active"),), "client": None},
    ]
    for case in cases:
        arguments: dict[str, Any] = {"client": kms, "expected": EXPECTED, "scope": SCOPE, **case}
        with pytest.raises(KeyProviderError) as caught:
            create_aws_kms_key_provider(**arguments)
        assert caught.value.code == "KEY_INVALID_ARGUMENT", case
        assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert kms.calls == []


def test_a_retired_key_is_accepted_in_the_configuration_and_never_used() -> None:
    kms = FakeKms()
    provider = build(kms, extra=(AwsKmsKey(kms.create_key(), "retired"),))
    assert provider.stats().generate_data_key_calls == 0 and kms.calls == []


def test_the_provider_prints_no_arn_and_cannot_be_pickled_or_copied() -> None:
    import copy

    kms = FakeKms()
    provider = build(kms)
    assert "arn:" not in repr(provider) and str(ACCOUNT) not in repr(provider)
    for attempt in (pickle.dumps, copy.copy, copy.deepcopy):
        with pytest.raises(TypeError):
            attempt(provider)
    assert dataclasses.is_dataclass(provider) is False


# --------------------------------------------------------------------------------- leaks


def _sentinels(kms: FakeKms, provider_inputs: list[str]) -> set[str]:
    found = {SDK_TEXT, SDK_REQUEST_ID, *provider_inputs}
    for plaintext in kms.plaintexts:
        found |= {plaintext.hex(), base64.b64encode(plaintext).decode(), repr(plaintext)}
    for arn in kms.keys:
        found.add(arn)
        found.add(arn.rsplit("/", 1)[1])
    return {item for item in found if len(item) >= 8}


def _texts(error: BaseException) -> list[str]:
    texts = [str(error), repr(error), repr(error.args), repr(getattr(error, "__dict__", {}))]
    texts.append("".join(traceback.format_exception(error)))
    tb = error.__traceback__
    while tb is not None:
        frame = tb.tb_frame
        if "redact_secret_vault" in frame.f_code.co_filename:
            texts.extend(f"{name}={value!r}" for name, value in frame.f_locals.items() if name != "self")
        tb = tb.tb_next
    return texts


def test_nothing_the_sdk_says_reaches_an_error_a_traceback_a_log_a_warning_or_a_stream(
    capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    kms = FakeKms()
    # DEBUG is enabled for the SDK's loggers below, which the guard refuses unless the application opts in.
    provider = build(kms, allow_sdk_debug_logging=True)
    errors: list[KeyProviderError] = []

    async def scenario() -> None:
        key = await provider.generate_data_key(ctx())
        stored = StoredKey(key.key_ref, key.wrapped_key)
        for name in ("InvalidCiphertextException", "DisabledException", "ThrottlingException", "ReadTimeoutError", "X"):
            for operation in (
                lambda: provider.generate_data_key(ctx()),
                lambda: provider.unwrap_data_key(stored, ctx()),
                lambda: provider.rewrap_data_key(stored, ctx()),
            ):
                kms.next_failure = sdk_error(name, key.key_ref)
                try:
                    await operation()
                except KeyProviderError as error:
                    errors.append(error)
        kms.next_failure = FakeSdkError("Boom", key.key_ref)
        for bad in (ctx(CAPTURE_B, tenant="not in scope"),):
            try:
                await provider.generate_data_key(bad)
            except KeyProviderError as error:
                errors.append(error)

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        root = logging.getLogger()
        previous = root.level
        root.setLevel(logging.DEBUG)
        names = ("botocore", "boto3", "urllib3", "asyncio")
        saved = {name: logging.getLogger(name).level for name in names}
        for name in names:
            logging.getLogger(name).setLevel(logging.DEBUG)
        try:
            with caplog.at_level(logging.DEBUG):
                run(scenario())
        finally:
            root.setLevel(previous)
            for name, level in saved.items():
                logging.getLogger(name).setLevel(level)

    sentinels = _sentinels(kms, [NS, TENANT, CAPTURE_A, ACCOUNT])
    assert len(errors) >= 15
    for error in errors:
        assert error.__cause__ is None and error.__context__ is None
        for text in _texts(error):
            for sentinel in sentinels - {NS, TENANT, CAPTURE_A, ACCOUNT}:
                assert sentinel not in text, f"{sentinel[:8]}... in an error of {error.code}"
    streams = capsys.readouterr()
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    for text in (streams.out, streams.err, log_text):
        for sentinel in sentinels:
            assert sentinel not in text
    assert [r for r in caplog.records if r.name.split(".")[0] in ("botocore", "boto3", "urllib3")] == [], (
        "the provider itself and an injected fake emit no SDK log record"
    )


# -------------------------------------------------------------------------- isolation


def test_the_module_imports_neither_boto3_nor_cryptography() -> None:
    probe = (
        "import sys\n"
        "import redact_secret_vault.keys.aws_kms\n"
        "banned = {'boto3', 'botocore', 'cryptography', 'cffi', 'psycopg'}\n"
        "hit = sorted(m for m in sys.modules if m.split('.')[0] in banned)\n"
        "assert not hit, hit\n"
    )
    subprocess.run(
        [sys.executable, "-I", "-c", probe],
        check=True,
        env={"PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
    )


def test_the_provider_serves_a_record_crypto_round_trip() -> None:
    pytest.importorskip("cryptography")
    from crypto_support import binding, context, payload

    from redact_secret_vault.crypto import create_record_crypto

    kms = FakeKms()
    crypto = create_record_crypto(key_provider=build(kms))

    async def scenario() -> None:
        records = ((binding("a"), payload(b"SYNTHETIC-VALUE-AAAA")), (binding("b"), payload(b"SYNTHETIC-VALUE-BBBB")))
        sealed = await crypto.seal_capture(context(), records)
        opened = await crypto.open_capture(
            StoredKey(sealed.key_ref, sealed.wrapped_key),
            context(),
            tuple((record[0], envelope) for record, envelope in zip(records, sealed.envelopes, strict=True)),
        )
        assert [bytes(item.value) for item in opened] == [b"SYNTHETIC-VALUE-AAAA", b"SYNTHETIC-VALUE-BBBB"]

    run(scenario())
    assert sorted({name for name, _ in kms.calls}) == ["Decrypt", "GenerateDataKey"]
