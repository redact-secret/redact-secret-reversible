"""``RecordCrypto`` over a ``KeyProvider``: round trips, tampering, swaps, bindings, provider failures, buffers."""

from __future__ import annotations

import asyncio
import dataclasses
import inspect
from typing import Any

import pytest
from crypto_support import (
    CAPTURE,
    CAPTURE_2,
    DEK,
    MATERIAL,
    NS,
    InsecureTestKeyProvider,
    ScriptedProvider,
    all_zero,
    binding,
    context,
    entry_id,
    payload,
    track_buffers,
)

pytest.importorskip("cryptography")

from redact_secret_vault import crypto  # noqa: E402
from redact_secret_vault.crypto import (  # noqa: E402
    LocalKey,
    LocalKeyScope,
    create_local_key_provider,
    create_record_crypto,
)
from redact_secret_vault.persistent import (  # noqa: E402
    DataKey,
    Grant,
    KeyProviderError,
    RecordCryptoError,
    StoredKey,
    limits,
)


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def local_provider(*, tenants: tuple[str, ...] | None = None) -> Any:
    return create_local_key_provider(
        keys=(LocalKey("2026-10", MATERIAL, "active"),), scope=LocalKeyScope((NS,), tenants)
    )


_DEFAULT: Any = object()


def seal(crypto_: Any, records: Any, ctx: Any = _DEFAULT) -> Any:
    return run(crypto_.seal_capture(context() if ctx is _DEFAULT else ctx, records))


def open_(crypto_: Any, sealed: Any, records: Any, ctx: Any = _DEFAULT) -> Any:
    stored = StoredKey(sealed.key_ref, sealed.wrapped_key)
    return run(crypto_.open_capture(stored, context() if ctx is _DEFAULT else ctx, records))


def failure(fn: Any) -> Exception:
    """The ``RecordCryptoError`` or ``KeyProviderError`` ``fn`` raises, with no link to anything else."""

    captured: Exception | None = None
    try:
        fn()
    except (RecordCryptoError, KeyProviderError) as thrown:
        captured = thrown
    assert captured is not None, "expected an error"
    assert captured.__cause__ is None
    assert captured.__context__ is None
    assert not hasattr(captured, "__notes__")
    return captured


def code_of(fn: Any) -> str:
    return failure(fn).code  # type: ignore[attr-defined]


# --------------------------------------------------------------------------
# Round trips
# --------------------------------------------------------------------------


def test_a_capture_of_several_entries_round_trips_in_order() -> None:
    rc = create_record_crypto(key_provider=local_provider())
    records = (
        (binding("a"), payload(b"SYNTHETIC-ONE", type="type-one")),
        (
            binding("b", session_id="session-synthetic", max_uses=3),
            payload(b"", type="type-two", grants=(Grant("sink-b", ("z", "a")), Grant("sink-a", ("body",)))),
        ),
        (binding("c"), payload(b"\x00\xff" * 1000, policy_revision="rev-1")),
    )
    sealed = seal(rc, records)
    assert sealed.key_ref == "local:2026-10"
    assert len(sealed.envelopes) == 3 and len(set(sealed.envelopes)) == 3
    opened = open_(rc, sealed, tuple((b, e) for (b, _), e in zip(records, sealed.envelopes, strict=True)))
    assert [bytes(p.value) for p in opened] == [b"SYNTHETIC-ONE", b"", b"\x00\xff" * 1000]
    assert [p.type for p in opened] == ["type-one", "type-two", "synthetic-finding-type"]
    assert opened[1].grants == (Grant("sink-a", ("body",)), Grant("sink-b", ("a", "z")))
    assert [p.policy_revision for p in opened] == [None, None, "rev-1"]
    assert all(isinstance(p.value, bytearray) for p in opened)


def test_every_seal_draws_fresh_nonces_and_a_fresh_data_key() -> None:
    rc = create_record_crypto(key_provider=local_provider())
    records = ((binding("a"), payload()),)
    first, second = seal(rc, records), seal(rc, records)
    assert first.envelopes != second.envelopes
    assert first.wrapped_key != second.wrapped_key
    nonces = {e[6:18] for e in (*first.envelopes, *second.envelopes)}
    assert len(nonces) == 2


def test_the_provider_is_called_once_per_operation() -> None:
    provider = InsecureTestKeyProvider(acknowledge_insecure="test-only")
    rc = create_record_crypto(key_provider=provider)
    records = tuple((binding(c), payload()) for c in "abc")
    sealed = seal(rc, records)
    assert provider.calls == 1
    open_(rc, sealed, tuple((b, e) for (b, _), e in zip(records, sealed.envelopes, strict=True)))
    assert provider.calls == 2
    run(rc.rewrap_capture_key(StoredKey(sealed.key_ref, sealed.wrapped_key), context()))
    assert provider.calls == 3
    assert rc.profile == "aes-256-gcm-hkdf-v1"


def test_rewrap_keeps_the_data_key_and_changes_the_wrapped_form() -> None:
    old = create_local_key_provider(keys=(LocalKey("old", MATERIAL, "active"),), scope=LocalKeyScope((NS,)))
    rc_old = create_record_crypto(key_provider=old)
    records = ((binding("a"), payload()),)
    sealed = seal(rc_old, records)
    rotated = create_local_key_provider(
        keys=(LocalKey("new", bytes(range(32)), "active"), LocalKey("old", MATERIAL, "decrypt-only")),
        scope=LocalKeyScope((NS,)),
    )
    rc = create_record_crypto(key_provider=rotated)
    new_key = run(rc.rewrap_capture_key(StoredKey(sealed.key_ref, sealed.wrapped_key), context()))
    assert new_key.key_ref == "local:new" and new_key.wrapped_key != sealed.wrapped_key
    opened = run(rc.open_capture(new_key, context(), ((binding("a"), sealed.envelopes[0]),)))
    assert bytes(opened[0].value) == b"SYNTHETIC-VALUE-0001"


# --------------------------------------------------------------------------
# Tampering and swaps
# --------------------------------------------------------------------------


def one_sealed() -> tuple[Any, Any, Any]:
    rc = create_record_crypto(key_provider=local_provider())
    records = ((binding("a", session_id="session-synthetic"), payload()),)
    return rc, records, seal(rc, records)


def test_flipping_any_bit_of_an_envelope_is_rejected_and_never_returns_a_payload() -> None:
    rc, records, sealed = one_sealed()
    envelope = sealed.envelopes[0]
    for index in range(len(envelope)):
        for bit in (0, 7):
            tampered = bytearray(envelope)
            tampered[index] ^= 1 << bit
            error = failure(lambda t=bytes(tampered): open_(rc, sealed, ((records[0][0], t),)))
            assert isinstance(error, RecordCryptoError)
            if index < 4:
                expected = {"RECORD_MALFORMED"}
            elif index < 6:
                expected = {"RECORD_UNSUPPORTED"}
            elif index < 18 or index >= 22:
                expected = {"RECORD_INTEGRITY"}
            else:
                expected = {"RECORD_MALFORMED", "RECORD_LIMIT"}
            assert error.code in expected, (index, bit, error.code)


def test_a_truncated_or_extended_envelope_is_rejected() -> None:
    rc, records, sealed = one_sealed()
    envelope = sealed.envelopes[0]
    for changed in (envelope[:-1], envelope + b"\x00", envelope[:21], b""):
        assert code_of(lambda c=changed: open_(rc, sealed, ((records[0][0], c),))).startswith("RECORD_")


@pytest.mark.parametrize(
    "patch",
    [
        {"session_id": "session-other"},
        {"session_id": None},
        {"created_at": 1_790_000_000_001},
        {"expires_at": 1_790_003_600_001},
        {"max_uses": 2},
    ],
)
def test_a_changed_binding_field_fails_authentication(patch: dict[str, Any]) -> None:
    rc, records, sealed = one_sealed()
    changed = dataclasses.replace(records[0][0], **patch)
    assert code_of(lambda: open_(rc, sealed, ((changed, sealed.envelopes[0]),))) == "RECORD_INTEGRITY"


def test_an_envelope_swapped_between_entries_of_one_capture_fails() -> None:
    rc = create_record_crypto(key_provider=local_provider())
    records = ((binding("a"), payload(b"SYNTHETIC-A")), (binding("b"), payload(b"SYNTHETIC-B")))
    sealed = seal(rc, records)
    swapped = ((records[0][0], sealed.envelopes[1]), (records[1][0], sealed.envelopes[0]))
    assert code_of(lambda: open_(rc, sealed, swapped)) == "RECORD_INTEGRITY"


def test_an_envelope_swapped_between_captures_tenants_or_sessions_fails() -> None:
    rc = create_record_crypto(key_provider=local_provider())
    # The same token and therefore the same entry identifier in two captures, two tenants, two sessions.
    one = seal(rc, ((binding("a"), payload(b"SYNTHETIC-1")),), context(CAPTURE))
    two = seal(rc, ((binding("a", capture=CAPTURE_2), payload(b"SYNTHETIC-2")),), context(CAPTURE_2))
    # Capture 2's envelope under capture 1's key and binding: another data key.
    assert code_of(lambda: open_(rc, one, ((binding("a"), two.envelopes[0]),), context(CAPTURE))) == "RECORD_INTEGRITY"
    # Capture 2's envelope under capture 2's key but capture 1's binding: the key is for another context.
    stored2 = StoredKey(two.key_ref, two.wrapped_key)
    other_ctx = run(
        rc.open_capture(stored2, context(CAPTURE_2), ((binding("a", capture=CAPTURE_2), two.envelopes[0]),))
    )
    assert bytes(other_ctx[0].value) == b"SYNTHETIC-2"
    assert (
        code_of(lambda: run(rc.open_capture(stored2, context(CAPTURE), ((binding("a"), two.envelopes[0]),))))
        == "KEY_INTEGRITY"
    )
    # Tenants: same provider scope, two tenants.
    tenant_b = "tenant-other-synthetic"
    t1 = seal(rc, ((binding("a"), payload()),), context())
    t2 = seal(rc, ((binding("a", tenant=tenant_b), payload()),), context(tenant=tenant_b))
    assert (
        code_of(lambda: open_(rc, t1, ((binding("a", tenant=tenant_b), t2.envelopes[0]),), context(tenant=tenant_b)))
        == "KEY_INTEGRITY"
    )
    # Sessions: one capture key, the envelope of a session-bound entry offered under another session.
    sess = seal(rc, ((binding("a", session_id="session-1"), payload()),))
    assert (
        code_of(lambda: open_(rc, sess, ((binding("a", session_id="session-2"), sess.envelopes[0]),)))
        == "RECORD_INTEGRITY"
    )


def test_a_wrapped_key_of_another_capture_fails_as_key_integrity() -> None:
    rc = create_record_crypto(key_provider=local_provider())
    one = seal(rc, ((binding("a"), payload()),), context(CAPTURE))
    two = seal(rc, ((binding("a", capture=CAPTURE_2), payload()),), context(CAPTURE_2))
    stored = StoredKey(two.key_ref, two.wrapped_key)
    assert (
        code_of(lambda: run(rc.open_capture(stored, context(CAPTURE), ((binding("a"), one.envelopes[0]),))))
        == "KEY_INTEGRITY"
    )


def test_a_wrong_key_reference_never_falls_back_to_another_key() -> None:
    rc = create_record_crypto(key_provider=local_provider())
    sealed = seal(rc, ((binding("a"), payload()),))
    stored = StoredKey("local:2026-07", sealed.wrapped_key)
    assert (
        code_of(lambda: run(rc.open_capture(stored, context(), ((binding("a"), sealed.envelopes[0]),))))
        == "KEY_UNAVAILABLE"
    )


def test_open_is_all_or_nothing_and_leaves_no_decrypted_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    rc = create_record_crypto(key_provider=local_provider())
    records = tuple((binding(c), payload(f"SYNTHETIC-{c}".encode())) for c in "abc")
    sealed = seal(rc, records)
    envelopes = list(sealed.envelopes)
    tampered = bytearray(envelopes[1])
    tampered[-1] ^= 1
    envelopes[1] = bytes(tampered)
    created = track_buffers(monkeypatch)
    pairs = tuple((b, e) for (b, _), e in zip(records, envelopes, strict=True))
    assert code_of(lambda: open_(rc, sealed, pairs)) == "RECORD_INTEGRITY"
    assert created, "the allocator was not injected"
    assert all_zero(created)


# --------------------------------------------------------------------------
# Bindings and arguments
# --------------------------------------------------------------------------


def test_a_duplicate_entry_is_rejected_by_seal_and_open() -> None:
    rc = create_record_crypto(key_provider=InsecureTestKeyProvider(acknowledge_insecure="test-only"))
    twice = ((binding("a"), payload()), (binding("a"), payload()))
    assert code_of(lambda: seal(rc, twice)) == "RECORD_INVALID_ARGUMENT"
    assert (
        code_of(
            lambda: run(
                rc.open_capture(StoredKey("k:1", b"x"), context(), ((binding("a"), b"e"), (binding("a"), b"e")))
            )
        )
        == "RECORD_INVALID_ARGUMENT"
    )


@pytest.mark.parametrize(
    "patch",
    [{"namespace": "ns-other"}, {"tenant": "tenant-other"}, {"capture_id": CAPTURE_2}],
)
def test_a_binding_outside_the_context_is_rejected(patch: dict[str, Any]) -> None:
    provider = InsecureTestKeyProvider(acknowledge_insecure="test-only")
    rc = create_record_crypto(key_provider=provider)
    mismatched = dataclasses.replace(binding("a"), **patch)
    assert code_of(lambda: seal(rc, ((mismatched, payload()),))) == "RECORD_INVALID_ARGUMENT"
    assert provider.calls == 0


def test_malformed_arguments_are_rejected_before_the_provider_is_called() -> None:
    provider = InsecureTestKeyProvider(acknowledge_insecure="test-only")
    rc = create_record_crypto(key_provider=provider)
    good = (binding("a"), payload())
    bad_records: list[Any] = [
        (),
        [good],
        (good, None),
        (good[0],),
        ((binding("a"), "not a payload"),),
        ((dataclasses.replace(binding("a"), max_uses=0), payload()),),
        ((binding("a"), payload(type="")),),
        ((binding("a"), payload(grants=())),),
        ((binding("a"), payload(type="lone-\ud800")),),
        None,
    ]
    for records in bad_records:
        assert code_of(lambda r=records: seal(rc, r)) == "RECORD_INVALID_ARGUMENT"
    for bad_context in (
        None,
        "ctx",
        dataclasses.replace(context(), capture_id="cap_short"),
        dataclasses.replace(context(), tenant=""),
    ):
        assert code_of(lambda c=bad_context: seal(rc, (good,), c)) == "RECORD_INVALID_ARGUMENT"
    assert code_of(lambda: seal(rc, ((binding("a"), payload(b"x" * (limits.MAX_VALUE_BYTES + 1))),))) == "RECORD_LIMIT"
    assert provider.calls == 0


def test_the_entry_ceilings_are_enforced_before_any_cryptography() -> None:
    provider = InsecureTestKeyProvider(acknowledge_insecure="test-only")
    rc = create_record_crypto(key_provider=provider)
    too_many_for_seal = tuple((binding("a"), payload()) for _ in range(limits.MAX_CREATE_ENTRIES + 1))
    assert code_of(lambda: seal(rc, too_many_for_seal)) == "RECORD_LIMIT"
    too_many_for_open = tuple((binding("a"), b"e") for _ in range(limits.MAX_RESTORE_ENTRIES + 1))
    assert code_of(lambda: run(rc.open_capture(StoredKey("k:1", b"x"), context(), too_many_for_open))) == "RECORD_LIMIT"
    assert provider.calls == 0


def test_open_refuses_a_malformed_envelope_or_stored_key_before_unwrapping() -> None:
    provider = InsecureTestKeyProvider(acknowledge_insecure="test-only")
    rc = create_record_crypto(key_provider=provider)
    pair = ((binding("a"), b"not an envelope"),)
    assert code_of(lambda: run(rc.open_capture(StoredKey("k:1", b"x"), context(), pair))) == "RECORD_MALFORMED"
    envelope_ok = seal(create_record_crypto(key_provider=provider), ((binding("a"), payload()),)).envelopes[0]
    provider.calls = 0
    for stored, expected in (
        (StoredKey("", b"x"), "RECORD_INVALID_ARGUMENT"),
        (StoredKey("k:1", b""), "RECORD_INVALID_ARGUMENT"),
        (StoredKey("k:1", bytes(limits.WRAPPED_KEY_MAX_BYTES + 1)), "RECORD_LIMIT"),
        ("stored", "RECORD_INVALID_ARGUMENT"),
    ):
        assert code_of(lambda s=stored: run(rc.open_capture(s, context(), ((binding("a"), envelope_ok),)))) == expected
    assert provider.calls == 0


def test_create_record_crypto_validates_its_arguments() -> None:
    provider = InsecureTestKeyProvider(acknowledge_insecure="test-only")
    for bad in (None, object(), "provider"):
        assert code_of(lambda b=bad: create_record_crypto(key_provider=b)) == "RECORD_INVALID_ARGUMENT"
    for timeout in (0, -1, True, float("nan"), float("inf"), "5", None, 10**9):
        assert (
            code_of(lambda t=timeout: create_record_crypto(key_provider=provider, key_timeout_s=t))
            == "RECORD_INVALID_ARGUMENT"
        )
    assert create_record_crypto(key_provider=provider, key_timeout_s=0.5)
    assert create_record_crypto(key_provider=provider, key_timeout_s=3)


def test_no_public_entry_point_takes_a_nonce() -> None:
    public = [getattr(crypto, name) for name in crypto.__all__]
    checked = 0
    for obj in public:
        targets = [obj] + [
            getattr(obj, n) for n in dir(obj) if not n.startswith("_") and callable(getattr(obj, n, None))
        ]
        for target in targets:
            try:
                signature = inspect.signature(target)
            except (TypeError, ValueError):
                continue
            checked += 1
            assert not [p for p in signature.parameters if "nonce" in p.lower() or p in {"iv", "salt"}], target
    assert checked > 10
    for name in ("seal_capture", "open_capture", "rewrap_capture_key"):
        method = getattr(crypto.KeyProviderRecordCrypto, name)
        assert list(inspect.signature(method).parameters)[:1] == ["self"]
        assert "nonce" not in inspect.signature(method).parameters


# --------------------------------------------------------------------------
# A provider that fails, stalls, or misbehaves
# --------------------------------------------------------------------------


async def good_key(_: Any) -> DataKey:
    return DataKey("test:k", b"wrapped", bytearray(DEK))


def scripted(**handlers: Any) -> ScriptedProvider:
    return ScriptedProvider(**handlers)


@pytest.mark.parametrize(
    "code", ["KEY_UNAVAILABLE", "KEY_INTEGRITY", "KEY_TIMEOUT", "KEY_THROTTLED", "KEY_ABORTED", "KEY_INVALID_ARGUMENT"]
)
def test_a_key_provider_error_passes_as_a_fresh_error_with_the_same_code(code: str) -> None:
    async def fail(*_: Any) -> Any:
        raise KeyProviderError(code)  # type: ignore[arg-type]

    rc = create_record_crypto(key_provider=scripted(generate=fail, unwrap=fail, rewrap=fail))
    error = failure(lambda: seal(rc, ((binding("a"), payload()),)))
    assert isinstance(error, KeyProviderError) and error.code == code
    stored = StoredKey("k:1", b"x")
    assert code_of(lambda: run(rc.open_capture(stored, context(), ((binding("a"), seal_for_open()),)))) == code
    assert code_of(lambda: run(rc.rewrap_capture_key(stored, context()))) == code


def seal_for_open() -> bytes:
    rc = create_record_crypto(key_provider=InsecureTestKeyProvider(acknowledge_insecure="test-only"))
    return seal(rc, ((binding("a"), payload()),)).envelopes[0]


def test_a_foreign_exception_from_the_provider_becomes_key_unavailable() -> None:
    marker = "SENTINEL-DRIVER-MESSAGE-7f3a"

    async def explode(*_: Any) -> Any:
        raise RuntimeError(marker)

    rc = create_record_crypto(key_provider=scripted(generate=explode, unwrap=explode, rewrap=explode))
    error = failure(lambda: seal(rc, ((binding("a"), payload()),)))
    assert isinstance(error, KeyProviderError) and error.code == "KEY_UNAVAILABLE"
    assert marker not in repr(error) + str(error) + repr(error.args)


def test_a_provider_that_does_not_answer_in_time_is_a_timeout_and_its_late_key_is_overwritten() -> None:
    late: list[bytearray] = []

    async def slow(_: Any) -> DataKey:
        await asyncio.sleep(0.15)
        key = bytearray(DEK)
        late.append(key)
        return DataKey("test:k", b"wrapped", key)

    rc = create_record_crypto(key_provider=scripted(generate=slow), key_timeout_s=0.05)

    async def scenario() -> None:
        with pytest.raises(KeyProviderError) as caught:
            await rc.seal_capture(context(), ((binding("a"), payload()),))
        assert caught.value.code == "KEY_TIMEOUT"
        assert caught.value.__cause__ is None and caught.value.__context__ is None
        await asyncio.sleep(0.2)

    run(scenario())
    # The task was cancelled at its await, so it never produced a key; if it had, it would be zero.
    assert all(not any(k) for k in late)


def test_a_late_result_after_a_timeout_is_overwritten_when_the_provider_ignores_cancellation() -> None:
    produced: list[bytearray] = []

    async def stubborn(_: Any) -> DataKey:
        try:
            await asyncio.sleep(0.15)
        except asyncio.CancelledError:
            pass  # a provider that swallows cancellation and answers anyway
        key = bytearray(DEK)
        produced.append(key)
        return DataKey("test:k", b"wrapped", key)

    rc = create_record_crypto(key_provider=scripted(generate=stubborn), key_timeout_s=0.05)

    async def scenario() -> None:
        with pytest.raises(KeyProviderError) as caught:
            await rc.seal_capture(context(), ((binding("a"), payload()),))
        assert caught.value.code == "KEY_TIMEOUT"
        await asyncio.sleep(0.2)

    run(scenario())
    assert produced and all(not any(k) for k in produced)


def test_cancelling_the_caller_propagates_and_overwrites_the_key_that_arrives_late() -> None:
    produced: list[bytearray] = []

    async def slow(_: Any) -> DataKey:
        try:
            await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            pass
        key = bytearray(DEK)
        produced.append(key)
        return DataKey("test:k", b"wrapped", key)

    rc = create_record_crypto(key_provider=scripted(generate=slow), key_timeout_s=5)

    async def scenario() -> None:
        task = asyncio.ensure_future(rc.seal_capture(context(), ((binding("a"), payload()),)))
        await asyncio.sleep(0.02)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.2)

    run(scenario())
    assert produced and all(not any(k) for k in produced)


def test_a_provider_that_returns_something_out_of_contract_is_key_unavailable_and_its_key_is_overwritten() -> None:
    wrong_size = bytearray(b"\x01" * 16)
    as_bytes = DataKey("test:k", b"w", bytes(DEK))  # type: ignore[arg-type]
    empty_wrapped = DataKey("test:k", b"", bytearray(DEK))
    empty_ref = DataKey("", b"w", bytearray(DEK))
    short = DataKey("test:k", b"w", wrong_size)
    for result in (short, as_bytes, empty_wrapped, empty_ref, "key", None, {"plaintext_key": bytearray(DEK)}):

        async def generate(_: Any, result: Any = result) -> Any:
            return result

        rc = create_record_crypto(key_provider=scripted(generate=generate))
        assert code_of(lambda rc=rc: seal(rc, ((binding("a"), payload()),))) == "KEY_UNAVAILABLE"
    assert not any(wrong_size)
    assert not any(empty_wrapped.plaintext_key) and not any(empty_ref.plaintext_key)

    for result in (bytearray(16), bytes(DEK), "key", None):

        async def unwrap(*_: Any, result: Any = result) -> Any:
            return result

        rc = create_record_crypto(key_provider=scripted(unwrap=unwrap))
        envelope = seal_for_open()
        stored = StoredKey("k:1", b"x")
        assert (
            code_of(lambda rc=rc, e=envelope, st=stored: run(rc.open_capture(st, context(), ((binding("a"), e),))))
            == "KEY_UNAVAILABLE"
        )

    async def rewrap(*_: Any) -> Any:
        return StoredKey("", b"w")

    rc = create_record_crypto(key_provider=scripted(rewrap=rewrap))
    assert code_of(lambda: run(rc.rewrap_capture_key(StoredKey("k:1", b"x"), context()))) == "KEY_UNAVAILABLE"


def test_a_provider_method_that_is_not_a_coroutine_is_key_unavailable() -> None:
    class Sync:
        profile = "sync"

        def generate_data_key(self, context: Any) -> Any:
            return DataKey("test:k", b"w", bytearray(DEK))

        def unwrap_data_key(self, stored: Any, context: Any) -> Any:
            return bytearray(DEK)

        def rewrap_data_key(self, stored: Any, context: Any) -> Any:
            return stored

    rc = create_record_crypto(key_provider=Sync())  # type: ignore[arg-type]
    assert code_of(lambda: seal(rc, ((binding("a"), payload()),))) == "KEY_UNAVAILABLE"


# --------------------------------------------------------------------------
# Buffers
# --------------------------------------------------------------------------


def test_buffers_are_zero_after_a_successful_seal(monkeypatch: pytest.MonkeyPatch) -> None:
    rc = create_record_crypto(key_provider=local_provider())
    created = track_buffers(monkeypatch)
    seal(rc, tuple((binding(c), payload()) for c in "abc"))
    assert len(created) >= 3 and all_zero(created)


def test_buffers_are_zero_after_a_successful_open_except_the_returned_values(monkeypatch: pytest.MonkeyPatch) -> None:
    rc = create_record_crypto(key_provider=local_provider())
    records = tuple((binding(c), payload()) for c in "abc")
    sealed = seal(rc, records)
    created = track_buffers(monkeypatch)
    opened = open_(rc, sealed, tuple((b, e) for (b, _), e in zip(records, sealed.envelopes, strict=True)))
    values = tuple(p.value for p in opened)
    assert all(any(v) for v in values), "the caller must be handed the plaintext"
    assert all_zero(created, except_=values)
    for value in values:  # the caller overwrites what it was handed
        value[:] = bytes(len(value))
    assert all_zero(created)


@pytest.mark.parametrize("stage", ["seal-invalid", "seal-provider", "open-integrity", "open-malformed", "open-key"])
def test_buffers_are_zero_after_every_failure_path(monkeypatch: pytest.MonkeyPatch, stage: str) -> None:
    rc = create_record_crypto(key_provider=local_provider())
    records = ((binding("a"), payload()), (binding("b"), payload()))
    sealed = seal(rc, records)
    pairs = tuple((b, e) for (b, _), e in zip(records, sealed.envelopes, strict=True))
    created = track_buffers(monkeypatch)
    if stage == "seal-invalid":
        failure(lambda: seal(rc, ((binding("a"), payload()), (binding("b"), payload(type="")))))
    elif stage == "seal-provider":
        bad = create_record_crypto(key_provider=scripted(generate=lambda _: _raise_foreign()))
        failure(lambda: seal(bad, records))
    elif stage == "open-integrity":
        tampered = bytearray(pairs[1][1])
        tampered[30] ^= 1
        failure(lambda: open_(rc, sealed, (pairs[0], (pairs[1][0], bytes(tampered)))))
    elif stage == "open-malformed":
        failure(lambda: open_(rc, sealed, (pairs[0], (pairs[1][0], b"junk"))))
    else:
        failure(lambda: run(rc.open_capture(StoredKey("local:nope", sealed.wrapped_key), context(), pairs)))
    assert all_zero(created)


async def _raise_foreign() -> Any:
    raise RuntimeError("provider failure")


# --------------------------------------------------------------------------
# Two sealed captures never share an entry key or a nonce, even for one value
# --------------------------------------------------------------------------


def test_the_same_value_sealed_twice_shares_no_ciphertext_prefix() -> None:
    rc = create_record_crypto(key_provider=local_provider())
    one = seal(rc, ((binding("a"), payload()),)).envelopes[0]
    two = seal(rc, ((binding("a"), payload()),)).envelopes[0]
    assert one[22:] != two[22:] and one[6:18] != two[6:18]
    assert len(one) == len(two)


def test_entry_identifiers_derive_from_the_tenant_so_equal_tokens_differ_between_tenants() -> None:
    assert entry_id("a") != entry_id("a", tenant="tenant-other-synthetic")
