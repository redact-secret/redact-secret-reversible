"""Validators, ported from packages/vault-contracts/test/validate.test.mjs.

Every case of that file is here, in the same order, followed by the cases the
Python type model adds: UTF-16 length, lone surrogates, ``bool`` and ``float``
as ``int``, the ``2**53`` boundary, and the absence of exception links.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from typing import Any

import pytest

from redact_secret_vault.persistent import (
    Attempt,
    CaptureGeneration,
    CommitRestoreInput,
    CreateCaptureInput,
    DeleteCiphertextInput,
    EntryUse,
    InspectAttemptInput,
    InvalidateRecoveredInput,
    NewCapture,
    NewEntry,
    ReadCapturesInput,
    ReadEntriesInput,
    ReplaceCaptureKeyInput,
    RevokeCaptureInput,
    StoreCapabilities,
    StoreError,
    StoreScope,
    SweepInput,
    is_capture_id,
    is_entry_id,
    is_identifier,
    is_key_ref,
    is_namespace,
    is_well_formed,
    limits,
    missing_capabilities,
    validate_commit_restore,
    validate_create_capture,
    validate_delete_ciphertext,
    validate_initialize_namespace,
    validate_inspect_attempt,
    validate_invalidate_recovered,
    validate_namespace,
    validate_read_captures,
    validate_read_entries,
    validate_replace_capture_key,
    validate_revoke_capture,
    validate_sweep,
)

scope = StoreScope("ns-synthetic", "tenant-acme-synthetic")
capture_id = "cap_" + "a" * 26
other_capture_id = "cap_" + "b" * 26
entry_id = "0" * 64
entry_id_2 = "1" * 64
MAX_INT = 2**53 - 1

caps = StoreCapabilities(
    contract_version=1,
    adapter="test",
    profile="test",
    atomic_create=True,
    max_create_entries=4,
    max_create_bytes=64,
    atomic_restore=True,
    max_restore_entries=4,
    max_restore_captures=2,
    authoritative_commit=True,
    revocation_fences=True,
    attempt_receipts=True,
    store_clock=True,
    max_clock_skew_ms=2000,
    durability="durable",
    cross_process=True,
    restore_detection="none",
    max_envelope_bytes=32,
)


def entry(**patch: Any) -> NewEntry:
    return NewEntry(**{"entry_id": entry_id, "max_uses": 1, "envelope": bytes(8), **patch})


def create(
    patch: dict[str, Any] | None = None, capture: dict[str, Any] | None = None, entries: Any = None
) -> CreateCaptureInput:
    new_capture = NewCapture(
        **{
            "capture_id": capture_id,
            "session_tag": None,
            "created_at": 1000,
            "expires_at": 2000,
            "lookup_version": 1,
            "key_ref": "local:k1",
            "wrapped_key": bytes([1]),
            **(capture or {}),
        }
    )
    base: dict[str, Any] = {
        "scope": scope,
        "epoch": 1,
        "now": 1000,
        "capture": new_capture,
        "entries": (entry(),) if entries is None else entries,
    }
    return CreateCaptureInput(**{**base, **(patch or {})})


def use(**patch: Any) -> EntryUse:
    return EntryUse(
        **{
            "entry_id": entry_id,
            "capture_id": capture_id,
            "count": 1,
            "lifecycle_revision": 1,
            "ciphertext_revision": 1,
            **patch,
        }
    )


def commit(**patch: Any) -> CommitRestoreInput:
    base: dict[str, Any] = {
        "scope": scope,
        "epoch": 1,
        "now": 1000,
        "attempt": Attempt("attempt-1", bytes(32)),
        "receipt_expires_at": 3000,
        "captures": (CaptureGeneration(capture_id, 1),),
        "uses": (use(),),
    }
    return CommitRestoreInput(**{**base, **patch})


def code(fn: Callable[[], None]) -> str:
    """The ``StoreError`` code ``fn`` raises, or ``"ok"``. Fails if the error carries a link."""

    captured: StoreError | None = None
    try:
        fn()
    except StoreError as thrown:
        captured = thrown
    if captured is None:
        return "ok"
    assert captured.__cause__ is None
    assert captured.__context__ is None
    assert not hasattr(captured, "__notes__")
    return captured.code


# --------------------------------------------------------------------------
# validate.test.mjs, case by case
# --------------------------------------------------------------------------


def test_identifier_predicates() -> None:
    assert is_namespace("support-prod.eu:1")
    assert not is_namespace("has space")
    assert not is_namespace("x" * 129)
    assert is_identifier("tenant-\U0001f600")
    assert not is_identifier("lone-\ud800")
    assert not is_identifier("\udc00-lone")
    assert not is_identifier("")
    assert not is_identifier("x" * 257)
    assert is_well_formed("\U0001f600")
    assert is_capture_id(capture_id)
    assert not is_capture_id("cap_" + "A" * 26)
    assert is_entry_id(entry_id)
    assert not is_entry_id("F" * 64)


def test_missing_capabilities_accepts_a_complete_store_and_names_each_gap() -> None:
    assert missing_capabilities(caps) == ()
    for flag in (
        "atomic_create",
        "atomic_restore",
        "authoritative_commit",
        "revocation_fences",
        "attempt_receipts",
        "store_clock",
    ):
        assert missing_capabilities(dataclasses.replace(caps, **{flag: False})) == (flag,)
    assert missing_capabilities(dataclasses.replace(caps, contract_version=2)) == ("contract_version",)  # type: ignore[arg-type]
    over = dataclasses.replace(caps, max_create_entries=limits.MAX_CREATE_ENTRIES + 1)
    assert missing_capabilities(over) == ("max_create_entries",)
    assert missing_capabilities(dataclasses.replace(caps, max_restore_captures=0)) == ("max_restore_captures",)
    assert missing_capabilities(dataclasses.replace(caps, max_clock_skew_ms=120_000)) == ("max_clock_skew_ms",)
    assert missing_capabilities(None) == ("capabilities",)


def test_create_capture_validation() -> None:
    assert code(lambda: validate_create_capture(create(), caps)) == "ok"
    bad = [
        create({"scope": StoreScope("bad ns", "t")}),
        create({"scope": StoreScope("ns", "lone-\ud800")}),
        create({"epoch": 0}),
        create({"now": 1.5}),
        create(capture={"capture_id": "cap_short"}),
        create(capture={"session_tag": "nothex"}),
        create(capture={"expires_at": 1000}),
        create(capture={"expires_at": 1000 + limits.MAX_CAPTURE_LIFETIME_MS + 1}),
        create(capture={"lookup_version": 2}),
        create(capture={"key_ref": ""}),
        create(capture={"wrapped_key": b""}),
        create(capture={"wrapped_key": bytes(limits.WRAPPED_KEY_MAX_BYTES + 1)}),
        create(entries=()),
        create(entries=(entry(), entry())),
        create(entries=(entry(max_uses=0),)),
        create(entries=(entry(max_uses=limits.MAX_USES + 1),)),
        create(entries=(entry(envelope=b""),)),
        create(entries=(entry(entry_id="zz"),)),
    ]
    for item in bad:
        assert code(lambda item=item: validate_create_capture(item, caps)) == "STORE_INVALID_ARGUMENT"
    session = create(capture={"session_tag": "a" * 64})
    assert code(lambda: validate_create_capture(session, caps)) == "ok"

    many = tuple(entry(entry_id=str(i) * 64, envelope=bytes(1)) for i in range(5))
    assert code(lambda: validate_create_capture(create(entries=many), caps)) == "STORE_CAPABILITY"
    too_big = create(entries=(entry(envelope=bytes(33)),))
    assert code(lambda: validate_create_capture(too_big, caps)) == "STORE_CAPABILITY"
    heavy = tuple(entry(entry_id=str(i) * 64, envelope=bytes(32)) for i in range(3))
    assert code(lambda: validate_create_capture(create(entries=heavy), caps)) == "STORE_CAPABILITY"


def test_commit_restore_validation() -> None:
    assert code(lambda: validate_commit_restore(commit(), caps)) == "ok"
    one = use()
    bad = [
        commit(attempt=Attempt("bad id", bytes(32))),
        commit(attempt=Attempt("a", bytes(31))),
        commit(captures=()),
        commit(uses=()),
        commit(uses=(one, one)),
        commit(captures=(CaptureGeneration(capture_id, 1), CaptureGeneration(capture_id, 1))),
        commit(uses=(use(count=0),)),
        commit(uses=(use(count=-1),)),
        commit(uses=(use(count=1.5),)),
        commit(uses=(use(capture_id=other_capture_id),)),
        commit(captures=(CaptureGeneration(capture_id, 1), CaptureGeneration(other_capture_id, 1))),
        commit(uses=(use(lifecycle_revision=0),)),
        commit(receipt_expires_at=-1),
        commit(epoch=1.2),
    ]
    for item in bad:
        assert code(lambda item=item: validate_commit_restore(item, caps)) == "STORE_INVALID_ARGUMENT"
    five = tuple(use(entry_id=str(i) * 64) for i in range(5))
    assert code(lambda: validate_commit_restore(commit(uses=five), caps)) == "STORE_CAPABILITY"


def test_remaining_operation_validators() -> None:
    def ok(fn: Callable[[], None]) -> None:
        assert code(fn) == "ok"

    def invalid(fn: Callable[[], None]) -> None:
        assert code(fn) == "STORE_INVALID_ARGUMENT"

    ok(lambda: validate_read_entries(ReadEntriesInput(scope, (entry_id, entry_id_2)), caps))
    invalid(lambda: validate_read_entries(ReadEntriesInput(scope, (entry_id, entry_id)), caps))
    invalid(lambda: validate_read_entries(ReadEntriesInput(scope, ()), caps))
    ok(lambda: validate_read_captures(ReadCapturesInput(scope, (capture_id,)), caps))
    invalid(lambda: validate_read_captures(ReadCapturesInput(scope, ("x",)), caps))

    revoke = RevokeCaptureInput(scope, capture_id, 1, 0, False)
    ok(lambda: validate_revoke_capture(revoke))
    invalid(lambda: validate_revoke_capture(dataclasses.replace(revoke, retention_ms=limits.MAX_RETENTION_MS + 1)))
    invalid(lambda: validate_revoke_capture(dataclasses.replace(revoke, fence_absent="yes")))  # type: ignore[arg-type]

    replace = ReplaceCaptureKeyInput(scope, capture_id, 1, "local:k2", bytes([1]))
    ok(lambda: validate_replace_capture_key(replace))
    invalid(lambda: validate_replace_capture_key(dataclasses.replace(replace, key_ref="x" * 513)))

    ok(lambda: validate_delete_ciphertext(DeleteCiphertextInput(scope, capture_id, 1)))
    invalid(lambda: validate_delete_ciphertext(DeleteCiphertextInput(scope, capture_id, -1)))
    ok(lambda: validate_sweep(SweepInput("ns", 1, 10)))
    invalid(lambda: validate_sweep(SweepInput("ns", 1, 0)))
    invalid(lambda: validate_sweep(SweepInput("ns", 1, limits.MAX_SWEEP_LIMIT + 1)))
    ok(lambda: validate_initialize_namespace("ns", 1))
    invalid(lambda: validate_initialize_namespace("ns", 0))
    ok(lambda: validate_invalidate_recovered(InvalidateRecoveredInput("ns", 2)))
    invalid(lambda: validate_invalidate_recovered(InvalidateRecoveredInput("n s", 2)))


# --------------------------------------------------------------------------
# What the Python type model adds
# --------------------------------------------------------------------------


def test_the_remaining_validators_reject_a_foreign_object_and_inspect_attempt_checks_its_fields() -> None:
    ok_input = InspectAttemptInput(scope, "attempt-1")
    assert code(lambda: validate_inspect_attempt(ok_input)) == "ok"
    for bad in (InspectAttemptInput(scope, "bad id"), InspectAttemptInput(scope, ""), object(), None, {}):
        assert code(lambda bad=bad: validate_inspect_attempt(bad)) == "STORE_INVALID_ARGUMENT"  # type: ignore[arg-type]
    assert code(lambda: validate_namespace("ns")) == "ok"
    assert code(lambda: validate_namespace("n s")) == "STORE_INVALID_ARGUMENT"


def test_every_validator_rejects_none_and_a_wrong_type() -> None:
    for fn in (
        lambda v: validate_create_capture(v, caps),
        lambda v: validate_read_entries(v, caps),
        lambda v: validate_read_captures(v, caps),
        lambda v: validate_commit_restore(v, caps),
        validate_revoke_capture,
        validate_inspect_attempt,
        validate_replace_capture_key,
        validate_delete_ciphertext,
        validate_sweep,
        validate_invalidate_recovered,
    ):
        for bad in (None, 0, "scope", scope, {}):
            assert code(lambda fn=fn, bad=bad: fn(bad)) == "STORE_INVALID_ARGUMENT"


def test_utf16_length_is_counted_in_code_units_not_code_points() -> None:
    # 128 supplementary characters are 256 UTF-16 units: accepted. 129 are 258: rejected.
    assert is_identifier("\U0001f600" * 128)
    assert not is_identifier("\U0001f600" * 129)
    # 200 supplementary characters are 400 units, although len() says 200.
    assert not is_identifier("\U0001f600" * 200)
    assert len("\U0001f600" * 200) == 200
    # 256 BMP characters are accepted; 257 are not.
    assert is_identifier("a" * 256)
    assert not is_identifier("a" * 257)
    # The same counting reaches a tenant in a scope.
    long_tenant = StoreScope("ns", "\U0001f600" * 200)
    assert (
        code(lambda: validate_read_entries(ReadEntriesInput(long_tenant, (entry_id,)), caps))
        == "STORE_INVALID_ARGUMENT"
    )


def test_a_key_reference_is_limited_in_utf8_bytes() -> None:
    assert is_key_ref("k" * 512)
    assert not is_key_ref("k" * 513)
    assert is_key_ref("é" * 256)  # 2 bytes each: 512 bytes
    assert not is_key_ref("é" * 257)
    assert is_key_ref("\U0001f600" * 128)  # 4 bytes each: 512 bytes
    assert not is_key_ref("\U0001f600" * 129)
    assert not is_key_ref("")
    assert not is_key_ref("key-\ud800")


def test_a_surrogate_code_point_is_never_well_formed() -> None:
    assert is_well_formed("")
    assert is_well_formed("plain")
    for text in ("\ud800", "\udc00", "a\ud800b", chr(0xD83D) + chr(0xDE00), "\udfff\ud800"):
        assert not is_well_formed(text)
        assert not is_identifier(text)
        assert not is_key_ref(text)
    # A real supplementary character is one code point and is well-formed.
    assert is_well_formed(chr(0x1F600))
    assert not is_well_formed(b"bytes")
    assert not is_well_formed(None)


def test_no_normalization_is_applied() -> None:
    nfc = "café"
    nfd = "café"
    assert nfc != nfd
    assert is_identifier(nfc) and is_identifier(nfd)


def test_patterns_are_anchored_ascii_and_reject_a_trailing_newline() -> None:
    assert not is_namespace("ns\n")
    assert not is_namespace("٣")
    assert not is_namespace("nsé")
    assert not is_capture_id(capture_id + "\n")
    assert not is_entry_id(entry_id + "\n")
    assert not is_entry_id("٠" * 64)
    assert not is_capture_id("cap_" + "ａ" * 26)  # fullwidth a


@pytest.mark.parametrize("bad", [True, False, 1.0, 2.0, float("nan"), float("inf"), "1", None, b"1"])
def test_a_bool_a_float_or_a_non_number_is_never_an_int(bad: Any) -> None:
    assert code(lambda: validate_create_capture(create({"epoch": bad}), caps)) == "STORE_INVALID_ARGUMENT"
    assert code(lambda: validate_create_capture(create({"now": bad}), caps)) == "STORE_INVALID_ARGUMENT"
    assert code(lambda: validate_create_capture(create(capture={"created_at": bad}), caps)) == "STORE_INVALID_ARGUMENT"
    assert (
        code(lambda: validate_create_capture(create(entries=(entry(max_uses=bad),)), caps)) == "STORE_INVALID_ARGUMENT"
    )
    assert code(lambda: validate_commit_restore(commit(uses=(use(count=bad),)), caps)) == "STORE_INVALID_ARGUMENT"
    assert code(lambda: validate_sweep(SweepInput("ns", bad, 1))) == "STORE_INVALID_ARGUMENT"
    assert code(lambda: validate_sweep(SweepInput("ns", 1, bad))) == "STORE_INVALID_ARGUMENT"


def test_true_is_not_an_acceptable_lookup_version_or_flag() -> None:
    # True == 1 in Python; the checks use the exact type.
    assert (
        code(lambda: validate_create_capture(create(capture={"lookup_version": True}), caps))
        == "STORE_INVALID_ARGUMENT"
    )
    assert missing_capabilities(dataclasses.replace(caps, contract_version=True)) == ("contract_version",)  # type: ignore[arg-type]
    assert missing_capabilities(dataclasses.replace(caps, atomic_create=1)) == ("atomic_create",)  # type: ignore[arg-type]
    assert missing_capabilities(dataclasses.replace(caps, cross_process=1)) == ("cross_process",)  # type: ignore[arg-type]


def test_the_two_to_the_fifty_three_boundary() -> None:
    # Timestamps and the epoch accept 2**53 - 1 and reject 2**53.
    assert code(lambda: validate_sweep(SweepInput("ns", MAX_INT, 1))) == "ok"
    assert code(lambda: validate_sweep(SweepInput("ns", MAX_INT + 1, 1))) == "STORE_INVALID_ARGUMENT"
    assert code(lambda: validate_sweep(SweepInput("ns", -1, 1))) == "STORE_INVALID_ARGUMENT"
    assert code(lambda: validate_initialize_namespace("ns", MAX_INT)) == "ok"
    assert code(lambda: validate_initialize_namespace("ns", MAX_INT + 1)) == "STORE_INVALID_ARGUMENT"
    assert code(lambda: validate_initialize_namespace("ns", 2**64)) == "STORE_INVALID_ARGUMENT"
    near = create({"epoch": MAX_INT, "now": MAX_INT}, {"created_at": MAX_INT - 1000, "expires_at": MAX_INT})
    assert code(lambda: validate_create_capture(near, caps)) == "ok"
    beyond = create(capture={"created_at": MAX_INT, "expires_at": MAX_INT + 1})
    assert code(lambda: validate_create_capture(beyond, caps)) == "STORE_INVALID_ARGUMENT"
    receipt = commit(receipt_expires_at=MAX_INT)
    assert code(lambda: validate_commit_restore(receipt, caps)) == "ok"
    assert (
        code(lambda: validate_commit_restore(commit(receipt_expires_at=MAX_INT + 1), caps)) == "STORE_INVALID_ARGUMENT"
    )
    revision = commit(
        uses=(use(lifecycle_revision=MAX_INT, ciphertext_revision=MAX_INT),),
        captures=(CaptureGeneration(capture_id, MAX_INT),),
    )
    assert code(lambda: validate_commit_restore(revision, caps)) == "ok"
    too_far = commit(captures=(CaptureGeneration(capture_id, MAX_INT + 1),))
    assert code(lambda: validate_commit_restore(too_far, caps)) == "STORE_INVALID_ARGUMENT"
    # A capability above 2**53 - 1 is not a usable limit.
    assert missing_capabilities(dataclasses.replace(caps, max_create_bytes=MAX_INT + 1)) == ("max_create_bytes",)
    assert missing_capabilities(dataclasses.replace(caps, max_create_bytes=MAX_INT)) == ()


def test_byte_fields_accept_bytes_only() -> None:
    for bad in (bytearray(8), memoryview(bytes(8)), "x" * 8, [0] * 8, None):
        item = create(entries=(entry(envelope=bad),))
        assert code(lambda item=item: validate_create_capture(item, caps)) == "STORE_INVALID_ARGUMENT"
    for bad in (bytearray(1), "k", None):
        item = create(capture={"wrapped_key": bad})
        assert code(lambda item=item: validate_create_capture(item, caps)) == "STORE_INVALID_ARGUMENT"


def test_a_list_cannot_stand_in_for_a_tuple() -> None:
    # A list could change after validation.
    assert code(lambda: validate_create_capture(create(entries=[entry()]), caps)) == "STORE_INVALID_ARGUMENT"
    assert code(lambda: validate_read_entries(ReadEntriesInput(scope, [entry_id]), caps)) == "STORE_INVALID_ARGUMENT"  # type: ignore[arg-type]
    assert code(lambda: validate_commit_restore(commit(uses=[use()]), caps)) == "STORE_INVALID_ARGUMENT"


def test_a_str_subclass_is_not_a_str() -> None:
    class Spoof(str):
        __slots__ = ()

    assert not is_namespace(Spoof("ns"))
    assert not is_identifier(Spoof("tenant"))
    assert not is_entry_id(Spoof(entry_id))


def test_validators_do_not_mutate_or_keep_their_input() -> None:
    item = create()
    before = repr(item)
    validate_create_capture(item, caps)
    assert repr(item) == before


def test_each_error_has_no_cause_context_or_notes_and_a_one_frame_traceback() -> None:
    captured: StoreError | None = None
    try:
        validate_create_capture(create({"epoch": 0}), caps)
    except StoreError as thrown:
        captured = thrown
    assert captured is not None
    assert captured.__cause__ is None
    assert captured.__context__ is None
    assert not hasattr(captured, "__notes__")
    frames = []
    tb = captured.__traceback__
    while tb is not None:
        frames.append(tb.tb_frame.f_code.co_name)
        tb = tb.tb_next
    # Only the test frame and the entry point; no internal helper frame holds the input.
    assert frames == [
        "test_each_error_has_no_cause_context_or_notes_and_a_one_frame_traceback",
        "validate_create_capture",
    ]
