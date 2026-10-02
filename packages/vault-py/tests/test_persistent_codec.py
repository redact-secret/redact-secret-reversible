"""The canonical encoders and digests beyond the shared vectors.

Boundaries of the limits, Python string and integer rules (UTF-16 length, lone
surrogates, ``bool`` and ``float`` as ``int``, ``2**53``), ordering by UTF-8 bytes,
round trips, the absence of exception links, and that no error repeats an input.
"""

from __future__ import annotations

import dataclasses
import pickle
import random
import traceback
from typing import Any

import pytest

from redact_secret_vault.persistent import (
    ALGORITHM_AES_256_GCM,
    MAX_PAYLOAD_BYTES,
    Grant,
    RecordBinding,
    RecordCryptoError,
    RecordPayload,
    RequestDigestInput,
    RequestPath,
    RequestUse,
    SessionTagInput,
    create_digester,
    decode_payload,
    derive_entry_id,
    encode_aad,
    encode_envelope,
    encode_payload,
    entry_key_info,
    limits,
    parse_envelope,
    plan_payload,
    write_payload,
)

NS = "ns-synthetic"
TENANT = "tenant-acme-synthetic"
CAPTURE = "cap_" + "a" * 26
CAPTURE_2 = "cap_" + "b" * 26
ENTRY = "0" * 64
ENTRY_2 = "1" * 64
TOKEN = "<rsv_" + "a" * 26 + ">"
MAX_INT = 2**53 - 1
SUPPLEMENTARY = chr(0x10000)
FULLWIDTH_TILDE = chr(0xFF5E)


def rejects(fn: Any, code: str) -> RecordCryptoError:
    captured: RecordCryptoError | None = None
    try:
        fn()
    except RecordCryptoError as thrown:
        captured = thrown
    assert captured is not None, f"expected {code}"
    assert captured.code == code
    assert captured.__cause__ is None
    assert captured.__context__ is None
    assert not hasattr(captured, "__notes__")
    return captured


def binding(**patch: Any) -> RecordBinding:
    base = RecordBinding(NS, TENANT, CAPTURE, ENTRY, None, 1000, 2000, 1)
    return dataclasses.replace(base, **patch)


def payload(**patch: Any) -> RecordPayload:
    base = RecordPayload(bytearray(b"synthetic-value"), "synthetic-type", (Grant("sink-a", ("body",)),), None)
    return dataclasses.replace(base, **patch)


# --------------------------------------------------------------------------
# entryId and entry-key info
# --------------------------------------------------------------------------


def test_entry_id_rejects_a_malformed_input() -> None:
    assert len(derive_entry_id(NS, TENANT, TOKEN)) == 64
    for args in (
        ("bad ns", TENANT, TOKEN),
        (NS, "", TOKEN),
        (NS, "lone-\ud800", TOKEN),
        (NS, SUPPLEMENTARY * 200, TOKEN),  # 400 UTF-16 units although len() is 200
        (NS, TENANT, "rsv_" + "a" * 26),
        (NS, TENANT, "<rsv_" + "a" * 25 + ">"),
        (NS, TENANT, "<rsv_" + "A" * 26 + ">"),
        (NS, TENANT, TOKEN + "\n"),
        (NS, TENANT, None),
        (NS, TENANT, b"<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>"),
    ):
        rejects(lambda args=args: derive_entry_id(*args), "RECORD_INVALID_ARGUMENT")


def test_entry_id_keeps_nfc_and_nfd_spellings_apart() -> None:
    nfc, nfd = "café", "café"
    assert derive_entry_id(NS, nfc, TOKEN) != derive_entry_id(NS, nfd, TOKEN)


def test_entry_id_accepts_the_longest_identifier_and_not_one_unit_more() -> None:
    assert derive_entry_id(NS, "a" * 256, TOKEN)
    assert derive_entry_id(NS, SUPPLEMENTARY * 128, TOKEN)
    rejects(lambda: derive_entry_id(NS, "a" * 257, TOKEN), "RECORD_INVALID_ARGUMENT")
    rejects(lambda: derive_entry_id(NS, SUPPLEMENTARY * 129, TOKEN), "RECORD_INVALID_ARGUMENT")


def test_entry_key_info_layout() -> None:
    info = entry_key_info(ENTRY)
    assert info == b"rsv-entry-key-v1\x00" + bytes([ALGORITHM_AES_256_GCM]) + b"\x00\x40" + ENTRY.encode()
    rejects(lambda: entry_key_info("F" * 64), "RECORD_INVALID_ARGUMENT")


# --------------------------------------------------------------------------
# AAD
# --------------------------------------------------------------------------


def test_aad_timestamp_and_use_boundaries() -> None:
    assert encode_aad(binding(created_at=0, expires_at=1))
    assert encode_aad(binding(created_at=MAX_INT - 1, expires_at=MAX_INT))
    assert encode_aad(binding(max_uses=1)) and encode_aad(binding(max_uses=limits.MAX_USES))
    day = limits.MAX_CAPTURE_LIFETIME_MS
    assert encode_aad(binding(created_at=0, expires_at=day))
    for patch in (
        {"created_at": MAX_INT, "expires_at": MAX_INT + 1},
        {"created_at": -1},
        {"expires_at": 1000},  # lifetime 0
        {"expires_at": 999},
        {"created_at": 0, "expires_at": day + 1},
        {"max_uses": 0},
        {"max_uses": limits.MAX_USES + 1},
        {"session_id": ""},
        {"session_id": "lone-\ud800"},
        {"tenant": "lone-\ud800"},
        {"namespace": "bad ns"},
        {"capture_id": "cap_short"},
        {"entry_id": "zz"},
    ):
        rejects(lambda patch=patch: encode_aad(binding(**patch)), "RECORD_INVALID_ARGUMENT")


@pytest.mark.parametrize("bad", [True, False, 1.0, 1000.0, float("nan"), "1000", None, b"x"])
def test_aad_rejects_bool_float_and_non_numbers(bad: Any) -> None:
    for field in ("created_at", "expires_at", "max_uses"):
        rejects(lambda field=field: encode_aad(binding(**{field: bad})), "RECORD_INVALID_ARGUMENT")


def test_aad_session_bound_flag_and_a_foreign_object() -> None:
    plain = encode_aad(binding(session_id=None))
    bound = encode_aad(binding(session_id="session-1"))
    assert plain != bound
    for bad in (None, {}, object(), "binding"):
        rejects(lambda bad=bad: encode_aad(bad), "RECORD_INVALID_ARGUMENT")


def test_every_aad_field_changes_the_bytes() -> None:
    base = encode_aad(binding(session_id="s"))
    for patch in (
        {"namespace": "ns-other"},
        {"tenant": "tenant-other"},
        {"capture_id": CAPTURE_2},
        {"entry_id": ENTRY_2},
        {"session_id": "t"},
        {"session_id": None},
        {"created_at": 1001},
        {"expires_at": 2001},
        {"max_uses": 2},
    ):
        assert encode_aad(binding(**{"session_id": "s", **patch})) != base, patch


# --------------------------------------------------------------------------
# Payload
# --------------------------------------------------------------------------


def test_value_limit_boundary() -> None:
    assert encode_payload(payload(value=bytearray(limits.MAX_VALUE_BYTES - 100)))
    rejects(lambda: encode_payload(payload(value=bytearray(limits.MAX_VALUE_BYTES + 1))), "RECORD_LIMIT")


def test_payload_must_fit_the_envelope_ceiling() -> None:
    paths = tuple("p" * 250 + f"{i:06d}" for i in range(limits.MAX_PATHS_PER_GRANT))
    big = payload(value=bytearray(limits.MAX_VALUE_BYTES), grants=(Grant("sink-a", paths),))
    rejects(lambda: encode_payload(big), "RECORD_LIMIT")
    ok = payload(value=bytearray(limits.MAX_VALUE_BYTES - 70_000), grants=(Grant("sink-a", paths),))
    assert len(encode_payload(ok)) <= MAX_PAYLOAD_BYTES


def test_grant_and_path_count_boundaries() -> None:
    many = tuple(Grant(f"sink-{i:03d}", ("body",)) for i in range(limits.MAX_GRANTS))
    assert decode_payload(encode_payload(payload(grants=many))).grants == many
    rejects(lambda: encode_payload(payload(grants=(*many, Grant("sink-zzz", ("body",))))), "RECORD_LIMIT")
    paths = tuple(f"path-{i:03d}" for i in range(limits.MAX_PATHS_PER_GRANT))
    assert decode_payload(encode_payload(payload(grants=(Grant("sink-a", paths),)))).grants[0].paths == paths
    rejects(lambda: encode_payload(payload(grants=(Grant("sink-a", (*paths, "path-zzz")),))), "RECORD_LIMIT")
    rejects(lambda: encode_payload(payload(grants=())), "RECORD_INVALID_ARGUMENT")
    rejects(lambda: encode_payload(payload(grants=(Grant("sink-a", ()),))), "RECORD_INVALID_ARGUMENT")


def test_type_and_policy_revision_are_limited_in_utf8_bytes() -> None:
    assert encode_payload(payload(type="t" * 256))
    rejects(lambda: encode_payload(payload(type="t" * 257)), "RECORD_LIMIT")
    two_byte = "é"  # 2 bytes
    assert encode_payload(payload(type=two_byte * 128))
    rejects(lambda: encode_payload(payload(type=two_byte * 129)), "RECORD_LIMIT")  # 258 bytes, 129 characters
    rejects(lambda: encode_payload(payload(type="")), "RECORD_INVALID_ARGUMENT")
    assert encode_payload(payload(policy_revision="r" * 256))
    rejects(lambda: encode_payload(payload(policy_revision="r" * 257)), "RECORD_LIMIT")
    rejects(lambda: encode_payload(payload(policy_revision=two_byte * 129)), "RECORD_LIMIT")


def test_an_empty_policy_revision_stays_distinct_from_an_absent_one() -> None:
    absent = decode_payload(encode_payload(payload(policy_revision=None)))
    empty = decode_payload(encode_payload(payload(policy_revision="")))
    assert absent.policy_revision is None
    assert empty.policy_revision == ""
    assert encode_payload(payload(policy_revision=None)) != encode_payload(payload(policy_revision=""))


@pytest.mark.parametrize(
    "patch",
    [
        {"type": "lone-\ud800"},
        {"policy_revision": "lone-\ud800"},
        {"grants": (Grant("lone-\ud800", ("body",)),)},
        {"grants": (Grant("sink-a", ("lone-\ud800",)),)},
        {"grants": (Grant("sink-a", (chr(0xDC00),)),)},
        {"grants": (Grant("sink-a", (SUPPLEMENTARY * 129,)),)},  # 258 UTF-16 units
        {"grants": (Grant("", ("body",)),)},
        {"grants": (Grant("sink-a", ("",)),)},
        {"grants": (Grant("sink-a", ("body", "body")),)},
        {"grants": (Grant("sink-a", ("body",)), Grant("sink-a", ("other",)))},
        {"grants": [Grant("sink-a", ("body",))]},
        {"grants": (Grant("sink-a", ["body"]),)},
        {"grants": (("sink-a", ("body",)),)},
        {"type": b"bytes"},
        {"type": None},
        {"policy_revision": 5},
        {"value": "text"},
        {"value": None},
        {"value": [1, 2]},
    ],
)
def test_encode_payload_rejects_a_malformed_payload(patch: dict[str, Any]) -> None:
    rejects(lambda: encode_payload(payload(**patch)), "RECORD_INVALID_ARGUMENT")


def test_a_lone_surrogate_never_becomes_a_replacement_character() -> None:
    secret = "SENTINEL-IDENTIFIER-" + chr(0xD800)
    error = rejects(lambda: encode_payload(payload(type=secret)), "RECORD_INVALID_ARGUMENT")
    text = "".join(traceback.format_exception(error)) + repr(error) + str(error) + repr(error.args)
    assert "SENTINEL" not in text
    assert not isinstance(error, UnicodeError)


def test_grants_and_paths_are_ordered_by_utf8_bytes_not_by_utf16_units() -> None:
    # U+FF5E is ef bd 9e; U+10000 is f0 90 80 80. UTF-8 order puts U+FF5E first; a UTF-16 sort would not.
    sinks = (Grant(SUPPLEMENTARY, ("body",)), Grant(FULLWIDTH_TILDE, ("body",)))
    decoded = decode_payload(encode_payload(payload(grants=sinks)))
    assert [g.sink for g in decoded.grants] == [FULLWIDTH_TILDE, SUPPLEMENTARY]
    decoded = decode_payload(encode_payload(payload(grants=(Grant("sink-a", (SUPPLEMENTARY, FULLWIDTH_TILDE)),))))
    assert decoded.grants[0].paths == (FULLWIDTH_TILDE, SUPPLEMENTARY)


def test_unsorted_caller_input_is_canonicalized_and_identical_to_sorted_input() -> None:
    shuffled = payload(grants=(Grant("sink-b", ("z", "a", "m")), Grant("sink-a", ("y", "b"))))
    sorted_ = payload(grants=(Grant("sink-a", ("b", "y")), Grant("sink-b", ("a", "m", "z"))))
    assert encode_payload(shuffled) == encode_payload(sorted_)


def test_random_payloads_round_trip_through_the_canonical_form() -> None:
    rng = random.Random(0x5EED)
    alphabet = ["a", "b", "z", "0", "-", "é", "€", FULLWIDTH_TILDE, SUPPLEMENTARY, chr(0x1F600), "﻿"]

    def word() -> str:
        return "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 8)))

    for _ in range(200):
        grants = []
        sinks = {word() for _ in range(rng.randint(1, 4))}
        for sink in sinks:
            grants.append(Grant(sink, tuple({word() for _ in range(rng.randint(1, 5))})))
        original = RecordPayload(
            bytearray(rng.randbytes(rng.randint(0, 64))),
            word(),
            tuple(grants),
            rng.choice([None, "", word()]),
        )
        encoded = encode_payload(original)
        decoded = decode_payload(encoded)
        assert bytes(decoded.value) == bytes(original.value)
        assert decoded.type == original.type
        assert decoded.policy_revision == original.policy_revision
        by_sink = {g.sink: sorted(g.paths, key=lambda p: p.encode()) for g in original.grants}
        assert [g.sink for g in decoded.grants] == sorted(by_sink, key=lambda s: s.encode())
        for grant in decoded.grants:
            assert list(grant.paths) == by_sink[grant.sink]
        assert encode_payload(decoded) == encoded


def test_a_leading_byte_order_mark_is_kept() -> None:
    decoded = decode_payload(encode_payload(payload(type="﻿bom")))
    assert decoded.type == "﻿bom"


def test_plan_then_write_equals_encode_and_a_non_plan_is_refused() -> None:
    source = payload()
    plan = plan_payload(source)
    assert write_payload(plan) == encode_payload(source)
    assert "synthetic-value" not in repr(plan)
    rejects(lambda: write_payload("not a plan"), "RECORD_INVALID_ARGUMENT")  # type: ignore[arg-type]


def test_decode_accepts_bytes_bytearray_and_memoryview_and_returns_an_independent_value() -> None:
    encoded = encode_payload(payload())
    for form in (bytes(encoded), bytearray(encoded), memoryview(bytes(encoded))):
        assert decode_payload(form).type == "synthetic-type"
    mutable = bytearray(encoded)
    decoded = decode_payload(mutable)
    mutable[:] = bytes(len(mutable))
    assert bytes(decoded.value) == b"synthetic-value"
    for bad in ("text", None, 5, [1], memoryview(bytes(8)).cast("H")):
        rejects(lambda bad=bad: decode_payload(bad), "RECORD_INVALID_ARGUMENT")


def _raw_payload(sink: str, path: str) -> bytes:
    def lp16(raw: bytes) -> bytes:
        return len(raw).to_bytes(2, "big") + raw

    head = b"\x01" + bytes(4) + lp16(b"t") + b"\x00\x01"
    return head + lp16(sink.encode()) + b"\x00\x01" + lp16(path.encode()) + b"\x00" + lp16(b"")


def test_decode_counts_identifier_length_in_utf16_units() -> None:
    # 128 supplementary characters are 256 units: accepted. 129 are 258 units (and 516 bytes): RECORD_LIMIT.
    assert decode_payload(_raw_payload("sink-a", SUPPLEMENTARY * 128)).grants[0].paths == (SUPPLEMENTARY * 128,)
    rejects(lambda: decode_payload(_raw_payload("sink-a", SUPPLEMENTARY * 129)), "RECORD_LIMIT")
    rejects(lambda: decode_payload(_raw_payload(SUPPLEMENTARY * 129, "body")), "RECORD_LIMIT")
    assert decode_payload(_raw_payload("sink-a", "a" * 256))
    rejects(lambda: decode_payload(_raw_payload("sink-a", "a" * 257)), "RECORD_LIMIT")


def test_decode_refuses_an_oversized_input_before_reading_it() -> None:
    rejects(lambda: decode_payload(bytes(MAX_PAYLOAD_BYTES + 1)), "RECORD_LIMIT")


def test_encoded_payloads_are_buffers_the_caller_can_overwrite() -> None:
    encoded = encode_payload(payload())
    assert isinstance(encoded, bytearray)
    encoded[:] = bytes(len(encoded))
    assert not any(encoded)


# --------------------------------------------------------------------------
# Envelope
# --------------------------------------------------------------------------


def test_envelope_round_trip_and_boundaries() -> None:
    nonce = bytes(range(12))
    ciphertext = bytes(range(40))
    envelope = encode_envelope(nonce, ciphertext)
    assert envelope[:6] == b"RSVE\x01\x01"
    parts = parse_envelope(envelope)
    assert (parts.nonce, parts.ciphertext) == (nonce, ciphertext)
    assert encode_envelope(nonce, bytes(17))
    rejects(lambda: encode_envelope(nonce, bytes(16)), "RECORD_INVALID_ARGUMENT")
    rejects(lambda: encode_envelope(nonce[:11], ciphertext), "RECORD_INVALID_ARGUMENT")
    rejects(lambda: encode_envelope(nonce + b"x", ciphertext), "RECORD_INVALID_ARGUMENT")
    rejects(lambda: encode_envelope(bytearray(nonce), ciphertext), "RECORD_INVALID_ARGUMENT")  # type: ignore[arg-type]
    biggest = limits.MAX_ENVELOPE_BYTES - 22
    assert len(encode_envelope(nonce, bytes(biggest))) == limits.MAX_ENVELOPE_BYTES
    rejects(lambda: encode_envelope(nonce, bytes(biggest + 1)), "RECORD_LIMIT")


def test_parse_envelope_rejects_a_foreign_type_and_an_oversized_input() -> None:
    for bad in ("RSVE", None, 3, [1]):
        rejects(lambda bad=bad: parse_envelope(bad), "RECORD_INVALID_ARGUMENT")
    rejects(lambda: parse_envelope(bytes(limits.MAX_ENVELOPE_BYTES + 1)), "RECORD_LIMIT")


# --------------------------------------------------------------------------
# Request digest and session tag
# --------------------------------------------------------------------------

KEY = bytes(range(0x40, 0x60))


def request(**patch: Any) -> RequestDigestInput:
    base = RequestDigestInput(
        namespace=NS,
        tenant=TENANT,
        principal_id="principal-1",
        session_id=None,
        sink="sink-a",
        purpose="purpose-synthetic",
        capture_ids=(CAPTURE,),
        uses=(RequestUse(ENTRY, (RequestPath("body", 1),)),),
    )
    return dataclasses.replace(base, **patch)


def test_keyed_and_unkeyed_digests_differ_and_are_32_bytes() -> None:
    keyed = create_digester(key=KEY).request_digest(request())
    unkeyed = create_digester(unkeyed=True).request_digest(request())
    assert len(keyed) == len(unkeyed) == 32
    assert keyed != unkeyed
    assert create_digester(key=bytes(32)).request_digest(request()) != keyed


def test_digester_construction_rules() -> None:
    rejects(lambda: create_digester(), "RECORD_INVALID_ARGUMENT")
    rejects(lambda: create_digester(key=KEY, unkeyed=True), "RECORD_INVALID_ARGUMENT")
    rejects(lambda: create_digester(key=KEY[:31]), "RECORD_INVALID_ARGUMENT")
    rejects(lambda: create_digester(key=KEY + b"x"), "RECORD_INVALID_ARGUMENT")
    rejects(lambda: create_digester(key="x" * 32), "RECORD_INVALID_ARGUMENT")  # type: ignore[arg-type]
    rejects(lambda: create_digester(unkeyed=1), "RECORD_INVALID_ARGUMENT")  # type: ignore[arg-type]
    mutable = bytearray(KEY)
    digester = create_digester(key=mutable)
    before = digester.request_digest(request())
    mutable[:] = bytes(32)
    assert digester.request_digest(request()) == before


def test_digester_neither_prints_nor_pickles_its_key() -> None:
    digester = create_digester(key=KEY)
    assert KEY.hex() not in repr(digester) and str(KEY) not in repr(digester)
    with pytest.raises(TypeError):
        pickle.dumps(digester)


def test_request_digest_is_order_insensitive_and_every_field_matters() -> None:
    digester = create_digester(key=KEY)
    two_captures = request(capture_ids=(CAPTURE, CAPTURE_2))
    swapped = request(capture_ids=(CAPTURE_2, CAPTURE))
    assert digester.request_digest(two_captures) == digester.request_digest(swapped)
    uses = (
        RequestUse(ENTRY, (RequestPath("b", 1), RequestPath("a", 2))),
        RequestUse(ENTRY_2, (RequestPath("c", 3),)),
    )
    reordered = (
        RequestUse(ENTRY_2, (RequestPath("c", 3),)),
        RequestUse(ENTRY, (RequestPath("a", 2), RequestPath("b", 1))),
    )
    assert digester.request_digest(request(uses=uses)) == digester.request_digest(request(uses=reordered))
    base = digester.request_digest(request())
    for patch in (
        {"namespace": "ns-other"},
        {"tenant": "tenant-other"},
        {"principal_id": "principal-2"},
        {"session_id": "session-1"},
        {"sink": "sink-b"},
        {"purpose": "other-purpose"},
        {"capture_ids": (CAPTURE_2,)},
        {"uses": (RequestUse(ENTRY_2, (RequestPath("body", 1),)),)},
        {"uses": (RequestUse(ENTRY, (RequestPath("other", 1),)),)},
        {"uses": (RequestUse(ENTRY, (RequestPath("body", 2),)),)},
    ):
        assert digester.request_digest(request(**patch)) != base, patch


def test_request_digest_sorts_by_utf8_bytes() -> None:
    digester = create_digester(key=KEY)
    one = request(uses=(RequestUse(ENTRY, (RequestPath(SUPPLEMENTARY, 1), RequestPath(FULLWIDTH_TILDE, 1))),))
    two = request(uses=(RequestUse(ENTRY, (RequestPath(FULLWIDTH_TILDE, 1), RequestPath(SUPPLEMENTARY, 1))),))
    assert digester.request_digest(one) == digester.request_digest(two)


def test_request_digest_limits_and_malformed_inputs() -> None:
    digester = create_digester(key=KEY)

    def uses(occurrences: Any) -> tuple[RequestUse, ...]:
        return (RequestUse(ENTRY, (RequestPath("body", occurrences),)),)

    assert digester.request_digest(request(uses=uses(1)))
    assert digester.request_digest(request(uses=uses(0xFFFF_FFFF)))
    rejects(lambda: digester.request_digest(request(uses=uses(0xFFFF_FFFF + 1))), "RECORD_LIMIT")
    for occurrences in (0, -1, True, 1.0, 2**64):
        rejects(lambda o=occurrences: digester.request_digest(request(uses=uses(o))), "RECORD_INVALID_ARGUMENT")
    assert digester.request_digest(request(purpose="p" * 1024))
    rejects(lambda: digester.request_digest(request(purpose="p" * 1025)), "RECORD_LIMIT")
    rejects(lambda: digester.request_digest(request(purpose="é" * 513)), "RECORD_LIMIT")
    rejects(lambda: digester.request_digest(request(purpose="")), "RECORD_INVALID_ARGUMENT")
    rejects(lambda: digester.request_digest(request(purpose="lone-\ud800")), "RECORD_INVALID_ARGUMENT")
    ids = tuple(f"cap_{'a' * 24}{chr(97 + i // 26)}{chr(97 + i % 26)}" for i in range(limits.MAX_RESTORE_CAPTURES + 1))
    assert digester.request_digest(request(capture_ids=ids[:-1]))
    rejects(lambda: digester.request_digest(request(capture_ids=ids)), "RECORD_LIMIT")
    for patch in (
        {"capture_ids": ()},
        {"capture_ids": (CAPTURE, CAPTURE)},
        {"capture_ids": [CAPTURE]},
        {"uses": ()},
        {"uses": (RequestUse(ENTRY, (RequestPath("a", 1),)), RequestUse(ENTRY, (RequestPath("b", 1),)))},
        {"uses": (RequestUse(ENTRY, ()),)},
        {"uses": (RequestUse(ENTRY, (RequestPath("a", 1), RequestPath("a", 2))),)},
        {"uses": (RequestUse("zz", (RequestPath("a", 1),)),)},
        {"principal_id": "lone-\ud800"},
        {"session_id": ""},
        {"sink": SUPPLEMENTARY * 129},
        {"namespace": "bad ns"},
    ):
        rejects(lambda patch=patch: digester.request_digest(request(**patch)), "RECORD_INVALID_ARGUMENT")
    rejects(lambda: digester.request_digest(None), "RECORD_INVALID_ARGUMENT")  # type: ignore[arg-type]


def test_session_tag_is_lowercase_hex_and_rejects_a_lone_surrogate() -> None:
    digester = create_digester(key=KEY)
    tag = digester.session_tag(SessionTagInput(NS, TENANT, CAPTURE, "session-1"))
    assert len(tag) == 64 and tag == tag.lower() and set(tag) <= set("0123456789abcdef")
    assert tag != digester.session_tag(SessionTagInput(NS, TENANT, CAPTURE, "session-2"))
    assert tag != digester.session_tag(SessionTagInput(NS, TENANT, CAPTURE_2, "session-1"))
    assert tag != create_digester(unkeyed=True).session_tag(SessionTagInput(NS, TENANT, CAPTURE, "session-1"))
    for patch in ({"session_id": "lone-\ud800"}, {"session_id": ""}, {"tenant": "lone-\ud800"}, {"capture_id": "x"}):
        data = {"namespace": NS, "tenant": TENANT, "capture_id": CAPTURE, "session_id": "session-1", **patch}
        rejects(lambda data=data: digester.session_tag(SessionTagInput(**data)), "RECORD_INVALID_ARGUMENT")
    rejects(lambda: digester.session_tag(None), "RECORD_INVALID_ARGUMENT")  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


def test_a_rejection_is_raised_from_the_entry_point_and_holds_no_helper_frame() -> None:
    error = rejects(lambda: decode_payload(b"\x01"), "RECORD_MALFORMED")
    names = []
    tb = error.__traceback__
    while tb is not None:
        names.append(tb.tb_frame.f_code.co_name)
        tb = tb.tb_next
    # The test helper, its lambda, and the entry-point wrapper; no _Reader or decoder frame.
    assert names == ["rejects", "<lambda>", "entry"]
