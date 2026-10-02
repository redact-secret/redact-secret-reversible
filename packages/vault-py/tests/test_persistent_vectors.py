"""The standard-library groups of conformance/persistent/v1/vectors.json, reproduced byte for byte.

``entryId``, ``aad``, ``payload``, ``requestDigest``, ``sessionTag``, and the envelope
framing, plus every negative case of the envelope and payload decoders. The groups
that need AES-256-GCM or HKDF (``entryKey``, the envelope AEAD, ``localWrap``, ``negative.open``,
``negative.localUnwrap``) are reproduced by ``test_crypto_vectors.py``.
"""

from __future__ import annotations

from typing import Any

import pytest
from persistent_vectors import binding_from, load_vectors, payload_from

from redact_secret_vault.persistent import (
    RecordCryptoError,
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
    parse_envelope,
)

V = load_vectors()


def expect_code(fn: Any, code: str) -> None:
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


def request_from(data: dict[str, Any]) -> RequestDigestInput:
    return RequestDigestInput(
        namespace=data["namespace"],
        tenant=data["tenant"],
        principal_id=data["principalId"],
        session_id=data["sessionId"],
        sink=data["sink"],
        purpose=data["purpose"],
        capture_ids=tuple(data["captureIds"]),
        uses=tuple(
            RequestUse(u["entryId"], tuple(RequestPath(p["path"], p["occurrences"]) for p in u["paths"]))
            for u in data["uses"]
        ),
    )


def digester_for(vector: dict[str, Any]) -> Any:
    if vector["mode"] == "keyed":
        return create_digester(key=bytes.fromhex(vector["key"]))
    assert vector["mode"] == "unkeyed" and vector["key"] is None
    return create_digester(unkeyed=True)


def test_the_loader_saw_every_group() -> None:
    assert {"entryId", "sessionTag", "requestDigest", "entryKey", "aad", "payload", "envelope", "localWrap"} <= set(V)
    assert set(V["negative"]) == {"envelope", "payload", "open", "localUnwrap"}


@pytest.mark.parametrize("vector", V["entryId"], ids=lambda v: v["entryId"][:8])
def test_entry_id(vector: dict[str, Any]) -> None:
    assert derive_entry_id(vector["namespace"], vector["tenant"], vector["token"]) == vector["entryId"]


@pytest.mark.parametrize("vector", V["sessionTag"], ids=lambda v: f"{v['mode']}-{v['sessionTag'][:8]}")
def test_session_tag(vector: dict[str, Any]) -> None:
    i = vector["input"]
    tag = digester_for(vector).session_tag(SessionTagInput(i["namespace"], i["tenant"], i["captureId"], i["sessionId"]))
    assert tag == vector["sessionTag"]


@pytest.mark.parametrize("vector", V["requestDigest"], ids=lambda v: v["name"])
def test_request_digest(vector: dict[str, Any]) -> None:
    digest = digester_for(vector).request_digest(request_from(vector["input"]))
    assert digest.hex() == vector["requestDigest"]


@pytest.mark.parametrize("vector", V["aad"], ids=lambda v: v["name"])
def test_aad(vector: dict[str, Any]) -> None:
    assert encode_aad(binding_from(vector["binding"])).hex() == vector["aad"]


@pytest.mark.parametrize("vector", V["payload"], ids=lambda v: v["name"])
def test_payload_encodes_and_decodes_back(vector: dict[str, Any]) -> None:
    encoded = encode_payload(payload_from(vector["payload"]))
    assert encoded.hex() == vector["bytes"]
    decoded = decode_payload(bytes.fromhex(vector["bytes"]))
    original = vector["payload"]
    assert bytes(decoded.value).hex() == original["value"]
    assert decoded.type == original["type"]
    assert decoded.policy_revision == original["policyRevision"]
    assert [{"sink": g.sink, "paths": list(g.paths)} for g in decoded.grants] == vector["canonicalGrants"]
    # A decoder's output encodes to the same bytes.
    assert encode_payload(decoded) == encoded


@pytest.mark.parametrize("vector", V["envelope"], ids=lambda v: v["name"])
def test_envelope_framing(vector: dict[str, Any]) -> None:
    assert encode_aad(binding_from(vector["binding"])).hex() == vector["aad"]
    assert encode_payload(payload_from(vector["payload"])).hex() == vector["plaintext"]
    envelope = bytes.fromhex(vector["envelope"])
    parts = parse_envelope(envelope)
    assert parts.nonce.hex() == vector["nonce"]
    assert len(parts.ciphertext) == len(vector["plaintext"]) // 2 + 16
    assert encode_envelope(parts.nonce, parts.ciphertext) == envelope


@pytest.mark.parametrize("case", V["negative"]["envelope"], ids=lambda c: c["name"])
def test_negative_envelope(case: dict[str, Any]) -> None:
    expect_code(lambda: parse_envelope(bytes.fromhex(case["envelope"])), case["error"])


@pytest.mark.parametrize("case", V["negative"]["payload"], ids=lambda c: c["name"])
def test_negative_payload(case: dict[str, Any]) -> None:
    expect_code(lambda: decode_payload(bytes.fromhex(case["payload"])), case["error"])


def test_an_unsupported_algorithm_in_negative_open_is_refused_at_the_envelope_stage() -> None:
    # Before any key is used; the full open path is exercised by test_crypto_vectors.py.
    cases = [c for c in V["negative"]["open"] if c["name"] == "algorithm 2"]
    assert len(cases) == 1
    expect_code(lambda: parse_envelope(bytes.fromhex(cases[0]["envelope"])), cases[0]["error"])
