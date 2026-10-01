"""The groups of conformance/persistent/v1/vectors.json that need ``cryptography``.

``entryKey``, the envelope (fixed data key and nonce, reproduced through the private seal
function; opened through the public API), ``localWrap``, ``negative.open``, and
``negative.localUnwrap``. The standard-library groups are in test_persistent_vectors.py.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from crypto_support import InsecureTestKeyProvider
from persistent_vectors import binding_from, load_vectors, payload_from

pytest.importorskip("cryptography")

from redact_secret_vault.crypto import (  # noqa: E402
    LocalKey,
    LocalKeyScope,
    create_local_key_provider,
    create_record_crypto,
)
from redact_secret_vault.crypto.record_crypto import _seal_entry, derive_entry_key  # noqa: E402
from redact_secret_vault.persistent import (  # noqa: E402
    KeyContext,
    KeyProviderError,
    RecordCryptoError,
    StoredKey,
    encode_aad,
    encode_payload,
    parse_envelope,
)

V = load_vectors()


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def context_of(binding: Any) -> KeyContext:
    return KeyContext(binding.namespace, binding.tenant, binding.capture_id)


def open_with(vector: dict[str, Any], dek_hex: str | None = None) -> Any:
    """Open the vector's envelope through the public API, with a provider that returns its data key."""

    binding = binding_from(vector["binding"])
    provider = InsecureTestKeyProvider(acknowledge_insecure="test-only", dek=bytes.fromhex(dek_hex or vector["dek"]))
    crypto = create_record_crypto(key_provider=provider)
    return run(
        crypto.open_capture(
            StoredKey("test:fixed", b"test-wrapped-key"),
            context_of(binding),
            ((binding, bytes.fromhex(vector["envelope"])),),
        )
    )


def error_code(fn: Any) -> str:
    captured: Exception | None = None
    try:
        fn()
    except (RecordCryptoError, KeyProviderError) as thrown:
        captured = thrown
    assert captured is not None, "expected an error"
    assert captured.__cause__ is None and captured.__context__ is None
    assert not hasattr(captured, "__notes__")
    return captured.code  # type: ignore[attr-defined]


def test_the_insecure_provider_refuses_to_construct_without_the_acknowledgement() -> None:
    with pytest.raises(ValueError):
        InsecureTestKeyProvider(acknowledge_insecure="yes")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        InsecureTestKeyProvider()  # type: ignore[call-arg]


@pytest.mark.parametrize("vector", V["entryKey"], ids=lambda v: v["entryId"][:8])
def test_entry_key(vector: dict[str, Any]) -> None:
    dek = bytearray(bytes.fromhex(vector["dek"]))
    key = derive_entry_key(dek, vector["entryId"])
    assert bytes(key).hex() == vector["entryKey"]
    key[:] = bytes(32)


@pytest.mark.parametrize("vector", V["envelope"], ids=lambda v: v["name"])
def test_envelope_is_reproduced_with_the_fixed_nonce_and_opens_through_the_public_api(vector: dict[str, Any]) -> None:
    binding = binding_from(vector["binding"])
    nonce = bytes.fromhex(vector["nonce"])
    key = derive_entry_key(bytearray(bytes.fromhex(vector["dek"])), binding.entry_id)
    plaintext = encode_payload(payload_from(vector["payload"]))
    assert _seal_entry(key, nonce, plaintext, encode_aad(binding)).hex() == vector["envelope"]
    assert parse_envelope(bytes.fromhex(vector["envelope"])).nonce == nonce
    opened = open_with(vector)
    assert len(opened) == 1
    assert encode_payload(opened[0]).hex() == vector["plaintext"]


@pytest.mark.parametrize("case", V["negative"]["open"], ids=lambda c: c["name"])
def test_negative_open(case: dict[str, Any]) -> None:
    assert error_code(lambda: open_with(case)) == case["error"]


def scoped_provider(vector: dict[str, Any], key_id: str | None = None) -> Any:
    context = vector["context"]
    return create_local_key_provider(
        keys=(LocalKey(key_id or vector["keyId"], bytes.fromhex(vector["material"]), "active"),),
        scope=LocalKeyScope((context["namespace"],)),
    )


@pytest.mark.parametrize("vector", V["localWrap"], ids=lambda v: v["keyRef"])
def test_local_wrap(vector: dict[str, Any]) -> None:
    provider = scoped_provider(vector)
    context = KeyContext(
        **{
            "namespace": vector["context"]["namespace"],
            "tenant": vector["context"]["tenant"],
            "capture_id": vector["context"]["captureId"],
        }
    )
    material = provider._held[vector["keyId"]]
    assert bytes(provider._wrapping_key(material, context)).hex() == vector["wrappingKey"]
    wrapped = provider._wrap(bytearray(bytes.fromhex(vector["dek"])), context, bytes.fromhex(vector["nonce"]))
    assert wrapped.key_ref == vector["keyRef"]
    assert wrapped.wrapped_key.hex() == vector["wrappedKey"]
    unwrapped = run(provider.unwrap_data_key(StoredKey(vector["keyRef"], bytes.fromhex(vector["wrappedKey"])), context))
    assert bytes(unwrapped).hex() == vector["dek"]


@pytest.mark.parametrize("case", V["negative"]["localUnwrap"], ids=lambda c: c["name"])
def test_negative_local_unwrap(case: dict[str, Any]) -> None:
    provider = scoped_provider(case)
    c = case["context"]
    context = KeyContext(c["namespace"], c["tenant"], c["captureId"])
    stored = StoredKey(case["keyRef"], bytes.fromhex(case["wrappedKey"]))
    assert error_code(lambda: run(provider.unwrap_data_key(stored, context))) == case["error"]
