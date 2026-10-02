"""Sealing and opening captures at the limits of the record format.

Correctness at maximum size, with a generous time bound that only catches a pathology (a quadratic loop
or an accidental copy per entry). The measured times that decide whether the layer offloads work to a
thread are printed with ``-s`` and recorded in docs/decisions/python-persistence-api-and-packaging.md.
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest
from crypto_support import CAPTURE, CREATED, EXPIRES, MATERIAL, NS, TENANT, context

pytest.importorskip("cryptography")

from redact_secret_vault.crypto import (  # noqa: E402
    LocalKey,
    LocalKeyScope,
    create_local_key_provider,
    create_record_crypto,
)
from redact_secret_vault.persistent import (  # noqa: E402
    Grant,
    RecordBinding,
    RecordPayload,
    StoredKey,
    derive_entry_id,
    limits,
)

ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
GENEROUS_SECONDS = 20.0


def entry_id(index: int) -> str:
    digits, rest = [], index
    for _ in range(26):
        digits.append(ALPHABET[rest % 32])
        rest //= 32
    return derive_entry_id(NS, TENANT, "<rsv_" + "".join(digits) + ">")


def records(count: int, size: int) -> tuple[tuple[RecordBinding, RecordPayload], ...]:
    value = os.urandom(size)
    return tuple(
        (
            RecordBinding(NS, TENANT, CAPTURE, entry_id(i), None, CREATED, EXPIRES, 1),
            RecordPayload(bytearray(value), "synthetic-type", (Grant("sink-a", ("body",)),), None),
        )
        for i in range(count)
    )


@pytest.mark.parametrize(
    ("label", "count", "size"),
    [
        ("1 x 1 MiB (largest value)", 1, limits.MAX_VALUE_BYTES),
        ("1024 x 1 KiB (most entries)", limits.MAX_CREATE_ENTRIES, 1024),
        ("1024 x 8 KiB (default value limit)", limits.MAX_CREATE_ENTRIES, 8192),
    ],
)
def test_a_capture_at_the_limits_round_trips(label: str, count: int, size: int) -> None:
    provider = create_local_key_provider(keys=(LocalKey("2026-10", MATERIAL, "active"),), scope=LocalKeyScope((NS,)))
    rc = create_record_crypto(key_provider=provider)
    source = records(count, size)

    async def scenario() -> tuple[float, float]:
        started = time.perf_counter()
        sealed = await rc.seal_capture(context(), source)
        sealed_s = time.perf_counter() - started
        assert len(sealed.envelopes) == count
        assert all(len(e) <= limits.MAX_ENVELOPE_BYTES for e in sealed.envelopes)
        pairs = tuple((b, e) for (b, _), e in zip(source, sealed.envelopes, strict=True))
        started = time.perf_counter()
        opened = await rc.open_capture(StoredKey(sealed.key_ref, sealed.wrapped_key), context(), pairs)
        opened_s = time.perf_counter() - started
        assert len(opened) == count
        assert all(bytes(o.value) == bytes(p.value) for o, (_, p) in zip(opened, source, strict=True))
        return sealed_s, opened_s

    sealed_s, opened_s = asyncio.run(scenario())
    print(f"\n{label}: seal {sealed_s * 1000:.1f} ms, open {opened_s * 1000:.1f} ms")
    assert sealed_s < GENEROUS_SECONDS and opened_s < GENEROUS_SECONDS
