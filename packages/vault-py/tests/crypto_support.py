"""Test-only support for the crypto modules. Nothing here is in the wheel.

* ``InsecureTestKeyProvider``: a deterministic provider that returns a fixed data key. It
  refuses to construct without the acknowledgement ``"test-only"``, as the JavaScript one does
  (docs/specs/persistent-vault.md section 6.3).
* ``ScriptedProvider``: a provider whose behavior each test scripts, to exercise how the record
  crypto treats a failing, slow, or misbehaving provider.
* ``track_buffers``: injects the buffer allocator so a test can check that every buffer the package
  allocated is all zero after a call (docs/plans/python-persistence-parity.md section 6.4).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from redact_secret_vault.persistent import (
    DataKey,
    Grant,
    KeyContext,
    RecordBinding,
    RecordPayload,
    StoredKey,
    _buffers,
    derive_entry_id,
)

NS = "ns-synthetic"
TENANT = "tenant-acme-synthetic"
CAPTURE = "cap_" + "a" * 26
CAPTURE_2 = "cap_" + "b" * 26
DEK = bytes(range(32))
MATERIAL = bytes(range(0x80, 0xA0))
CREATED, EXPIRES = 1_790_000_000_000, 1_790_003_600_000


def token(letter: str) -> str:
    return "<rsv_" + letter * 26 + ">"


def entry_id(letter: str = "a", *, tenant: str = TENANT) -> str:
    return derive_entry_id(NS, tenant, token(letter))


def context(capture: str = CAPTURE, *, tenant: str = TENANT) -> KeyContext:
    return KeyContext(NS, tenant, capture)


def binding(letter: str = "a", *, capture: str = CAPTURE, tenant: str = TENANT, **patch: Any) -> RecordBinding:
    base = {
        "namespace": NS,
        "tenant": tenant,
        "capture_id": capture,
        "entry_id": entry_id(letter, tenant=tenant),
        "session_id": None,
        "created_at": CREATED,
        "expires_at": EXPIRES,
        "max_uses": 1,
        **patch,
    }
    return RecordBinding(**base)


def payload(value: bytes = b"SYNTHETIC-VALUE-0001", **patch: Any) -> RecordPayload:
    base: dict[str, Any] = {
        "value": bytearray(value),
        "type": "synthetic-finding-type",
        "grants": (Grant("sink-a", ("body",)),),
        "policy_revision": None,
        **patch,
    }
    return RecordPayload(**base)


class InsecureTestKeyProvider:
    """Returns ``dek`` as the data key of every capture. Test-only."""

    profile = "insecure-test-v1"

    def __init__(self, *, acknowledge_insecure: str, dek: bytes = DEK, key_ref: str = "test:fixed") -> None:
        if acknowledge_insecure != "test-only":
            raise ValueError('InsecureTestKeyProvider needs acknowledge_insecure="test-only"')
        self._dek = dek
        self._key_ref = key_ref
        self.calls = 0

    def _key(self) -> bytearray:
        buffer = _buffers.new_buffer(len(self._dek))
        buffer[:] = self._dek
        return buffer

    async def generate_data_key(self, context: KeyContext) -> DataKey:
        self.calls += 1
        return DataKey(self._key_ref, b"test-wrapped-key", self._key())

    async def unwrap_data_key(self, stored: StoredKey, context: KeyContext) -> bytearray:
        self.calls += 1
        return self._key()

    async def rewrap_data_key(self, stored: StoredKey, context: KeyContext) -> StoredKey:
        self.calls += 1
        return StoredKey(self._key_ref, b"test-wrapped-key")


class ScriptedProvider:
    """A provider whose three methods are whatever the test passes in. Counts its calls."""

    profile = "scripted-test-v1"

    def __init__(
        self,
        generate: Callable[[KeyContext], Awaitable[Any]] | None = None,
        unwrap: Callable[[StoredKey, KeyContext], Awaitable[Any]] | None = None,
        rewrap: Callable[[StoredKey, KeyContext], Awaitable[Any]] | None = None,
    ) -> None:
        self._generate, self._unwrap, self._rewrap = generate, unwrap, rewrap
        self.calls = 0

    def generate_data_key(self, context: KeyContext) -> Any:
        self.calls += 1
        assert self._generate is not None
        return self._generate(context)

    def unwrap_data_key(self, stored: StoredKey, context: KeyContext) -> Any:
        self.calls += 1
        assert self._unwrap is not None
        return self._unwrap(stored, context)

    def rewrap_data_key(self, stored: StoredKey, context: KeyContext) -> Any:
        self.calls += 1
        assert self._rewrap is not None
        return self._rewrap(stored, context)


def track_buffers(monkeypatch: pytest.MonkeyPatch) -> list[bytearray]:
    """Record every buffer ``persistent._buffers.new_buffer`` hands out from now on."""

    created: list[bytearray] = []
    original = _buffers.new_buffer

    def tracking(size: int) -> bytearray:
        buffer = original(size)
        created.append(buffer)
        return buffer

    monkeypatch.setattr(_buffers, "new_buffer", tracking)
    return created


def all_zero(buffers: list[bytearray], *, except_: tuple[bytearray, ...] = ()) -> bool:
    """True when every tracked buffer, except the ones the caller was handed, is zero."""

    return all(not any(b) for b in buffers if not any(b is kept for kept in except_))
