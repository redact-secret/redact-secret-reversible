"""The local key provider of docs/specs/persistent-vault.md section 6.3.

A ``KeyProvider`` over key material the application injects. Mirrors
``packages/vault-crypto/src/local-key-provider.ts`` with one difference, recorded
in docs/decisions/python-persistence-api-and-packaging.md: material is bytes in
process memory, never a non-extractable handle, so its profile is named
``local-bytes-hkdf-aes-256-gcm-v1`` and not the JavaScript profile.

Limits, restated from the specification: the material is in process memory; anyone
who obtains it and a copy of the store can decrypt every capture wrapped under it;
every wrapping key derives from one material, so retiring that material makes every
capture under it unreadable; there is no per-tenant or per-capture erasure. The
provider does not load, store, or rotate material, reads no environment variable,
has no default key and no passphrase path, and caches no unwrapped key. The caller's
buffer is copied and may be overwritten; ``close`` overwrites the copies.

Wrapped key: ``0x01 || nonce(12) || ciphertext(32) || tag(16)``. The wrapping key is
``HKDF-SHA-256(material, salt = 32 zero bytes, info = "rsv-local-wrap-v1" 0x00 ||
lp16(namespace) || lp16(tenant) || lp16(captureId))``; no associated data is passed,
the context is bound through the derivation.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Final, Literal

from ..persistent import _buffers
from ..persistent import limits as _limits
from ..persistent.codec import label, lp16, utf8
from ..persistent.contracts import DataKey, KeyContext, StoredKey, _NoPickle
from ..persistent.errors import KeyProviderError, KeyProviderErrorCode
from ..persistent.validate import is_capture_id, is_identifier, is_namespace
from . import _primitives
from ._provider_call import ProviderReject

LOCAL_KEY_PROVIDER_PROFILE: Final = "local-bytes-hkdf-aes-256-gcm-v1"
#: Leading byte of a wrapped key.
LOCAL_WRAP_VERSION: Final = 1

_KEY_REF_PREFIX: Final = "local:"
_KEY_ID: Final = re.compile(r"[A-Za-z0-9._-]{1,64}")
_MATERIAL_BYTES: Final = 32
_NONCE_BYTES: Final = _primitives.NONCE_BYTES
_TAG_BYTES: Final = _primitives.TAG_BYTES
_WRAPPED_BYTES: Final = 1 + _NONCE_BYTES + _limits.DATA_KEY_BYTES + _TAG_BYTES

LocalKeyState = Literal["active", "decrypt-only", "retired"]


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class LocalKey(_NoPickle):
    #: 1 to 64 characters of ``[A-Za-z0-9._-]``. The key reference is ``local:<id>``.
    id: str
    #: 32 bytes. Copied; the caller may overwrite its buffer once the provider is built.
    material: bytes | bytearray
    state: LocalKeyState

    def __repr__(self) -> str:
        return f"LocalKey(id={self.id!r}, state={self.state!r}, material=<{len(self.material)} bytes>)"


@dataclass(frozen=True, slots=True)
class LocalKeyScope:
    """The namespaces, and optionally the tenants, a provider may serve. Required."""

    namespaces: tuple[str, ...]
    tenants: tuple[str, ...] | None = None


def _reject(code: KeyProviderErrorCode) -> None:
    raise ProviderReject(code)


def _wrap_info(context: KeyContext) -> bytes:
    """``"rsv-local-wrap-v1" 0x00 || lp16(namespace) || lp16(tenant) || lp16(captureId)``."""

    return b"".join(
        (
            label("rsv-local-wrap-v1"),
            lp16(utf8(context.namespace)),
            lp16(utf8(context.tenant)),
            lp16(utf8(context.capture_id)),
        )
    )


def _snapshot_context(context: object) -> KeyContext:
    # is_identifier tests well-formedness, so encoding below never substitutes a replacement character.
    if (
        not isinstance(context, KeyContext)
        or not is_namespace(context.namespace)
        or not is_identifier(context.tenant)
        or not is_capture_id(context.capture_id)
    ):
        _reject("KEY_INVALID_ARGUMENT")
    return context  # type: ignore[return-value]


def _snapshot_stored(stored: object) -> StoredKey:
    if (
        not isinstance(stored, StoredKey)
        or type(stored.key_ref) is not str
        or not isinstance(stored.wrapped_key, bytes)
    ):
        _reject("KEY_INVALID_ARGUMENT")
    if (
        len(stored.key_ref) == 0
        or len(stored.wrapped_key) == 0
        or len(stored.wrapped_key) > _limits.WRAPPED_KEY_MAX_BYTES
    ):
        _reject("KEY_INVALID_ARGUMENT")
    return StoredKey(stored.key_ref, bytes(stored.wrapped_key))


class LocalKeyProvider:
    """Build it with ``create_local_key_provider``."""

    __slots__ = ("_active", "_closed", "_held", "_namespaces", "_tenants")

    def __init__(
        self,
        held: dict[str, bytearray],
        active: str,
        namespaces: frozenset[str],
        tenants: frozenset[str] | None,
    ) -> None:
        self._held = held
        self._active = active
        self._namespaces = namespaces
        self._tenants = tenants
        self._closed = False

    @property
    def profile(self) -> str:
        return LOCAL_KEY_PROVIDER_PROFILE

    def __repr__(self) -> str:
        return f"LocalKeyProvider(profile={LOCAL_KEY_PROVIDER_PROFILE!r}, keys={len(self._held)})"

    def __reduce__(self) -> tuple[object, ...]:
        raise TypeError("LocalKeyProvider must not be pickled or copied")

    def close(self) -> None:
        """Overwrite the copies of key material. Every later call fails ``KEY_UNAVAILABLE``."""

        self._closed = True
        for material in self._held.values():
            _buffers.zero(material)
        self._held.clear()

    # -- internals: raise ProviderReject, never a foreign exception -----------

    def _in_scope(self, context: KeyContext) -> bool:
        return context.namespace in self._namespaces and (self._tenants is None or context.tenant in self._tenants)

    def _wrapping_key(self, material: bytearray, context: KeyContext) -> bytearray:
        key = _buffers.new_buffer(_limits.DATA_KEY_BYTES)
        if not _primitives.hkdf_sha256_into(material, _wrap_info(context), key):
            _buffers.zero(key)
            _reject("KEY_UNAVAILABLE")
        return key

    def _wrap(self, dek: bytearray, context: KeyContext, nonce: bytes) -> StoredKey:
        material = self._held.get(self._active)
        if material is None:
            _reject("KEY_UNAVAILABLE")
        wrapping_key = self._wrapping_key(material, context)  # type: ignore[arg-type]
        try:
            sealed = bytearray(len(dek) + _TAG_BYTES)
            if not _primitives.aes_gcm_encrypt_into(wrapping_key, nonce, dek, None, sealed):
                _reject("KEY_UNAVAILABLE")
        finally:
            _buffers.zero(wrapping_key)
        wrapped = bytes([LOCAL_WRAP_VERSION]) + nonce + bytes(sealed)
        return StoredKey(_KEY_REF_PREFIX + self._active, wrapped)

    def _unwrap(self, stored: StoredKey, context: KeyContext) -> bytearray:
        if self._closed or not self._in_scope(context):
            _reject("KEY_UNAVAILABLE")
        material = None
        if stored.key_ref.startswith(_KEY_REF_PREFIX):
            material = self._held.get(stored.key_ref[len(_KEY_REF_PREFIX) :])
        if material is None:
            _reject("KEY_UNAVAILABLE")
        wrapped = stored.wrapped_key
        if len(wrapped) != _WRAPPED_BYTES or wrapped[0] != LOCAL_WRAP_VERSION:
            _reject("KEY_INTEGRITY")
        wrapping_key = self._wrapping_key(material, context)  # type: ignore[arg-type]
        dek = _buffers.new_buffer(_limits.DATA_KEY_BYTES)
        authentic = False
        try:
            nonce = wrapped[1 : 1 + _NONCE_BYTES]
            authentic = _primitives.aes_gcm_decrypt_into(wrapping_key, nonce, wrapped[1 + _NONCE_BYTES :], None, dek)
        finally:
            _buffers.zero(wrapping_key)
            if not authentic:
                _buffers.zero(dek)
        if not authentic:
            _reject("KEY_INTEGRITY")
        return dek

    def _generate(self, context: KeyContext) -> DataKey:
        ctx = _snapshot_context(context)
        if self._closed or not self._in_scope(ctx):
            _reject("KEY_UNAVAILABLE")
        dek = _buffers.random_buffer(_limits.DATA_KEY_BYTES)
        complete = False
        try:
            stored = self._wrap(dek, ctx, secrets.token_bytes(_NONCE_BYTES))
            complete = True
            return DataKey(stored.key_ref, stored.wrapped_key, dek)
        finally:
            if not complete:
                _buffers.zero(dek)

    def _rewrap(self, stored: StoredKey, context: KeyContext) -> StoredKey:
        snapshot = _snapshot_stored(stored)
        ctx = _snapshot_context(context)
        dek = self._unwrap(snapshot, ctx)
        try:
            return self._wrap(dek, ctx, secrets.token_bytes(_NONCE_BYTES))
        finally:
            _buffers.zero(dek)

    # -- KeyProvider ----------------------------------------------------------

    async def generate_data_key(self, context: KeyContext) -> DataKey:
        """A fresh random 256-bit data key under the active wrapping key."""

        code: KeyProviderErrorCode | None = None
        result: DataKey | None = None
        try:
            result = self._generate(context)
        except ProviderReject as rejected:
            code = rejected.code
        except Exception:
            code = "KEY_UNAVAILABLE"
        finally:
            del context
        if code is not None:
            raise KeyProviderError(code)
        assert result is not None
        return result

    async def unwrap_data_key(self, stored: StoredKey, context: KeyContext) -> bytearray:
        """Unwrap with exactly the key ``stored.key_ref`` names; never another key."""

        code: KeyProviderErrorCode | None = None
        result: bytearray | None = None
        try:
            result = self._unwrap(_snapshot_stored(stored), _snapshot_context(context))
        except ProviderReject as rejected:
            code = rejected.code
        except Exception:
            code = "KEY_UNAVAILABLE"
        finally:
            del stored, context
        if code is not None:
            raise KeyProviderError(code)
        assert result is not None
        return result

    async def rewrap_data_key(self, stored: StoredKey, context: KeyContext) -> StoredKey:
        """The same data key under the active wrapping key, for the same context."""

        code: KeyProviderErrorCode | None = None
        result: StoredKey | None = None
        try:
            result = self._rewrap(stored, context)
        except ProviderReject as rejected:
            code = rejected.code
        except Exception:
            code = "KEY_UNAVAILABLE"
        finally:
            del stored, context
        if code is not None:
            raise KeyProviderError(code)
        assert result is not None
        return result


def _build(keys: object, scope: object) -> LocalKeyProvider:
    if not isinstance(scope, LocalKeyScope):
        _reject("KEY_INVALID_ARGUMENT")
    namespaces, tenants = scope.namespaces, scope.tenants  # type: ignore[union-attr]
    if type(namespaces) is not tuple or len(namespaces) == 0 or not all(is_namespace(n) for n in namespaces):
        _reject("KEY_INVALID_ARGUMENT")
    if tenants is not None and (
        type(tenants) is not tuple or len(tenants) == 0 or not all(is_identifier(t) for t in tenants)
    ):
        _reject("KEY_INVALID_ARGUMENT")
    if type(keys) is not tuple or len(keys) == 0:
        _reject("KEY_INVALID_ARGUMENT")
    # Validate every key before copying any, so a rejected configuration copies nothing.
    declared: dict[str, LocalKey] = {}
    active: str | None = None
    for key in keys:
        if not isinstance(key, LocalKey) or type(key.id) is not str or _KEY_ID.fullmatch(key.id) is None:
            _reject("KEY_INVALID_ARGUMENT")
        if key.id in declared or key.state not in ("active", "decrypt-only", "retired"):
            _reject("KEY_INVALID_ARGUMENT")
        if not isinstance(key.material, (bytes, bytearray)) or len(key.material) != _MATERIAL_BYTES:
            _reject("KEY_INVALID_ARGUMENT")
        if key.state == "active":
            if active is not None:
                _reject("KEY_INVALID_ARGUMENT")
            active = key.id
        declared[key.id] = key
    if active is None:
        _reject("KEY_INVALID_ARGUMENT")
    held: dict[str, bytearray] = {}
    for key_id, key in declared.items():
        # A retired key neither wraps nor unwraps: its material is not copied or kept.
        if key.state == "retired":
            continue
        copy = _buffers.new_buffer(_MATERIAL_BYTES)
        copy[:] = key.material
        held[key_id] = copy
    return LocalKeyProvider(
        held,
        active,  # type: ignore[arg-type]
        frozenset(namespaces),
        None if tenants is None else frozenset(tenants),
    )


def create_local_key_provider(*, keys: tuple[LocalKey, ...], scope: LocalKeyScope) -> LocalKeyProvider:
    """Exactly one key is ``active``; identifiers are unique; the scope is explicit.

    ``KeyProviderError("KEY_INVALID_ARGUMENT")`` otherwise.
    """

    code: KeyProviderErrorCode | None = None
    provider: LocalKeyProvider | None = None
    try:
        provider = _build(keys, scope)
    except ProviderReject as rejected:
        code = rejected.code
    except Exception:
        code = "KEY_INVALID_ARGUMENT"
    if code is not None:
        raise KeyProviderError(code)
    assert provider is not None
    return provider
