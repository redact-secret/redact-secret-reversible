"""``RecordCrypto`` over a ``KeyProvider``: one data key per capture, one derived
AES-256-GCM key per entry, one random nonce per encryption (spec section 3.3).

Mirrors ``packages/vault-crypto/src/record-crypto.ts``. The provider is called once
per ``seal_capture``, once per ``open_capture``, and once per ``rewrap_capture_key``;
no key is cached between calls.

Buffers and errors follow plan sections 3.4 and 3.6:

* data keys, entry keys, and decrypted payloads are ``bytearray`` allocated through
  ``persistent._buffers`` and overwritten on every path, success or failure;
* a failure inside is turned into a new error raised from the public method's own
  frame, after the ``except`` block has ended, so ``__cause__`` and ``__context__``
  are ``None`` and the traceback does not reach a frame that held a key;
* ``asyncio.CancelledError`` and the other ``BaseException`` subclasses are never
  converted.

There is no nonce parameter anywhere in the public API. A nonce is drawn from the
CSPRNG in the process that encrypts; only ``_seal_entry``, which tests use with a
fixed nonce to reproduce the vectors, takes one, and it is not exported.
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass
from typing import Final

from ..persistent import _buffers
from ..persistent import limits as _limits
from ..persistent._reject import Reject, reject
from ..persistent.codec import (
    NONCE_BYTES,
    TAG_BYTES,
    EnvelopeParts,
    PayloadPlan,
    check_binding,
    decode_payload,
    encode_aad,
    encode_envelope,
    parse_envelope,
    plan_payload,
    write_payload,
)
from ..persistent.contracts import (
    KeyContext,
    KeyProvider,
    RecordBinding,
    RecordPayload,
    SealedCapture,
    StoredKey,
)
from ..persistent.derive import entry_key_info
from ..persistent.errors import (
    KeyProviderError,
    KeyProviderErrorCode,
    RecordCryptoError,
    RecordCryptoErrorCode,
)
from ..persistent.validate import is_capture_id, is_identifier, is_key_ref, is_namespace
from . import _primitives
from ._provider_call import (
    ProviderReject,
    call_provider,
    check_data_key,
    check_plaintext_key,
    check_stored_key,
    discard_data_key,
    discard_plaintext_key,
)

RECORD_CRYPTO_PROFILE: Final = "aes-256-gcm-hkdf-v1"
DEFAULT_KEY_TIMEOUT_S: Final = 5.0
_MAX_KEY_TIMEOUT_S: Final = 2_147_483.0


@dataclass(frozen=True, slots=True)
class _Failure:
    """What a public method re-raises, as a fresh error, once its ``except`` block has ended."""

    record: RecordCryptoErrorCode | None = None
    key: KeyProviderErrorCode | None = None


def _error(failure: _Failure) -> KeyProviderError | RecordCryptoError:
    """A new error, to be raised by the caller from its own frame."""

    if failure.key is not None:
        return KeyProviderError(failure.key)
    assert failure.record is not None
    return RecordCryptoError(failure.record)


def _snapshot_context(context: object) -> KeyContext:
    if not isinstance(context, KeyContext):
        reject("RECORD_INVALID_ARGUMENT")
    if (
        not is_namespace(context.namespace)
        or not is_identifier(context.tenant)
        or not is_capture_id(context.capture_id)
    ):
        reject("RECORD_INVALID_ARGUMENT")
    return context


def _snapshot_stored_key(stored: object) -> StoredKey:
    if not isinstance(stored, StoredKey) or not is_key_ref(stored.key_ref) or not isinstance(stored.wrapped_key, bytes):
        reject("RECORD_INVALID_ARGUMENT")
    if len(stored.wrapped_key) == 0:
        reject("RECORD_INVALID_ARGUMENT")
    if len(stored.wrapped_key) > _limits.WRAPPED_KEY_MAX_BYTES:
        reject("RECORD_LIMIT")
    return StoredKey(stored.key_ref, bytes(stored.wrapped_key))


@dataclass(frozen=True, slots=True)
class _Bound:
    binding: RecordBinding
    aad: bytes
    item: object


def _bind_records(context: KeyContext, records: object, ceiling: int) -> list[_Bound]:
    """Validate the bindings of one capture: each inside ``context``, no entry twice."""

    if type(records) is not tuple or len(records) == 0:
        reject("RECORD_INVALID_ARGUMENT")
    if len(records) > ceiling:
        reject("RECORD_LIMIT")
    seen: set[str] = set()
    bound: list[_Bound] = []
    for record in records:
        if type(record) is not tuple or len(record) != 2:
            reject("RECORD_INVALID_ARGUMENT")
        binding = check_binding(record[0])
        if (
            binding.namespace != context.namespace
            or binding.tenant != context.tenant
            or binding.capture_id != context.capture_id
            or binding.entry_id in seen
        ):
            reject("RECORD_INVALID_ARGUMENT")
        seen.add(binding.entry_id)
        bound.append(_Bound(binding, encode_aad(binding), record[1]))
    return bound


def derive_entry_key(dek: bytearray, entry_id: str) -> bytearray:
    """The entry key of spec section 3.3 in a new buffer the caller overwrites.

    ``HKDF-SHA-256(ikm = dek, salt = 32 zero bytes, info = "rsv-entry-key-v1" 0x00
    || u8 algorithm || lp16(entryId), length = 32)``.
    """

    info = entry_key_info(entry_id)
    key = _buffers.new_buffer(_limits.DATA_KEY_BYTES)
    if not _primitives.hkdf_sha256_into(dek, info, key):
        _buffers.zero(key)
        reject("RECORD_UNSUPPORTED")
    return key


def _seal_entry(entry_key: bytearray, nonce: bytes, plaintext: bytearray, aad: bytes) -> bytes:
    """The envelope of one entry under a given nonce. Tests only: the public API draws its own."""

    sealed = bytearray(len(plaintext) + TAG_BYTES)
    if not _primitives.aes_gcm_encrypt_into(entry_key, nonce, plaintext, aad, sealed):
        reject("RECORD_UNSUPPORTED")
    return encode_envelope(nonce, bytes(sealed))


def _open_entry(entry_key: bytearray, parts: EnvelopeParts, aad: bytes) -> RecordPayload:
    """Authenticate and decode one envelope. The plaintext buffer is overwritten before returning or failing."""

    plaintext = _buffers.new_buffer(len(parts.ciphertext) - TAG_BYTES)
    try:
        if not _primitives.aes_gcm_decrypt_into(entry_key, parts.nonce, parts.ciphertext, aad, plaintext):
            reject("RECORD_INTEGRITY")
        return decode_payload(plaintext)
    finally:
        _buffers.zero(plaintext)


class KeyProviderRecordCrypto:
    """A ``RecordCrypto`` of profile ``aes-256-gcm-hkdf-v1``. Build it with ``create_record_crypto``."""

    __slots__ = ("_provider", "_timeout_s")

    def __init__(self, provider: KeyProvider, timeout_s: float) -> None:
        self._provider = provider
        self._timeout_s = timeout_s

    @property
    def profile(self) -> str:
        return RECORD_CRYPTO_PROFILE

    def __repr__(self) -> str:
        return f"KeyProviderRecordCrypto(profile={RECORD_CRYPTO_PROFILE!r})"

    def __reduce__(self) -> tuple[object, ...]:
        raise TypeError("KeyProviderRecordCrypto must not be pickled or copied")

    # -- seal ---------------------------------------------------------------

    async def _seal(
        self, context: KeyContext, records: tuple[tuple[RecordBinding, RecordPayload], ...]
    ) -> SealedCapture:
        ctx = _snapshot_context(context)
        bound = _bind_records(ctx, records, _limits.MAX_CREATE_ENTRIES)
        plans: list[PayloadPlan] = [plan_payload(entry.item) for entry in bound]  # type: ignore[arg-type]

        provider = self._provider
        data_key = await call_provider(
            lambda: provider.generate_data_key(ctx), check_data_key, discard_data_key, self._timeout_s
        )
        try:
            envelopes: list[bytes] = []
            for entry, plan in zip(bound, plans, strict=True):
                entry_key = derive_entry_key(data_key.plaintext_key, entry.binding.entry_id)
                payload: bytearray | None = None
                try:
                    payload = write_payload(plan)
                    envelopes.append(_seal_entry(entry_key, secrets.token_bytes(NONCE_BYTES), payload, entry.aad))
                finally:
                    _buffers.zero(payload)
                    _buffers.zero(entry_key)
            return SealedCapture(data_key.key_ref, bytes(data_key.wrapped_key), tuple(envelopes))
        finally:
            _buffers.zero(data_key.plaintext_key)

    async def seal_capture(
        self, context: KeyContext, records: tuple[tuple[RecordBinding, RecordPayload], ...]
    ) -> SealedCapture:
        """One data key from the provider, then one envelope per record, in order."""

        failure: _Failure | None = None
        result: SealedCapture | None = None
        try:
            result = await self._seal(context, records)
        except (Reject, RecordCryptoError) as error:
            failure = _Failure(record=error.code)
        except (ProviderReject, KeyProviderError) as error:
            failure = _Failure(key=error.code)
        except Exception:
            failure = _Failure(record="RECORD_UNSUPPORTED")
        finally:
            # A traceback keeps this frame, and a frame keeps its locals: drop the arguments first.
            del context, records
        if failure is not None:
            raise _error(failure)
        assert result is not None
        return result

    # -- open ---------------------------------------------------------------

    async def _open(
        self, stored: StoredKey, context: KeyContext, records: tuple[tuple[RecordBinding, bytes], ...]
    ) -> tuple[RecordPayload, ...]:
        ctx = _snapshot_context(context)
        key = _snapshot_stored_key(stored)
        bound = _bind_records(ctx, records, _limits.MAX_RESTORE_ENTRIES)
        # Every envelope is parsed, and its version and algorithm checked, before any key is unwrapped.
        envelopes = [parse_envelope(entry.item) for entry in bound]  # type: ignore[arg-type]

        provider = self._provider
        dek = await call_provider(
            lambda: provider.unwrap_data_key(key, ctx), check_plaintext_key, discard_plaintext_key, self._timeout_s
        )
        opened: list[RecordPayload] = []
        complete = False
        try:
            for entry, parts in zip(bound, envelopes, strict=True):
                entry_key = derive_entry_key(dek, entry.binding.entry_id)
                try:
                    opened.append(_open_entry(entry_key, parts, entry.aad))
                finally:
                    _buffers.zero(entry_key)
            complete = True
            return tuple(opened)
        finally:
            if not complete:
                for payload in opened:
                    _buffers.zero(payload.value)
                opened.clear()
            _buffers.zero(dek)

    async def open_capture(
        self, stored: StoredKey, context: KeyContext, records: tuple[tuple[RecordBinding, bytes], ...]
    ) -> tuple[RecordPayload, ...]:
        """Payloads in the order of ``records``: all of them, or an error, never a partial result.

        Each returned ``value`` is a ``bytearray`` the caller overwrites.
        """

        failure: _Failure | None = None
        result: tuple[RecordPayload, ...] | None = None
        try:
            result = await self._open(stored, context, records)
        except (Reject, RecordCryptoError) as error:
            failure = _Failure(record=error.code)
        except (ProviderReject, KeyProviderError) as error:
            failure = _Failure(key=error.code)
        except Exception:
            failure = _Failure(record="RECORD_INTEGRITY")
        finally:
            del stored, context, records
        if failure is not None:
            raise _error(failure)
        assert result is not None
        return result

    # -- rewrap -------------------------------------------------------------

    async def _rewrap(self, stored: StoredKey, context: KeyContext) -> StoredKey:
        ctx = _snapshot_context(context)
        key = _snapshot_stored_key(stored)
        provider = self._provider
        return await call_provider(
            lambda: provider.rewrap_data_key(key, ctx), check_stored_key, lambda _result: None, self._timeout_s
        )

    async def rewrap_capture_key(self, stored: StoredKey, context: KeyContext) -> StoredKey:
        """The same data key wrapped under the provider's active key, for the same context."""

        failure: _Failure | None = None
        result: StoredKey | None = None
        try:
            result = await self._rewrap(stored, context)
        except (Reject, RecordCryptoError) as error:
            failure = _Failure(record=error.code)
        except (ProviderReject, KeyProviderError) as error:
            failure = _Failure(key=error.code)
        except Exception:
            failure = _Failure(record="RECORD_UNSUPPORTED")
        finally:
            del stored, context
        if failure is not None:
            raise _error(failure)
        assert result is not None
        return result


def create_record_crypto(
    *, key_provider: KeyProvider, key_timeout_s: float = DEFAULT_KEY_TIMEOUT_S
) -> KeyProviderRecordCrypto:
    """A ``RecordCrypto`` over ``key_provider``. ``key_timeout_s`` bounds each provider call (default 5 s)."""

    failure: RecordCryptoErrorCode | None = None
    provider = key_provider
    if not all(
        callable(getattr(provider, name, None)) for name in ("generate_data_key", "unwrap_data_key", "rewrap_data_key")
    ):
        failure = "RECORD_INVALID_ARGUMENT"
    elif type(key_timeout_s) not in (int, float) or not math.isfinite(key_timeout_s):
        failure = "RECORD_INVALID_ARGUMENT"
    elif not 0 < key_timeout_s <= _MAX_KEY_TIMEOUT_S:
        failure = "RECORD_INVALID_ARGUMENT"
    if failure is not None:
        raise RecordCryptoError(failure)
    return KeyProviderRecordCrypto(provider, float(key_timeout_s))
