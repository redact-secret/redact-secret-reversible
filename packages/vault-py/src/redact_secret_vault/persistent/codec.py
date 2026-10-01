"""Canonical encodings of record format version 1.

Associated data (spec section 3.4), payload and envelope (section 3.5), under
the limits of section 3.6. Mirrors ``packages/vault-crypto/src/codec.ts``. Pure
functions: no key, no randomness, no I/O, no AEAD. Standard library only.

Every failure is a ``RecordCryptoError`` with a fixed message and neither
``__cause__`` nor ``__context__``. A decoder never allocates what a length
field claims: it checks the length against the bytes present first.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from ..utf16 import utf16_length
from . import _buffers
from . import limits as _limits
from ._reject import reject, sanitized
from .contracts import Grant, RecordBinding, RecordPayload
from .validate import (
    is_capture_id,
    is_entry_id,
    is_identifier,
    is_namespace,
    is_positive_int,
    is_timestamp,
    is_well_formed,
)

FORMAT_VERSION: Final = 1
PAYLOAD_VERSION: Final = 1
#: AES-256-GCM, 96-bit nonce, 128-bit tag (spec section 3.3). The only allowed algorithm.
ALGORITHM_AES_256_GCM: Final = 1
NONCE_BYTES: Final = 12
TAG_BYTES: Final = 16

_MAGIC: Final = b"RSVE"
#: magic, formatVersion, algorithm, nonce, u32 length.
_ENVELOPE_HEADER_BYTES: Final = len(_MAGIC) + 1 + 1 + NONCE_BYTES + 4
MAX_SEALED_BYTES: Final = _limits.MAX_ENVELOPE_BYTES - _ENVELOPE_HEADER_BYTES
#: The largest payload whose envelope still fits ``MAX_ENVELOPE_BYTES``.
MAX_PAYLOAD_BYTES: Final = MAX_SEALED_BYTES - TAG_BYTES

_BYTES_LIKE: Final = (bytes, bytearray, memoryview)


# --------------------------------------------------------------------------
# Byte helpers
# --------------------------------------------------------------------------


def label(text: str) -> bytes:
    """A label followed by one zero byte: how every domain separator of sections 3 and 7.3 is written."""

    return text.encode("ascii") + b"\x00"


def utf8(text: object) -> bytes:
    """UTF-8 of a well-formed string. A lone surrogate is ``RECORD_INVALID_ARGUMENT``.

    The test comes first and the encoding is always strict, so a failure is a
    fixed error and never a ``UnicodeEncodeError`` that carries the string.
    """

    if not is_well_formed(text):
        reject("RECORD_INVALID_ARGUMENT")
    return text.encode("utf-8", "strict")  # type: ignore[union-attr]


def lp16(data: bytes) -> bytes:
    if len(data) > 0xFFFF:
        reject("RECORD_LIMIT")
    return len(data).to_bytes(2, "big") + data


def u8(value: int) -> bytes:
    return value.to_bytes(1, "big")


def u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _view(data: object) -> memoryview:
    """A flat byte view of ``data``, or ``RECORD_INVALID_ARGUMENT``."""

    if not isinstance(data, _BYTES_LIKE):
        reject("RECORD_INVALID_ARGUMENT")
    view = memoryview(data)
    if view.ndim != 1 or view.format != "B" or not view.contiguous:
        reject("RECORD_INVALID_ARGUMENT")
    return view


def _from_utf8(view: memoryview) -> str:
    """Strict UTF-8 decoding. Invalid input is ``RECORD_MALFORMED``; a leading U+FEFF is kept."""

    text: str | None
    try:
        text = str(view, "utf-8", "strict")
    except UnicodeDecodeError:
        text = None
    if text is None:
        reject("RECORD_MALFORMED")
    return text


class _Reader:
    """A bounds-checked cursor. It returns views and never allocates from a length field."""

    __slots__ = ("_offset", "_view")

    def __init__(self, view: memoryview) -> None:
        self._view = view
        self._offset = 0

    @property
    def remaining(self) -> int:
        return len(self._view) - self._offset

    def take(self, length: int) -> memoryview:
        if length > self.remaining:
            reject("RECORD_MALFORMED")
        chunk = self._view[self._offset : self._offset + length]
        self._offset += length
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def end(self) -> None:
        if self.remaining != 0:
            reject("RECORD_MALFORMED")


# --------------------------------------------------------------------------
# Binding and associated data
# --------------------------------------------------------------------------


def check_binding(binding: object) -> RecordBinding:
    """Validate a binding against the contract. ``RECORD_INVALID_ARGUMENT`` otherwise."""

    if not isinstance(binding, RecordBinding):
        reject("RECORD_INVALID_ARGUMENT")
    if (
        not is_namespace(binding.namespace)
        or not is_identifier(binding.tenant)
        or not is_capture_id(binding.capture_id)
        or not is_entry_id(binding.entry_id)
    ):
        reject("RECORD_INVALID_ARGUMENT")
    if binding.session_id is not None and not is_identifier(binding.session_id):
        reject("RECORD_INVALID_ARGUMENT")
    if not is_timestamp(binding.created_at) or not is_timestamp(binding.expires_at):
        reject("RECORD_INVALID_ARGUMENT")
    lifetime = binding.expires_at - binding.created_at
    if lifetime <= 0 or lifetime > _limits.MAX_CAPTURE_LIFETIME_MS:
        reject("RECORD_INVALID_ARGUMENT")
    if not is_positive_int(binding.max_uses) or binding.max_uses > _limits.MAX_USES:
        reject("RECORD_INVALID_ARGUMENT")
    return binding


def _aad(binding: RecordBinding) -> bytes:
    b = check_binding(binding)
    session = b"" if b.session_id is None else utf8(b.session_id)
    return b"".join(
        (
            label("rsv-aad-v1"),
            u8(FORMAT_VERSION),
            u8(ALGORITHM_AES_256_GCM),
            lp16(utf8(b.namespace)),
            lp16(utf8(b.tenant)),
            lp16(utf8(b.capture_id)),
            lp16(utf8(b.entry_id)),
            u8(0 if b.session_id is None else 1),
            lp16(session),
            u64(b.created_at),
            u64(b.expires_at),
            u32(b.max_uses),
        )
    )


@sanitized
def encode_aad(binding: RecordBinding) -> bytes:
    """The associated data of section 3.4 for one entry."""

    return _aad(binding)


# --------------------------------------------------------------------------
# Payload
# --------------------------------------------------------------------------


def _canonical_set(values: object) -> list[bytes]:
    """UTF-8 of each identifier, ascending by those bytes, a duplicate rejected."""

    if type(values) is not tuple:
        reject("RECORD_INVALID_ARGUMENT")
    encoded: list[bytes] = []
    for value in values:
        if not is_identifier(value):
            reject("RECORD_INVALID_ARGUMENT")
        encoded.append(utf8(value))
    # bytes compare as unsigned values; this is the order of the specification, not str order.
    encoded.sort()
    for previous, current in zip(encoded, encoded[1:], strict=False):
        if previous == current:
            reject("RECORD_INVALID_ARGUMENT")
    return encoded


@dataclass(frozen=True, slots=True, repr=False)
class PayloadPlan:
    """A validated payload ready to be written.

    It holds the encoded metadata and a reference to the caller's value, not a
    copy: plaintext is copied only by ``write_payload``, into a buffer the
    caller of that function overwrites.
    """

    value: memoryview
    value_bytes: int
    type: bytes
    grants: tuple[tuple[bytes, tuple[bytes, ...]], ...]
    policy_revision: bytes | None
    size: int

    def __repr__(self) -> str:
        return f"PayloadPlan(size={self.size})"


def _plan(payload: object) -> PayloadPlan:
    if not isinstance(payload, RecordPayload):
        reject("RECORD_INVALID_ARGUMENT")
    type_, grants, policy_revision = payload.type, payload.grants, payload.policy_revision
    value = _view(payload.value)
    value_bytes = len(value)
    if value_bytes > _limits.MAX_VALUE_BYTES:
        reject("RECORD_LIMIT")
    if type(type_) is not str or len(type_) == 0:
        reject("RECORD_INVALID_ARGUMENT")
    # A code point is at least one UTF-8 byte, so a longer string cannot fit.
    if len(type_) > _limits.TYPE_MAX_BYTES:
        reject("RECORD_LIMIT")
    type_bytes = utf8(type_)
    if len(type_bytes) > _limits.TYPE_MAX_BYTES:
        reject("RECORD_LIMIT")

    revision_bytes: bytes | None = None
    if policy_revision is not None:
        if type(policy_revision) is not str:
            reject("RECORD_INVALID_ARGUMENT")
        if len(policy_revision) > _limits.POLICY_REVISION_MAX_BYTES:
            reject("RECORD_LIMIT")
        revision_bytes = utf8(policy_revision)
        if len(revision_bytes) > _limits.POLICY_REVISION_MAX_BYTES:
            reject("RECORD_LIMIT")

    if type(grants) is not tuple or len(grants) == 0:
        reject("RECORD_INVALID_ARGUMENT")
    if len(grants) > _limits.MAX_GRANTS:
        reject("RECORD_LIMIT")
    revision_size = 0 if revision_bytes is None else len(revision_bytes)
    size = 1 + 4 + value_bytes + 2 + len(type_bytes) + 2 + 1 + 2 + revision_size
    encoded_grants: list[tuple[bytes, tuple[bytes, ...]]] = []
    for grant in grants:
        if not isinstance(grant, Grant) or type(grant.paths) is not tuple or len(grant.paths) == 0:
            reject("RECORD_INVALID_ARGUMENT")
        if len(grant.paths) > _limits.MAX_PATHS_PER_GRANT:
            reject("RECORD_LIMIT")
        if not is_identifier(grant.sink):
            reject("RECORD_INVALID_ARGUMENT")
        sink = utf8(grant.sink)
        paths = tuple(_canonical_set(grant.paths))
        size += 2 + len(sink) + 2
        for path in paths:
            size += 2 + len(path)
        if size > MAX_PAYLOAD_BYTES:
            reject("RECORD_LIMIT")
        encoded_grants.append((sink, paths))
    if size > MAX_PAYLOAD_BYTES:
        reject("RECORD_LIMIT")
    encoded_grants.sort(key=lambda grant: grant[0])
    for previous, current in zip(encoded_grants, encoded_grants[1:], strict=False):
        if previous[0] == current[0]:
            reject("RECORD_INVALID_ARGUMENT")
    return PayloadPlan(value, value_bytes, type_bytes, tuple(encoded_grants), revision_bytes, size)


def _write(plan: PayloadPlan) -> bytearray:
    # The value is referenced, not copied, by the plan: refuse one that changed size since.
    value = plan.value
    if len(value) != plan.value_bytes:
        reject("RECORD_INVALID_ARGUMENT")
    out = _buffers.new_buffer(plan.size)
    offset = 0

    def put(chunk: bytes | bytearray | memoryview) -> None:
        nonlocal offset
        out[offset : offset + len(chunk)] = chunk
        offset += len(chunk)

    put(u8(PAYLOAD_VERSION))
    put(u32(plan.value_bytes))
    put(value)
    put(lp16(plan.type))
    put(u16(len(plan.grants)))
    for sink, paths in plan.grants:
        put(lp16(sink))
        put(u16(len(paths)))
        for path in paths:
            put(lp16(path))
    put(u8(0 if plan.policy_revision is None else 1))
    put(lp16(plan.policy_revision or b""))
    return out


@sanitized
def plan_payload(payload: RecordPayload) -> PayloadPlan:
    """Validate a payload and return what ``write_payload`` needs. Nothing is copied yet."""

    return _plan(payload)


@sanitized
def write_payload(plan: PayloadPlan) -> bytearray:
    """Write a planned payload. The result holds plaintext; the caller overwrites it."""

    if not isinstance(plan, PayloadPlan):
        reject("RECORD_INVALID_ARGUMENT")
    return _write(plan)


@sanitized
def encode_payload(payload: RecordPayload) -> bytearray:
    """The plaintext of section 3.5.

    Grants are ordered by the UTF-8 bytes of their sink and paths by their UTF-8
    bytes; a duplicate sink, or a duplicate path within a grant, is rejected. The
    result holds the value: overwrite it.
    """

    return _write(_plan(payload))


def _read_identifier(reader: _Reader, previous: memoryview | None) -> tuple[memoryview, str]:
    raw = reader.take(reader.u16())
    if len(raw) == 0:
        reject("RECORD_MALFORMED")
    if previous is not None and bytes(previous) >= bytes(raw):
        reject("RECORD_MALFORMED")
    text = _from_utf8(raw)
    if utf16_length(text) > _limits.IDENTIFIER_MAX_LENGTH:
        reject("RECORD_LIMIT")
    return raw, text


@sanitized
def decode_payload(data: bytes | bytearray | memoryview) -> RecordPayload:
    """Strict inverse of ``encode_payload``.

    Rejects an unknown version, a length past the input, a value over a limit, a
    zero count, a non-canonical order, a duplicate, a presence flag other than 0
    or 1, a non-empty field whose flag is 0, invalid UTF-8, and trailing bytes.
    ``value`` is a fresh ``bytearray`` the caller overwrites.
    """

    view = _view(data)
    if len(view) > MAX_PAYLOAD_BYTES:
        reject("RECORD_LIMIT")
    reader = _Reader(view)
    if reader.u8() != PAYLOAD_VERSION:
        reject("RECORD_UNSUPPORTED")

    value_bytes = reader.u32()
    if value_bytes > _limits.MAX_VALUE_BYTES:
        reject("RECORD_LIMIT")
    value_view = reader.take(value_bytes)

    type_length = reader.u16()
    if type_length > _limits.TYPE_MAX_BYTES:
        reject("RECORD_LIMIT")
    if type_length == 0:
        reject("RECORD_MALFORMED")
    type_text = _from_utf8(reader.take(type_length))

    grant_count = reader.u16()
    if grant_count == 0:
        reject("RECORD_MALFORMED")
    if grant_count > _limits.MAX_GRANTS:
        reject("RECORD_LIMIT")
    grants: list[Grant] = []
    previous_sink: memoryview | None = None
    for _ in range(grant_count):
        sink_raw, sink_text = _read_identifier(reader, previous_sink)
        previous_sink = sink_raw
        path_count = reader.u16()
        if path_count == 0:
            reject("RECORD_MALFORMED")
        if path_count > _limits.MAX_PATHS_PER_GRANT:
            reject("RECORD_LIMIT")
        paths: list[str] = []
        previous_path: memoryview | None = None
        for _ in range(path_count):
            path_raw, path_text = _read_identifier(reader, previous_path)
            previous_path = path_raw
            paths.append(path_text)
        grants.append(Grant(sink_text, tuple(paths)))

    has_policy_revision = reader.u8()
    if has_policy_revision not in (0, 1):
        reject("RECORD_MALFORMED")
    revision_length = reader.u16()
    if revision_length > _limits.POLICY_REVISION_MAX_BYTES:
        reject("RECORD_LIMIT")
    if has_policy_revision == 0 and revision_length != 0:
        reject("RECORD_MALFORMED")
    revision_text = _from_utf8(reader.take(revision_length))
    reader.end()

    value = _buffers.new_buffer(value_bytes)
    value[:] = value_view
    return RecordPayload(value, type_text, tuple(grants), revision_text if has_policy_revision == 1 else None)


# --------------------------------------------------------------------------
# Envelope
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EnvelopeParts:
    #: 12 bytes.
    nonce: bytes
    #: AES-GCM output: ciphertext followed by the 16-byte tag.
    ciphertext: bytes


@sanitized
def encode_envelope(nonce: bytes, ciphertext: bytes) -> bytes:
    """The stored envelope of section 3.5: ``"RSVE" || u8 1 || u8 1 || nonce || lp32(ciphertext || tag)``."""

    if not isinstance(nonce, bytes) or not isinstance(ciphertext, bytes):
        reject("RECORD_INVALID_ARGUMENT")
    if len(nonce) != NONCE_BYTES or len(ciphertext) <= TAG_BYTES:
        reject("RECORD_INVALID_ARGUMENT")
    if len(ciphertext) > MAX_SEALED_BYTES:
        reject("RECORD_LIMIT")
    return b"".join((_MAGIC, u8(FORMAT_VERSION), u8(ALGORITHM_AES_256_GCM), nonce, u32(len(ciphertext)), ciphertext))


@sanitized
def parse_envelope(data: bytes | bytearray | memoryview) -> EnvelopeParts:
    """Strict parse of an envelope; the AEAD is not involved.

    The magic, the version, and the algorithm allowlist are checked before any
    length, and a length is checked against the bytes present before anything
    is read. The returned parts are copies.
    """

    view = _view(data)
    if len(view) > _limits.MAX_ENVELOPE_BYTES:
        reject("RECORD_LIMIT")
    reader = _Reader(view)
    if bytes(reader.take(len(_MAGIC))) != _MAGIC:
        reject("RECORD_MALFORMED")
    if reader.u8() != FORMAT_VERSION:
        reject("RECORD_UNSUPPORTED")
    if reader.u8() != ALGORITHM_AES_256_GCM:
        reject("RECORD_UNSUPPORTED")
    nonce = bytes(reader.take(NONCE_BYTES))
    sealed_bytes = reader.u32()
    if sealed_bytes > MAX_SEALED_BYTES:
        reject("RECORD_LIMIT")
    if sealed_bytes != reader.remaining or sealed_bytes <= TAG_BYTES:
        reject("RECORD_MALFORMED")
    return EnvelopeParts(nonce, bytes(reader.take(sealed_bytes)))
