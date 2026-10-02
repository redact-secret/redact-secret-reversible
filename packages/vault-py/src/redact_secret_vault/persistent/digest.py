"""The request digest (spec section 7.3) and the session tag (section 3.2).

Both are HMAC-SHA-256 under the application's digest key, or SHA-256 when the
application explicitly chose unkeyed digests. Mirrors
``packages/vault-crypto/src/digest.ts``. Standard library only.

The digest key is held as ``bytes``: Python cannot overwrite it (plan section
3.6). It is the application's own key, supplied explicitly; it is never read from
the environment, and the object refuses ``repr`` of it and pickling.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from . import limits as _limits
from ._reject import reject, sanitized
from .codec import label, lp16, u8, u16, u32, utf8
from .validate import (
    is_capture_id,
    is_entry_id,
    is_identifier,
    is_namespace,
    is_well_formed,
)

DIGEST_KEY_BYTES = 32
_MAX_PATHS_PER_USE = 0xFFFF
_MAX_OCCURRENCES = 0xFFFF_FFFF


@dataclass(frozen=True, slots=True)
class RequestPath:
    path: str
    #: 1 to 2**32 - 1.
    occurrences: int


@dataclass(frozen=True, slots=True)
class RequestUse:
    entry_id: str
    paths: tuple[RequestPath, ...]


@dataclass(frozen=True, slots=True)
class RequestDigestInput:
    namespace: str
    tenant: str
    principal_id: str
    #: The session resolved for this request, or None.
    session_id: str | None
    sink: str
    purpose: str
    #: Every capture the request names. Sorted here.
    capture_ids: tuple[str, ...]
    #: Each entry once. Entries and paths are sorted here.
    uses: tuple[RequestUse, ...]


@dataclass(frozen=True, slots=True)
class SessionTagInput:
    namespace: str
    tenant: str
    capture_id: str
    session_id: str


def _sorted_unique(items: list, key) -> list:  # type: ignore[no-untyped-def]
    """Ascending by the UTF-8 bytes ``key`` returns; a duplicate is rejected."""

    items.sort(key=key)
    for previous, current in zip(items, items[1:], strict=False):
        if key(previous) == key(current):
            reject("RECORD_INVALID_ARGUMENT")
    return items


def _encode_request(request: object) -> bytes:
    if not isinstance(request, RequestDigestInput):
        reject("RECORD_INVALID_ARGUMENT")
    r = request
    if not is_namespace(r.namespace) or not is_identifier(r.tenant):
        reject("RECORD_INVALID_ARGUMENT")
    if not is_identifier(r.principal_id) or not is_identifier(r.sink):
        reject("RECORD_INVALID_ARGUMENT")
    if r.session_id is not None and not is_identifier(r.session_id):
        reject("RECORD_INVALID_ARGUMENT")
    if type(r.purpose) is not str or len(r.purpose) == 0 or not is_well_formed(r.purpose):
        reject("RECORD_INVALID_ARGUMENT")
    # A code point is at least one UTF-8 byte, so a longer string cannot fit.
    if len(r.purpose) > _limits.PURPOSE_MAX_BYTES:
        reject("RECORD_LIMIT")
    purpose = utf8(r.purpose)
    if len(purpose) > _limits.PURPOSE_MAX_BYTES:
        reject("RECORD_LIMIT")

    if type(r.capture_ids) is not tuple or len(r.capture_ids) == 0:
        reject("RECORD_INVALID_ARGUMENT")
    if len(r.capture_ids) > _limits.MAX_RESTORE_CAPTURES:
        reject("RECORD_LIMIT")
    captures: list[bytes] = []
    for capture_id in r.capture_ids:
        if not is_capture_id(capture_id):
            reject("RECORD_INVALID_ARGUMENT")
        captures.append(utf8(capture_id))
    _sorted_unique(captures, lambda b: b)

    if type(r.uses) is not tuple or len(r.uses) == 0:
        reject("RECORD_INVALID_ARGUMENT")
    if len(r.uses) > _limits.MAX_RESTORE_ENTRIES:
        reject("RECORD_LIMIT")
    encoded_uses: list[tuple[bytes, list[tuple[bytes, int]]]] = []
    for use in r.uses:
        if not isinstance(use, RequestUse) or not is_entry_id(use.entry_id):
            reject("RECORD_INVALID_ARGUMENT")
        if type(use.paths) is not tuple or len(use.paths) == 0:
            reject("RECORD_INVALID_ARGUMENT")
        if len(use.paths) > _MAX_PATHS_PER_USE:
            reject("RECORD_LIMIT")
        paths: list[tuple[bytes, int]] = []
        for item in use.paths:
            if not isinstance(item, RequestPath) or not is_identifier(item.path):
                reject("RECORD_INVALID_ARGUMENT")
            occurrences = item.occurrences
            if type(occurrences) is not int or occurrences < 1 or occurrences > _limits.MAX_TIMESTAMP:
                reject("RECORD_INVALID_ARGUMENT")
            if occurrences > _MAX_OCCURRENCES:
                reject("RECORD_LIMIT")
            paths.append((utf8(item.path), occurrences))
        _sorted_unique(paths, lambda item: item[0])
        encoded_uses.append((utf8(use.entry_id), paths))
    _sorted_unique(encoded_uses, lambda use: use[0])

    session = b"" if r.session_id is None else utf8(r.session_id)
    parts = [
        label("rsv-request-v1"),
        lp16(utf8(r.namespace)),
        lp16(utf8(r.tenant)),
        lp16(utf8(r.principal_id)),
        u8(0 if r.session_id is None else 1),
        lp16(session),
        lp16(utf8(r.sink)),
        lp16(purpose),
        u16(len(captures)),
    ]
    parts.extend(lp16(capture) for capture in captures)
    parts.append(u16(len(encoded_uses)))
    for entry_id, paths in encoded_uses:
        parts.append(lp16(entry_id))
        parts.append(u16(len(paths)))
        for path, occurrences in paths:
            parts.append(lp16(path))
            parts.append(u32(occurrences))
    return b"".join(parts)


def _encode_session_tag(tag: object) -> bytes:
    if not isinstance(tag, SessionTagInput):
        reject("RECORD_INVALID_ARGUMENT")
    if not is_namespace(tag.namespace) or not is_identifier(tag.tenant):
        reject("RECORD_INVALID_ARGUMENT")
    if not is_capture_id(tag.capture_id) or not is_identifier(tag.session_id):
        reject("RECORD_INVALID_ARGUMENT")
    return b"".join(
        (
            label("rsv-session-tag-v1"),
            lp16(utf8(tag.namespace)),
            lp16(utf8(tag.tenant)),
            lp16(utf8(tag.capture_id)),
            lp16(utf8(tag.session_id)),
        )
    )


class Digester:
    """MAC of section 7.3 under one key. Build it with ``create_digester``."""

    __slots__ = ("_key",)

    def __init__(self, key: bytes | None) -> None:
        self._key = key

    def _mac(self, message: bytes) -> bytes:
        if self._key is None:
            return hashlib.sha256(message).digest()
        return hmac.digest(self._key, message, "sha256")

    @sanitized
    def request_digest(self, request: RequestDigestInput) -> bytes:
        """32 bytes."""

        return self._mac(_encode_request(request))

    @sanitized
    def session_tag(self, tag: SessionTagInput) -> str:
        """64 lowercase hexadecimal characters."""

        return self._mac(_encode_session_tag(tag)).hex()

    def __repr__(self) -> str:
        return f"Digester(keyed={self._key is not None})"

    def __reduce__(self) -> tuple[object, ...]:
        raise TypeError("Digester must not be pickled or copied")


@sanitized
def create_digester(*, key: bytes | bytearray | None = None, unkeyed: bool = False) -> Digester:
    """HMAC-SHA-256 under a 32-byte ``key``, or SHA-256 when ``unkeyed=True``; exactly one.

    The unkeyed form accepts that a party reading the store can test guesses
    against what is stored (spec section 7.3). The key is copied: the caller's
    buffer is not retained and may be overwritten once this returns.
    """

    if type(unkeyed) is not bool:
        reject("RECORD_INVALID_ARGUMENT")
    if key is not None and not unkeyed:
        if not isinstance(key, (bytes, bytearray)) or len(key) != DIGEST_KEY_BYTES:
            reject("RECORD_INVALID_ARGUMENT")
        return Digester(bytes(key))
    if key is None and unkeyed:
        return Digester(None)
    reject("RECORD_INVALID_ARGUMENT")
