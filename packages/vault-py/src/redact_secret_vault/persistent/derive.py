"""Derivations of record format version 1 that need only the standard library.

The entry identifier (spec section 3.2) and the ``info`` string of the entry key
(section 3.3). The HKDF itself needs ``cryptography`` and lives in
``redact_secret_vault.crypto``.
"""

from __future__ import annotations

import hashlib
import re
from typing import Final

from ._reject import reject, sanitized
from .codec import ALGORITHM_AES_256_GCM, label, lp16, u8, utf8
from .validate import is_entry_id, is_identifier, is_namespace

_ISSUED_TOKEN: Final = re.compile(r"<rsv_[a-z2-7]{26}>")


@sanitized
def derive_entry_id(namespace: str, tenant: str, token: str) -> str:
    """``hex(SHA-256("rsv-entry-id-v1" 0x00 || lp16(namespace) || lp16(tenant) || lp16(token)))``.

    ``token`` is the issued token as written, including ``<`` and ``>``. The
    digest is unkeyed (spec section 3.2); a token carries 128 bits from the CSPRNG.
    """

    if not is_namespace(namespace) or not is_identifier(tenant):
        reject("RECORD_INVALID_ARGUMENT")
    if type(token) is not str or _ISSUED_TOKEN.fullmatch(token) is None:
        reject("RECORD_INVALID_ARGUMENT")
    message = label("rsv-entry-id-v1") + lp16(utf8(namespace)) + lp16(utf8(tenant)) + lp16(utf8(token))
    return hashlib.sha256(message).hexdigest()


@sanitized
def entry_key_info(entry_id: str) -> bytes:
    """``"rsv-entry-key-v1" 0x00 || u8 algorithm || lp16(entryId)``: the HKDF ``info`` of an entry key."""

    if not is_entry_id(entry_id):
        reject("RECORD_INVALID_ARGUMENT")
    return label("rsv-entry-key-v1") + u8(ALGORITHM_AES_256_GCM) + lp16(utf8(entry_id))
