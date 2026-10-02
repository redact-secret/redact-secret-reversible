"""Internal: HKDF-SHA-256 and AES-256-GCM over ``cryptography``, into caller-owned buffers.

``cryptography`` 47 added ``HKDF.derive_into`` and ``AESGCM.encrypt_into`` /
``decrypt_into`` (https://cryptography.io/en/latest/hazmat/primitives/aead/), so an
entry key and a decrypted payload are written straight into a ``bytearray`` this
package overwrites, and never exist as immutable ``bytes``. ``AESGCM(key)`` copies
the key into the backing library's context, which Python cannot clear (plan
section 3.6).

Every function reports failure by return value. A ``cryptography`` exception
(``InvalidTag`` among them) is caught and dropped inside the function and never
bound outside it, so none of them can become a ``__cause__`` or ``__context__``.
"""

from __future__ import annotations

from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ZERO_SALT: Final = bytes(32)
TAG_BYTES: Final = 16
NONCE_BYTES: Final = 12


def hkdf_sha256_into(ikm: bytearray, info: bytes, out: bytearray) -> bool:
    """HKDF-SHA-256 with a 32-byte zero salt, ``len(out)`` bytes of output into ``out``."""

    ok = True
    try:
        HKDF(algorithm=hashes.SHA256(), length=len(out), salt=ZERO_SALT, info=info).derive_into(ikm, out)
    except Exception:
        ok = False
    return ok


def aes_gcm_encrypt_into(
    key: bytearray, nonce: bytes, plaintext: bytearray | bytes, aad: bytes | None, out: bytearray
) -> bool:
    """``ciphertext || tag`` into ``out``, which is ``len(plaintext) + 16`` bytes."""

    ok = True
    try:
        AESGCM(key).encrypt_into(nonce, plaintext, aad, out)
    except Exception:
        ok = False
    return ok


def aes_gcm_decrypt_into(key: bytearray, nonce: bytes, sealed: bytes, aad: bytes | None, out: bytearray) -> bool:
    """Plaintext of ``ciphertext || tag`` into ``out`` (``len(sealed) - 16`` bytes); False if not authentic."""

    ok = True
    try:
        AESGCM(key).decrypt_into(nonce, sealed, aad, out)
    except Exception:
        ok = False
    return ok
