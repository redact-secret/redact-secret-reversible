"""Internal: the one place a secret-holding buffer is allocated.

Python cannot clear ``bytes`` or ``str``. What it can do is hold keys and
decrypted values in ``bytearray`` and overwrite them (plan section 3.6). Every
such buffer this package owns comes from ``new_buffer`` and is passed to
``zero`` on every path, so a test can inject the allocator and check that each
buffer is all zero afterwards.
"""

from __future__ import annotations

import secrets


def new_buffer(size: int) -> bytearray:
    return bytearray(size)


def zero(buffer: bytearray | None) -> None:
    if buffer is not None:
        buffer[:] = bytes(len(buffer))


def random_buffer(size: int) -> bytearray:
    """CSPRNG bytes in a buffer the caller overwrites.

    ``secrets.token_bytes`` returns immutable ``bytes``; that temporary cannot
    be cleared. Stated, not solved (plan section 3.6).
    """

    raw = secrets.token_bytes(size)
    buffer = new_buffer(size)
    buffer[:] = raw
    return buffer
