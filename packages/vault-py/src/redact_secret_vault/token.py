"""Issued-token grammar.

Ported from ``packages/vault/src/token.ts``: a token is ``<rsv_`` + 26
lowercase RFC 4648 base32 characters + ``>``. This package reuses the exact
same grammar so a consumer that inspects tokens from both a JS
``@redact-secret/vault``/``vault-server`` and this Python server sees one
consistent shape; the grammar itself carries no authority (see
docs/decisions/2026-09-27-bind-issued-tokens-to-approved-output.md) and
nothing here depends on token *values* matching across languages.

Randomness uses :mod:`secrets` (CSPRNG-backed) rather than porting the
TypeScript implementation's manual bit-packing of ``crypto.getRandomValues``
output — a candid, harmless implementation difference: both draw at least
128 bits of CSPRNG entropy per token.

The marker-detection regex differs for the same reason ``re`` gives no
portable equivalent to JavaScript's ``\\p{Cf}`` Unicode-property escape: this
module strips every Unicode category-Cf (format) character from the text
before searching for a literal, case-insensitive ``rsv_`` marker, rather than
allowing Cf characters only between the four marker characters. This is
slightly more permissive about where invisible characters may sit and is
documented as a difference in docs/research/python-server-integration-2026-09-27.md;
it never under-detects a spoofed marker.
"""

from __future__ import annotations

import re
import secrets
import unicodedata

ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
TOKEN_BODY_LENGTH = 26

TOKEN_PATTERN = re.compile(r"<rsv_[a-z2-7]{26}>")

_MARKER_PATTERN = re.compile(r"rsv_", re.IGNORECASE)


def _strip_format_characters(text: str) -> str:
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def count_markers(text: str) -> int:
    """Count occurrences of the (possibly obfuscated) ``rsv_`` marker."""

    return len(_MARKER_PATTERN.findall(_strip_format_characters(text)))


def has_marker(text: str) -> bool:
    return count_markers(text) > 0


def new_token() -> str:
    body = "".join(secrets.choice(ALPHABET) for _ in range(TOKEN_BODY_LENGTH))
    return f"<rsv_{body}>"


def new_capture_id() -> str:
    body = "".join(secrets.choice(ALPHABET) for _ in range(TOKEN_BODY_LENGTH))
    return f"cap_{body}"


def find_tokens(text: str) -> list[str]:
    return TOKEN_PATTERN.findall(text)
