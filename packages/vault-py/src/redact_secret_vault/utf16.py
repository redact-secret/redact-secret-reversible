"""UTF-16 code-unit range handling.

``@redact-secret/core`` reports every finding range as a ``[start, end)`` pair
of UTF-16 code-unit offsets into the JavaScript string that produced it
(node_modules/@redact-secret/core dist/types.d.ts). Python ``str`` indexes by
Unicode code point, not UTF-16 code unit, so a supplementary-plane character
(for example an emoji outside the Basic Multilingual Plane) is one Python
index but two UTF-16 units. This module converts core's offsets back to
Python string indices so ``utf16_slice`` selects exactly the span
``input[start:end]`` would select in JavaScript, matching
docs/research/core-integration.md's "JavaScript ranges are half-open UTF-16
code-unit offsets."
"""

from __future__ import annotations

import bisect


def build_unit_offsets(text: str) -> list[int]:
    """``offsets[i]`` is the UTF-16 code-unit offset at which Python character
    index ``i`` begins; ``offsets[len(text)]`` is the text's total UTF-16
    length."""

    offsets = [0] * (len(text) + 1)
    unit = 0
    for i, ch in enumerate(text):
        offsets[i] = unit
        unit += 2 if ord(ch) > 0xFFFF else 1
    offsets[len(text)] = unit
    return offsets


def utf16_length(text: str) -> int:
    return sum(2 if ord(ch) > 0xFFFF else 1 for ch in text)


def char_index(offsets: list[int], unit: int) -> int:
    """The Python character index at which UTF-16 unit ``unit`` begins.
    Raises ``ValueError`` if ``unit`` does not land on a character
    boundary."""

    index = bisect.bisect_left(offsets, unit)
    if index >= len(offsets) or offsets[index] != unit:
        raise ValueError(f"utf-16 offset {unit} is not aligned to a code point boundary")
    return index


def utf16_slice(text: str, start: int, end: int, offsets: list[int] | None = None) -> str:
    """Equivalent to JavaScript's ``text.slice(start, end)`` for a ``start``/
    ``end`` pair of UTF-16 code-unit offsets. Raises ``ValueError`` if either
    offset does not land on a Python character boundary — this never happens
    for a well-formed core finding, since a detector never splits a
    surrogate pair (an astral character is one Unicode code point)."""

    offsets = offsets if offsets is not None else build_unit_offsets(text)
    start_index = char_index(offsets, start)
    end_index = char_index(offsets, end)
    return text[start_index:end_index]
