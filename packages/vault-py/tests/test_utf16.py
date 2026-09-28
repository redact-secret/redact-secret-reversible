"""Unit tests for UTF-16 offset handling (astral characters, ZWJ emoji)."""

from __future__ import annotations

from redact_secret_vault.utf16 import build_unit_offsets, utf16_length, utf16_slice


def test_bmp_only_offsets_match_python_indices():
    text = "hello"
    offsets = build_unit_offsets(text)
    assert offsets == [0, 1, 2, 3, 4, 5]
    assert utf16_slice(text, 1, 4, offsets) == "ell"


def test_astral_character_counts_as_two_utf16_units():
    # U+1F511 KEY is outside the BMP: one Python code point, two UTF-16 units.
    text = "a\U0001F511b"
    assert utf16_length(text) == 1 + 2 + 1
    offsets = build_unit_offsets(text)
    assert offsets == [0, 1, 3, 4]
    assert utf16_slice(text, 1, 3, offsets) == "\U0001F511"
    assert utf16_slice(text, 0, 1, offsets) == "a"
    assert utf16_slice(text, 3, 4, offsets) == "b"


def test_zwj_emoji_sequence_length():
    # Family emoji built from a ZWJ sequence of astral emoji.
    text = "\U0001F468‍\U0001F469‍\U0001F467"
    # Three astral code points (2 units each) + two ZWJ (1 unit each).
    assert utf16_length(text) == 2 + 1 + 2 + 1 + 2
    offsets = build_unit_offsets(text)
    assert utf16_slice(text, 0, offsets[-1], offsets) == text
