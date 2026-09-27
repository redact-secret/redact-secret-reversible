"""Unit tests for the issued-token grammar and marker detection."""

from __future__ import annotations

from redact_secret_vault_server.token import (
    TOKEN_PATTERN,
    count_markers,
    find_tokens,
    has_marker,
    new_capture_id,
    new_token,
)


def test_new_token_matches_grammar():
    token = new_token()
    assert TOKEN_PATTERN.fullmatch(token)


def test_new_capture_id_shape():
    capture_id = new_capture_id()
    assert capture_id.startswith("cap_")
    assert len(capture_id) == len("cap_") + 26


def test_tokens_are_distinct():
    tokens = {new_token() for _ in range(200)}
    assert len(tokens) == 200


def test_find_tokens_extracts_every_occurrence():
    token = new_token()
    text = f"a {token} b {token}"
    assert find_tokens(text) == [token, token]


def test_marker_detected_case_insensitively():
    assert has_marker("literal RSV_ text")
    assert has_marker("literal rsv_ text")
    assert count_markers("rsv_ ... rsv_") == 2


def test_marker_detected_through_invisible_format_characters():
    # U+200B ZERO WIDTH SPACE is Unicode category Cf (format).
    spoofed = "r​s​v​_"
    assert has_marker(spoofed)


def test_no_marker_in_ordinary_text():
    assert not has_marker("nothing sensitive here")
