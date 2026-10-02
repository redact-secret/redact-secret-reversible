"""Mechanical validation shared by every store adapter and by the server.

Mirrors ``packages/vault-contracts/src/validate.ts`` (docs/specs/persistent-vault.md
sections 3.2 and 4.2). These checks protect a store's own invariants against a
faulty caller. They are not authorization.

Python differences from the TypeScript source, each decided in
docs/plans/python-persistence-parity.md sections 3.5 and 3.6:

* A ``str`` is a sequence of code points. Lengths of identifiers are counted in
  UTF-16 code units, byte limits in UTF-8 bytes, and any surrogate code point is
  a lone surrogate, including the two halves of a pair written as two code points).
* Patterns use ``re.fullmatch`` with explicit ASCII classes and no flags.
* An integer is ``type(x) is int``: ``bool`` and ``float`` are rejected, and the
  range is ``0 <= x <= 2**53 - 1`` (``1 <=`` where a positive value is required).
* A byte string is ``bytes``; a sequence is ``tuple``, so a caller cannot change
  it after it was validated.

Each ``validate_*`` function is a thin entry point: the checks are plain
functions that return a code, and the entry point raises a fresh error from its
own frame, outside any ``except`` block, so ``__cause__`` and ``__context__``
are both ``None``.
"""

from __future__ import annotations

import re
from typing import Final

from ..utf16 import utf16_length
from . import limits as _limits
from .contracts import (
    Attempt,
    CaptureGeneration,
    CommitRestoreInput,
    CreateCaptureInput,
    DeleteCiphertextInput,
    EntryUse,
    InspectAttemptInput,
    InvalidateRecoveredInput,
    NewCapture,
    NewEntry,
    ReadCapturesInput,
    ReadEntriesInput,
    ReplaceCaptureKeyInput,
    RevokeCaptureInput,
    StoreCapabilities,
    StoreScope,
    SweepInput,
)
from .errors import StoreError, StoreErrorCode

_NAMESPACE: Final = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_ATTEMPT_ID: Final = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_CAPTURE_ID: Final = re.compile(r"cap_[a-z2-7]{26}")
_ENTRY_ID: Final = re.compile(r"[0-9a-f]{64}")
_SESSION_TAG: Final = re.compile(r"[0-9a-f]{64}")
_SURROGATE: Final = re.compile("[\ud800-\udfff]")

#: Largest ``max_clock_skew_ms`` a store may declare.
_MAX_CLOCK_SKEW_CEILING_MS: Final = 60_000

_INVALID: Final[StoreErrorCode] = "STORE_INVALID_ARGUMENT"
_CAPABILITY: Final[StoreErrorCode] = "STORE_CAPABILITY"


# --------------------------------------------------------------------------
# Predicates
# --------------------------------------------------------------------------


def is_well_formed(text: object) -> bool:
    """True for a ``str`` with no surrogate code point (so no lone surrogate)."""

    return type(text) is str and _SURROGATE.search(text) is None


def is_int(value: object) -> bool:
    """True for a real ``int`` (not ``bool``, not ``float``) in ``0 .. 2**53 - 1``."""

    return type(value) is int and 0 <= value <= _limits.MAX_TIMESTAMP


def is_positive_int(value: object) -> bool:
    return type(value) is int and 1 <= value <= _limits.MAX_TIMESTAMP


def is_timestamp(value: object) -> bool:
    return is_int(value)


def is_namespace(value: object) -> bool:
    return type(value) is str and _NAMESPACE.fullmatch(value) is not None


def is_identifier(value: object) -> bool:
    """A tenant, session, sink, path, or principal identifier: 1 to 256 UTF-16 code units, well-formed."""

    if type(value) is not str:
        return False
    # A code point is at least one UTF-16 unit, so a longer string cannot fit.
    if not 0 < len(value) <= _limits.IDENTIFIER_MAX_LENGTH:
        return False
    return _SURROGATE.search(value) is None and utf16_length(value) <= _limits.IDENTIFIER_MAX_LENGTH


def is_capture_id(value: object) -> bool:
    return type(value) is str and _CAPTURE_ID.fullmatch(value) is not None


def is_entry_id(value: object) -> bool:
    return type(value) is str and _ENTRY_ID.fullmatch(value) is not None


def is_attempt_id(value: object) -> bool:
    return type(value) is str and _ATTEMPT_ID.fullmatch(value) is not None


def is_session_tag(value: object) -> bool:
    return type(value) is str and _SESSION_TAG.fullmatch(value) is not None


def is_key_ref(value: object) -> bool:
    if type(value) is not str:
        return False
    # A code point is at least one UTF-8 byte.
    if not 0 < len(value) <= _limits.KEY_REF_MAX_BYTES:
        return False
    return _SURROGATE.search(value) is None and len(value.encode("utf-8")) <= _limits.KEY_REF_MAX_BYTES


def _is_bytes(value: object, low: int, high: int) -> bool:
    return isinstance(value, bytes) and low <= len(value) <= high


def _is_eq_one(value: object) -> bool:
    return type(value) is int and value == 1


# --------------------------------------------------------------------------
# Capabilities
# --------------------------------------------------------------------------


def missing_capabilities(capabilities: object) -> tuple[str, ...]:
    """The capabilities a persistent server requires that a store lacks or declares out of range.

    Names are the ``StoreCapabilities`` field names. An empty tuple means the
    store may be used. Durability and restore detection are judged by the
    caller, which may hold explicit opt-ins.
    """

    if not isinstance(capabilities, StoreCapabilities):
        return ("capabilities",)
    c = capabilities
    missing: list[str] = []
    if not _is_eq_one(c.contract_version):
        missing.append("contract_version")
    for name in (
        "atomic_create",
        "atomic_restore",
        "authoritative_commit",
        "revocation_fences",
        "attempt_receipts",
        "store_clock",
    ):
        if getattr(c, name) is not True:
            missing.append(name)

    def bounded(value: object, ceiling: int) -> bool:
        return is_positive_int(value) and value <= ceiling  # type: ignore[operator]

    if not bounded(c.max_create_entries, _limits.MAX_CREATE_ENTRIES):
        missing.append("max_create_entries")
    if not is_positive_int(c.max_create_bytes):
        missing.append("max_create_bytes")
    if not bounded(c.max_restore_entries, _limits.MAX_RESTORE_ENTRIES):
        missing.append("max_restore_entries")
    if not bounded(c.max_restore_captures, _limits.MAX_RESTORE_CAPTURES):
        missing.append("max_restore_captures")
    if not bounded(c.max_envelope_bytes, _limits.MAX_ENVELOPE_BYTES):
        missing.append("max_envelope_bytes")
    if not is_timestamp(c.max_clock_skew_ms) or c.max_clock_skew_ms > _MAX_CLOCK_SKEW_CEILING_MS:
        missing.append("max_clock_skew_ms")
    if c.durability not in ("volatile", "durable"):
        missing.append("durability")
    if type(c.cross_process) is not bool:
        missing.append("cross_process")
    if type(c.restore_detection) is not str or len(c.restore_detection) == 0:
        missing.append("restore_detection")
    if type(c.adapter) is not str or type(c.profile) is not str:
        missing.append("adapter")
    return tuple(missing)


# --------------------------------------------------------------------------
# Checks: each returns a code, or None when the input is acceptable
# --------------------------------------------------------------------------


def _scope_ok(scope: object) -> bool:
    return isinstance(scope, StoreScope) and is_namespace(scope.namespace) and is_identifier(scope.tenant)


def _stored_key_ok(key_ref: object, wrapped_key: object) -> bool:
    return is_key_ref(key_ref) and _is_bytes(wrapped_key, 1, _limits.WRAPPED_KEY_MAX_BYTES)


def _check_create_capture(input: object, capabilities: StoreCapabilities) -> StoreErrorCode | None:
    if not isinstance(input, CreateCaptureInput) or not _scope_ok(input.scope):
        return _INVALID
    if not is_positive_int(input.epoch) or not is_timestamp(input.now):
        return _INVALID
    capture = input.capture
    if not isinstance(capture, NewCapture) or not is_capture_id(capture.capture_id):
        return _INVALID
    if capture.session_tag is not None and not is_session_tag(capture.session_tag):
        return _INVALID
    if not is_timestamp(capture.created_at) or not is_timestamp(capture.expires_at):
        return _INVALID
    lifetime = capture.expires_at - capture.created_at
    if lifetime <= 0 or lifetime > _limits.MAX_CAPTURE_LIFETIME_MS:
        return _INVALID
    if not _is_eq_one(capture.lookup_version):
        return _INVALID
    if not _stored_key_ok(capture.key_ref, capture.wrapped_key):
        return _INVALID
    entries = input.entries
    if type(entries) is not tuple or len(entries) == 0:
        return _INVALID
    if len(entries) > capabilities.max_create_entries:
        return _CAPABILITY
    seen: set[str] = set()
    total = 0
    for entry in entries:
        if not isinstance(entry, NewEntry) or not is_entry_id(entry.entry_id) or entry.entry_id in seen:
            return _INVALID
        seen.add(entry.entry_id)
        if not is_positive_int(entry.max_uses) or entry.max_uses > _limits.MAX_USES:
            return _INVALID
        if not _is_bytes(entry.envelope, 1, _limits.MAX_ENVELOPE_BYTES):
            return _INVALID
        if len(entry.envelope) > capabilities.max_envelope_bytes:
            return _CAPABILITY
        total += len(entry.envelope)
    if total > capabilities.max_create_bytes:
        return _CAPABILITY
    return None


def _check_id_list(ids: object, predicate: object, ceiling: int) -> StoreErrorCode | None:
    if type(ids) is not tuple or len(ids) == 0:
        return _INVALID
    if len(ids) > ceiling:
        return _CAPABILITY
    seen: set[str] = set()
    for item in ids:
        if not predicate(item) or item in seen:  # type: ignore[operator]
            return _INVALID
        seen.add(item)
    return None


def _check_read_entries(input: object, capabilities: StoreCapabilities) -> StoreErrorCode | None:
    if not isinstance(input, ReadEntriesInput) or not _scope_ok(input.scope):
        return _INVALID
    return _check_id_list(input.entry_ids, is_entry_id, capabilities.max_restore_entries)


def _check_read_captures(input: object, capabilities: StoreCapabilities) -> StoreErrorCode | None:
    if not isinstance(input, ReadCapturesInput) or not _scope_ok(input.scope):
        return _INVALID
    return _check_id_list(input.capture_ids, is_capture_id, capabilities.max_restore_captures)


def _check_commit_restore(input: object, capabilities: StoreCapabilities) -> StoreErrorCode | None:
    if not isinstance(input, CommitRestoreInput) or not _scope_ok(input.scope):
        return _INVALID
    if not is_positive_int(input.epoch) or not is_timestamp(input.now) or not is_timestamp(input.receipt_expires_at):
        return _INVALID
    attempt = input.attempt
    if not isinstance(attempt, Attempt) or not is_attempt_id(attempt.attempt_id):
        return _INVALID
    if not _is_bytes(attempt.request_digest, _limits.REQUEST_DIGEST_BYTES, _limits.REQUEST_DIGEST_BYTES):
        return _INVALID
    if type(input.captures) is not tuple or len(input.captures) == 0:
        return _INVALID
    if type(input.uses) is not tuple or len(input.uses) == 0:
        return _INVALID
    if len(input.captures) > capabilities.max_restore_captures:
        return _CAPABILITY
    if len(input.uses) > capabilities.max_restore_entries:
        return _CAPABILITY
    captures: set[str] = set()
    for capture in input.captures:
        if not isinstance(capture, CaptureGeneration) or not is_capture_id(capture.capture_id):
            return _INVALID
        if capture.capture_id in captures or not is_positive_int(capture.generation):
            return _INVALID
        captures.add(capture.capture_id)
    entries: set[str] = set()
    used: set[str] = set()
    for use in input.uses:
        if not isinstance(use, EntryUse) or not is_entry_id(use.entry_id) or use.entry_id in entries:
            return _INVALID
        entries.add(use.entry_id)
        if not is_capture_id(use.capture_id) or use.capture_id not in captures:
            return _INVALID
        used.add(use.capture_id)
        if not is_positive_int(use.count) or use.count > _limits.MAX_USES:
            return _INVALID
        if not is_positive_int(use.lifecycle_revision) or not is_positive_int(use.ciphertext_revision):
            return _INVALID
    if len(used) != len(captures):
        return _INVALID
    return None


def _check_revoke_capture(input: object) -> StoreErrorCode | None:
    if not isinstance(input, RevokeCaptureInput) or not _scope_ok(input.scope):
        return _INVALID
    if not is_capture_id(input.capture_id) or not is_timestamp(input.now):
        return _INVALID
    if not is_timestamp(input.retention_ms) or input.retention_ms > _limits.MAX_RETENTION_MS:
        return _INVALID
    if type(input.fence_absent) is not bool:
        return _INVALID
    return None


def _check_inspect_attempt(input: object) -> StoreErrorCode | None:
    if not isinstance(input, InspectAttemptInput) or not _scope_ok(input.scope):
        return _INVALID
    return None if is_attempt_id(input.attempt_id) else _INVALID


def _check_replace_capture_key(input: object) -> StoreErrorCode | None:
    if not isinstance(input, ReplaceCaptureKeyInput) or not _scope_ok(input.scope):
        return _INVALID
    if not is_capture_id(input.capture_id) or not is_positive_int(input.key_revision):
        return _INVALID
    return None if _stored_key_ok(input.key_ref, input.wrapped_key) else _INVALID


def _check_delete_ciphertext(input: object) -> StoreErrorCode | None:
    if not isinstance(input, DeleteCiphertextInput) or not _scope_ok(input.scope):
        return _INVALID
    return None if is_capture_id(input.capture_id) and is_timestamp(input.now) else _INVALID


def _check_sweep(input: object) -> StoreErrorCode | None:
    if not isinstance(input, SweepInput) or not is_namespace(input.namespace) or not is_timestamp(input.now):
        return _INVALID
    if not is_positive_int(input.limit) or input.limit > _limits.MAX_SWEEP_LIMIT:
        return _INVALID
    return None


def _check_namespace(namespace: object) -> StoreErrorCode | None:
    return None if is_namespace(namespace) else _INVALID


def _check_initialize_namespace(namespace: object, epoch: object) -> StoreErrorCode | None:
    if not is_namespace(namespace) or not is_positive_int(epoch):
        return _INVALID
    return None


def _check_invalidate_recovered(input: object) -> StoreErrorCode | None:
    if not isinstance(input, InvalidateRecoveredInput) or not is_namespace(input.namespace):
        return _INVALID
    return None if is_positive_int(input.new_epoch) else _INVALID


# --------------------------------------------------------------------------
# Entry points
# --------------------------------------------------------------------------


def validate_create_capture(input: CreateCaptureInput, capabilities: StoreCapabilities) -> None:
    code = _check_create_capture(input, capabilities)
    if code is not None:
        raise StoreError(code)


def validate_read_entries(input: ReadEntriesInput, capabilities: StoreCapabilities) -> None:
    code = _check_read_entries(input, capabilities)
    if code is not None:
        raise StoreError(code)


def validate_read_captures(input: ReadCapturesInput, capabilities: StoreCapabilities) -> None:
    code = _check_read_captures(input, capabilities)
    if code is not None:
        raise StoreError(code)


def validate_commit_restore(input: CommitRestoreInput, capabilities: StoreCapabilities) -> None:
    code = _check_commit_restore(input, capabilities)
    if code is not None:
        raise StoreError(code)


def validate_revoke_capture(input: RevokeCaptureInput) -> None:
    code = _check_revoke_capture(input)
    if code is not None:
        raise StoreError(code)


def validate_inspect_attempt(input: InspectAttemptInput) -> None:
    code = _check_inspect_attempt(input)
    if code is not None:
        raise StoreError(code)


def validate_replace_capture_key(input: ReplaceCaptureKeyInput) -> None:
    code = _check_replace_capture_key(input)
    if code is not None:
        raise StoreError(code)


def validate_delete_ciphertext(input: DeleteCiphertextInput) -> None:
    code = _check_delete_ciphertext(input)
    if code is not None:
        raise StoreError(code)


def validate_sweep(input: SweepInput) -> None:
    code = _check_sweep(input)
    if code is not None:
        raise StoreError(code)


def validate_namespace(namespace: str) -> None:
    code = _check_namespace(namespace)
    if code is not None:
        raise StoreError(code)


def validate_initialize_namespace(namespace: str, epoch: int) -> None:
    code = _check_initialize_namespace(namespace, epoch)
    if code is not None:
        raise StoreError(code)


def validate_invalidate_recovered(input: InvalidateRecoveredInput) -> None:
    code = _check_invalidate_recovered(input)
    if code is not None:
        raise StoreError(code)
