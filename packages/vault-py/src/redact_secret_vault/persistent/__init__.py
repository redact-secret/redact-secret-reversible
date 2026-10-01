"""Persistent vault contracts for Python: types, errors, limits, and validators.

Status: groundwork only. Python persistence is **not implemented and not
supported**; nothing here stores, encrypts, or shares a retained value. See
docs/plans/python-persistence-parity.md. This package imports only the
standard library.

The persistent modules require Python 3.11 or later
(docs/decisions/python-persistence-api-and-packaging.md). The rest of
``redact_secret_vault`` keeps its own floor.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):  # pragma: no cover - exercised on 3.10 only
    raise ImportError("redact_secret_vault.persistent requires Python 3.11 or later")

from . import limits
from .contracts import *  # noqa: F403
from .contracts import __all__ as _contracts_all
from .errors import (
    KeyProviderError,
    KeyProviderErrorCode,
    RecordCryptoError,
    RecordCryptoErrorCode,
    StoreError,
    StoreErrorCode,
)
from .validate import (
    is_attempt_id,
    is_capture_id,
    is_entry_id,
    is_identifier,
    is_key_ref,
    is_namespace,
    is_session_tag,
    is_timestamp,
    is_well_formed,
    missing_capabilities,
    validate_commit_restore,
    validate_create_capture,
    validate_delete_ciphertext,
    validate_initialize_namespace,
    validate_inspect_attempt,
    validate_invalidate_recovered,
    validate_namespace,
    validate_read_captures,
    validate_read_entries,
    validate_replace_capture_key,
    validate_revoke_capture,
    validate_sweep,
)

__all__ = [
    *_contracts_all,
    "KeyProviderError",
    "KeyProviderErrorCode",
    "RecordCryptoError",
    "RecordCryptoErrorCode",
    "StoreError",
    "StoreErrorCode",
    "is_attempt_id",
    "is_capture_id",
    "is_entry_id",
    "is_identifier",
    "is_key_ref",
    "is_namespace",
    "is_session_tag",
    "is_timestamp",
    "is_well_formed",
    "limits",
    "missing_capabilities",
    "validate_commit_restore",
    "validate_create_capture",
    "validate_delete_ciphertext",
    "validate_initialize_namespace",
    "validate_inspect_attempt",
    "validate_invalidate_recovered",
    "validate_namespace",
    "validate_read_captures",
    "validate_read_entries",
    "validate_replace_capture_key",
    "validate_revoke_capture",
    "validate_sweep",
]
