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
from .codec import (
    ALGORITHM_AES_256_GCM,
    FORMAT_VERSION,
    MAX_PAYLOAD_BYTES,
    NONCE_BYTES,
    PAYLOAD_VERSION,
    TAG_BYTES,
    EnvelopeParts,
    PayloadPlan,
    decode_payload,
    encode_aad,
    encode_envelope,
    encode_payload,
    parse_envelope,
    plan_payload,
    write_payload,
)
from .contracts import *  # noqa: F403
from .contracts import __all__ as _contracts_all
from .derive import derive_entry_id, entry_key_info
from .digest import (
    DIGEST_KEY_BYTES,
    Digester,
    RequestDigestInput,
    RequestPath,
    RequestUse,
    SessionTagInput,
    create_digester,
)
from .errors import (
    KeyProviderError,
    KeyProviderErrorCode,
    RecordCryptoError,
    RecordCryptoErrorCode,
    StoreError,
    StoreErrorCode,
)
from .server import (
    DeleteCiphertextResult,
    LifecycleDecision,
    LifecycleDecisionInput,
    LifecycleOperation,
    LifecyclePolicy,
    LifecycleRequest,
    PersistentCaptureOptions,
    PersistentCaptureResult,
    PersistentRestoreRequest,
    PersistentRestoreResult,
    PersistentServerVault,
    ResolveAttemptRequest,
    ResolveAttemptResult,
    RevokeResult,
    SessionResolver,
    create_persistent_server_vault,
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
    "ALGORITHM_AES_256_GCM",
    "FORMAT_VERSION",
    "MAX_PAYLOAD_BYTES",
    "NONCE_BYTES",
    "PAYLOAD_VERSION",
    "TAG_BYTES",
    "EnvelopeParts",
    "PayloadPlan",
    "decode_payload",
    "encode_aad",
    "encode_envelope",
    "encode_payload",
    "parse_envelope",
    "plan_payload",
    "write_payload",
    "derive_entry_id",
    "entry_key_info",
    "DeleteCiphertextResult",
    "LifecycleDecision",
    "LifecycleDecisionInput",
    "LifecycleOperation",
    "LifecyclePolicy",
    "LifecycleRequest",
    "PersistentCaptureOptions",
    "PersistentCaptureResult",
    "PersistentRestoreRequest",
    "PersistentRestoreResult",
    "PersistentServerVault",
    "ResolveAttemptRequest",
    "ResolveAttemptResult",
    "RevokeResult",
    "SessionResolver",
    "create_persistent_server_vault",
    "DIGEST_KEY_BYTES",
    "Digester",
    "RequestDigestInput",
    "RequestPath",
    "RequestUse",
    "SessionTagInput",
    "create_digester",
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
