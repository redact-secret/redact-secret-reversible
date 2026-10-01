"""Hard limits of record format version 1.

Each constant equals the field of the same name in
``packages/vault-contracts/src/limits.ts`` (``namespaceMaxLength`` is
``NAMESPACE_MAX_LENGTH``), and a test compares the two files value by value
(docs/specs/persistent-vault.md sections 3.6 and 4.2).
"""

from __future__ import annotations

from typing import Final

CONTRACT_VERSION: Final = 1
NAMESPACE_MAX_LENGTH: Final = 128
IDENTIFIER_MAX_LENGTH: Final = 256
ATTEMPT_ID_MAX_LENGTH: Final = 128
PURPOSE_MAX_BYTES: Final = 1024
TYPE_MAX_BYTES: Final = 256
POLICY_REVISION_MAX_BYTES: Final = 256
MAX_GRANTS: Final = 64
MAX_PATHS_PER_GRANT: Final = 256
MAX_VALUE_BYTES: Final = 1024 * 1024
MAX_ENVELOPE_BYTES: Final = 1024 * 1024 + 64 * 1024
KEY_REF_MAX_BYTES: Final = 512
WRAPPED_KEY_MAX_BYTES: Final = 4096
MAX_CAPTURE_LIFETIME_MS: Final = 24 * 60 * 60 * 1000
MAX_USES: Final = 1000
MAX_CREATE_ENTRIES: Final = 1024
MAX_RESTORE_ENTRIES: Final = 1024
MAX_RESTORE_CAPTURES: Final = 64
#: ``Number.MAX_SAFE_INTEGER``: every timestamp, epoch, revision, and count is at most this.
MAX_TIMESTAMP: Final = 2**53 - 1
MAX_RECEIPT_HORIZON_MS: Final = 48 * 60 * 60 * 1000
MAX_RETENTION_MS: Final = 30 * 24 * 60 * 60 * 1000
MAX_SWEEP_LIMIT: Final = 10_000
REQUEST_DIGEST_BYTES: Final = 32
DATA_KEY_BYTES: Final = 32
