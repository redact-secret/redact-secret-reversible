"""Error codes for the Python server authority package.

Mirrors ``packages/vault/src/errors.ts`` in shape (a fixed error code plus an
optional denial reason and core error code), ported to idiomatic Python
(``enum.Enum`` instead of a TypeScript string-literal union) rather than
copied verbatim, per the S1 ADR's "Python type names may differ, but the
decision tuple, denial vocabulary, and fail-closed behavior must match."
"""

from __future__ import annotations

from enum import Enum


class VaultServerErrorCode(str, Enum):
    """Mirrors ``VaultErrorCode`` (packages/vault/src/errors.ts)."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    UNSUPPORTED_RUNTIME = "UNSUPPORTED_RUNTIME"
    CORE_FAILURE = "CORE_FAILURE"
    BLOCKED_FINDING = "BLOCKED_FINDING"
    UNREDACTED_FINDINGS = "UNREDACTED_FINDINGS"
    TOKEN_LITERAL_IN_INPUT = "TOKEN_LITERAL_IN_INPUT"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    TOKEN_GENERATION_FAILED = "TOKEN_GENERATION_FAILED"
    INVARIANT_VIOLATION = "INVARIANT_VIOLATION"
    RESTORE_DENIED = "RESTORE_DENIED"
    BUSY = "BUSY"
    DISPOSED = "DISPOSED"


class ServerDenialReason(str, Enum):
    """``ServerDenialReason`` — extends the in-memory vault's ``DenialReason``
    verbatim (the first eight members) with the server-only reasons the S1
    ADR adds (see docs/decisions/2026-09-27-define-server-authority-interface.md
    section 4). Never redefine the first eight; a Python consumer comparing
    against the vault's own ``DenialReason`` strings must see the same
    values.
    """

    # Reused verbatim from the in-memory vault's DenialReason.
    INVALID_REQUEST = "invalid-request"
    MALFORMED_TOKEN = "malformed-token"
    UNKNOWN_TOKEN = "unknown-token"
    SOURCE = "source"
    EXPIRED = "expired"
    SINK_OR_PATH = "sink-or-path"
    BUDGET = "budget"
    POLICY = "policy"

    # Server-only additions (ADR section 4).
    UNAUTHENTICATED = "unauthenticated"
    TENANT_MISMATCH = "tenant-mismatch"
    MISSING_PURPOSE = "missing-purpose"
    REVOKED = "revoked"
    STALE_POLICY = "stale-policy"
    RATE_LIMITED = "rate-limited"
    POLICY_EVALUATION_ERROR = "policy-evaluation-error"


class VaultServerError(Exception):
    """Mirrors ``VaultError`` (packages/vault/src/errors.ts). Never carries a
    restored value, fixture, or raw input in its message, matching this
    repository's security boundary."""

    def __init__(
        self,
        code: VaultServerErrorCode,
        *,
        core_code: str | None = None,
        reason: ServerDenialReason | None = None,
    ) -> None:
        self.code = code
        self.core_code = core_code
        self.reason = reason
        detail = f" reason={reason.value}" if reason is not None else ""
        detail += f" core_code={core_code}" if core_code is not None else ""
        super().__init__(f"{code.value}{detail}")
