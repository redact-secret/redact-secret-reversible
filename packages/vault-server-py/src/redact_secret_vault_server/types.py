"""Idiomatic Python port of the S1 server authority interface.

Reference: docs/decisions/2026-09-27-define-server-authority-interface.md.
The ADR states its TypeScript signatures are "language-neutral in intent — a
native Python distribution under #17 implements equivalent semantics, not
this exact syntax." This module is that equivalent: dataclasses in place of
``interface``, ``enum.Enum`` in place of string-literal unions, and
``typing.Protocol`` in place of a bare function type, while keeping the same
field names (snake_case) and the same decision tuple, denial vocabulary, and
audit event shape.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from .errors import ServerDenialReason

__all__ = [
    "Principal",
    "PrincipalResolver",
    "RestoreSource",
    "RestoreDecisionInput",
    "PolicyDecision",
    "ServerReleasePolicy",
    "ServerAuditOperation",
    "ServerAuditEvent",
    "ServerAuditHook",
    "CaptureGrant",
    "CaptureOptions",
    "IssuedToken",
    "CaptureResult",
    "RestoreRequest",
    "RestoreResult",
    "VaultServerStats",
]


@dataclass(frozen=True, slots=True)
class Principal:
    """Opaque, application-issued identity. Carries no server authority by
    itself (ADR section 1)."""

    id: str
    tenant: str
    attributes: Mapping[str, str] | None = None


@runtime_checkable
class PrincipalResolver(Protocol):
    """Resolves the trusted principal for one restore call from
    request-scoped, server-trusted context the consuming application already
    verified. May be a plain function or an ``async def``; both are awaited
    uniformly by ``InMemoryVaultServer.restore``.

    Must raise rather than return a partial or best-effort ``Principal``. A
    resolver that cannot establish trust MUST leave the restore denied
    (``unauthenticated``); it must never default to an anonymous or shared
    principal.
    """

    def __call__(self, context: Any) -> Principal | Awaitable[Principal]: ...


@dataclass(frozen=True, slots=True)
class RestoreSource:
    """Which capture issued the entry, and its owning tenant."""

    capture_id: str
    issued_tenant: str
    session_id: str | None = None


@dataclass(frozen=True, slots=True)
class RestoreDecisionInput:
    """Generalizes the in-memory vault's ``ReleaseRequest`` (ADR section 2).
    ``capture_id``/``sink``/``path``/``type``/``occurrences``/
    ``total_occurrences``/``used`` carry the same meaning; ``principal``,
    ``tenant``, ``source.issued_tenant``, ``source.session_id``, ``purpose``,
    ``max_uses``, and ``policy_revision`` are new.
    """

    principal: Principal
    tenant: str
    source: RestoreSource
    sink: str
    path: str
    purpose: str
    type: str
    occurrences: int
    total_occurrences: int
    used: int
    max_uses: int
    requested_at: int
    policy_revision: str | None = None


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """``PolicyDecision`` (ADR section 3)."""

    allow: bool
    reason: ServerDenialReason | None = None

    def __post_init__(self) -> None:
        if self.allow and self.reason is not None:
            raise ValueError("an allowing PolicyDecision must not carry a reason")
        if not self.allow and self.reason is None:
            raise ValueError("a denying PolicyDecision must carry a reason")


ServerReleasePolicy = Callable[[RestoreDecisionInput], PolicyDecision | Awaitable[PolicyDecision]]
"""``ServerReleasePolicy`` (ADR section 3). Evaluated fresh for every
occurrence of every path in a restore request, never cached. May be a plain
function or ``async def``. A raised exception, a rejected coroutine, or a
non-``PolicyDecision`` return value is denial (``policy-evaluation-error``);
this interface has no allow-on-error mode."""


class ServerAuditOperation(str, Enum):
    RESOLVE_PRINCIPAL = "resolve-principal"
    RESTORE = "restore"
    REVOKE = "revoke"
    POLICY_ERROR = "policy-error"


@dataclass(frozen=True, slots=True)
class ServerAuditEvent:
    """``ServerAuditEvent`` (ADR section 5). Every field is a fixed enum, a
    count, a timestamp, or an application-defined identifier — never a
    free-text field, so there is nowhere in this type for a restored value to
    live."""

    operation: ServerAuditOperation
    outcome: str  # "committed" | "denied" | "failed"
    at: int
    principal_id: str | None = None
    tenant: str | None = None
    sink: str | None = None
    path: str | None = None
    purpose: str | None = None
    reason: ServerDenialReason | None = None
    code: str | None = None
    entries: int | None = None
    policy_revision: str | None = None
    request_id: str | None = None


ServerAuditHook = Callable[[ServerAuditEvent], None]
"""Receives safe metadata only. Exceptions it raises are swallowed and never
change an operation's outcome (ADR section 5)."""


# --- Capture-side types -----------------------------------------------------
#
# The ADR is explicitly restore-only; it defines no capture interface. These
# types describe this package's own in-memory capture surface, kept close to
# `@redact-secret/vault`'s `CaptureOptions`/`CaptureResult`
# (packages/vault/src/types.ts) but adding `issued_tenant`, which the S1
# tenant check (`RestoreDecisionInput.source.issued_tenant`) needs and the
# single-tenant in-memory vault does not.


@dataclass(frozen=True, slots=True)
class CaptureGrant:
    """Mirrors ``ReleaseGrant``: one destination a capture's values may be
    restored into."""

    sink: str
    paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CaptureOptions:
    issued_tenant: str
    release: tuple[CaptureGrant, ...]
    max_uses: int = 1
    unredacted: str = "reject"  # "reject" | "pass-through"
    policy: Mapping[str, str] | None = None
    eligible: Callable[[Mapping[str, Any]], bool] | None = None


@dataclass(frozen=True, slots=True)
class IssuedToken:
    token: str
    type: str


@dataclass(frozen=True, slots=True)
class CaptureResult:
    capture_id: str
    text: str
    tokens: tuple[IssuedToken, ...]
    passed_through: int
    passed_through_types: tuple[str, ...]
    unrestorable: int
    expires_at: int


@dataclass(frozen=True, slots=True)
class RestoreRequest:
    """The application-supplied half of a restore call. Combined with a
    resolved ``Principal`` (via ``PrincipalResolver``) to build the
    per-occurrence ``RestoreDecisionInput`` the policy sees."""

    sink: str
    captures: tuple[str, ...]
    fields: Mapping[str, str]
    purpose: str
    tenant: str | None = None
    session_id: str | None = None
    policy_revision: str | None = None
    context: Any = None
    request_id: str | None = None


@dataclass(frozen=True, slots=True)
class RestoreResult:
    fields: Mapping[str, str]
    restored: int


@dataclass(frozen=True, slots=True)
class VaultServerStats:
    entries: int
    retained_bytes: int
    captures: int
    disposed: bool
    expires_at: int
