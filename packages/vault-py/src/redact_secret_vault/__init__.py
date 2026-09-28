"""``redact_secret_vault``: a native Python server authority layer for
redact-secret-reversible.

Implements the S1 contract
(docs/decisions/2026-09-27-define-server-authority-interface.md) idiomatically
in Python: principal/tenant resolution, a fail-closed decision-tuple policy
evaluation, the extended denial vocabulary, and an audit event shape with no
field capable of carrying a restored value. Storage is in-memory only.

Capture depends on a qualified service boundary
(:mod:`redact_secret_vault.core_client`) to the JavaScript-only
``@redact-secret/core`` package, because no native Python distribution of the
core exists (see docs/research/python-server-integration-2026-09-27.md). This
package never reimplements secret detection.
"""

from .core_client import CoreClient, CoreFinding, CoreScanOutcome, NodeCoreBridge
from .errors import ServerDenialReason, VaultServerError, VaultServerErrorCode
from .server import DEFAULT_LIMITS, InMemoryVaultServer, create_vault_server
from .types import (
    CaptureGrant,
    CaptureOptions,
    CaptureResult,
    IssuedToken,
    PiiRetention,
    PolicyDecision,
    Principal,
    PrincipalResolver,
    RestoreDecisionInput,
    RestoreRequest,
    RestoreResult,
    RestoreSource,
    ServerAuditEvent,
    ServerAuditHook,
    ServerAuditOperation,
    ServerReleasePolicy,
    VaultServerStats,
)

__version__ = "0.1.0a2"

__all__ = [
    "__version__",
    "CoreClient",
    "CoreFinding",
    "CoreScanOutcome",
    "NodeCoreBridge",
    "ServerDenialReason",
    "VaultServerError",
    "VaultServerErrorCode",
    "DEFAULT_LIMITS",
    "InMemoryVaultServer",
    "create_vault_server",
    "CaptureGrant",
    "CaptureOptions",
    "CaptureResult",
    "IssuedToken",
    "PiiRetention",
    "PolicyDecision",
    "Principal",
    "PrincipalResolver",
    "RestoreDecisionInput",
    "RestoreRequest",
    "RestoreResult",
    "RestoreSource",
    "ServerAuditEvent",
    "ServerAuditHook",
    "ServerAuditOperation",
    "ServerReleasePolicy",
    "VaultServerStats",
]
