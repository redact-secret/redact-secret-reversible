"""Reference ``ServerReleasePolicy`` implementations.

Python port of the "Reference policy examples" in
docs/decisions/2026-09-27-define-server-authority-interface.md. Illustrative
only: synthetic sink/purpose literals, no real deployment logic, not a
recommendation for any specific production policy.
"""

from __future__ import annotations

from collections.abc import Sequence

from .errors import ServerDenialReason
from .types import PolicyDecision, RestoreDecisionInput, ServerReleasePolicy

_ALLOW = PolicyDecision(allow=True)


def deny_by_default(_input: RestoreDecisionInput) -> PolicyDecision:
    """Nothing is allowed unless another rule explicitly says so. The
    recommended base for every deployment."""

    return PolicyDecision(allow=False, reason=ServerDenialReason.POLICY)


def allow_same_tenant_only(input: RestoreDecisionInput) -> PolicyDecision:
    """Never allow restoration across a tenant boundary."""

    if input.tenant == input.source.issued_tenant:
        return _ALLOW
    return PolicyDecision(allow=False, reason=ServerDenialReason.TENANT_MISMATCH)


# Synthetic-only sink/purpose literals; see the ADR's reference examples.
SUPPORT_SINK = "support-ticket-reply-sink-synthetic"
SUPPORT_SINK_PURPOSES = frozenset({"support-reply-purpose-synthetic"})


def purpose_limited(input: RestoreDecisionInput) -> PolicyDecision:
    """An allowlist of (sink, purpose) pairs: a support-reply sink may only
    be used for a declared support purpose, and only within the same
    tenant."""

    if input.sink != SUPPORT_SINK:
        return PolicyDecision(allow=False, reason=ServerDenialReason.SINK_OR_PATH)
    if input.purpose not in SUPPORT_SINK_PURPOSES:
        return PolicyDecision(allow=False, reason=ServerDenialReason.MISSING_PURPOSE)
    return allow_same_tenant_only(input)


def all_of(*policies: ServerReleasePolicy) -> ServerReleasePolicy:
    """Compose several policies: a deployment typically chains rules, and the
    first denial wins. Each policy may be sync or ``async``."""

    async def _chained(input: RestoreDecisionInput) -> PolicyDecision:
        import inspect

        for policy in policies:
            decision = policy(input)
            if inspect.isawaitable(decision):
                decision = await decision
            if not decision.allow:
                return decision
        return _ALLOW

    return _chained


__all__: Sequence[str] = [
    "deny_by_default",
    "allow_same_tenant_only",
    "purpose_limited",
    "all_of",
    "SUPPORT_SINK",
    "SUPPORT_SINK_PURPOSES",
]
