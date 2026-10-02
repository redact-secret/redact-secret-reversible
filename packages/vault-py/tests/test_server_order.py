"""The restore preflight order of ``InMemoryVaultServer`` (docs/decisions/define-server-authority-interface.md, the nine
steps commented in ``server.py``), pinned the way the JavaScript suite pins it
(``packages/vault-server/test/order-and-denials.test.mjs``, ``ordering:`` tests) and further.

For each rung of the order, the request makes that rung's condition true **and every later rung's condition true at the
same time**; the denial must name that rung. A server that evaluated two checks in the other order would report a lower
rung and fail the case. ``server-epic-reconciliation.md`` listed the missing Python order test as a gap of #17 and #18.

Needs no Node.js: the core is a fake that reports the synthetic fixture. Every literal is synthetic.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import pytest

from redact_secret_vault import (
    CaptureGrant,
    CaptureOptions,
    InMemoryVaultServer,
    PolicyDecision,
    Principal,
    RestoreRequest,
    ServerDenialReason,
    VaultServerError,
    VaultServerErrorCode,
)
from redact_secret_vault.core_client import CoreFinding, CoreScanOutcome

ISSUING_TENANT = "tenant-acme-synthetic"
OTHER_TENANT = "tenant-northwind-synthetic"
SINK = "sink-a-synthetic"
WRONG_SINK = "sink-b-synthetic"
PURPOSE = "purpose-synthetic"
FIXTURE = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000"
FORGED = "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>"
TTL_MS = 1000


class FakeCore:
    """Reports the one synthetic fixture in the input as a ``redact`` finding."""

    def scan(self, text: str, *, policy: Any = None, limits: Any = None) -> CoreScanOutcome:
        start = text.find(FIXTURE)
        findings = (
            ()
            if start < 0
            else (
                CoreFinding(
                    id="finding-1",
                    type="github_token",
                    detector="synthetic",
                    confidence="high",
                    obfuscation="none",
                    start=start,
                    end=start + len(FIXTURE),
                    action="redact",
                ),
            )
        )
        return CoreScanOutcome(findings=findings, core_version="synthetic", artifact="synthetic")


class Clock:
    def __init__(self) -> None:
        self.ms = 1_790_000_000_000

    def __call__(self) -> float:
        return self.ms


class Rig:
    def __init__(self, *, principal_tenant: str = ISSUING_TENANT) -> None:
        self.clock = Clock()
        self.policy_calls = 0
        self.policy_allows = True
        self.principal_tenant = principal_tenant
        self.resolver_fails = False

        def resolve(_context: Any) -> Principal:
            if self.resolver_fails:
                raise PermissionError("no verified session (synthetic)")
            return Principal(id="user-synthetic-1", tenant=self.principal_tenant)

        def policy(_decision: Any) -> PolicyDecision:
            self.policy_calls += 1
            if self.policy_allows:
                return PolicyDecision(allow=True)
            return PolicyDecision(allow=False, reason=ServerDenialReason.POLICY)

        self.server = InMemoryVaultServer(
            core_client=FakeCore(),
            principal_resolver=resolve,
            release_policy=policy,
            now=self.clock,
            limits={"entry_ttl_ms": TTL_MS},
        )

    def capture(self, *, max_uses: int = 1) -> Any:
        return self.server.capture(
            f"deploy with {FIXTURE} now",
            CaptureOptions(
                issued_tenant=ISSUING_TENANT,
                release=(CaptureGrant(sink=SINK, paths=("body",)),),
                max_uses=max_uses,
            ),
        )

    async def restore(self, captured: Any, **override: Any) -> Any:
        fields = override.pop("fields", {"body": captured.text})
        request = RestoreRequest(
            sink=override.pop("sink", SINK),
            captures=override.pop("captures", (captured.capture_id,)),
            fields=fields,
            purpose=override.pop("purpose", PURPOSE),
            context={},
        )
        return await self.server.restore(request)


async def denial(rig: Rig, captured: Any, **override: Any) -> ServerDenialReason:
    with pytest.raises(VaultServerError) as caught:
        await rig.restore(captured, **override)
    assert caught.value.code == VaultServerErrorCode.RESTORE_DENIED
    assert caught.value.reason is not None
    return caught.value.reason


def run(coro: Any) -> Any:
    return asyncio.run(coro)


# Each scenario arms its own condition and every later one. ``twice`` doubles the token in the field, which is over the
# budget of an entry with ``max_uses=1``.
def _scenario_unauthenticated(rig: Rig, captured: Any) -> dict[str, Any]:
    rig.resolver_fails = True
    rig.principal_tenant = OTHER_TENANT
    rig.clock.ms += 2 * TTL_MS
    rig.policy_allows = False
    return {"fields": {"body": FORGED}, "sink": WRONG_SINK, "purpose": ""}


def _scenario_malformed(rig: Rig, captured: Any) -> dict[str, Any]:
    rig.principal_tenant = OTHER_TENANT
    rig.clock.ms += 2 * TTL_MS
    rig.policy_allows = False
    return {"fields": {"body": "<rsv_ broken " + captured.tokens[0].token}, "sink": WRONG_SINK, "purpose": ""}


def _scenario_unknown(rig: Rig, captured: Any) -> dict[str, Any]:
    rig.principal_tenant = OTHER_TENANT
    rig.clock.ms += 2 * TTL_MS
    rig.policy_allows = False
    return {"fields": {"body": f"{captured.tokens[0].token} {FORGED}"}, "sink": WRONG_SINK, "purpose": ""}


def _scenario_source(rig: Rig, captured: Any) -> dict[str, Any]:
    rig.principal_tenant = OTHER_TENANT
    rig.clock.ms += 2 * TTL_MS - 1  # still live at this instant: the entry's own expiry is later rungs' business
    rig.policy_allows = False
    return {"captures": ("cap_unrelated_synthetic",), "sink": WRONG_SINK, "purpose": ""}


def _scenario_tenant(rig: Rig, captured: Any) -> dict[str, Any]:
    rig.principal_tenant = OTHER_TENANT
    rig.clock.ms += 2 * TTL_MS
    rig.policy_allows = False
    return {"sink": WRONG_SINK, "purpose": ""}


def _scenario_expired(rig: Rig, captured: Any) -> dict[str, Any]:
    rig.clock.ms += 2 * TTL_MS
    rig.policy_allows = False
    return {"sink": WRONG_SINK, "purpose": ""}


def _scenario_sink(rig: Rig, captured: Any) -> dict[str, Any]:
    rig.policy_allows = False
    return {"sink": WRONG_SINK, "purpose": "", "fields": {"body": f"{captured.text} {captured.text}"}}


def _scenario_purpose(rig: Rig, captured: Any) -> dict[str, Any]:
    rig.policy_allows = False
    return {"purpose": "", "fields": {"body": f"{captured.text} {captured.text}"}}


def _scenario_budget(rig: Rig, captured: Any) -> dict[str, Any]:
    rig.policy_allows = False
    return {"fields": {"body": f"{captured.text} {captured.text}"}}


def _scenario_policy(rig: Rig, captured: Any) -> dict[str, Any]:
    rig.policy_allows = False
    return {}


RUNGS: list[tuple[str, ServerDenialReason, Callable[[Rig, Any], dict[str, Any]], bool]] = [
    # name, expected reason, arming, whether the policy may be reached
    ("unauthenticated", ServerDenialReason.UNAUTHENTICATED, _scenario_unauthenticated, False),
    ("malformed-token", ServerDenialReason.MALFORMED_TOKEN, _scenario_malformed, False),
    ("unknown-token", ServerDenialReason.UNKNOWN_TOKEN, _scenario_unknown, False),
    ("source", ServerDenialReason.SOURCE, _scenario_source, False),
    ("tenant-mismatch", ServerDenialReason.TENANT_MISMATCH, _scenario_tenant, False),
    ("expired", ServerDenialReason.EXPIRED, _scenario_expired, False),
    ("sink-or-path", ServerDenialReason.SINK_OR_PATH, _scenario_sink, False),
    ("missing-purpose", ServerDenialReason.MISSING_PURPOSE, _scenario_purpose, False),
    ("budget", ServerDenialReason.BUDGET, _scenario_budget, False),
    ("policy", ServerDenialReason.POLICY, _scenario_policy, True),
]


@pytest.mark.parametrize(("name", "reason", "arm", "policy_reached"), RUNGS, ids=[r[0] for r in RUNGS])
def test_a_rung_is_reported_over_every_later_condition_that_is_also_true(
    name: str, reason: ServerDenialReason, arm: Callable[[Rig, Any], dict[str, Any]], policy_reached: bool
) -> None:
    async def scenario() -> None:
        rig = Rig()
        captured = rig.capture(max_uses=1)
        start = rig.clock.ms
        override = arm(rig, captured)
        assert await denial(rig, captured, **override) == reason, name
        assert (rig.policy_calls > 0) is policy_reached, "the policy ran before an earlier check had denied"
        # A denied request consumes nothing: with every condition healed the capture still restores. (Not after an
        # expiry: a denial sweeps the entries that are past their time, which is the server's own cleanup.)
        if rig.clock.ms == start:
            rig.resolver_fails = False
            rig.principal_tenant = ISSUING_TENANT
            rig.policy_allows = True
            result = await rig.restore(captured)
            assert result.fields["body"] == f"deploy with {FIXTURE} now"

    run(scenario())


def test_the_order_is_a_strict_chain_over_all_rungs() -> None:
    """The rungs the parametrized cases exercise are the whole chain, in the order the specification gives."""

    assert [r[0] for r in RUNGS] == [
        "unauthenticated",
        "malformed-token",
        "unknown-token",
        "source",
        "tenant-mismatch",
        "expired",
        "sink-or-path",
        "missing-purpose",
        "budget",
        "policy",
    ]
