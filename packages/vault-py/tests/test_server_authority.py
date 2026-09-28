"""S1 server-only adversarial cases.

The shared conformance corpus (``conformance/v1/corpus.json``) predates the
S1 ADR and has no tenant, purpose, or principal concept yet — see
``conformance/README.md``: "Server-only classes (principal, tenant, policy
revision)... are left to their future corpus versions." The ADR names the
exact classes a future corpus version must cover, and asks #16/#17 to
implement them as executable cases in the meantime
(docs/decisions/2026-09-27-define-server-authority-interface.md,
"Consequences"). This file is that implementation, mirroring the ADR's own
"Negative and adversarial examples" section: principal-resolution failure,
cross-tenant, missing/invalid purpose, revoked-vs-unknown-token,
policy-evaluation-error/timeout, and policy-revision staleness.

All literals are unmistakably synthetic (`*-synthetic*`), matching
CONVENTIONS.md's security-sensitive-change rule; none is a real credential.
"""

from __future__ import annotations

import asyncio
import shutil

import pytest

from redact_secret_vault import (
    CaptureGrant,
    CaptureOptions,
    InMemoryVaultServer,
    NodeCoreBridge,
    PolicyDecision,
    Principal,
    RestoreRequest,
    ServerAuditEvent,
    ServerDenialReason,
    VaultServerError,
    VaultServerErrorCode,
)
from redact_secret_vault.policies import (
    all_of,
    allow_same_tenant_only,
    deny_by_default,
    purpose_limited,
)

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="node is required for the @redact-secret/core service boundary",
)

ISSUING_TENANT = "tenant-acme-synthetic"
OTHER_TENANT = "tenant-northwind-synthetic"
SUPPORT_SINK = "support-ticket-reply-sink-synthetic"
SUPPORT_PURPOSE = "support-reply-purpose-synthetic"
FIXTURE_SECRET = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000"


def _core() -> NodeCoreBridge:
    return NodeCoreBridge()


def _resolver_for(tenant: str):
    def resolve(context):
        return Principal(id="user-synthetic-042", tenant=context.get("tenant", tenant))

    return resolve


async def _capture_one(server: InMemoryVaultServer, *, issued_tenant: str) -> tuple[str, str]:
    result = server.capture(
        f"deploy with {FIXTURE_SECRET} now",
        CaptureOptions(
            issued_tenant=issued_tenant,
            release=(CaptureGrant(sink=SUPPORT_SINK, paths=("body",)),),
        ),
    )
    return result.capture_id, result.tokens[0].token


# -- 1. Principal-resolution failure -----------------------------------------


def test_principal_resolution_failure_denies_unauthenticated():
    async def run():
        def failing_resolver(_context):
            raise PermissionError("no verified session (synthetic)")

        server = InMemoryVaultServer(
            core_client=_core(),
            principal_resolver=failing_resolver,
            release_policy=deny_by_default,
        )
        capture_id, token = await _capture_one(server, issued_tenant=ISSUING_TENANT)
        with pytest.raises(VaultServerError) as excinfo:
            await server.restore(
                RestoreRequest(
                    sink=SUPPORT_SINK,
                    captures=(capture_id,),
                    fields={"body": token},
                    purpose=SUPPORT_PURPOSE,
                    tenant=ISSUING_TENANT,
                    context={},
                )
            )
        assert excinfo.value.code == VaultServerErrorCode.RESTORE_DENIED
        assert excinfo.value.reason == ServerDenialReason.UNAUTHENTICATED

    asyncio.run(run())


def test_no_principal_resolver_configured_denies_unauthenticated():
    async def run():
        server = InMemoryVaultServer(core_client=_core(), release_policy=deny_by_default)
        capture_id, token = await _capture_one(server, issued_tenant=ISSUING_TENANT)
        with pytest.raises(VaultServerError) as excinfo:
            await server.restore(
                RestoreRequest(
                    sink=SUPPORT_SINK,
                    captures=(capture_id,),
                    fields={"body": token},
                    purpose=SUPPORT_PURPOSE,
                    tenant=ISSUING_TENANT,
                )
            )
        assert excinfo.value.reason == ServerDenialReason.UNAUTHENTICATED

    asyncio.run(run())


# -- 2. Cross-tenant read ------------------------------------------------------


def test_cross_tenant_read_denies_tenant_mismatch():
    # Mirrors the ADR's `crossTenantRead` example verbatim in spirit: a
    # principal in one tenant requesting a value captured under another.
    async def run():
        server = InMemoryVaultServer(
            core_client=_core(),
            principal_resolver=_resolver_for(OTHER_TENANT),
            release_policy=allow_same_tenant_only,
        )
        capture_id, token = await _capture_one(server, issued_tenant=ISSUING_TENANT)
        with pytest.raises(VaultServerError) as excinfo:
            await server.restore(
                RestoreRequest(
                    sink=SUPPORT_SINK,
                    captures=(capture_id,),
                    fields={"body": token},
                    purpose=SUPPORT_PURPOSE,
                    tenant=OTHER_TENANT,
                    context={"tenant": OTHER_TENANT},
                )
            )
        assert excinfo.value.code == VaultServerErrorCode.RESTORE_DENIED
        assert excinfo.value.reason == ServerDenialReason.TENANT_MISMATCH

    asyncio.run(run())


def test_same_tenant_read_is_allowed():
    async def run():
        server = InMemoryVaultServer(
            core_client=_core(),
            principal_resolver=_resolver_for(ISSUING_TENANT),
            release_policy=allow_same_tenant_only,
        )
        capture_id, token = await _capture_one(server, issued_tenant=ISSUING_TENANT)
        result = await server.restore(
            RestoreRequest(
                sink=SUPPORT_SINK,
                captures=(capture_id,),
                fields={"body": token},
                purpose=SUPPORT_PURPOSE,
                tenant=ISSUING_TENANT,
                context={"tenant": ISSUING_TENANT},
            )
        )
        assert FIXTURE_SECRET in result.fields["body"]

    asyncio.run(run())


# -- 3. Missing / invalid purpose ---------------------------------------------


def test_missing_purpose_denies():
    async def run():
        server = InMemoryVaultServer(
            core_client=_core(),
            principal_resolver=_resolver_for(ISSUING_TENANT),
            release_policy=allow_same_tenant_only,
        )
        capture_id, token = await _capture_one(server, issued_tenant=ISSUING_TENANT)
        with pytest.raises(VaultServerError) as excinfo:
            await server.restore(
                RestoreRequest(
                    sink=SUPPORT_SINK,
                    captures=(capture_id,),
                    fields={"body": token},
                    purpose="",
                    tenant=ISSUING_TENANT,
                    context={"tenant": ISSUING_TENANT},
                )
            )
        assert excinfo.value.reason == ServerDenialReason.MISSING_PURPOSE

    asyncio.run(run())


def test_purpose_not_in_allowlist_denies_missing_purpose():
    # Mirrors the ADR's `purposeLimited` reference policy exactly.
    async def run():
        server = InMemoryVaultServer(
            core_client=_core(),
            principal_resolver=_resolver_for(ISSUING_TENANT),
            release_policy=purpose_limited,
        )
        capture_id, token = await _capture_one(server, issued_tenant=ISSUING_TENANT)
        with pytest.raises(VaultServerError) as excinfo:
            await server.restore(
                RestoreRequest(
                    sink=SUPPORT_SINK,
                    captures=(capture_id,),
                    fields={"body": token},
                    purpose="not-an-allowed-purpose-synthetic",
                    tenant=ISSUING_TENANT,
                    context={"tenant": ISSUING_TENANT},
                )
            )
        assert excinfo.value.reason == ServerDenialReason.MISSING_PURPOSE

    asyncio.run(run())


# -- 4. Revoked-vs-unknown-token ----------------------------------------------


def test_revoked_token_reuse_denies_revoked_not_unknown():
    async def run():
        server = InMemoryVaultServer(
            core_client=_core(),
            principal_resolver=_resolver_for(ISSUING_TENANT),
            release_policy=allow_same_tenant_only,
        )
        capture_id, token = await _capture_one(server, issued_tenant=ISSUING_TENANT)
        removed = server.revoke(capture_id)
        assert removed == 1
        with pytest.raises(VaultServerError) as excinfo:
            await server.restore(
                RestoreRequest(
                    sink=SUPPORT_SINK,
                    captures=(capture_id,),
                    fields={"body": token},
                    purpose=SUPPORT_PURPOSE,
                    tenant=ISSUING_TENANT,
                    context={"tenant": ISSUING_TENANT},
                )
            )
        # This server keeps a revocation tombstone (ADR section 4 permits
        # this), so it can distinguish "existed, was revoked" from "never
        # existed / forged" — richer signal for incident response than a
        # store with no tombstone, which would report "unknown-token"
        # instead (also conformant; see conformance_runtime.py).
        assert excinfo.value.reason == ServerDenialReason.REVOKED

    asyncio.run(run())


def test_forged_token_denies_unknown_token():
    async def run():
        server = InMemoryVaultServer(
            core_client=_core(),
            principal_resolver=_resolver_for(ISSUING_TENANT),
            release_policy=allow_same_tenant_only,
        )
        capture_id, _token = await _capture_one(server, issued_tenant=ISSUING_TENANT)
        forged = "<rsv_" + ("a" * 26) + ">"
        with pytest.raises(VaultServerError) as excinfo:
            await server.restore(
                RestoreRequest(
                    sink=SUPPORT_SINK,
                    captures=(capture_id,),
                    fields={"body": forged},
                    purpose=SUPPORT_PURPOSE,
                    tenant=ISSUING_TENANT,
                    context={"tenant": ISSUING_TENANT},
                )
            )
        assert excinfo.value.reason == ServerDenialReason.UNKNOWN_TOKEN

    asyncio.run(run())


# -- 5. Policy-evaluation-error / timeout -------------------------------------


def test_throwing_policy_denies_policy_evaluation_error():
    async def run():
        def throwing_policy(_input):
            raise RuntimeError("policy backend unreachable (synthetic)")

        server = InMemoryVaultServer(
            core_client=_core(),
            principal_resolver=_resolver_for(ISSUING_TENANT),
            release_policy=throwing_policy,
        )
        capture_id, token = await _capture_one(server, issued_tenant=ISSUING_TENANT)
        events: list[ServerAuditEvent] = []
        server2 = InMemoryVaultServer(
            core_client=_core(),
            principal_resolver=_resolver_for(ISSUING_TENANT),
            release_policy=throwing_policy,
            on_audit=events.append,
        )
        capture_id2, token2 = await _capture_one(server2, issued_tenant=ISSUING_TENANT)
        with pytest.raises(VaultServerError) as excinfo:
            await server2.restore(
                RestoreRequest(
                    sink=SUPPORT_SINK,
                    captures=(capture_id2,),
                    fields={"body": token2},
                    purpose=SUPPORT_PURPOSE,
                    tenant=ISSUING_TENANT,
                    context={"tenant": ISSUING_TENANT},
                )
            )
        assert excinfo.value.reason == ServerDenialReason.POLICY_EVALUATION_ERROR
        # A dedicated "policy-error" audit event was raised, distinct from
        # the generic "restore"/"denied" event (ADR section 5 vocabulary).
        assert any(e.operation.value == "policy-error" for e in events)

    asyncio.run(run())


def test_non_conforming_policy_return_denies_policy_evaluation_error():
    async def run():
        def bad_policy(_input):
            return True  # not a PolicyDecision — must not be treated as allow

        server = InMemoryVaultServer(
            core_client=_core(),
            principal_resolver=_resolver_for(ISSUING_TENANT),
            release_policy=bad_policy,
        )
        capture_id, token = await _capture_one(server, issued_tenant=ISSUING_TENANT)
        with pytest.raises(VaultServerError) as excinfo:
            await server.restore(
                RestoreRequest(
                    sink=SUPPORT_SINK,
                    captures=(capture_id,),
                    fields={"body": token},
                    purpose=SUPPORT_PURPOSE,
                    tenant=ISSUING_TENANT,
                    context={"tenant": ISSUING_TENANT},
                )
            )
        assert excinfo.value.reason == ServerDenialReason.POLICY_EVALUATION_ERROR

    asyncio.run(run())


def test_policy_timeout_denies_policy_evaluation_error():
    async def run():
        async def slow_policy(_input):
            await asyncio.sleep(10)
            return PolicyDecision(allow=True)

        server = InMemoryVaultServer(
            core_client=_core(),
            principal_resolver=_resolver_for(ISSUING_TENANT),
            release_policy=slow_policy,
            policy_timeout_s=0.05,
        )
        capture_id, token = await _capture_one(server, issued_tenant=ISSUING_TENANT)
        with pytest.raises(VaultServerError) as excinfo:
            await server.restore(
                RestoreRequest(
                    sink=SUPPORT_SINK,
                    captures=(capture_id,),
                    fields={"body": token},
                    purpose=SUPPORT_PURPOSE,
                    tenant=ISSUING_TENANT,
                    context={"tenant": ISSUING_TENANT},
                )
            )
        assert excinfo.value.reason == ServerDenialReason.POLICY_EVALUATION_ERROR

    asyncio.run(run())


def test_no_policy_configured_fails_closed():
    async def run():
        server = InMemoryVaultServer(core_client=_core(), principal_resolver=_resolver_for(ISSUING_TENANT))
        capture_id, token = await _capture_one(server, issued_tenant=ISSUING_TENANT)
        with pytest.raises(VaultServerError) as excinfo:
            await server.restore(
                RestoreRequest(
                    sink=SUPPORT_SINK,
                    captures=(capture_id,),
                    fields={"body": token},
                    purpose=SUPPORT_PURPOSE,
                    tenant=ISSUING_TENANT,
                    context={"tenant": ISSUING_TENANT},
                )
            )
        assert excinfo.value.reason == ServerDenialReason.POLICY

    asyncio.run(run())


# -- 6. Policy-revision staleness ---------------------------------------------


def test_stale_policy_revision_denies():
    # No mandated linearization mechanism (the ADR leaves multi-process
    # policy-revision consistency to the store contract, #19); this shows
    # the injection point — `policy_revision` reaches the policy on every
    # call — carries enough information for a policy to enforce staleness
    # itself.
    async def run():
        current_revision = {"value": "policy-rev-2-synthetic"}

        def revision_pinned_policy(decision_input):
            if decision_input.policy_revision != current_revision["value"]:
                return PolicyDecision(allow=False, reason=ServerDenialReason.STALE_POLICY)
            return PolicyDecision(allow=True)

        server = InMemoryVaultServer(
            core_client=_core(),
            principal_resolver=_resolver_for(ISSUING_TENANT),
            release_policy=revision_pinned_policy,
        )
        capture_id, token = await _capture_one(server, issued_tenant=ISSUING_TENANT)
        with pytest.raises(VaultServerError) as excinfo:
            await server.restore(
                RestoreRequest(
                    sink=SUPPORT_SINK,
                    captures=(capture_id,),
                    fields={"body": token},
                    purpose=SUPPORT_PURPOSE,
                    tenant=ISSUING_TENANT,
                    context={"tenant": ISSUING_TENANT},
                    policy_revision="policy-rev-1-synthetic-stale",
                )
            )
        assert excinfo.value.reason == ServerDenialReason.STALE_POLICY

    asyncio.run(run())


# -- Composition, reentrancy, and audit shape ---------------------------------


def test_all_of_composes_policies_first_denial_wins():
    async def run():
        chained = all_of(allow_same_tenant_only, purpose_limited)
        server = InMemoryVaultServer(
            core_client=_core(),
            principal_resolver=_resolver_for(OTHER_TENANT),
            release_policy=chained,
        )
        capture_id, token = await _capture_one(server, issued_tenant=ISSUING_TENANT)
        with pytest.raises(VaultServerError) as excinfo:
            await server.restore(
                RestoreRequest(
                    sink=SUPPORT_SINK,
                    captures=(capture_id,),
                    fields={"body": token},
                    purpose=SUPPORT_PURPOSE,
                    tenant=OTHER_TENANT,
                    context={"tenant": OTHER_TENANT},
                )
            )
        assert excinfo.value.reason == ServerDenialReason.TENANT_MISMATCH

    asyncio.run(run())


def test_audit_event_has_no_field_capable_of_carrying_a_restored_value():
    # Structural guarantee: enumerate every field ServerAuditEvent declares
    # and assert none is a free-text/value-shaped field.
    import dataclasses

    field_names = {f.name for f in dataclasses.fields(ServerAuditEvent)}
    forbidden = {"value", "message", "description", "text", "plaintext", "restored"}
    assert field_names.isdisjoint(forbidden)


def test_committed_restore_audit_event_and_no_leakage():
    async def run():
        events: list[ServerAuditEvent] = []
        server = InMemoryVaultServer(
            core_client=_core(),
            principal_resolver=_resolver_for(ISSUING_TENANT),
            release_policy=allow_same_tenant_only,
            on_audit=events.append,
        )
        capture_id, token = await _capture_one(server, issued_tenant=ISSUING_TENANT)
        await server.restore(
            RestoreRequest(
                sink=SUPPORT_SINK,
                captures=(capture_id,),
                fields={"body": token},
                purpose=SUPPORT_PURPOSE,
                tenant=ISSUING_TENANT,
                context={"tenant": ISSUING_TENANT},
            )
        )
        assert any(e.operation.value == "restore" and e.outcome == "committed" for e in events)
        for event in events:
            serialized = repr(event)
            assert FIXTURE_SECRET not in serialized
            assert token not in serialized

    asyncio.run(run())


def test_reentrant_policy_gets_busy():
    # A policy that calls back into the same server mid-restore must not
    # interleave with the half-finished operation.
    async def run():
        server_ref: dict[str, InMemoryVaultServer] = {}

        async def reentrant_policy(_input):
            with pytest.raises(VaultServerError) as excinfo:
                server_ref["server"].capture(
                    "irrelevant",
                    CaptureOptions(issued_tenant=ISSUING_TENANT, release=(CaptureGrant("s", ("p",)),)),
                )
            assert excinfo.value.code == VaultServerErrorCode.BUSY
            return PolicyDecision(allow=False, reason=ServerDenialReason.POLICY)

        server = InMemoryVaultServer(
            core_client=_core(),
            principal_resolver=_resolver_for(ISSUING_TENANT),
            release_policy=reentrant_policy,
        )
        server_ref["server"] = server
        capture_id, token = await _capture_one(server, issued_tenant=ISSUING_TENANT)
        with pytest.raises(VaultServerError):
            await server.restore(
                RestoreRequest(
                    sink=SUPPORT_SINK,
                    captures=(capture_id,),
                    fields={"body": token},
                    purpose=SUPPORT_PURPOSE,
                    tenant=ISSUING_TENANT,
                    context={"tenant": ISSUING_TENANT},
                )
            )

    asyncio.run(run())
