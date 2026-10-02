"""The persistent server profile (docs/specs/persistent-vault.md sections 7 and 8) over the reference store.

Python persistence is not implemented and not supported. These tests show that this module follows the profile on
the cases written here, against an in-memory store and a fake core. They say nothing about a database adapter, the
Node.js bridge, durability, or a deployment. Everything is synthetic.
"""

from __future__ import annotations

import asyncio
import math
import sys
import time
from typing import Any

import pytest

pytest.importorskip("cryptography")

from server_support import (  # noqa: E402
    CTX_A,
    CTX_B,
    FORGED_TOKEN,
    NAMESPACE,
    OTHER_TENANT,
    PURPOSE,
    RELEASE,
    SECRET_A,
    SECRET_B,
    SECRET_C,
    SINK,
    START,
    TENANT,
    Clock,
    FakeCore,
    ctx,
    make_rig,
)

from redact_secret_vault import (  # noqa: E402
    CaptureGrant,
    PolicyDecision,
    RestoreRequest,
    ServerAuditOperation,
    ServerDenialReason,
    VaultServerError,
    VaultServerErrorCode,
)
from redact_secret_vault.persistent import (  # noqa: E402
    CaptureRejected,
    InvalidateRecoveredInput,
    KeyProviderError,
    LifecycleDecision,
    LifecycleRequest,
    PersistentCaptureOptions,
    StoreError,
    create_persistent_server_vault,
)

pytestmark = pytest.mark.skipif(sys.version_info < (3, 11), reason="the persistent modules need Python 3.11")

CODE = VaultServerErrorCode
DENIAL = ServerDenialReason


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def raises(code: VaultServerErrorCode, reason: ServerDenialReason | None = None) -> Any:
    """``pytest.raises`` that also pins the code and, for a denial, the reason."""

    class _Checker:
        def __enter__(self) -> _Checker:
            self._inner = pytest.raises(VaultServerError)
            self.info = self._inner.__enter__()
            return self

        def __exit__(self, *exc: Any) -> bool:
            swallowed = self._inner.__exit__(*exc)
            if swallowed:
                error = self.info.value
                assert error.code == code, f"expected {code.value}, got {error.code.value}/{error.reason}"
                assert error.reason == reason, f"expected reason {reason}, got {error.reason}"
                assert error.__cause__ is None and error.__context__ is None
            return swallowed

    return _Checker()


def denied(reason: ServerDenialReason) -> Any:
    return raises(CODE.RESTORE_DENIED, reason)


# ---------------------------------------------------------------------------- the factory


def test_a_round_trip_restores_into_the_granted_field_once() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture()
        assert SECRET_A not in captured.text and len(captured.tokens) == 1
        assert captured.tenant == TENANT and captured.session_bound is False
        restored = await rig.restore(captured)
        assert restored.fields["body"] == f"secret {SECRET_A} here"
        assert restored.restored == 1 and restored.tenant == TENANT and restored.attempt_id is not None
        with denied(DENIAL.BUDGET):
            await rig.restore(captured)

    run(scenario())


def test_expected_pii_activation_is_required_and_checked_before_anything_is_stored() -> None:
    async def scenario() -> None:
        for bad in (None, "", 7, "x" * 513):
            with raises(CODE.INVALID_ARGUMENT):
                await make_rig(expected_pii_activation=bad)
        # A core that reports another identity: the worker fails closed at creation.
        different = FakeCore("credentials=full;selectors=pii:global;families=;vocabulary=pii-context/v2")
        with raises(CODE.PII_ACTIVATION_MISMATCH):
            await make_rig(core=different)
        # A core without a PII surface reports none, which is not what was expected either.
        with raises(CODE.PII_ACTIVATION_MISMATCH):
            await make_rig(core=FakeCore(None))
        # Two workers over one store: the second's core disagrees, and it stores nothing.
        first = await make_rig()
        second_core = FakeCore("credentials=full;selectors=pii:global;families=;vocabulary=pii-context/v2")
        with raises(CODE.PII_ACTIVATION_MISMATCH):
            await create_persistent_server_vault(**{**first.options, "core_client": second_core})
        assert first.store.mutations() == 0

    run(scenario())


def test_a_core_whose_activation_changes_fails_the_capture_before_it_stores_anything() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        rig.core.activation = "credentials=full;selectors=pii:global;families=;vocabulary=pii-context/v2"
        with raises(CODE.PII_ACTIVATION_MISMATCH):
            await rig.capture()
        assert rig.store.mutations() == 0

    run(scenario())


def test_a_core_failure_at_creation_is_reported_by_code() -> None:
    async def scenario() -> None:
        with raises(CODE.INVARIANT_VIOLATION):
            await make_rig(core=FakeCore(fail=RuntimeError("synthetic core failure")))
        with raises(CODE.CORE_FAILURE):
            await make_rig(core=FakeCore(fail=VaultServerError(CODE.CORE_FAILURE, core_code="SYNTHETIC")))

    run(scenario())


def test_the_digest_key_is_required_unless_waived_and_never_both() -> None:
    async def scenario() -> None:
        with raises(CODE.INVALID_ARGUMENT):
            await make_rig(digest_key=None)
        with raises(CODE.INVALID_ARGUMENT):
            await make_rig(digest_key=b"short")
        with raises(CODE.INVALID_ARGUMENT):
            await make_rig(allow_unkeyed_digests=True)
        with raises(CODE.INVALID_ARGUMENT):
            await make_rig(digest_key=None, allow_unkeyed_digests="yes")
        rig = await make_rig(digest_key=None, allow_unkeyed_digests=True)
        assert (await rig.restore(await rig.capture())).restored == 1

    run(scenario())


def test_the_store_must_declare_what_the_profile_needs() -> None:
    async def scenario() -> None:
        base = (await make_rig(open_server=False)).store
        capabilities = base.capabilities()
        import dataclasses

        for field in (
            "atomic_create",
            "atomic_restore",
            "authoritative_commit",
            "revocation_fences",
            "attempt_receipts",
        ):
            rig = await make_rig(open_server=False)
            rig.store.capabilities_override = dataclasses.replace(capabilities, **{field: False})
            with raises(CODE.UNSUPPORTED_STORE):
                await create_persistent_server_vault(**rig.options)
        # A volatile or single-process store is refused unless the application says it knows.
        rig = await make_rig(open_server=False)
        with raises(CODE.UNSUPPORTED_STORE):
            await create_persistent_server_vault(**{**rig.options, "allow_non_durable_store": False})
        # A durable store that declares no restore detection is refused unless the application says it knows.
        durable = dataclasses.replace(capabilities, durability="durable", cross_process=True, restore_detection="none")
        rig.store.capabilities_override = durable
        with raises(CODE.UNSUPPORTED_STORE):
            await create_persistent_server_vault(**{**rig.options, "allow_non_durable_store": False})
        assert (
            await create_persistent_server_vault(
                **{**rig.options, "allow_non_durable_store": False, "allow_no_restore_detection": True}
            )
        ).namespace == NAMESPACE
        # A capabilities call that raises is the same refusal, and its error is not kept.
        rig.store.capabilities = lambda: (_ for _ in ()).throw(RuntimeError("synthetic driver failure"))  # type: ignore[method-assign]
        with raises(CODE.UNSUPPORTED_STORE):
            await create_persistent_server_vault(**rig.options)

    run(scenario())


def test_creation_fails_closed_unless_the_namespace_is_serving_at_the_configured_epoch() -> None:
    async def scenario() -> None:
        with raises(CODE.STORE_QUARANTINED):
            await make_rig(initialize=False)
        rig = await make_rig(open_server=False, epoch=1)
        await rig.memory.quarantine(NAMESPACE)
        with raises(CODE.STORE_QUARANTINED):
            await create_persistent_server_vault(**rig.options)
        await rig.memory.invalidate_recovered(InvalidateRecoveredInput(NAMESPACE, 2))
        with raises(CODE.STORE_QUARANTINED):  # serving, but at epoch 2 and configured for 1
            await create_persistent_server_vault(**rig.options)
        assert rig.store.count("initialize_namespace") == 0  # it never initializes a namespace
        rig.store.fail["recovery_state"] = lambda: StoreError("STORE_UNAVAILABLE")
        with raises(CODE.STORE_UNAVAILABLE):
            await create_persistent_server_vault(**rig.options)

    run(scenario())


def test_options_are_validated() -> None:
    async def scenario() -> None:
        bad: list[dict[str, Any]] = [
            {"namespace": "bad namespace"},
            {"recovery_epoch": 0},
            {"recovery_epoch": True},
            {"resolve_principal": None},
            {"policy": "allow"},
            {"lifecycle_policy": None},
            {"resolve_session": 1},
            {"on_audit": 1},
            {"now": 1},
            {"policy_revision": 1},
            {"resolver_timeout_s": 0},
            {"policy_timeout_s": -1},
            {"store_timeout_s": math.nan},
            {"crypto_timeout_s": 10_000},
            {"max_commit_retries": 11},
            {"max_commit_retries": True},
            {"receipt_grace_ms": -1},
            {"tombstone_retention_ms": 2**40},
            {"limits": {"max_entries": 0}},
            {"limits": {"unknown": 1}},
            {
                "limits": {"entry_ttl_ms": 24 * 60 * 60 * 1000},
                "receipt_grace_ms": 24 * 60 * 60 * 1000,
            },  # past the 48 hour horizon
            {"store": object()},
            {"crypto": object()},
            {"core_client": object()},
        ]
        for patch in bad:
            with raises(CODE.INVALID_ARGUMENT):
                await make_rig(**patch)

    run(scenario())


def test_a_late_close_refuses_further_use_and_changes_nothing_else() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture()
        before = rig.store.mutations()
        await rig.vault.close()
        for call in (rig.capture(), rig.restore(captured), rig.revoke(captured)):
            with raises(CODE.CLOSED):
                await call
        assert rig.store.mutations() == before  # close revokes nothing and deletes nothing

    run(scenario())


# --------------------------------------------------------------------------------- capture


def test_capture_takes_tenant_and_session_only_from_the_resolvers() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        bound = await rig.capture(context=ctx(session="session-synthetic-one"))
        assert bound.session_bound is True and bound.tenant == TENANT
        free = await rig.capture(context=CTX_A)
        assert free.session_bound is False
        other = await rig.capture(context=CTX_B)
        assert other.tenant == OTHER_TENANT
        # The capture row holds a keyed tag, not the session identifier.
        capture_row = next(iter(rig.rows().captures.values()))
        assert capture_row.session_tag is not None and "session-synthetic-one" not in capture_row.session_tag

    run(scenario())


def test_capture_stores_ciphertext_only() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        await rig.capture(f"{SECRET_A} and {SECRET_B}")
        rows = rig.rows()
        assert len(rows.entries) == 2
        for entry in rows.entries.values():
            assert SECRET_A.encode() not in entry.envelope and SECRET_B.encode() not in entry.envelope
        for capture in rows.captures.values():
            assert SECRET_A.encode() not in capture.wrapped_key

    run(scenario())


def test_a_capture_that_retains_nothing_stores_nothing_and_asks_the_policy_once() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        result = await rig.capture("nothing to hide here")
        assert result.tokens == () and result.text == "nothing to hide here"
        assert rig.store.mutations() == 0 and rig.provider.calls["generate"] == 0
        assert len(rig.lifecycle_calls) == 1 and rig.lifecycle_calls[0].entries == 0

    run(scenario())


def test_the_lifecycle_policy_sees_the_operation_and_decides_before_any_store_mutation() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        await rig.capture(f"{SECRET_A} {SECRET_B}", context=ctx(session="session-synthetic-one"))
        seen = rig.lifecycle_calls[0]
        assert seen.operation == "capture" and seen.entries == 2 and seen.bytes == len(SECRET_A) + len(SECRET_B)
        assert seen.tenant == TENANT and seen.session_id == "session-synthetic-one" and seen.capture_id is None
        for decide in (
            lambda _i: LifecycleDecision(allow=False),
            lambda _i: {"allow": True},
            lambda _i: True,
            lambda _i: None,
        ):
            rig.lifecycle = decide
            before = rig.store.mutations()
            with raises(CODE.LIFECYCLE_DENIED):
                await rig.capture()
            assert rig.store.mutations() == before and rig.provider.calls["generate"] == 1

        def boom(_input: Any) -> Any:
            raise RuntimeError("synthetic policy failure")

        rig.lifecycle = boom
        with raises(CODE.LIFECYCLE_DENIED):
            await rig.capture()

    run(scenario())


def test_a_slow_lifecycle_policy_times_out_and_denies() -> None:
    async def scenario() -> None:
        rig = await make_rig(policy_timeout_s=0.05)

        async def slow(_input: Any) -> LifecycleDecision:
            await asyncio.sleep(1)
            return LifecycleDecision(allow=True)

        rig.lifecycle = slow
        with raises(CODE.LIFECYCLE_DENIED):
            await rig.capture()
        assert rig.store.mutations() == 0

    run(scenario())


def test_capture_needs_a_principal() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        for context in ({"principal": "principal-unknown"}, None, {}):
            with raises(CODE.LIFECYCLE_DENIED):
                await rig.capture(context=context)
        assert rig.store.mutations() == 0

    run(scenario())


def test_capture_gate_errors_are_the_in_memory_servers_codes() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        with raises(CODE.BLOCKED_FINDING):
            await rig.capture(policy={"github_token": "block"})
        with raises(CODE.UNREDACTED_FINDINGS):
            await rig.capture(policy={"github_token": "warn"})
        passed = await rig.capture(policy={"github_token": "warn"}, unredacted="pass-through")
        assert passed.passed_through == 1 and passed.tokens == () and SECRET_A in passed.text
        with raises(CODE.TOKEN_LITERAL_IN_INPUT):
            await rig.capture(f"{SECRET_A} <rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>")
        with raises(CODE.LIMIT_EXCEEDED):
            await rig.capture("x" * (2 << 20))
        small = await make_rig(limits={"max_entries": 1})
        with raises(CODE.LIMIT_EXCEEDED):
            await small.capture(f"{SECRET_A} {SECRET_B}")
        assert small.store.mutations() == 0  # a refused capture stores nothing and leaves no fence
        for options in ({"max_uses": 0}, {"unredacted": "maybe"}, {"release": ()}, {"eligible": 1}):
            with raises(CODE.INVALID_ARGUMENT):
                await rig.capture(**options)
        with raises(CODE.INVALID_ARGUMENT):
            await rig.capture(request_id="x" * 300)
        with raises(CODE.INVALID_ARGUMENT):
            await rig.capture(request_id="<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>")

    run(scenario())


def test_an_eligible_callback_can_only_narrow() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        result = await rig.capture(f"{SECRET_A} {SECRET_B}", eligible=lambda finding: False)
        assert result.tokens == () and result.unrestorable == 2 and rig.store.mutations() == 0
        assert "<SECRET_1>" in result.text and "<SECRET_2>" in result.text

    run(scenario())


def test_an_identifier_with_a_lone_surrogate_is_an_argument_error() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        for grant in (
            CaptureGrant(sink="sink-\ud800", paths=("body",)),
            CaptureGrant(sink=SINK, paths=("bo\udc00dy",)),
        ):
            with raises(CODE.INVALID_ARGUMENT):
                await rig.capture(release=(grant,))
        assert rig.store.mutations() == 0

    run(scenario())


def test_a_failed_capture_returns_nothing_and_a_provider_outage_is_key_unavailable() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        rig.provider.fail["generate"] = lambda: KeyProviderError("KEY_UNAVAILABLE")
        with raises(CODE.KEY_UNAVAILABLE):
            await rig.capture()
        assert rig.store.mutations() == 0
        rig.provider.fail["generate"] = lambda: RuntimeError("synthetic SDK failure")
        with raises(CODE.KEY_UNAVAILABLE):
            await rig.capture()
        del rig.provider.fail["generate"]
        rig.provider.delay["generate"] = 1
        slow = await make_rig(crypto_timeout_s=0.05)
        slow.provider.delay["generate"] = 1
        with raises(CODE.KEY_UNAVAILABLE):
            await slow.capture()

    run(scenario())


def test_create_capture_failures_are_classified_and_an_ambiguous_one_is_fenced_once() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        rig.store.fail["create_capture"] = lambda: StoreError("STORE_UNAVAILABLE")
        with raises(CODE.STORE_UNAVAILABLE):
            await rig.capture()
        assert rig.store.count("revoke_capture") == 0  # nothing was applied, so nothing to fence
        rig.store.fail["create_capture"] = lambda: StoreError("STORE_AMBIGUOUS")
        with raises(CODE.STORE_UNAVAILABLE):
            await rig.capture()
        fence = [item for name, item in rig.store.calls if name == "revoke_capture"]
        assert len(fence) == 1 and fence[0].fence_absent is True
        del rig.store.fail["create_capture"]
        for result, code in (
            ("quarantined", CODE.STORE_QUARANTINED),
            ("clock-skew", CODE.CLOCK_SKEW),
            ("stale", CODE.STORE_UNAVAILABLE),
            ("exists", CODE.INVARIANT_VIOLATION),
            ("fenced", CODE.INVARIANT_VIOLATION),
        ):
            rig.store.override["create_capture"] = lambda _i, reason=result: CaptureRejected(reason=reason)
            with raises(code):
                await rig.capture()
        # A result this server cannot interpret says nothing about whether the capture exists: it is fenced too.
        rig.store.override["create_capture"] = lambda _i: "gibberish"
        fences = rig.store.count("revoke_capture")
        with raises(CODE.INVARIANT_VIOLATION):
            await rig.capture()
        assert rig.store.count("revoke_capture") == fences + 1

    run(scenario())


# ---------------------------------------------------------------------------------- restore


def test_a_malformed_request_is_denied_before_anyone_is_resolved() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture()
        resolver_calls: list[Any] = []

        def resolver(context: Any) -> Any:
            resolver_calls.append(context)
            from server_support import resolve_principal

            return resolve_principal(context)

        rig2 = await make_rig(resolve_principal=resolver)
        c2 = await rig2.capture()
        resolver_calls.clear()
        with denied(DENIAL.INVALID_REQUEST):
            await rig2.restore(c2, fields={"bad path\ud800": "x"})
        with denied(DENIAL.INVALID_REQUEST):
            await rig2.restore(c2, fields={f"f{n}": "x" for n in range(65)})
        with denied(DENIAL.INVALID_REQUEST):
            await rig2.restore(c2, fields={"body": 7})
        with denied(DENIAL.INVALID_REQUEST):
            await rig2.restore(c2, fields={"body": "x" * ((1 << 20) + 1)})
        assert resolver_calls == []
        for patch in (
            {"sink": ""},
            {"purpose": 7},
            {"purpose": "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>"},
            {"purpose": "p" * 2000},
            {"captures": ()},
            {"captures": ("not-a-capture",)},
            {"captures": tuple(f"cap_{'a' * 25}{chr(97 + n % 26)}" for n in range(65))},
            {"fields": [1]},
            {"attempt_id": "bad attempt"},
            {"request_id": "x" * 300},
        ):
            with raises(CODE.INVALID_ARGUMENT):
                await rig.restore(captured, **patch)

    run(scenario())


def test_the_principal_is_resolved_with_a_deadline_and_a_failure_denies_unauthenticated() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture()
        with denied(DENIAL.UNAUTHENTICATED):
            await rig.restore(captured, context={"principal": "principal-unknown"})
        assert rig.audits[-1].operation == ServerAuditOperation.RESOLVE_PRINCIPAL
        slow = await make_rig(resolver_timeout_s=0.05)
        c2 = await slow.capture()

        async def hang(_context: Any) -> Any:
            await asyncio.sleep(1)

        slow.options["resolve_principal"] = hang
        hung = await create_persistent_server_vault(**{**slow.options, "resolve_principal": hang})
        with pytest.raises(VaultServerError) as error:
            await hung.restore(slow.restore_request(c2))
        assert error.value.reason == DENIAL.UNAUTHENTICATED
        # A resolver that returns something else than a Principal is a failure to resolve.
        weird = await create_persistent_server_vault(**{**slow.options, "resolve_principal": lambda _c: {"id": "x"}})
        with pytest.raises(VaultServerError) as error:
            await weird.restore(slow.restore_request(c2))
        assert error.value.reason == DENIAL.UNAUTHENTICATED

    run(scenario())


def test_a_session_resolver_that_fails_denies_and_a_malformed_session_does_too() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture()
        for resolver in (lambda _c: (_ for _ in ()).throw(RuntimeError("synthetic")), lambda _c: "bad\ud800session"):
            vault = await create_persistent_server_vault(**{**rig.options, "resolve_session": resolver})
            with pytest.raises(VaultServerError) as error:
                await vault.restore(rig.restore_request(captured))
            assert error.value.reason == DENIAL.UNAUTHENTICATED

    run(scenario())


def test_malformed_markers_and_an_empty_purpose_are_denied_after_the_principal_is_known() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture()
        with denied(DENIAL.MALFORMED_TOKEN):
            await rig.restore(captured, fields={"body": f"{captured.tokens[0].token} and <rsv_ broken"})
        assert rig.audits[-1].principal_id == "principal-synthetic-0001"
        with denied(DENIAL.MISSING_PURPOSE):
            await rig.restore(captured, purpose="")
        assert rig.store.count("read_entries") == 0 and rig.provider.calls["unwrap"] == 0

    run(scenario())


def test_a_request_with_no_token_is_returned_unchanged_with_no_store_call_and_no_attempt() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture()
        calls = len(rig.store.calls)
        result = await rig.restore(captured, fields={"body": "no token here", "subject": "none"})
        assert dict(result.fields) == {"body": "no token here", "subject": "none"}
        assert result.restored == 0 and result.attempt_id is None
        assert len(rig.store.calls) == calls

    run(scenario())


def test_the_denials_of_step_four_come_in_the_specified_order() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        # Unknown before everything: a forged token.
        captured = await rig.capture()
        with denied(DENIAL.UNKNOWN_TOKEN):
            await rig.restore(captured, fields={"body": f"{captured.tokens[0].token} {FORGED_TOKEN}"})
        # Revoked before source: the revoked capture is not even named.
        other = await rig.capture(f"x {SECRET_B} y")
        await rig.revoke(captured)
        with denied(DENIAL.REVOKED):
            await rig.restore(captured, captures=(other.capture_id,))
        # Source before expiry and budget, and a session-bound capture needs its session before any key is unwrapped.
        bound = await rig.capture(context=ctx(session="session-synthetic-one"))
        with denied(DENIAL.SOURCE):
            await rig.restore(bound, captures=(other.capture_id,), context=ctx(session="session-synthetic-one"))
        with denied(DENIAL.SOURCE):
            await rig.restore(bound, context=ctx(session="session-synthetic-two"))
        with denied(DENIAL.SOURCE):
            await rig.restore(bound)
        assert rig.provider.calls["unwrap"] == 0
        # Expiry before budget: an exhausted entry of an expired capture is expired.
        used = await rig.capture(f"x {SECRET_A} y")
        await rig.restore(used)
        rig.clock.advance(10 * 60 * 1000)
        with denied(DENIAL.EXPIRED):
            await rig.restore(used)
        assert rig.provider.calls["unwrap"] == 1

    run(scenario())


def test_one_unwrap_per_capture_and_a_tampered_record_is_an_integrity_failure() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture(f"{SECRET_A} {SECRET_B}")
        field = " ".join(token.token for token in captured.tokens)
        result = await rig.restore(captured, fields={"body": field})
        assert result.restored == 2 and rig.provider.calls["unwrap"] == 1
        tampered = await rig.capture()
        entry = next(e for e in rig.rows().entries.values() if e.capture_id == tampered.capture_id)
        entry.envelope = entry.envelope[:-1] + bytes([entry.envelope[-1] ^ 1])
        with denied(DENIAL.INTEGRITY_FAILURE):
            await rig.restore(tampered)
        # Nothing was consumed, and nothing partial was returned.
        assert entry.used == 0

    run(scenario())


def test_a_provider_failure_at_restore_is_a_denial_not_an_error() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture()
        for failure, reason in (
            (lambda: KeyProviderError("KEY_UNAVAILABLE"), DENIAL.KEY_UNAVAILABLE),
            (lambda: KeyProviderError("KEY_THROTTLED"), DENIAL.KEY_UNAVAILABLE),
            (lambda: KeyProviderError("KEY_INTEGRITY"), DENIAL.INTEGRITY_FAILURE),
            (lambda: RuntimeError("synthetic SDK failure"), DENIAL.KEY_UNAVAILABLE),
        ):
            rig.provider.fail["unwrap"] = failure
            with denied(reason):
                await rig.restore(captured)
        del rig.provider.fail["unwrap"]
        assert (await rig.restore(captured)).restored == 1  # no use was consumed by the failures

    run(scenario())


def test_grants_come_from_the_authenticated_record() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture()
        with denied(DENIAL.SINK_OR_PATH):
            await rig.restore(captured, sink="sink-not-granted")
        with denied(DENIAL.SINK_OR_PATH):
            await rig.restore(captured, fields={"elsewhere": captured.text})
        assert (await rig.restore(captured, fields={"subject": captured.text})).restored == 1

    run(scenario())


def test_the_policy_runs_between_the_read_and_the_commit_for_every_entry_and_path() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture(f"{SECRET_A} {SECRET_B}", max_uses=4)
        token_a, token_b = (token.token for token in captured.tokens)
        commits_during_policy: list[int] = []

        def policy(decision: Any) -> PolicyDecision:
            commits_during_policy.append(rig.store.count("commit_restore"))
            return PolicyDecision(allow=True)

        rig.policy = policy
        await rig.restore(captured, fields={"body": f"{token_a} {token_a} {token_b}", "subject": token_a})
        assert commits_during_policy == [0, 0, 0] and len(rig.policy_calls) == 3
        by_path = {(call.path, call.occurrences, call.total_occurrences, call.type) for call in rig.policy_calls}
        assert ("body", 2, 3, "github_token") in by_path and ("subject", 1, 3, "github_token") in by_path
        first = rig.policy_calls[0]
        assert first.principal.id == "principal-synthetic-0001" and first.tenant == TENANT and first.purpose == PURPOSE
        assert first.source.issued_tenant == TENANT and first.used == 0 and first.max_uses == 4

    run(scenario())


def test_policy_denials_and_failures_are_denials_and_never_allow() -> None:
    async def scenario() -> None:
        rig = await make_rig(policy_timeout_s=0.05)
        captured = await rig.capture(max_uses=10)
        for reason in ("policy", "rate-limited", "stale-policy", "tenant-mismatch"):
            rig.policy = lambda _i, reason=reason: PolicyDecision(allow=False, reason=ServerDenialReason(reason))
            with denied(ServerDenialReason(reason)):
                await rig.restore(captured)

        def boom(_input: Any) -> Any:
            raise RuntimeError("synthetic policy failure")

        async def slow(_input: Any) -> PolicyDecision:
            await asyncio.sleep(1)
            return PolicyDecision(allow=True)

        for decide in (boom, slow, lambda _i: True, lambda _i: None, lambda _i: {"allow": True}):
            rig.policy = decide
            with denied(DENIAL.POLICY_EVALUATION_ERROR):
                await rig.restore(captured)
            assert rig.audits[-1].operation == ServerAuditOperation.POLICY_ERROR and rig.audits[-1].outcome == "failed"
        # A denial reason outside the vocabulary a policy may return is an evaluation error.
        rig.policy = lambda _i: PolicyDecision(allow=False, reason=ServerDenialReason.INTEGRITY_FAILURE)
        with denied(DENIAL.POLICY_EVALUATION_ERROR):
            await rig.restore(captured)
        assert rig.store.count("commit_restore") == 0

    run(scenario())


def test_a_policy_revision_that_changes_between_policy_and_commit_denies_stale_policy() -> None:
    async def scenario() -> None:
        revisions = iter(["rev-1", "rev-1", "rev-2"])
        state = {"current": "rev-1"}
        rig = await make_rig(policy_revision=lambda: state["current"])
        captured = await rig.capture()

        def policy(_decision: Any) -> PolicyDecision:
            state["current"] = "rev-2"
            return PolicyDecision(allow=True)

        rig.policy = policy
        with denied(DENIAL.STALE_POLICY):
            await rig.restore(captured)
        assert next(revisions) == "rev-1"
        # The revision at issuance is part of the authenticated record, and is shown to the policy.
        state["current"] = "rev-1"
        rig.policy = lambda _d: PolicyDecision(allow=True)
        fresh = await rig.capture()
        await rig.restore(fresh)
        assert rig.policy_calls[-1].policy_revision == "rev-1"
        with raises(CODE.INVALID_ARGUMENT):
            state["current"] = 5  # type: ignore[assignment]
            await rig.capture()

    run(scenario())


def test_the_commit_outcomes_map_to_denials_and_errors() -> None:
    async def scenario() -> None:
        from redact_secret_vault.persistent import (
            RestoreAlreadyCommitted,
            RestoreAttemptMismatch,
            RestoreRejected,
        )

        rig = await make_rig()
        captured = await rig.capture(max_uses=10)
        table: list[tuple[Any, Any]] = [
            (RestoreRejected(reason="revoked"), ("denied", DENIAL.REVOKED)),
            (RestoreRejected(reason="expired"), ("denied", DENIAL.EXPIRED)),
            (RestoreRejected(reason="budget"), ("denied", DENIAL.BUDGET)),
            (RestoreRejected(reason="unknown"), ("denied", DENIAL.UNKNOWN_TOKEN)),
            (RestoreAlreadyCommitted(), ("denied", DENIAL.ATTEMPT_ALREADY_COMMITTED)),
            (RestoreAttemptMismatch(), ("denied", DENIAL.ATTEMPT_MISMATCH)),
            (RestoreRejected(reason="clock-skew"), ("failed", CODE.CLOCK_SKEW)),
            (RestoreRejected(reason="quarantined"), ("failed", CODE.STORE_QUARANTINED)),
            ("gibberish", ("failed", CODE.COMMIT_AMBIGUOUS)),
        ]
        for result, (kind, expected) in table:
            rig.store.override["commit_restore"] = lambda _i, result=result: result
            if kind == "denied":
                with denied(expected):
                    await rig.restore(captured)
            else:
                with raises(expected):
                    await rig.restore(captured)
        del rig.store.override["commit_restore"]

    run(scenario())


def test_a_stale_commit_reads_again_up_to_the_limit_and_then_conflicts() -> None:
    async def scenario() -> None:
        from redact_secret_vault.persistent import RestoreRejected

        rig = await make_rig(max_commit_retries=2)
        captured = await rig.capture(max_uses=5)
        rig.store.override["commit_restore"] = lambda _i: RestoreRejected(reason="stale")
        with raises(CODE.RESTORE_CONFLICT):
            await rig.restore(captured)
        assert rig.store.count("commit_restore") == 3 and rig.store.count("read_entries") == 3
        assert len(rig.policy_calls) == 3  # the policy is evaluated again on every round
        entry = next(iter(rig.rows().entries.values()))
        assert entry.used == 0
        # One stale round and then success: the retry reuses the attempt.
        del rig.store.override["commit_restore"]
        seen: list[Any] = []

        async def record(commit: Any) -> None:
            seen.append(commit.attempt.attempt_id)

        def first(_commit: Any) -> Any:
            del rig.store.override["commit_restore"]
            return RestoreRejected(reason="stale")

        rig.store.before["commit_restore"] = record
        rig.store.override["commit_restore"] = first
        await rig.restore(captured)
        assert len(seen) == 2 and seen[0] == seen[1]

    run(scenario())


def test_an_unclassified_failure_at_commit_is_ambiguous_with_the_attempt_and_is_never_retried() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture(max_uses=2)
        for failure in (
            lambda: StoreError("STORE_AMBIGUOUS"),
            lambda: RuntimeError("synthetic driver failure"),
            lambda: asyncio.TimeoutError(),
        ):
            rig.store.fail["commit_restore"] = failure
            before = rig.store.count("commit_restore")
            with pytest.raises(VaultServerError) as error:
                await rig.restore(captured, attempt_id="attempt-synthetic-one")
            assert error.value.code == CODE.COMMIT_AMBIGUOUS and error.value.attempt_id == "attempt-synthetic-one"
            assert rig.store.count("commit_restore") == before + 1
        rig.store.fail["commit_restore"] = lambda: StoreError("STORE_UNAVAILABLE")
        with pytest.raises(VaultServerError) as error:
            await rig.restore(captured)
        assert error.value.code == CODE.STORE_UNAVAILABLE and error.value.attempt_id is None

    run(scenario())


def test_a_commit_that_outlives_the_store_deadline_is_ambiguous() -> None:
    async def scenario() -> None:
        rig = await make_rig(store_timeout_s=0.05)
        captured = await rig.capture()

        async def slow(_input: Any) -> None:
            await asyncio.sleep(1)

        rig.store.before["commit_restore"] = slow
        with pytest.raises(VaultServerError) as error:
            await rig.restore(captured, attempt_id="attempt-synthetic-slow")
        assert error.value.code == CODE.COMMIT_AMBIGUOUS and error.value.attempt_id == "attempt-synthetic-slow"

    run(scenario())


def test_store_read_failures_are_unavailable_and_a_lying_store_is_an_invariant_violation() -> None:
    async def scenario() -> None:
        from redact_secret_vault.persistent import ReadEntriesResult, RecoveryState

        rig = await make_rig()
        captured = await rig.capture()
        rig.store.fail["read_entries"] = lambda: StoreError("STORE_UNAVAILABLE")
        with raises(CODE.STORE_UNAVAILABLE):
            await rig.restore(captured)
        rig.store.fail["read_entries"] = lambda: StoreError("STORE_INVALID_ARGUMENT")
        with raises(CODE.INVARIANT_VIOLATION):
            await rig.restore(captured)
        rig.store.fail["read_entries"] = lambda: RuntimeError("synthetic")
        with raises(CODE.STORE_UNAVAILABLE):
            await rig.restore(captured)
        del rig.store.fail["read_entries"]

        def lie(mutate: Any) -> Any:
            def tamper(result: ReadEntriesResult, _input: Any) -> Any:
                return mutate(result)

            return tamper

        import dataclasses

        lies = {
            "none": lambda r: None,
            "foreign-entry": lambda r: dataclasses.replace(
                r, entries=r.entries + (dataclasses.replace(r.entries[0], entry_id="f" * 64),)
            ),
            "duplicate-entry": lambda r: dataclasses.replace(r, entries=r.entries + r.entries),
            "missing-capture": lambda r: dataclasses.replace(r, captures=()),
            "mismatched-capture": lambda r: dataclasses.replace(
                r, entries=(dataclasses.replace(r.entries[0], capture_id="cap_" + "z" * 26),)
            ),
            "float-revision": lambda r: dataclasses.replace(
                r, entries=(dataclasses.replace(r.entries[0], lifecycle_revision=1.0),)
            ),
            "negative-used": lambda r: dataclasses.replace(r, entries=(dataclasses.replace(r.entries[0], used=-1),)),
            "oversized-envelope": lambda r: dataclasses.replace(
                r, entries=(dataclasses.replace(r.entries[0], envelope=b"x" * (2 << 20)),)
            ),
            "wrong-epoch": lambda r: dataclasses.replace(r, captures=(dataclasses.replace(r.captures[0], epoch=9),)),
        }
        for name, mutate in lies.items():
            rig.store.tamper["read_entries"] = lie(mutate)
            with raises(CODE.INVARIANT_VIOLATION):
                await rig.restore(captured)
            assert rig.store.count("commit_restore") == 0, name
        rig.store.tamper["read_entries"] = lie(
            lambda r: dataclasses.replace(r, recovery=RecoveryState(epoch=1, state="quarantined"))
        )
        with raises(CODE.STORE_QUARANTINED):
            await rig.restore(captured)

    run(scenario())


# ------------------------------------------------------------------- attempts, lifecycle


def test_attempts_deduplicate_and_resolve_attempt_never_returns_fields() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture(max_uses=3)
        first = await rig.restore(captured, attempt_id="attempt-synthetic-one")
        assert first.attempt_id == "attempt-synthetic-one"
        with denied(DENIAL.ATTEMPT_ALREADY_COMMITTED):
            await rig.restore(captured, attempt_id="attempt-synthetic-one")
        with denied(DENIAL.ATTEMPT_MISMATCH):
            await rig.restore(captured, attempt_id="attempt-synthetic-one", purpose="purpose-synthetic-other")
        request = rig.restore_request(captured, attempt_id="attempt-synthetic-one")
        resolved = await rig.vault.resolve_attempt(request)
        assert resolved.state == "committed" and resolved.committed_at == START and not hasattr(resolved, "fields")
        different = rig.restore_request(captured, attempt_id="attempt-synthetic-one", purpose="purpose-synthetic-other")
        assert (await rig.vault.resolve_attempt(different)).state == "attempt-mismatch"
        absent = rig.restore_request(captured, attempt_id="attempt-synthetic-never")
        assert (await rig.vault.resolve_attempt(absent)).state == "absent"
        # Another principal of the same tenant under the same attempt identifier is a different request.
        other = rig.restore_request(
            captured, attempt_id="attempt-synthetic-one", context=ctx("principal-synthetic-0003")
        )
        assert (await rig.vault.resolve_attempt(other)).state == "attempt-mismatch"
        for patch in ({"attempt_id": None}, {"fields": {"body": "<rsv_ broken"}}, {"sink": ""}):
            with raises(CODE.INVALID_ARGUMENT):
                await rig.vault.resolve_attempt(
                    rig.restore_request(captured, **{"attempt_id": "attempt-synthetic-x", **patch})
                )

    run(scenario())


def test_a_lost_acknowledgement_is_resolved_through_the_receipt_and_the_use_is_spent() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture()
        calls = {"n": 0}

        def lose(result: Any, _input: Any) -> Any:
            calls["n"] += 1
            raise StoreError("STORE_AMBIGUOUS")

        rig.store.tamper["commit_restore"] = lose
        with pytest.raises(VaultServerError) as error:
            await rig.restore(captured, attempt_id="attempt-synthetic-lost")
        assert error.value.code == CODE.COMMIT_AMBIGUOUS
        del rig.store.tamper["commit_restore"]
        resolved = await rig.vault.resolve_attempt(rig.restore_request(captured, attempt_id="attempt-synthetic-lost"))
        assert resolved.state == "committed"
        with denied(DENIAL.BUDGET):  # a new attempt: the single use is spent
            await rig.restore(captured)

    run(scenario())


def test_revoke_and_delete_are_scoped_idempotent_and_state_that_no_key_was_retired() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture(f"{SECRET_A} {SECRET_B}")
        assert (
            await rig.vault.revoke(LifecycleRequest(context=CTX_B, capture_id=captured.capture_id))
        ).outcome == "not-found"
        assert (await rig.revoke(captured)).entries == 2
        assert (await rig.revoke(captured)).outcome == "already-revoked"
        with denied(DENIAL.REVOKED):
            await rig.restore(captured)
        deleted = await rig.vault.delete_capture_ciphertext(
            LifecycleRequest(context=CTX_A, capture_id=captured.capture_id)
        )
        assert deleted.outcome == "deleted" and deleted.entries == 2 and deleted.key_retired is False
        absent = await rig.vault.delete_capture_ciphertext(
            LifecycleRequest(context=CTX_A, capture_id="cap_" + "q" * 26)
        )
        assert absent.outcome == "not-found" and absent.key_retired is False
        assert [call.operation for call in rig.lifecycle_calls if call.operation != "capture"] == [
            "revoke",
            "revoke",
            "revoke",
            "delete-ciphertext",
            "delete-ciphertext",
        ]
        assert (
            rig.lifecycle_calls[-2].capture_id == captured.capture_id and rig.lifecycle_calls[-2].session_bound is False
        )

    run(scenario())


def test_a_session_bound_capture_is_managed_only_from_its_own_session() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        bound = await rig.capture(context=ctx(session="session-synthetic-one"))
        for context in (CTX_A, ctx(session="session-synthetic-two")):
            with raises(CODE.LIFECYCLE_DENIED):
                await rig.revoke(bound, context=context)
            with raises(CODE.LIFECYCLE_DENIED):
                await rig.vault.delete_capture_ciphertext(
                    LifecycleRequest(context=context, capture_id=bound.capture_id)
                )
        assert rig.store.count("revoke_capture") == 0
        assert (await rig.revoke(bound, context=ctx(session="session-synthetic-one"))).outcome == "revoked"
        assert rig.lifecycle_calls[-1].session_bound is True

    run(scenario())


def test_lifecycle_failures_are_classified_and_a_lifecycle_policy_denial_changes_nothing() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture()
        rig.lifecycle = lambda _i: LifecycleDecision(allow=False)
        with raises(CODE.LIFECYCLE_DENIED):
            await rig.revoke(captured)
        assert rig.store.count("revoke_capture") == 0
        rig.lifecycle = lambda _i: LifecycleDecision(allow=True)
        for operation, kind, code in (
            ("read_captures", lambda: StoreError("STORE_UNAVAILABLE"), CODE.STORE_UNAVAILABLE),
            ("read_captures", lambda: StoreError("STORE_INVALID_ARGUMENT"), CODE.INVARIANT_VIOLATION),
            ("revoke_capture", lambda: StoreError("STORE_AMBIGUOUS"), CODE.STORE_UNAVAILABLE),
        ):
            rig.store.fail[operation] = kind
            with raises(code):
                await rig.revoke(captured)
            del rig.store.fail[operation]
        rig.store.fail["delete_ciphertext"] = lambda: StoreError("STORE_UNAVAILABLE")
        with raises(CODE.STORE_UNAVAILABLE):
            await rig.vault.delete_capture_ciphertext(LifecycleRequest(context=CTX_A, capture_id=captured.capture_id))
        for bad in ("not-a-capture", None, 7):
            with raises(CODE.INVALID_ARGUMENT):
                await rig.vault.revoke(LifecycleRequest(context=CTX_A, capture_id=bad))  # type: ignore[arg-type]

    run(scenario())


# ----------------------------------------------------------- differences from the in-memory server


def test_differences_from_the_in_memory_server_table_of_specification_8_3() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture(max_uses=1)
        # Token of another tenant: its rows are not read, so the token is unknown (not tenant-mismatch).
        with denied(DENIAL.UNKNOWN_TOKEN):
            await rig.restore(captured, context=CTX_B)
        # Token of an exhausted entry: budget, until the row is swept (not unknown-token).
        await rig.restore(captured)
        with denied(DENIAL.BUDGET):
            await rig.restore(captured)
        # Token of a revoked capture after its ciphertext was deleted: unknown-token (not revoked).
        gone = await rig.capture(f"x {SECRET_B} y")
        await rig.revoke(gone)
        await rig.vault.delete_capture_ciphertext(LifecycleRequest(context=CTX_A, capture_id=gone.capture_id))
        with denied(DENIAL.UNKNOWN_TOKEN):
            await rig.restore(gone)
        # Wrong or missing session for a session-bound capture: source, from the tag, before any key is unwrapped.
        unwraps = rig.provider.calls["unwrap"]
        bound = await rig.capture(context=ctx(session="session-synthetic-one"))
        with denied(DENIAL.SOURCE):
            await rig.restore(bound, context=ctx(session="session-synthetic-two"))
        assert rig.provider.calls["unwrap"] == unwraps
        assert (await rig.restore(bound, context=ctx(session="session-synthetic-one"))).restored == 1
        # Captures named by one restore: up to the store's maxRestoreCaptures, at most 64.
        assert rig.store.capabilities().max_restore_captures <= 64
        with raises(CODE.INVALID_ARGUMENT):
            await rig.restore(captured, captures=tuple("cap_" + "a" * 25 + chr(97 + n % 26) for n in range(65)))
        # An explicit tenant or session on a restore is ignored: it has no effect.
        again = await rig.capture()
        in_memory_style = RestoreRequest(
            sink=SINK,
            captures=(again.capture_id,),
            fields={"body": again.text},
            purpose=PURPOSE,
            tenant=OTHER_TENANT,
            session_id="session-synthetic-forged",
            context=CTX_A,
        )
        assert (await rig.vault.restore(in_memory_style)).tenant == TENANT  # type: ignore[arg-type]
        # An identifier with a lone surrogate: an argument error at capture, the denial invalid-request in a path.
        with raises(CODE.INVALID_ARGUMENT):
            await rig.capture(release=(CaptureGrant(sink="s\ud800", paths=("body",)),))
        with denied(DENIAL.INVALID_REQUEST):
            await rig.restore(again, fields={"p\ud800": "x"})
        # Capture requires a principal.
        with raises(CODE.LIFECYCLE_DENIED):
            await rig.capture(context={"principal": "principal-unknown"})

    run(scenario())


def test_the_new_error_codes_and_denial_reasons_exist_only_in_the_persistent_vocabulary() -> None:
    assert {c.value for c in VaultServerErrorCode} >= {
        "UNSUPPORTED_STORE",
        "STORE_UNAVAILABLE",
        "STORE_QUARANTINED",
        "COMMIT_AMBIGUOUS",
        "RESTORE_CONFLICT",
        "CLOCK_SKEW",
        "LIFECYCLE_DENIED",
        "KEY_UNAVAILABLE",
        "CLOSED",
    }
    assert {r.value for r in ServerDenialReason} >= {
        "integrity-failure",
        "key-unavailable",
        "attempt-mismatch",
        "attempt-already-committed",
    }
    assert {o.value for o in ServerAuditOperation} >= {"capture", "delete-ciphertext", "resolve-attempt"}


# ---------------------------------------------------------------------------------- clocks


def test_the_record_clock_is_validated_floored_and_never_decreases() -> None:
    async def scenario() -> None:
        for bad in (True, math.nan, math.inf, -1, 2**53, "now", None):
            rig = await make_rig(now=lambda bad=bad: bad)
            with raises(CODE.INVALID_ARGUMENT):
                await rig.capture()

        def broken() -> int:
            raise RuntimeError("synthetic clock failure")

        rig = await make_rig(now=broken)
        with raises(CODE.INVALID_ARGUMENT):
            await rig.capture()
        # A float is floored; a reading that goes backwards does not move the server's time backwards.
        readings = iter([1_790_000_000_000.9, 1_790_000_005_000, 1_789_999_990_000, 1_790_000_005_000])
        floor = await make_rig(
            now=lambda: next(readings, 1_790_000_005_000), memory_options={"max_clock_skew_ms": 60_000}
        )
        floor.clock.ms = 1_790_000_000_000
        first = await floor.capture()
        assert first.expires_at == 1_790_000_000_000 + 10 * 60 * 1000
        second = await floor.capture()
        third = await floor.capture()  # the reading went back, the server's time did not
        assert third.expires_at >= second.expires_at

    run(scenario())


def test_the_default_clock_is_wall_time_in_milliseconds() -> None:
    async def scenario() -> None:
        rig = await make_rig(now=None)
        # The store has its own manual clock; skew bounds it. Wall time is far from START, so the store refuses.
        with raises(CODE.CLOCK_SKEW):
            await rig.capture()
        wall = await make_rig(now=None, memory_options={"now": lambda: time.time_ns() // 1_000_000})
        captured = await wall.capture()
        assert abs(captured.expires_at - 10 * 60 * 1000 - time.time_ns() // 1_000_000) < 5000

    run(scenario())


def test_deadlines_do_not_depend_on_the_record_clock() -> None:
    async def scenario() -> None:
        rig = await make_rig(policy_timeout_s=0.05)
        captured = await rig.capture()

        async def slow(_input: Any) -> PolicyDecision:
            await asyncio.sleep(1)
            return PolicyDecision(allow=True)

        rig.policy = slow
        started = time.monotonic()
        with denied(DENIAL.POLICY_EVALUATION_ERROR):
            await rig.restore(captured)
        assert time.monotonic() - started < 0.9  # a frozen record clock does not stop a deadline

    run(scenario())


def test_the_store_clock_judges_expiry_and_a_skewed_server_fails_closed() -> None:
    async def scenario() -> None:
        store_clock = Clock()
        rig = await make_rig(clock=store_clock)
        captured = await rig.capture()
        # The server's clock is moved past the skew bound away from the store's: the commit fails closed.
        skewed = await create_persistent_server_vault(**{**rig.options, "now": lambda: store_clock.ms + 10_000})
        with pytest.raises(VaultServerError) as error:
            await skewed.restore(rig.restore_request(captured))
        assert error.value.code == CODE.CLOCK_SKEW
        with raises(CODE.CLOCK_SKEW):
            await skewed.capture(f"{SECRET_A}", PersistentCaptureOptions(context=CTX_A, release=RELEASE))  # type: ignore[arg-type]

    run(scenario())


# ---------------------------------------------------------------- the language-neutral schedules


def test_the_server_level_schedules_pass_with_the_reference_store_and_the_crypto_layer() -> None:
    from schedule_support import have_orchestrator, load_corpus, run_schedules

    if not have_orchestrator():
        pytest.skip("needs node and the repository's conformance directory")
    report = run_schedules(level="server")
    server_cases = [case for case in load_corpus()["cases"] if case["level"] == "server"]
    by_id = {result["id"]: result for result in report["results"]}
    assert set(by_id) == {case["id"] for case in server_cases} and len(server_cases) >= 10
    failed = [f"{result['id']}: {result.get('detail')}" for result in by_id.values() if result["status"] != "passed"]
    assert failed == [], "every server-level schedule must pass: none may fail or be skipped"
    print(f"server-level schedules: {len(server_cases)} passed, 0 skipped")


# ----------------------------------------------------------------------- audit and sharing


def test_audit_events_cover_capture_ciphertext_deletion_and_attempt_resolution() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        captured = await rig.capture(f"{SECRET_A} {SECRET_B}", request_id="request-synthetic-1")
        capture_event = rig.audits[-1]
        assert capture_event.operation == ServerAuditOperation.CAPTURE and capture_event.outcome == "committed"
        assert capture_event.entries == 2 and capture_event.capture_id == captured.capture_id
        assert capture_event.principal_id == "principal-synthetic-0001" and capture_event.tenant == TENANT
        assert capture_event.request_id == "request-synthetic-1"
        restored = await rig.restore(captured, fields={"body": captured.tokens[0].token})
        restore_event = rig.audits[-1]
        assert restore_event.operation == ServerAuditOperation.RESTORE and restore_event.outcome == "committed"
        assert restore_event.attempt_id == restored.attempt_id and restore_event.entries == 1
        await rig.vault.resolve_attempt(
            rig.restore_request(captured, fields={"body": captured.tokens[0].token}, attempt_id=restored.attempt_id)
        )
        assert (
            rig.audits[-1].operation == ServerAuditOperation.RESOLVE_ATTEMPT and rig.audits[-1].outcome == "committed"
        )
        assert rig.audits[-1].attempt_id == restored.attempt_id
        await rig.vault.delete_capture_ciphertext(LifecycleRequest(context=CTX_A, capture_id=captured.capture_id))
        deleted = rig.audits[-1]
        assert deleted.operation == ServerAuditOperation.DELETE_CIPHERTEXT and deleted.entries == 2
        assert deleted.capture_id == captured.capture_id
        rig.lifecycle = lambda _i: LifecycleDecision(allow=False)
        with raises(CODE.LIFECYCLE_DENIED):
            await rig.capture()
        assert rig.audits[-1].outcome == "denied" and rig.audits[-1].code == "LIFECYCLE_DENIED"

        rig.lifecycle = lambda _i: LifecycleDecision(allow=True)

        # An audit hook that raises, or returns an awaitable that fails, never changes an operation's outcome.
        def boom(_event: Any) -> None:
            raise RuntimeError("synthetic hook failure")

        async def failing(_event: Any) -> None:
            raise RuntimeError("synthetic async hook failure")

        for hook in (boom, failing):
            noisy = await create_persistent_server_vault(**{**rig.options, "on_audit": hook})
            result = await noisy.capture(f"x {SECRET_C} y", PersistentCaptureOptions(context=CTX_A, release=RELEASE))
            assert len(result.tokens) == 1
        await asyncio.sleep(0)

    run(scenario())


def test_the_persistent_server_and_the_in_memory_server_share_one_capture_plan() -> None:
    from redact_secret_vault import capture_plan, server
    from redact_secret_vault.persistent import server as persistent_server

    assert server.plan_capture is capture_plan.plan_capture
    assert persistent_server.plan_capture is capture_plan.plan_capture
