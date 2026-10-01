"""Test-only: the server level of the schedule driver (docs/plans/python-persistence-parity.md section 6.3).

A persistent server over the reference store, the local key provider (public test constants, never a real key), the
Node.js core bridge, and fixed synthetic resolvers and allow-all policies. Nothing here is in the wheel. The fixed
identities and the fault names are those of ``conformance/persistent/v1/SCHEDULES.md``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from schedule_store import ScheduleStore

from redact_secret_vault import CaptureGrant, NodeCoreBridge, PolicyDecision, Principal, VaultServerError
from redact_secret_vault.crypto import LocalKey, LocalKeyScope, create_local_key_provider, create_record_crypto
from redact_secret_vault.persistent import (
    LifecycleDecision,
    LifecycleRequest,
    PersistentCaptureOptions,
    PersistentRestoreRequest,
    PersistentServerVault,
    StoreError,
    create_persistent_server_vault,
)

#: Public test constants, as in conformance/persistent/v1/vectors.json. Never a real key.
KEY_MATERIAL = bytes(0x80 + index for index in range(32))
DIGEST_KEY = bytes(0x40 + index for index in range(32))

#: The fixed synthetic identities of the server-level cases. Anything else is not authenticated.
PRINCIPALS = {
    "principal-a1": Principal(id="principal-a1", tenant="tenant-acme-synthetic"),
    "principal-a2": Principal(id="principal-a2", tenant="tenant-acme-synthetic"),
    "principal-b1": Principal(id="principal-b1", tenant="tenant-globex-synthetic"),
}

#: fault name -> (the call fails with, whether the store applies the call first)
FAULT_KINDS = {
    "unavailable": ("STORE_UNAVAILABLE", False),
    "before-first-write": ("STORE_UNAVAILABLE", False),
    "drop-connection": ("STORE_AMBIGUOUS", False),
    "after-commit-before-ack": ("STORE_AMBIGUOUS", True),
}

SERVER_OPERATIONS = frozenset({"capture", "restore", "revoke", "deleteCaptureCiphertext", "resolveAttempt"})


class FaultStore:
    """A ``Store`` that fails the next call of one operation in a named way, then behaves."""

    def __init__(self, inner: ScheduleStore) -> None:
        self._inner = inner
        self._armed: dict[str, str] = {}

    def arm(self, operation: str, kind: str) -> None:
        self._armed[operation] = kind

    def capabilities(self) -> Any:
        return self._inner.capabilities()

    def __getattr__(self, name: str) -> Any:
        target = getattr(self._inner, name)

        async def call(*args: Any, **kwargs: Any) -> Any:
            kind = self._armed.pop(name, None)
            if kind is None:
                return await target(*args, **kwargs)
            code, applied = FAULT_KINDS[kind]
            if applied:
                await target(*args, **kwargs)
            raise StoreError(code)  # type: ignore[arg-type]

        return call


class _Clock:
    def __init__(self, start: int) -> None:
        self.ms = start

    def now(self) -> int:
        return self.ms


@dataclass(slots=True)
class ServerRig:
    vault: PersistentServerVault
    store: FaultStore
    clock: _Clock


def _resolve_principal(context: Any) -> Principal:
    principal = PRINCIPALS.get(context.get("principal") if isinstance(context, dict) else None)
    if principal is None:
        raise PermissionError("unauthenticated")
    return principal


def _resolve_session(context: Any) -> str | None:
    return context.get("session") if isinstance(context, dict) else None


async def open_server(
    namespace: str, *, clock_start: int, core: Any | None = None, backend: str = "memory"
) -> ServerRig:
    clock: Any
    if backend == "postgres":
        # The server over the PostgreSQL adapter: the store reads its clock from a row this driver moves, and the
        # server's own clock is the same one.
        import pg_support

        clock = pg_support.DbClock(start=clock_start)
        inner: Any = await pg_support.open_store(pg_support.HookedPool(), clock=clock)
    else:
        clock = _Clock(clock_start)
        inner = ScheduleStore(now=clock.now)
    await inner.initialize_namespace(namespace, 1)
    store = FaultStore(inner)
    crypto = create_record_crypto(
        key_provider=create_local_key_provider(
            keys=(LocalKey(id="synthetic-2026-10", material=KEY_MATERIAL, state="active"),),
            scope=LocalKeyScope(namespaces=(namespace,)),
        )
    )
    # PII detection off: the core's own activation identity is observed once and then required of every scan.
    bridge = core if core is not None else NodeCoreBridge(pii=())
    probe_limits = {"maxInputBytes": 1 << 20, "maxFindings": 1024}
    activation = (await asyncio.to_thread(bridge.scan, "", policy=None, limits=probe_limits)).pii_activation
    vault = await create_persistent_server_vault(
        namespace=namespace,
        recovery_epoch=1,
        store=store,  # type: ignore[arg-type]
        crypto=crypto,
        core_client=bridge,
        expected_pii_activation=activation or "",
        digest_key=DIGEST_KEY,
        resolve_principal=_resolve_principal,
        resolve_session=_resolve_session,
        policy=lambda _decision: PolicyDecision(allow=True),
        lifecycle_policy=lambda _input: LifecycleDecision(allow=True),
        now=clock.now,
        allow_non_durable_store=True,
    )
    return ServerRig(vault=vault, store=store, clock=clock)


def _restore_request(data: dict[str, Any]) -> PersistentRestoreRequest:
    return PersistentRestoreRequest(
        context=data["context"],
        sink=data["sink"],
        purpose=data["purpose"],
        captures=tuple(data["captures"]),
        fields=data["fields"],
        attempt_id=data.get("attemptId"),
    )


async def server_call(
    rig: ServerRig, message: dict[str, Any], snake: dict[str, str], encode: Callable[[Any], Any]
) -> dict[str, Any]:
    """One server operation. ``snake`` maps a wire store-operation name to its method name, for the fault."""

    data = message.get("input") or {}
    fault = message.get("fault")
    if fault is not None:
        if fault.get("kind") not in FAULT_KINDS or fault.get("operation") not in snake:
            return {"error": "UNSUPPORTED_FAULT"}
        rig.store.arm(snake[fault["operation"]], fault["kind"])
    failure: tuple[str, dict[str, str]] | None = None
    result: Any = None
    try:
        operation = message["op"]
        if operation == "capture":
            result = await rig.vault.capture(
                data["text"],
                PersistentCaptureOptions(
                    context=data["context"],
                    release=tuple(CaptureGrant(sink=g["sink"], paths=tuple(g["paths"])) for g in data["release"]),
                    **({"max_uses": data["maxUses"]} if "maxUses" in data else {}),
                ),
            )
        elif operation == "restore":
            result = await rig.vault.restore(_restore_request(data))
        elif operation == "revoke":
            result = await rig.vault.revoke(LifecycleRequest(context=data["context"], capture_id=data["captureId"]))
        elif operation == "deleteCaptureCiphertext":
            result = await rig.vault.delete_capture_ciphertext(
                LifecycleRequest(context=data["context"], capture_id=data["captureId"])
            )
        elif operation == "resolveAttempt":
            result = await rig.vault.resolve_attempt(_restore_request(data))
        else:
            return {"error": "UNSUPPORTED_OPERATION"}
    except VaultServerError as error:
        detail: dict[str, str] = {}
        if error.reason is not None:
            detail["reason"] = error.reason.value
        if error.attempt_id is not None:
            detail["attemptId"] = error.attempt_id
        failure = (error.code.value, detail)
    except Exception:  # noqa: BLE001 - a foreign failure is reported by shape only
        failure = ("INTERNAL", {})
    if failure is not None:
        return {"error": failure[0], "detail": failure[1]}
    return {"result": encode(result)}
