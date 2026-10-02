"""Test-only support for the persistent server profile tests. Nothing here is in the wheel.

Everything is synthetic: no value here is, or resembles closely enough to be mistaken for, a real credential or key.

* ``FakeCore``: a ``CoreClient`` that reports each synthetic secret as a ``redact`` finding, so most tests need no
  Node.js process. The corpus parity and the schedule runs use the real bridge.
* ``SpyStore`` wraps the reference store: it counts calls, runs a hook before one, rewrites a result, or raises.
* ``make_rig`` builds a server over them, a local key provider (public test constants), and fixed resolvers.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from schedule_store import ScheduleStore

from redact_secret_vault import CaptureGrant, PolicyDecision, Principal
from redact_secret_vault.core_client import CoreFinding, CoreScanOutcome
from redact_secret_vault.crypto import LocalKey, LocalKeyScope, create_local_key_provider, create_record_crypto
from redact_secret_vault.persistent import (
    LifecycleDecision,
    LifecycleRequest,
    PersistentCaptureOptions,
    PersistentRestoreRequest,
    PersistentServerVault,
    create_persistent_server_vault,
)
from redact_secret_vault.utf16 import utf16_length

NAMESPACE = "support-synthetic"
TENANT = "tenant-acme-synthetic"
OTHER_TENANT = "tenant-globex-synthetic"
SECRET_A = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000"
SECRET_B = "ghp_SYNTHETICxREVOKEDxTESTx1111111111111"
SECRET_C = "ghp_SYNTHETICxREVOKEDxTESTx2222222222222"
SECRETS = (SECRET_A, SECRET_B, SECRET_C)
PURPOSE = "purpose-synthetic-support-reply"
SINK = "sink-a"
RELEASE = (CaptureGrant(sink=SINK, paths=("body", "subject")),)
FORGED_TOKEN = "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>"
ACTIVATION = "credentials=full;selectors=off;families=;vocabulary=pii-context/v2"
#: Public test constants, as in conformance/persistent/v1/vectors.json. Never a real key.
KEY_MATERIAL = bytes(0x80 + index for index in range(32))
DIGEST_KEY = bytes(0x40 + index for index in range(32))
START = 1_790_000_000_000

PRINCIPALS = {
    "principal-synthetic-0001": Principal(id="principal-synthetic-0001", tenant=TENANT),
    "principal-synthetic-0002": Principal(id="principal-synthetic-0002", tenant=OTHER_TENANT),
    "principal-synthetic-0003": Principal(id="principal-synthetic-0003", tenant=TENANT),
}


def ctx(principal: str = "principal-synthetic-0001", session: str | None = None) -> dict[str, str]:
    context = {"principal": principal}
    if session is not None:
        context["session"] = session
    return context


CTX_A = ctx()
CTX_B = ctx("principal-synthetic-0002")


class FakeCore:
    """Reports each synthetic secret in the input as one ``redact`` finding of type ``github_token``."""

    def __init__(self, activation: str | None = ACTIVATION, *, fail: BaseException | None = None) -> None:
        self.activation = activation
        self.fail = fail
        self.scans = 0

    def scan(self, text: str, *, policy: Any = None, limits: Any = None) -> CoreScanOutcome:
        self.scans += 1
        if self.fail is not None:
            raise self.fail
        spans: list[tuple[int, int]] = []
        for secret in SECRETS:
            start = text.find(secret)
            while start != -1:
                spans.append((start, start + len(secret)))
                start = text.find(secret, start + len(secret))
        spans.sort()
        findings = []
        for index, (start, end) in enumerate(spans):
            action = "redact"
            if isinstance(policy, dict):
                action = policy.get("github_token", policy.get("default", "redact"))
            findings.append(
                CoreFinding(
                    id=f"f{index}",
                    type="github_token",
                    detector="synthetic",
                    confidence="high",
                    obfuscation="none",
                    start=utf16_length(text[:start]),
                    end=utf16_length(text[:end]),
                    action=action,
                )
            )
        return CoreScanOutcome(
            findings=tuple(findings), core_version="fake", artifact="fake", pii_activation=self.activation
        )


class SpyStore:
    """The server-facing store: records every call; a test can run something first, rewrite a result, or fail it."""

    OPERATIONS = (
        "create_capture",
        "read_entries",
        "read_captures",
        "commit_restore",
        "revoke_capture",
        "inspect_attempt",
        "replace_capture_key",
        "delete_ciphertext",
        "sweep_expired",
        "recovery_state",
        "initialize_namespace",
        "quarantine",
        "invalidate_recovered",
    )

    def __init__(self, inner: ScheduleStore) -> None:
        self.inner = inner
        self.calls: list[tuple[str, Any]] = []
        self.before: dict[str, Callable[[Any], Awaitable[None]]] = {}
        self.tamper: dict[str, Callable[[Any, Any], Any]] = {}
        self.fail: dict[str, Callable[[], BaseException]] = {}
        #: Answers a call without reaching the store: nothing is applied.
        self.override: dict[str, Callable[[Any], Any]] = {}
        self.capabilities_override: Any = None

    def capabilities(self) -> Any:
        return self.capabilities_override if self.capabilities_override is not None else self.inner.capabilities()

    def count(self, operation: str) -> int:
        return sum(1 for name, _input in self.calls if name == operation)

    def mutations(self) -> int:
        mutating = {"create_capture", "commit_restore", "revoke_capture", "replace_capture_key", "delete_ciphertext"}
        return sum(1 for name, _input in self.calls if name in mutating)

    def __getattr__(self, name: str) -> Any:
        if name not in self.OPERATIONS:
            raise AttributeError(name)
        target = getattr(self.inner, name)

        async def call(*args: Any) -> Any:
            self.calls.append((name, args[0] if args else None))
            if name in self.before:
                await self.before[name](args[0] if args else None)
            if name in self.fail:
                raise self.fail[name]()
            if name in self.override:
                return self.override[name](args[0] if args else None)
            result = await target(*args)
            if name in self.tamper:
                result = self.tamper[name](result, args[0] if args else None)
            return result

        return call


class Clock:
    def __init__(self, start: int = START) -> None:
        self.ms = start

    def now(self) -> int:
        return self.ms

    def advance(self, ms: int) -> int:
        self.ms += ms
        return self.ms


@dataclass
class Rig:
    vault: PersistentServerVault
    store: SpyStore
    memory: ScheduleStore
    clock: Clock
    core: FakeCore
    crypto: Any
    provider: Any
    audits: list[Any] = field(default_factory=list)
    policy_calls: list[Any] = field(default_factory=list)
    lifecycle_calls: list[Any] = field(default_factory=list)
    policy: Callable[[Any], Any] = lambda _input: PolicyDecision(allow=True)  # noqa: E731
    lifecycle: Callable[[Any], Any] = lambda _input: LifecycleDecision(allow=True)  # noqa: E731
    options: dict[str, Any] = field(default_factory=dict)

    async def capture(self, text: str | None = None, **options: Any) -> Any:
        options.setdefault("context", CTX_A)
        options.setdefault("release", RELEASE)
        return await self.vault.capture(
            f"secret {SECRET_A} here" if text is None else text, PersistentCaptureOptions(**options)
        )

    def restore_request(self, captured: Any, **extra: Any) -> PersistentRestoreRequest:
        base: dict[str, Any] = {
            "context": CTX_A,
            "sink": SINK,
            "purpose": PURPOSE,
            "captures": (captured.capture_id,),
            "fields": {"body": captured.text},
        }
        base.update(extra)
        return PersistentRestoreRequest(**base)

    async def restore(self, captured: Any, **extra: Any) -> Any:
        return await self.vault.restore(self.restore_request(captured, **extra))

    async def revoke(self, captured: Any, **extra: Any) -> Any:
        return await self.vault.revoke(
            LifecycleRequest(context=extra.pop("context", CTX_A), capture_id=captured.capture_id)
        )

    def rows(self, tenant: str = TENANT) -> Any:
        namespace = self.memory._namespaces.get(NAMESPACE)
        return None if namespace is None else namespace.tenants.get(tenant)


class RecordingProvider:
    """Counts the local key provider's calls and can be made to fail."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.profile = inner.profile
        self.calls = {"generate": 0, "unwrap": 0, "rewrap": 0}
        self.fail: dict[str, Callable[[], BaseException]] = {}
        self.delay: dict[str, float] = {}

    async def generate_data_key(self, context: Any) -> Any:
        self.calls["generate"] += 1
        await self._maybe("generate")
        return await self.inner.generate_data_key(context)

    async def unwrap_data_key(self, stored: Any, context: Any) -> Any:
        self.calls["unwrap"] += 1
        await self._maybe("unwrap")
        return await self.inner.unwrap_data_key(stored, context)

    async def rewrap_data_key(self, stored: Any, context: Any) -> Any:
        self.calls["rewrap"] += 1
        return await self.inner.rewrap_data_key(stored, context)

    async def _maybe(self, name: str) -> None:
        if name in self.delay:
            await asyncio.sleep(self.delay[name])
        if name in self.fail:
            raise self.fail[name]()


def resolve_principal(context: Any) -> Principal:
    principal = PRINCIPALS.get(context.get("principal") if isinstance(context, dict) else None)
    if principal is None:
        raise PermissionError("unauthenticated")
    return principal


async def make_rig(
    *,
    clock: Clock | None = None,
    core: FakeCore | None = None,
    open_server: bool = True,
    initialize: bool = True,
    epoch: int = 1,
    memory_options: dict[str, Any] | None = None,
    **server_options: Any,
) -> Rig:
    clock = clock or Clock()
    memory = ScheduleStore(**{"now": clock.now, **(memory_options or {})})
    if initialize:
        assert (await memory.initialize_namespace(NAMESPACE, epoch)).outcome == "initialized"
    store = SpyStore(memory)
    provider = RecordingProvider(
        create_local_key_provider(
            keys=(LocalKey(id="synthetic-2026-10", material=KEY_MATERIAL, state="active"),),
            scope=LocalKeyScope(namespaces=(NAMESPACE,)),
        )
    )
    crypto = create_record_crypto(key_provider=provider)  # type: ignore[arg-type]
    core = core or FakeCore()
    rig = Rig(vault=None, store=store, memory=memory, clock=clock, core=core, crypto=crypto, provider=provider)  # type: ignore[arg-type]

    def policy(decision: Any) -> Any:
        rig.policy_calls.append(decision)
        return rig.policy(decision)

    def lifecycle(decision: Any) -> Any:
        rig.lifecycle_calls.append(decision)
        return rig.lifecycle(decision)

    options: dict[str, Any] = {
        "namespace": NAMESPACE,
        "recovery_epoch": epoch,
        "store": store,
        "crypto": crypto,
        "core_client": core,
        "expected_pii_activation": ACTIVATION,
        "digest_key": DIGEST_KEY,
        "resolve_principal": resolve_principal,
        "resolve_session": lambda context: context.get("session"),
        "policy": policy,
        "lifecycle_policy": lifecycle,
        "on_audit": rig.audits.append,
        "now": clock.now,
        "allow_non_durable_store": True,
    }
    options.update(server_options)
    rig.options = options
    if open_server:
        rig.vault = await create_persistent_server_vault(**options)
    return rig
