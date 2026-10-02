"""The persistent server profile (docs/specs/persistent-vault.md section 8).

``create_persistent_server_vault`` opens a server over an injected ``Store``, a ``RecordCrypto``, a digest key,
principal and session resolvers, a restore policy, and a lifecycle policy. Tenant and session come only from the
resolvers. The server keeps no lock of its own: every instance, in this process or another, may run operations
concurrently, and the store's transactions are the only thing that orders them (spec sections 5.2 and 7.1).

**Python persistence is not implemented and not supported.** This module is the Python counterpart of
``@redact-secret/vault-server/persistent``, run so far only against the reference store and the language-neutral
schedules. Nothing here qualifies a durable backend, the Node.js bridge it captures through, or a deployment.

Rules this module follows (docs/plans/python-persistence-parity.md):

* **Async only** (section 3.7). Every operation is a coroutine. They are ``def`` methods that return the coroutine of
  the private ``_entry`` wrapper, so the traceback of an error a caller receives starts in that wrapper's frame and no
  public frame holding a request survives.
* **Cancellation** (section 3.7). ``store.commit_restore`` and ``store.create_capture`` run in an inner task under
  ``asyncio.shield`` with the store timeout. When the caller's task is cancelled the server discards the staged output,
  overwrites its buffers, lets the inner task finish under its own timeout, and re-raises ``CancelledError``. No field
  is returned. The attempt is resolved later with ``resolve_attempt``, exactly as after ``COMMIT_AMBIGUOUS``.
  ``CancelledError``, ``KeyboardInterrupt``, and ``SystemExit`` are never converted and never swallowed.
* **Clocks** (section 3.8). Record time is wall time, ``time.time_ns() // 1_000_000`` by default or the application's
  ``now``, floored and made non-decreasing within the instance. Deadlines are timeouts of the event loop and never
  compared with a record timestamp.
* **No chained errors** (section 3.4). Every ``VaultServerError`` is built after the ``except`` block that classified
  the failure has ended, so neither ``__cause__`` nor ``__context__`` is set, and the entry wrapper drops its arguments
  before raising.
* **Buffers** (section 3.6). Values are held in ``bytearray`` and overwritten on every path. Python cannot clear
  ``bytes`` or ``str``: a value that is returned is a ``str``, and the slice it came from was one.
"""

from __future__ import annotations

import asyncio
import hmac
import inspect
import math
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Literal

from ..capture_plan import CapturePlan, plan_capture, resolve_capture_limits
from ..core_client import CoreClient
from ..errors import ServerDenialReason, VaultServerError, VaultServerErrorCode
from ..pii import resolve_expected_pii_activation
from ..token import TOKEN_PATTERN, count_markers, new_capture_id
from ..types import (
    CaptureGrant,
    IssuedToken,
    PiiRetention,
    PolicyDecision,
    Principal,
    RestoreDecisionInput,
    RestoreSource,
    ServerAuditEvent,
    ServerAuditHook,
    ServerAuditOperation,
    ServerReleasePolicy,
)
from . import _buffers
from . import limits as _limits
from .contracts import (
    Attempt,
    CaptureGeneration,
    CommitRestoreInput,
    CreateCaptureInput,
    DeleteCiphertextInput,
    EntryUse,
    Grant,
    InspectAttemptInput,
    KeyContext,
    NewCapture,
    NewEntry,
    ReadCapturesInput,
    ReadEntriesInput,
    ReadEntriesResult,
    RecordBinding,
    RecordCrypto,
    RecordPayload,
    RevokeCaptureInput,
    SealedCapture,
    Store,
    StoreCapabilities,
    StoredCapture,
    StoredEntry,
    StoredKey,
    StoreScope,
)
from .derive import derive_entry_id
from .digest import Digester, RequestDigestInput, RequestPath, RequestUse, SessionTagInput, create_digester
from .errors import KeyProviderError, RecordCryptoError, StoreError
from .validate import (
    is_attempt_id,
    is_capture_id,
    is_entry_id,
    is_identifier,
    is_key_ref,
    is_namespace,
    is_session_tag,
    is_timestamp,
    is_well_formed,
    missing_capabilities,
)

__all__ = [
    "DeleteCiphertextResult",
    "LifecycleDecision",
    "LifecycleDecisionInput",
    "LifecycleOperation",
    "LifecyclePolicy",
    "LifecycleRequest",
    "PersistentCaptureOptions",
    "PersistentCaptureResult",
    "PersistentRestoreRequest",
    "PersistentRestoreResult",
    "PersistentServerVault",
    "ResolveAttemptRequest",
    "ResolveAttemptResult",
    "RevokeResult",
    "SessionResolver",
    "create_persistent_server_vault",
]

_DEFAULT_CALLBACK_TIMEOUT_S: Final = 5.0
_DEFAULT_STORE_TIMEOUT_S: Final = 10.0
_DEFAULT_CRYPTO_TIMEOUT_S: Final = 15.0
_DEFAULT_COMMIT_RETRIES: Final = 3
_MAX_COMMIT_RETRIES: Final = 10
_DEFAULT_RECEIPT_GRACE_MS: Final = 60 * 60 * 1000
_DEFAULT_TOMBSTONE_RETENTION_MS: Final = 24 * 60 * 60 * 1000
_MAX_TIMEOUT_S: Final = 10 * 60.0

#: Reasons a ``ServerReleasePolicy`` may return; anything else is ``policy-evaluation-error``.
_POLICY_DENIAL_REASONS: Final = frozenset(
    {
        "invalid-request",
        "malformed-token",
        "unknown-token",
        "source",
        "expired",
        "sink-or-path",
        "budget",
        "policy",
        "unauthenticated",
        "tenant-mismatch",
        "missing-purpose",
        "revoked",
        "stale-policy",
        "rate-limited",
        "policy-evaluation-error",
    }
)

LifecycleOperation = Literal["capture", "revoke", "delete-ciphertext", "resolve-attempt"]

SessionResolver = Callable[[Any], "str | None | Awaitable[str | None]"]
"""Resolves the session a request belongs to from the same trusted context the principal resolver receives. ``None``
means no session: a capture made from such a context is not session-bound and can be restored from any session of its
tenant. A session identifier is an identifier, not a credential. A raise or a timeout denies."""


@dataclass(frozen=True, slots=True)
class LifecycleDecisionInput:
    operation: LifecycleOperation
    principal: Principal
    tenant: str
    session_id: str | None
    #: Absent for ``capture`` and ``resolve-attempt``.
    capture_id: str | None = None
    #: Of the capture, for ``revoke`` and ``delete-ciphertext``, when the capture exists.
    session_bound: bool | None = None
    #: For ``capture``: values about to be retained.
    entries: int | None = None
    #: For ``capture``: their total UTF-8 size.
    bytes: int | None = None
    requested_at: int = 0


@dataclass(frozen=True, slots=True)
class LifecycleDecision:
    allow: bool


LifecyclePolicy = Callable[[LifecycleDecisionInput], "LifecycleDecision | Awaitable[LifecycleDecision]"]
"""Asked once per ``capture``, ``revoke``, ``delete_capture_ciphertext``, and ``resolve_attempt``. Only
``LifecycleDecision(allow=True)`` allows. A raise, a timeout, or any other return value fails the operation
``LIFECYCLE_DENIED`` before any store mutation."""


@dataclass(frozen=True, slots=True)
class PersistentCaptureOptions:
    #: Passed verbatim to the resolvers. The capture's tenant and session come only from them.
    context: Any
    release: tuple[CaptureGrant, ...]
    max_uses: int = 1
    unredacted: str = "reject"
    policy: Mapping[str, str] | None = None
    eligible: Callable[[Mapping[str, Any]], bool] | None = None
    pii: PiiRetention | None = None
    #: Caller or transport correlation id, mirrored onto audit events.
    request_id: str | None = None


@dataclass(frozen=True, slots=True)
class PersistentCaptureResult:
    capture_id: str
    text: str
    tokens: tuple[IssuedToken, ...]
    passed_through: int
    passed_through_types: tuple[str, ...]
    unrestorable: int
    expires_at: int
    tenant: str
    session_bound: bool


@dataclass(frozen=True, slots=True)
class PersistentRestoreRequest:
    context: Any
    sink: str
    purpose: str
    captures: tuple[str, ...]
    fields: Mapping[str, str]
    #: Identifies this attempt for deduplication and for ``resolve_attempt``. Generated when omitted.
    attempt_id: str | None = None
    request_id: str | None = None


@dataclass(frozen=True, slots=True)
class PersistentRestoreResult:
    fields: Mapping[str, str]
    restored: int
    principal_id: str
    tenant: str
    #: ``None`` when the request held no token: nothing was committed.
    attempt_id: str | None = None


@dataclass(frozen=True, slots=True)
class LifecycleRequest:
    context: Any
    capture_id: str
    request_id: str | None = None


@dataclass(frozen=True, slots=True)
class RevokeResult:
    outcome: Literal["revoked", "already-revoked", "not-found"]
    #: Entry rows the capture had when it was revoked. Informational.
    entries: int


@dataclass(frozen=True, slots=True)
class DeleteCiphertextResult:
    outcome: Literal["deleted", "not-found"]
    entries: int
    #: Always ``False``. Deleting ciphertext from the live store retires no key and removes no copy held in a backup,
    #: replica, or log archive.
    key_retired: Literal[False] = False


#: A restore request plus its ``attempt_id``, to be resolved with ``resolve_attempt``.
ResolveAttemptRequest = PersistentRestoreRequest


@dataclass(frozen=True, slots=True)
class ResolveAttemptResult:
    state: Literal["committed", "absent", "attempt-mismatch"]
    committed_at: int | None = None


# --------------------------------------------------------------------------- internals


class _Stop(Exception):
    """An operation's outcome, carried to the entry wrapper. Holds codes only, never a value."""

    def __init__(
        self,
        code: VaultServerErrorCode,
        reason: ServerDenialReason | None,
        core_code: str | None,
        attempt_id: str | None,
    ):
        super().__init__("stop")
        self.code = code
        self.reason = reason
        self.core_code = core_code
        self.attempt_id = attempt_id


@dataclass(slots=True)
class _Use:
    token: str
    entry_id: str
    count: int
    paths: dict[str, int]


@dataclass(frozen=True, slots=True)
class _Resolved:
    principal: Principal
    tenant: str
    session_id: str | None


@dataclass(slots=True)
class _Parsed:
    context: Any
    sink: str
    purpose: str
    sources: tuple[str, ...]
    attempt_id: str | None
    request_id: str | None
    snapshot: list[tuple[str, str]]
    #: By issued token.
    uses: dict[str, tuple[int, dict[str, int]]]
    invalid: bool = False
    malformed: bool = False


def _utf8_length(text: str) -> int:
    """UTF-8 length of ``text``, counting a lone surrogate as three bytes, as the JavaScript profile does."""

    size: int | None = None
    try:
        size = len(text.encode("utf-8"))
    except UnicodeEncodeError:
        pass
    if size is not None:
        return size
    return sum(1 if c < 0x80 else 2 if c < 0x800 else 3 if c < 0x10000 else 4 for c in map(ord, text))


def _is_request_id(value: object) -> bool:
    if value is None:
        return True
    return (
        type(value) is str
        and len(value) <= _limits.IDENTIFIER_MAX_LENGTH
        and is_well_formed(value)
        and count_markers(value) == 0
    )


def _new_attempt_id() -> str:
    return "att_" + secrets.token_hex(16)


def _wipe(payloads: list[RecordPayload]) -> None:
    for payload in payloads:
        value = getattr(payload, "value", None)
        if isinstance(value, bytearray):
            _buffers.zero(value)


def _drain(task: asyncio.Future[Any]) -> None:
    """A done callback: retrieve the result so an abandoned inner task never logs "exception was never retrieved"."""

    if not task.cancelled():
        task.exception()


def _timeout_option(value: object, fallback: float) -> float:
    resolved = fallback if value is None else value
    if type(resolved) not in (int, float) or not math.isfinite(resolved) or not 0 < resolved <= _MAX_TIMEOUT_S:  # type: ignore[operator]
        raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
    return float(resolved)  # type: ignore[arg-type]


def _duration_option(value: object, fallback: int, ceiling: int) -> int:
    resolved = fallback if value is None else value
    if type(resolved) is not int or not 0 <= resolved <= ceiling:
        raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
    return resolved


# --------------------------------------------------------------------------- the factory


async def create_persistent_server_vault(
    *,
    namespace: str,
    recovery_epoch: int,
    store: Store,
    crypto: RecordCrypto,
    core_client: CoreClient,
    expected_pii_activation: str,
    resolve_principal: Callable[[Any], Principal | Awaitable[Principal]],
    policy: ServerReleasePolicy,
    lifecycle_policy: LifecyclePolicy,
    resolve_session: SessionResolver | None = None,
    digest_key: bytes | bytearray | None = None,
    allow_unkeyed_digests: bool = False,
    on_audit: ServerAuditHook | None = None,
    limits: Mapping[str, int] | None = None,
    now: Callable[[], int | float] | None = None,
    policy_revision: str | Callable[[], str] | None = None,
    resolver_timeout_s: float | None = None,
    policy_timeout_s: float | None = None,
    store_timeout_s: float | None = None,
    crypto_timeout_s: float | None = None,
    max_commit_retries: int | None = None,
    receipt_grace_ms: int | None = None,
    tombstone_retention_ms: int | None = None,
    allow_non_durable_store: bool = False,
    allow_no_restore_detection: bool = False,
) -> PersistentServerVault:
    """Opens the persistent server profile. Every argument is keyword-only.

    ``expected_pii_activation`` is required: the core's canonical activation identity this deployment expects. A worker
    whose core reports another identity fails ``PII_ACTIVATION_MISMATCH`` here, or on the first capture, before it
    stores anything, so workers that disagree never retain different sets for the same input. ``digest_key`` is 32
    bytes, the same in every process of the namespace, and is required unless ``allow_unkeyed_digests`` is ``True``.
    The function reads ``store.capabilities()`` once, refuses a store that lacks what the profile needs, and fails
    ``STORE_QUARANTINED`` unless the namespace is serving at ``recovery_epoch``. It never initializes a namespace.
    """

    failure: tuple[VaultServerErrorCode, str | None] | None = None
    vault: PersistentServerVault | None = None
    try:
        vault = await _open(
            namespace=namespace,
            recovery_epoch=recovery_epoch,
            store=store,
            crypto=crypto,
            core_client=core_client,
            expected_pii_activation=expected_pii_activation,
            resolve_principal=resolve_principal,
            policy=policy,
            lifecycle_policy=lifecycle_policy,
            resolve_session=resolve_session,
            digest_key=digest_key,
            allow_unkeyed_digests=allow_unkeyed_digests,
            on_audit=on_audit,
            limits=limits,
            now=now,
            policy_revision=policy_revision,
            resolver_timeout_s=resolver_timeout_s,
            policy_timeout_s=policy_timeout_s,
            store_timeout_s=store_timeout_s,
            crypto_timeout_s=crypto_timeout_s,
            max_commit_retries=max_commit_retries,
            receipt_grace_ms=receipt_grace_ms,
            tombstone_retention_ms=tombstone_retention_ms,
            allow_non_durable_store=allow_non_durable_store,
            allow_no_restore_detection=allow_no_restore_detection,
        )
    except _Stop as stop:
        failure = (stop.code, stop.core_code)
    if failure is not None:
        raise VaultServerError(failure[0], core_code=failure[1])
    assert vault is not None
    return vault


def _stop(code: VaultServerErrorCode, *, core_code: str | None = None) -> _Stop:
    return _Stop(code, None, core_code, None)


async def _open(**o: Any) -> PersistentServerVault:
    code = VaultServerErrorCode
    namespace, recovery_epoch, store, crypto = o["namespace"], o["recovery_epoch"], o["store"], o["crypto"]
    if not is_namespace(namespace):
        raise _stop(code.INVALID_ARGUMENT)
    if type(recovery_epoch) is not int or not 1 <= recovery_epoch <= _limits.MAX_TIMESTAMP:
        raise _stop(code.INVALID_ARGUMENT)
    if not callable(o["resolve_principal"]) or not callable(o["policy"]) or not callable(o["lifecycle_policy"]):
        raise _stop(code.INVALID_ARGUMENT)
    if o["resolve_session"] is not None and not callable(o["resolve_session"]):
        raise _stop(code.INVALID_ARGUMENT)
    if o["on_audit"] is not None and not callable(o["on_audit"]):
        raise _stop(code.INVALID_ARGUMENT)
    revision = o["policy_revision"]
    if revision is not None and type(revision) is not str and not callable(revision):
        raise _stop(code.INVALID_ARGUMENT)
    if o["now"] is not None and not callable(o["now"]):
        raise _stop(code.INVALID_ARGUMENT)
    for method in (
        "capabilities",
        "create_capture",
        "read_entries",
        "read_captures",
        "commit_restore",
        "revoke_capture",
        "inspect_attempt",
        "delete_ciphertext",
        "recovery_state",
    ):
        if not callable(getattr(store, method, None)):
            raise _stop(code.INVALID_ARGUMENT)
    if not callable(getattr(crypto, "seal_capture", None)) or not callable(getattr(crypto, "open_capture", None)):
        raise _stop(code.INVALID_ARGUMENT)
    if not callable(getattr(o["core_client"], "scan", None)):
        raise _stop(code.INVALID_ARGUMENT)

    # The expected PII activation identity is required for the persistent profile.
    expected = None
    shape_failed = False
    try:
        expected = resolve_expected_pii_activation(o["expected_pii_activation"])
    except VaultServerError:
        shape_failed = True
    if shape_failed or expected is None:
        raise _stop(code.INVALID_ARGUMENT)

    # Digest key: required, or explicitly waived. Never defaulted.
    digest_key, unkeyed = o["digest_key"], o["allow_unkeyed_digests"]
    if type(unkeyed) is not bool:
        raise _stop(code.INVALID_ARGUMENT)
    digester: Digester | None = None
    digester_failed = False
    try:
        if digest_key is not None and not unkeyed:
            digester = create_digester(key=digest_key)
        elif digest_key is None and unkeyed:
            digester = create_digester(unkeyed=True)
    except RecordCryptoError:
        digester_failed = True
    if digester_failed or digester is None:
        raise _stop(code.INVALID_ARGUMENT)

    timeouts = _Timeouts(
        resolver=_timeout_option(o["resolver_timeout_s"], _DEFAULT_CALLBACK_TIMEOUT_S),
        policy=_timeout_option(o["policy_timeout_s"], _DEFAULT_CALLBACK_TIMEOUT_S),
        store=_timeout_option(o["store_timeout_s"], _DEFAULT_STORE_TIMEOUT_S),
        crypto=_timeout_option(o["crypto_timeout_s"], _DEFAULT_CRYPTO_TIMEOUT_S),
    )
    max_commit_retries = _duration_option(o["max_commit_retries"], _DEFAULT_COMMIT_RETRIES, _MAX_COMMIT_RETRIES)
    receipt_grace_ms = _duration_option(
        o["receipt_grace_ms"], _DEFAULT_RECEIPT_GRACE_MS, _limits.MAX_CAPTURE_LIFETIME_MS
    )
    tombstone_retention_ms = _duration_option(
        o["tombstone_retention_ms"], _DEFAULT_TOMBSTONE_RETENTION_MS, _limits.MAX_RETENTION_MS
    )

    # Capabilities are read once and judged before anything else touches the store.
    capabilities: StoreCapabilities | None = None
    capabilities_failed = False
    try:
        capabilities = store.capabilities()
    except Exception:
        capabilities_failed = True
    if capabilities_failed or capabilities is None:
        raise _stop(code.UNSUPPORTED_STORE)
    if missing_capabilities(capabilities):
        raise _stop(code.UNSUPPORTED_STORE)
    if (capabilities.durability != "durable" or not capabilities.cross_process) and o[
        "allow_non_durable_store"
    ] is not True:
        raise _stop(code.UNSUPPORTED_STORE)
    if (
        capabilities.durability == "durable"
        and capabilities.restore_detection == "none"
        and o["allow_no_restore_detection"] is not True
    ):
        raise _stop(code.UNSUPPORTED_STORE)

    resolved_limits = resolve_capture_limits(o["limits"])
    if resolved_limits["entry_ttl_ms"] > _limits.MAX_CAPTURE_LIFETIME_MS:
        raise _stop(code.INVALID_ARGUMENT)
    # Section 7.5 sets a receipt's expiry to the latest capture expiry plus the skew bound plus the grace; section 4.2
    # has the store refuse one more than ``MAX_RECEIPT_HORIZON_MS`` past its own clock, which may itself be a skew bound
    # behind this server's. A configuration that can produce such a receipt would fail restores of a fresh capture.
    if (
        resolved_limits["entry_ttl_ms"] + 2 * capabilities.max_clock_skew_ms + receipt_grace_ms
        > _limits.MAX_RECEIPT_HORIZON_MS
    ):
        raise _stop(code.INVALID_ARGUMENT)

    impl = PersistentServerVault(
        namespace=namespace,
        recovery_epoch=recovery_epoch,
        store=store,
        crypto=crypto,
        core=o["core_client"],
        expected_pii_activation=expected,
        capabilities=capabilities,
        limits=resolved_limits,
        digester=digester,
        resolve_principal=o["resolve_principal"],
        resolve_session=o["resolve_session"],
        policy=o["policy"],
        lifecycle_policy=o["lifecycle_policy"],
        on_audit=o["on_audit"],
        policy_revision=revision,
        raw_clock=o["now"] if o["now"] is not None else (lambda: time.time_ns() // 1_000_000),
        timeouts=timeouts,
        max_commit_retries=max_commit_retries,
        receipt_grace_ms=receipt_grace_ms,
        tombstone_retention_ms=tombstone_retention_ms,
    )
    # Observe the core's activation identity now, so a worker whose core disagrees fails before it stores anything.
    await impl._probe_core()
    # Fail closed at creation when the namespace is not serving at the configured epoch.
    await impl._assert_serving()
    return impl


@dataclass(frozen=True, slots=True)
class _Timeouts:
    resolver: float
    policy: float
    store: float
    crypto: float


class PersistentServerVault:
    """An open persistent server. Build one with ``create_persistent_server_vault``.

    The operations are ``def`` methods returning coroutines; ``await`` them.
    """

    def __init__(
        self,
        *,
        namespace: str,
        recovery_epoch: int,
        store: Store,
        crypto: RecordCrypto,
        core: CoreClient,
        expected_pii_activation: str,
        capabilities: StoreCapabilities,
        limits: dict[str, int],
        digester: Digester,
        resolve_principal: Callable[[Any], Any],
        resolve_session: SessionResolver | None,
        policy: ServerReleasePolicy,
        lifecycle_policy: LifecyclePolicy,
        on_audit: ServerAuditHook | None,
        policy_revision: str | Callable[[], str] | None,
        raw_clock: Callable[[], int | float],
        timeouts: _Timeouts,
        max_commit_retries: int,
        receipt_grace_ms: int,
        tombstone_retention_ms: int,
    ) -> None:
        self._namespace = namespace
        self._epoch = recovery_epoch
        self._store = store
        self._crypto = crypto
        self._core = core
        self._expected_pii = expected_pii_activation
        self._pii_activation: str | None = None
        self._capabilities = capabilities
        self._limits = limits
        self._digester = digester
        self._resolve_principal = resolve_principal
        self._resolve_session = resolve_session
        self._policy = policy
        self._lifecycle_policy = lifecycle_policy
        self._on_audit = on_audit
        self._policy_revision_source = policy_revision
        self._raw_clock = raw_clock
        self._timeouts = timeouts
        self._max_commit_retries = max_commit_retries
        self._receipt_grace_ms = receipt_grace_ms
        self._tombstone_retention_ms = tombstone_retention_ms
        self._latest = 0
        self._closed = False

    # ------------------------------------------------------------------ properties

    @property
    def namespace(self) -> str:
        return self._namespace

    @property
    def pii_activation(self) -> str | None:
        """The activation identity the core reported when the server was opened."""

        return self._pii_activation

    @property
    def store_capabilities(self) -> StoreCapabilities:
        """The capabilities the store declared when this instance was created."""

        return self._capabilities

    def __repr__(self) -> str:
        return f"PersistentServerVault(namespace={self._namespace!r}, closed={self._closed})"

    def __reduce__(self) -> tuple[object, ...]:
        raise TypeError("PersistentServerVault must not be pickled or copied")

    # --------------------------------------------------------------- public methods

    def capture(self, input_text: str, options: PersistentCaptureOptions) -> Awaitable[PersistentCaptureResult]:
        """Resolves the principal and session from ``options.context``, asks the lifecycle policy, plans the capture
        through the shared capture plan, seals every retained value, and creates the capture in one store call."""

        return self._entry(self._capture, input_text, options)

    def restore(self, request: PersistentRestoreRequest) -> Awaitable[PersistentRestoreResult]:
        """Restores the tokens of ``request.fields`` into a copy of the fields, in the order of specification section
        7.2. Fields leave only on a definitive commit. A ``tenant`` or ``session_id`` on the request has no effect."""

        return self._entry(self._restore, request)

    def revoke(self, request: LifecycleRequest) -> Awaitable[RevokeResult]:
        """Denies future restores of one capture. Does not delete ciphertext."""

        return self._entry(self._revoke, request)

    def delete_capture_ciphertext(self, request: LifecycleRequest) -> Awaitable[DeleteCiphertextResult]:
        """Revokes, then deletes the capture's ciphertext from the live store. Not erasure."""

        return self._entry(self._delete, request)

    def resolve_attempt(self, request: ResolveAttemptRequest) -> Awaitable[ResolveAttemptResult]:
        """Reports whether an attempt committed. Never returns restored fields."""

        return self._entry(self._resolve_attempt, request)

    async def close(self) -> None:
        """Releases this instance. Revokes nothing, deletes nothing, and closes no store or provider."""

        self._closed = True

    async def _entry(self, implementation: Callable[..., Awaitable[Any]], *args: Any) -> Any:
        """Runs one operation and turns its ``_Stop`` into a fresh ``VaultServerError`` raised from this frame, outside
        any ``except`` block and after the arguments were dropped."""

        stop: _Stop | None = None
        result: Any = None
        try:
            result = await implementation(*args)
        except _Stop as caught:
            stop = caught
        args = ()
        implementation = None  # type: ignore[assignment]
        if stop is not None:
            code, reason, core_code, attempt_id = stop.code, stop.reason, stop.core_code, stop.attempt_id
            stop = None
            raise VaultServerError(code, core_code=core_code, reason=reason, attempt_id=attempt_id)
        return result

    # ------------------------------------------------------------------ helpers

    def _off_loop(self, function: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Awaitable[Any]:
        """Runs a blocking call that scans through the core off the event loop. A ``CoreClient`` that offers
        ``run_in_scan_executor`` (``NodeCoreBridge`` does) runs it on threads of its own, so scans never occupy the
        loop's default executor, which the application shares with everything else that calls ``asyncio.to_thread``;
        any other client keeps the default executor. Cancelling the awaiting task leaves a call that is already
        running to finish, and its result is discarded."""

        runner = getattr(self._core, "run_in_scan_executor", None)
        if callable(runner):
            return runner(function, *args, **kwargs)  # type: ignore[no-any-return]
        return asyncio.to_thread(function, *args, **kwargs)

    def _open_check(self) -> None:
        if self._closed:
            raise _stop(VaultServerErrorCode.CLOSED)

    def _now(self) -> int:
        """Integer milliseconds, never decreasing within this instance."""

        reading: Any = None
        failed = False
        try:
            reading = self._raw_clock()
        except Exception:
            failed = True
        if failed:
            raise _stop(VaultServerErrorCode.INVALID_ARGUMENT)
        if type(reading) is bool or not isinstance(reading, (int, float)):
            raise _stop(VaultServerErrorCode.INVALID_ARGUMENT)
        if isinstance(reading, float) and not math.isfinite(reading):
            raise _stop(VaultServerErrorCode.INVALID_ARGUMENT)
        value = math.floor(reading)
        if not 0 <= value <= _limits.MAX_TIMESTAMP:
            raise _stop(VaultServerErrorCode.INVALID_ARGUMENT)
        self._latest = max(self._latest, value)
        return self._latest

    def _revision(self) -> str | None:
        source = self._policy_revision_source
        if source is None:
            return None
        value: Any = source
        failed = False
        if callable(source):
            try:
                value = source()
            except Exception:
                failed = True
        if (
            failed
            or type(value) is not str
            or not is_well_formed(value)
            or _utf8_length(value) > _limits.POLICY_REVISION_MAX_BYTES
        ):
            raise _stop(VaultServerErrorCode.INVALID_ARGUMENT)
        return value

    def _audit(self, **fields: Any) -> None:
        if self._on_audit is None:
            return
        event = ServerAuditEvent(**fields)
        returned: Any = None
        try:
            returned = self._on_audit(event)
        except Exception:
            return  # Audit delivery never changes an operation's outcome.
        if inspect.isawaitable(returned):
            asyncio.ensure_future(_swallow(returned))  # noqa: RUF006

    async def _callback(self, call: Callable[[], Any], timeout_s: float) -> tuple[bool, Any]:
        """Calls an application callback with a deadline. ``(False, None)`` for a raise or a timeout: both deny."""

        failed = False
        value: Any = None
        try:
            result = call()
            if inspect.isawaitable(result):
                result = await asyncio.wait_for(result, timeout_s)
            value = result
        except Exception:
            failed = True
        return (not failed, value)

    async def _resolve(self, context: Any) -> _Resolved | None:
        """Principal and session from trusted context. ``None`` for any failure; callers map it to their denial."""

        ok, principal = await self._callback(lambda: self._resolve_principal(context), self._timeouts.resolver)
        if (
            not ok
            or type(principal) is not Principal
            or not is_identifier(principal.id)
            or not is_identifier(principal.tenant)
        ):
            return None
        session_id: str | None = None
        if self._resolve_session is not None:
            resolver = self._resolve_session
            ok, session = await self._callback(lambda: resolver(context), self._timeouts.resolver)
            if not ok:
                return None
            if session is not None:
                if not is_identifier(session):
                    return None
                session_id = session
        return _Resolved(principal=principal, tenant=principal.tenant, session_id=session_id)

    async def _lifecycle(self, **fields: Any) -> bool:
        ok, decision = await self._callback(
            lambda: self._lifecycle_policy(LifecycleDecisionInput(**fields)), self._timeouts.policy
        )
        return ok and type(decision) is LifecycleDecision and decision.allow is True

    async def _store_call(
        self, mutating: bool, call: Callable[[], Awaitable[Any]], *, on_cancel: Callable[[], None] | None = None
    ) -> tuple[str, Any]:
        """One store call with a deadline. Whatever the adapter raises is reduced to a kind; nothing of its error
        survives. A mutating call that times out, or fails in a way the adapter did not classify, has an unknown
        outcome. A mutating call runs in an inner task under ``asyncio.shield``: when the caller is cancelled the call
        still finishes under its own deadline, so the connection returns in a known state."""

        inner = asyncio.ensure_future(self._classified(mutating, call))
        if not mutating:
            return await inner
        try:
            return await asyncio.shield(inner)
        except asyncio.CancelledError:
            inner.add_done_callback(_drain)
            if on_cancel is not None:
                inner.add_done_callback(lambda _task: on_cancel())
            raise

    async def _classified(self, mutating: bool, call: Callable[[], Awaitable[Any]]) -> tuple[str, Any]:
        kind = "ok"
        value: Any = None
        try:
            value = await asyncio.wait_for(call(), self._timeouts.store)
        except StoreError as error:
            if error.code in ("STORE_UNAVAILABLE", "STORE_CLOSED"):
                kind = "unavailable"
            elif error.code in ("STORE_INVALID_ARGUMENT", "STORE_CAPABILITY"):
                kind = "invalid"
            else:
                kind = "ambiguous"
        except Exception:
            kind = "ambiguous" if mutating else "unavailable"
        return (kind, value)

    async def _crypto_call(self, work: Callable[[], Awaitable[Any]]) -> tuple[str, Any]:
        """All crypto and key-provider work of one operation, under one deadline. Kinds: ``ok``, ``limit`` (a record
        limit), ``integrity`` (an authentication or record failure), ``record`` (any other record failure), ``key``."""

        kind = "ok"
        value: Any = None
        try:
            value = await asyncio.wait_for(work(), self._timeouts.crypto)
        except KeyProviderError as error:
            kind = "integrity" if error.code == "KEY_INTEGRITY" else "key"
        except RecordCryptoError as error:
            kind = "limit" if error.code == "RECORD_LIMIT" else "record"
        except Exception:
            kind = "key"
        return (kind, value)

    async def _probe_core(self) -> None:
        """One scan of the empty string observes the core's activation identity (a worker's core realm pins it on its
        first scan)."""

        stop: _Stop | None = None
        try:
            outcome = await self._off_loop(
                self._core.scan,
                "",
                policy=None,
                limits={"maxInputBytes": self._limits["max_input_bytes"], "maxFindings": self._limits["max_findings"]},
            )
            if outcome.pii_activation != self._expected_pii:
                stop = _stop(VaultServerErrorCode.PII_ACTIVATION_MISMATCH)
            else:
                self._pii_activation = outcome.pii_activation
        except VaultServerError as error:
            stop = _stop(error.code, core_code=error.core_code)
        except Exception:
            stop = _stop(VaultServerErrorCode.INVARIANT_VIOLATION)
        if stop is not None:
            raise stop

    async def _assert_serving(self) -> None:
        kind, state = await self._store_call(False, lambda: self._store.recovery_state(self._namespace))
        if kind != "ok":
            raise _stop(VaultServerErrorCode.STORE_UNAVAILABLE)
        if getattr(state, "state", None) != "serving" or getattr(state, "epoch", None) != self._epoch:
            raise _stop(VaultServerErrorCode.STORE_QUARANTINED)

    # ------------------------------------------------------------------ capture

    async def _capture(self, input_text: str, options: PersistentCaptureOptions) -> PersistentCaptureResult:
        self._open_check()
        code = VaultServerErrorCode
        if not isinstance(input_text, str) or not isinstance(options, PersistentCaptureOptions):
            raise _stop(code.INVALID_ARGUMENT)
        request_id = options.request_id
        if not _is_request_id(request_id):
            raise _stop(code.INVALID_ARGUMENT)
        at = self._now()
        who: _Resolved | None = None

        def fail(error: VaultServerErrorCode, *, core_code: str | None = None) -> _Stop:
            self._audit(
                operation=ServerAuditOperation.CAPTURE,
                outcome="denied" if error == code.LIFECYCLE_DENIED else "failed",
                at=at,
                principal_id=None if who is None else who.principal.id,
                tenant=None if who is None else who.tenant,
                code=error.value,
                request_id=request_id,
            )
            return _stop(error, core_code=core_code)

        who = await self._resolve(options.context)
        if who is None:
            raise fail(code.LIFECYCLE_DENIED)

        # The same capture gate the in-memory server runs: block rejects, warn and allow pass through only when asked,
        # PII needs its exact-type allowlist. The core scan is blocking: it runs in a worker thread.
        plan: CapturePlan | None = None
        plan_error: tuple[VaultServerErrorCode, str | None] | None = None
        try:
            plan = await self._off_loop(
                plan_capture,
                self._core,
                input_text,
                options,
                self._limits,
                expected_pii_activation=self._expected_pii,
            )
        except VaultServerError as error:
            plan_error = (error.code, error.core_code)
        except Exception:
            plan_error = (code.INVARIANT_VIOLATION, None)
        if plan_error is not None:
            raise fail(plan_error[0], core_code=plan_error[1])
        assert plan is not None

        # Section 8.3: an identifier with a lone surrogate is the caller's argument error. The plan checks only length.
        for grant in plan.grants:
            if not is_identifier(grant.sink) or not all(is_identifier(path) for path in grant.paths):
                raise fail(code.INVALID_ARGUMENT)

        capture_id = new_capture_id()
        if not is_capture_id(capture_id):
            raise fail(code.INVARIANT_VIOLATION)
        # Read before any value is encoded, so a failing callback leaves no plaintext buffer behind.
        revision: str | None = None
        revision_failed = False
        try:
            revision = self._revision()
        except _Stop:
            revision_failed = True
        if revision_failed:
            raise fail(code.INVALID_ARGUMENT)
        expires_at = at + self._limits["entry_ttl_ms"]
        capabilities = self._capabilities
        if len(plan.retained) > capabilities.max_create_entries:
            raise fail(code.LIMIT_EXCEEDED)

        # Values are sliced from the caller's own input; the plan carries ranges only.
        values: list[bytearray] = []
        total_bytes = 0
        ill_formed = False
        for planned in plan.retained:
            value = plan.value_of(input_text, planned)
            if not is_well_formed(value):
                ill_formed = True
                break
            encoded = value.encode("utf-8")
            buffer = _buffers.new_buffer(len(encoded))
            buffer[:] = encoded
            values.append(buffer)
            total_bytes += len(encoded)
        if ill_formed:
            _zero_all(values)
            raise fail(code.INVALID_ARGUMENT)

        try:
            allowed = await self._lifecycle(
                operation="capture",
                principal=who.principal,
                tenant=who.tenant,
                session_id=who.session_id,
                entries=len(plan.retained),
                bytes=total_bytes,
                requested_at=at,
            )
        except BaseException:
            _zero_all(values)
            raise
        if not allowed:
            _zero_all(values)
            raise fail(code.LIFECYCLE_DENIED)

        final_plan: CapturePlan = plan
        final_who: _Resolved = who

        def result() -> PersistentCaptureResult:
            return PersistentCaptureResult(
                capture_id=capture_id,
                text=final_plan.text,
                tokens=tuple(IssuedToken(token=entry.token, type=entry.type) for entry in final_plan.retained),
                passed_through=final_plan.passed_through,
                passed_through_types=final_plan.passed_through_types,
                unrestorable=final_plan.unrestorable,
                expires_at=expires_at,
                tenant=final_who.tenant,
                session_bound=len(final_plan.retained) > 0 and final_who.session_id is not None,
            )

        # A capture that retains nothing has nothing to store or revoke (section 5.3).
        if not plan.retained:
            self._audit(
                operation=ServerAuditOperation.CAPTURE,
                outcome="committed",
                at=at,
                principal_id=who.principal.id,
                tenant=who.tenant,
                entries=0,
                request_id=request_id,
            )
            return result()

        scope = StoreScope(namespace=self._namespace, tenant=who.tenant)
        key_context = KeyContext(namespace=self._namespace, tenant=who.tenant, capture_id=capture_id)

        sealed: Any = None
        entry_ids: list[str] = []
        session_tag: str | None = None
        sealing: tuple[str, Any] = ("key", None)
        derive_failed = False
        try:
            try:
                entry_ids = [derive_entry_id(self._namespace, who.tenant, entry.token) for entry in plan.retained]
                if who.session_id is not None:
                    session_tag = self._digester.session_tag(
                        SessionTagInput(
                            namespace=self._namespace,
                            tenant=who.tenant,
                            capture_id=capture_id,
                            session_id=who.session_id,
                        )
                    )
            except RecordCryptoError:
                derive_failed = True
            if not derive_failed:
                records = tuple(
                    (
                        RecordBinding(
                            namespace=self._namespace,
                            tenant=who.tenant,
                            capture_id=capture_id,
                            entry_id=entry_ids[index],
                            session_id=who.session_id,
                            created_at=at,
                            expires_at=expires_at,
                            max_uses=plan.max_uses,
                        ),
                        RecordPayload(
                            value=values[index],
                            type=entry.type,
                            grants=tuple(Grant(sink=grant.sink, paths=grant.paths) for grant in plan.grants),
                            policy_revision=revision,
                        ),
                    )
                    for index, entry in enumerate(plan.retained)
                )
                sealing = await self._crypto_call(lambda: self._crypto.seal_capture(key_context, records))
                sealed = sealing[1]
        finally:
            _zero_all(values)
        if derive_failed:
            raise fail(code.INVARIANT_VIOLATION)
        if sealing[0] == "limit":
            raise fail(code.LIMIT_EXCEEDED)
        if sealing[0] in ("record", "integrity"):
            raise fail(code.INVARIANT_VIOLATION)
        if sealing[0] != "ok":
            raise fail(code.KEY_UNAVAILABLE)

        # Never trust the injected crypto layer's shape with the store's bounds.
        if (
            not isinstance(sealed, SealedCapture)
            or not is_key_ref(sealed.key_ref)
            or not isinstance(sealed.wrapped_key, bytes)
            or not 0 < len(sealed.wrapped_key) <= _limits.WRAPPED_KEY_MAX_BYTES
            or type(sealed.envelopes) is not tuple
            or len(sealed.envelopes) != len(plan.retained)
        ):
            raise fail(code.INVARIANT_VIOLATION)
        envelope_bytes = 0
        for envelope in sealed.envelopes:
            if not isinstance(envelope, bytes) or len(envelope) == 0:
                raise fail(code.INVARIANT_VIOLATION)
            if len(envelope) > capabilities.max_envelope_bytes:
                raise fail(code.LIMIT_EXCEEDED)
            envelope_bytes += len(envelope)
        if envelope_bytes > capabilities.max_create_bytes:
            raise fail(code.LIMIT_EXCEEDED)

        creation = CreateCaptureInput(
            scope=scope,
            epoch=self._epoch,
            now=self._now(),
            capture=NewCapture(
                capture_id=capture_id,
                key_ref=sealed.key_ref,
                wrapped_key=sealed.wrapped_key,
                session_tag=session_tag,
                created_at=at,
                expires_at=expires_at,
                lookup_version=1,
            ),
            entries=tuple(
                NewEntry(entry_id=entry_ids[index], max_uses=plan.max_uses, envelope=envelope)
                for index, envelope in enumerate(sealed.envelopes)
            ),
        )

        # The capture may exist. No token left this call, so it is unusable either way; a fence makes that durable. One
        # attempt, never part of the caller's outcome (section 8.2).
        async def fence() -> None:
            await self._store_call(
                True,
                lambda: self._store.revoke_capture(
                    RevokeCaptureInput(
                        scope=scope,
                        capture_id=capture_id,
                        now=self._now(),
                        retention_ms=self._tombstone_retention_ms,
                        fence_absent=True,
                    )
                ),
            )

        def fence_after_cancel() -> None:
            asyncio.ensure_future(_swallow(fence()))  # noqa: RUF006

        kind, created = await self._store_call(
            True, lambda: self._store.create_capture(creation), on_cancel=fence_after_cancel
        )
        if kind == "ambiguous":
            await fence()
            raise fail(code.STORE_UNAVAILABLE)
        if kind == "invalid":
            raise fail(code.INVARIANT_VIOLATION)
        if kind != "ok":
            raise fail(code.STORE_UNAVAILABLE)

        outcome = getattr(created, "outcome", None)
        if outcome != "created":
            reason = getattr(created, "reason", None) if outcome == "rejected" else None
            if reason == "quarantined":
                raise fail(code.STORE_QUARANTINED)
            if reason == "clock-skew":
                raise fail(code.CLOCK_SKEW)
            if reason == "stale":
                raise fail(code.STORE_UNAVAILABLE)
            if reason in ("exists", "fenced"):
                raise fail(code.INVARIANT_VIOLATION)
            # A result this server cannot interpret says nothing about whether the capture was created: the outcome is
            # unknown, as after a lost response.
            await fence()
            raise fail(code.INVARIANT_VIOLATION)

        self._audit(
            operation=ServerAuditOperation.CAPTURE,
            outcome="committed",
            at=at,
            principal_id=who.principal.id,
            tenant=who.tenant,
            entries=len(plan.retained),
            capture_id=capture_id,
            request_id=request_id,
        )
        return result()

    # ------------------------------------------------------------------ restore

    async def _restore(self, request: PersistentRestoreRequest) -> PersistentRestoreResult:
        self._open_check()
        parsed = self._parse_restore(request)
        sink, purpose, request_id = parsed.sink, parsed.purpose, parsed.request_id
        at = self._now()
        attempt_id = parsed.attempt_id if parsed.attempt_id is not None else _new_attempt_id()
        who: _Resolved | None = None
        code = VaultServerErrorCode

        def deny(reason: ServerDenialReason) -> _Stop:
            if reason == ServerDenialReason.UNAUTHENTICATED:
                operation = ServerAuditOperation.RESOLVE_PRINCIPAL
            elif reason == ServerDenialReason.POLICY_EVALUATION_ERROR:
                operation = ServerAuditOperation.POLICY_ERROR
            else:
                operation = ServerAuditOperation.RESTORE
            self._audit(
                operation=operation,
                outcome="failed" if reason == ServerDenialReason.POLICY_EVALUATION_ERROR else "denied",
                at=at,
                principal_id=None if who is None else who.principal.id,
                tenant=None if who is None else who.tenant,
                sink=sink,
                purpose=purpose,
                reason=reason,
                attempt_id=attempt_id,
                request_id=request_id,
            )
            return _Stop(code.RESTORE_DENIED, reason, None, None)

        def fail(error: VaultServerErrorCode) -> _Stop:
            self._audit(
                operation=ServerAuditOperation.RESTORE,
                outcome="failed",
                at=at,
                principal_id=None if who is None else who.principal.id,
                tenant=None if who is None else who.tenant,
                sink=sink,
                purpose=purpose,
                code=error.value,
                attempt_id=attempt_id,
                request_id=request_id,
            )
            return _Stop(error, None, None, attempt_id if error == code.COMMIT_AMBIGUOUS else None)

        if parsed.invalid:
            raise deny(ServerDenialReason.INVALID_REQUEST)

        # Step 2: principal and session, from trusted context only.
        who = await self._resolve(parsed.context)
        if who is None:
            raise deny(ServerDenialReason.UNAUTHENTICATED)
        resolved = who

        if parsed.malformed:
            raise deny(ServerDenialReason.MALFORMED_TOKEN)
        if len(purpose) == 0:
            raise deny(ServerDenialReason.MISSING_PURPOSE)

        # Step 3: nothing to restore. No store call, no attempt.
        if not parsed.uses:
            self._audit(
                operation=ServerAuditOperation.RESTORE,
                outcome="committed",
                at=at,
                principal_id=resolved.principal.id,
                tenant=resolved.tenant,
                sink=sink,
                purpose=purpose,
                entries=0,
                request_id=request_id,
            )
            return PersistentRestoreResult(
                fields=MappingProxyType(dict(parsed.snapshot)),
                restored=0,
                principal_id=resolved.principal.id,
                tenant=resolved.tenant,
            )
        if len(parsed.uses) > self._capabilities.max_restore_entries:
            raise deny(ServerDenialReason.INVALID_REQUEST)

        scope = StoreScope(namespace=self._namespace, tenant=resolved.tenant)
        uses: dict[str, _Use] = {}
        derive_failed = False
        try:
            for token, (count, paths) in parsed.uses.items():
                entry_id = derive_entry_id(self._namespace, resolved.tenant, token)
                uses[entry_id] = _Use(token=token, entry_id=entry_id, count=count, paths=dict(paths))
        except RecordCryptoError:
            derive_failed = True
        if derive_failed:
            raise deny(ServerDenialReason.INVALID_REQUEST)
        request_digest = self._request_digest(resolved, parsed, uses)
        if request_digest is None:
            raise deny(ServerDenialReason.INVALID_REQUEST)

        round_number = 0
        while True:
            outcome = await self._restore_once(
                parsed=parsed,
                resolved=resolved,
                scope=scope,
                uses=uses,
                request_digest=request_digest,
                attempt_id=attempt_id,
                deny=deny,
                fail=fail,
            )
            if outcome != "stale":
                self._audit(
                    operation=ServerAuditOperation.RESTORE,
                    outcome="committed",
                    at=at,
                    principal_id=resolved.principal.id,
                    tenant=resolved.tenant,
                    sink=sink,
                    purpose=purpose,
                    entries=len(uses),
                    attempt_id=attempt_id,
                    request_id=request_id,
                )
                return outcome
            if round_number >= self._max_commit_retries:
                raise fail(code.RESTORE_CONFLICT)
            round_number += 1

    def _request_digest(self, resolved: _Resolved, parsed: _Parsed, uses: dict[str, _Use]) -> bytes | None:
        digest: bytes | None = None
        try:
            digest = self._digester.request_digest(self._digest_input(resolved, parsed, uses))
        except RecordCryptoError:
            digest = None
        return digest

    def _digest_input(self, resolved: _Resolved, parsed: _Parsed, uses: dict[str, _Use]) -> RequestDigestInput:
        return RequestDigestInput(
            namespace=self._namespace,
            tenant=resolved.tenant,
            principal_id=resolved.principal.id,
            session_id=resolved.session_id,
            sink=parsed.sink,
            purpose=parsed.purpose,
            capture_ids=tuple(parsed.sources),
            uses=tuple(
                RequestUse(
                    entry_id=use.entry_id,
                    paths=tuple(RequestPath(path=path, occurrences=count) for path, count in use.paths.items()),
                )
                for use in uses.values()
            ),
        )

    async def _restore_once(
        self,
        *,
        parsed: _Parsed,
        resolved: _Resolved,
        scope: StoreScope,
        uses: dict[str, _Use],
        request_digest: bytes,
        attempt_id: str,
        deny: Callable[[ServerDenialReason], _Stop],
        fail: Callable[[VaultServerErrorCode], _Stop],
    ) -> PersistentRestoreResult | Literal["stale"]:
        """Steps 4 to 10 of specification section 7.2: one read, one evaluation, one commit."""

        sink, purpose = parsed.sink, parsed.purpose
        code = VaultServerErrorCode
        now = self._now()

        # Step 4: bounded read. It authorizes nothing; the commit checks again.
        kind, read = await self._store_call(
            False, lambda: self._store.read_entries(ReadEntriesInput(scope=scope, entry_ids=tuple(uses)))
        )
        if kind != "ok":
            raise fail(code.INVARIANT_VIOLATION if kind == "invalid" else code.STORE_UNAVAILABLE)
        view = _inspect_read(read, uses)
        if view is None:
            raise fail(code.INVARIANT_VIOLATION)
        recovery, entries, captures = view
        if recovery.state != "serving" or recovery.epoch != self._epoch:
            raise fail(code.STORE_QUARANTINED)

        for use in uses.values():
            if use.entry_id not in entries:
                raise deny(ServerDenialReason.UNKNOWN_TOKEN)
        for capture in captures.values():
            if capture.state != "live":
                raise deny(ServerDenialReason.REVOKED)
        for capture in captures.values():
            if capture.capture_id not in parsed.sources:
                raise deny(ServerDenialReason.SOURCE)
        # Session: checked on the keyed tag, before any key is unwrapped.
        for capture in captures.values():
            if capture.session_tag is None:
                continue
            if resolved.session_id is None:
                raise deny(ServerDenialReason.SOURCE)
            expected = self._session_tag(resolved, capture.capture_id)
            if expected is None or not _equal_tags(expected, capture.session_tag):
                raise deny(ServerDenialReason.SOURCE)
        for capture in captures.values():
            if now >= capture.expires_at:
                raise deny(ServerDenialReason.EXPIRED)
        for use in uses.values():
            entry = entries[use.entry_id]
            if entry.used + use.count > entry.max_uses:
                raise deny(ServerDenialReason.BUDGET)

        # Step 5: one unwrap per capture; every entry authenticated against the binding rebuilt from trusted scope.
        # All of them, or a denial.
        opened: dict[str, RecordPayload] = {}
        try:
            by_capture: dict[str, list[StoredEntry]] = {}
            for use in uses.values():
                entry = entries[use.entry_id]
                by_capture.setdefault(entry.capture_id, []).append(entry)

            async def open_all() -> None:
                for capture_id, group in by_capture.items():
                    capture = captures[capture_id]
                    payloads = await self._crypto.open_capture(
                        StoredKey(key_ref=capture.key_ref, wrapped_key=capture.wrapped_key),
                        KeyContext(namespace=self._namespace, tenant=resolved.tenant, capture_id=capture_id),
                        tuple(
                            (
                                RecordBinding(
                                    namespace=self._namespace,
                                    tenant=resolved.tenant,
                                    capture_id=capture_id,
                                    entry_id=entry.entry_id,
                                    session_id=None if capture.session_tag is None else resolved.session_id,
                                    created_at=capture.created_at,
                                    expires_at=capture.expires_at,
                                    max_uses=entry.max_uses,
                                ),
                                entry.envelope,
                            )
                            for entry in group
                        ),
                    )
                    # Hold every payload before checking its shape, so a malformed result is still overwritten below.
                    received = list(payloads) if isinstance(payloads, tuple) else []
                    for index, payload in enumerate(received):
                        if index < len(group) and _is_payload(payload):
                            opened[group[index].entry_id] = payload
                    if len(received) != len(group) or any(not _is_payload(payload) for payload in received):
                        _wipe([payload for payload in received if _is_payload(payload)])
                        raise RecordCryptoError("RECORD_MALFORMED")

            crypto_kind, _unused = await self._crypto_call(open_all)
            if crypto_kind == "key":
                raise deny(ServerDenialReason.KEY_UNAVAILABLE)
            if crypto_kind != "ok":
                raise deny(ServerDenialReason.INTEGRITY_FAILURE)

            # Step 6: grants, from the authenticated record.
            for use in uses.values():
                payload = opened[use.entry_id]
                grant = next((candidate for candidate in payload.grants if candidate.sink == sink), None)
                for path in use.paths:
                    if grant is None or path not in grant.paths:
                        raise deny(ServerDenialReason.SINK_OR_PATH)

            # Step 7: the application's policy, fresh for every entry and path, outside any store transaction.
            def current_revision() -> str | None:
                revision: str | None = None
                failed = False
                try:
                    revision = self._revision()
                except _Stop:
                    failed = True
                if failed:
                    raise deny(ServerDenialReason.POLICY_EVALUATION_ERROR)
                return revision

            revision_before = current_revision() if callable(self._policy_revision_source) else None
            for use in uses.values():
                entry = entries[use.entry_id]
                capture = captures[entry.capture_id]
                payload = opened[use.entry_id]
                for path, occurrences in use.paths.items():
                    decision_input = RestoreDecisionInput(
                        principal=resolved.principal,
                        tenant=resolved.tenant,
                        source=RestoreSource(
                            capture_id=capture.capture_id,
                            issued_tenant=resolved.tenant,
                            session_id=resolved.session_id if capture.session_tag is not None else None,
                        ),
                        sink=sink,
                        path=path,
                        purpose=purpose,
                        type=payload.type,
                        occurrences=occurrences,
                        total_occurrences=use.count,
                        used=entry.used,
                        max_uses=entry.max_uses,
                        requested_at=now,
                        policy_revision=payload.policy_revision,
                    )
                    ok, decision = await self._callback(
                        lambda decision_input=decision_input: self._policy(decision_input), self._timeouts.policy
                    )
                    if not ok or type(decision) is not PolicyDecision:
                        raise deny(ServerDenialReason.POLICY_EVALUATION_ERROR)
                    if not decision.allow:
                        reason = decision.reason
                        value = reason.value if isinstance(reason, ServerDenialReason) else reason
                        if value in _POLICY_DENIAL_REASONS:
                            raise deny(ServerDenialReason(value))
                        raise deny(ServerDenialReason.POLICY_EVALUATION_ERROR)
            # Section 7.4: narrow, not close, the window between policy and commit.
            if revision_before is not None and current_revision() != revision_before:
                raise deny(ServerDenialReason.STALE_POLICY)

            # Step 8: values become strings only now, when they are about to be returned.
            values: dict[str, str] = {}
            decode_failed = False
            try:
                for use in uses.values():
                    values[use.token] = bytes(opened[use.entry_id].value).decode("utf-8", "strict")
            except UnicodeDecodeError:
                decode_failed = True
            if decode_failed:
                values.clear()
                raise deny(ServerDenialReason.INTEGRITY_FAILURE)
            staged: dict[str, str] = {}
            restored = 0
            for path, text in parsed.snapshot:

                def substitute(match: Any) -> str:
                    nonlocal restored
                    restored += 1
                    return values[match.group(0)]

                staged[path] = TOKEN_PATTERN.sub(substitute, text)
            values.clear()

            # Step 9: the one transaction that consumes every use and records the attempt.
            latest_expiry = max((capture.expires_at for capture in captures.values()), default=0)
            commit = CommitRestoreInput(
                scope=scope,
                epoch=self._epoch,
                now=self._now(),
                attempt=Attempt(attempt_id=attempt_id, request_digest=request_digest),
                receipt_expires_at=latest_expiry + self._capabilities.max_clock_skew_ms + self._receipt_grace_ms,
                captures=tuple(
                    CaptureGeneration(capture_id=capture.capture_id, generation=capture.generation)
                    for capture in captures.values()
                ),
                uses=tuple(
                    EntryUse(
                        entry_id=use.entry_id,
                        capture_id=entries[use.entry_id].capture_id,
                        count=use.count,
                        lifecycle_revision=entries[use.entry_id].lifecycle_revision,
                        ciphertext_revision=entries[use.entry_id].ciphertext_revision,
                    )
                    for use in uses.values()
                ),
            )
            commit_kind, committed = await self._store_call(True, lambda: self._store.commit_restore(commit))
            if commit_kind == "unavailable":
                raise fail(code.STORE_UNAVAILABLE)
            if commit_kind == "invalid":
                raise fail(code.INVARIANT_VIOLATION)
            if commit_kind != "ok":
                # Unknown outcome: release nothing, retry nothing (section 7.3).
                raise fail(code.COMMIT_AMBIGUOUS)

            # Step 10: fields leave only on a definitive commit.
            outcome = getattr(committed, "outcome", None)
            if outcome == "committed":
                return PersistentRestoreResult(
                    fields=MappingProxyType(staged),
                    restored=restored,
                    principal_id=resolved.principal.id,
                    tenant=resolved.tenant,
                    attempt_id=attempt_id,
                )
            staged.clear()
            if outcome == "already-committed":
                raise deny(ServerDenialReason.ATTEMPT_ALREADY_COMMITTED)
            if outcome == "attempt-mismatch":
                raise deny(ServerDenialReason.ATTEMPT_MISMATCH)
            if outcome == "rejected":
                reason = getattr(committed, "reason", None)
                if reason == "stale":
                    return "stale"
                if reason == "revoked":
                    raise deny(ServerDenialReason.REVOKED)
                if reason == "expired":
                    raise deny(ServerDenialReason.EXPIRED)
                if reason == "budget":
                    raise deny(ServerDenialReason.BUDGET)
                if reason == "unknown":
                    raise deny(ServerDenialReason.UNKNOWN_TOKEN)
                if reason == "clock-skew":
                    raise fail(code.CLOCK_SKEW)
                if reason == "quarantined":
                    raise fail(code.STORE_QUARANTINED)
            # A result this server cannot interpret is not a commit.
            raise fail(code.COMMIT_AMBIGUOUS)
        finally:
            _wipe(list(opened.values()))

    def _session_tag(self, resolved: _Resolved, capture_id: str) -> str | None:
        tag: str | None = None
        try:
            tag = self._digester.session_tag(
                SessionTagInput(
                    namespace=self._namespace,
                    tenant=resolved.tenant,
                    capture_id=capture_id,
                    session_id=resolved.session_id,  # type: ignore[arg-type]
                )
            )
        except RecordCryptoError:
            tag = None
        return tag

    # --------------------------------------------------------------- lifecycle

    async def _lifecycle_start(
        self, operation: Literal["revoke", "delete-ciphertext"], request: LifecycleRequest
    ) -> Any:
        self._open_check()
        code = VaultServerErrorCode
        capture_id = getattr(request, "capture_id", None)
        request_id = getattr(request, "request_id", None)
        if not is_capture_id(capture_id) or not _is_request_id(request_id):
            raise _stop(code.INVALID_ARGUMENT)
        audit_operation = (
            ServerAuditOperation.REVOKE if operation == "revoke" else ServerAuditOperation.DELETE_CIPHERTEXT
        )
        at = self._now()
        who: _Resolved | None = None

        def fail(error: VaultServerErrorCode) -> _Stop:
            self._audit(
                operation=audit_operation,
                outcome="denied" if error == code.LIFECYCLE_DENIED else "failed",
                at=at,
                principal_id=None if who is None else who.principal.id,
                tenant=None if who is None else who.tenant,
                code=error.value,
                capture_id=capture_id,
                request_id=request_id,
            )
            return _stop(error)

        who = await self._resolve(getattr(request, "context", None))
        if who is None:
            raise fail(code.LIFECYCLE_DENIED)
        resolved = who
        scope = StoreScope(namespace=self._namespace, tenant=resolved.tenant)

        def done(result: Any, entries: int) -> Any:
            self._audit(
                operation=audit_operation,
                outcome="committed",
                at=at,
                principal_id=resolved.principal.id,
                tenant=resolved.tenant,
                entries=entries,
                capture_id=capture_id,
                request_id=request_id,
            )
            return result

        kind, captures = await self._store_call(
            False, lambda: self._store.read_captures(ReadCapturesInput(scope=scope, capture_ids=(capture_id,)))
        )
        if kind != "ok":
            raise fail(code.INVARIANT_VIOLATION if kind == "invalid" else code.STORE_UNAVAILABLE)
        if type(captures) is not tuple or len(captures) > 1:
            raise fail(code.INVARIANT_VIOLATION)
        capture: StoredCapture | None = captures[0] if captures else None
        if capture is not None:
            if not isinstance(capture, StoredCapture) or capture.capture_id != capture_id:
                raise fail(code.INVARIANT_VIOLATION)
            if capture.session_tag is not None and not is_session_tag(capture.session_tag):
                raise fail(code.INVARIANT_VIOLATION)
            # A session-bound capture is managed only from its own session.
            if capture.session_tag is not None:
                if resolved.session_id is None:
                    raise fail(code.LIFECYCLE_DENIED)
                expected = self._session_tag(resolved, capture_id)
                if expected is None or not _equal_tags(expected, capture.session_tag):
                    raise fail(code.LIFECYCLE_DENIED)
        allowed = await self._lifecycle(
            operation=operation,
            principal=resolved.principal,
            tenant=resolved.tenant,
            session_id=resolved.session_id,
            capture_id=capture_id,
            session_bound=None if capture is None else capture.session_tag is not None,
            requested_at=at,
        )
        if not allowed:
            raise fail(code.LIFECYCLE_DENIED)
        return resolved, capture, scope, capture_id, fail, done

    async def _revoke_in_store(self, scope: StoreScope, capture_id: str) -> tuple[str, Any]:
        """Revocation is idempotent, so an unknown outcome is reported as unavailable and the caller retries."""

        kind, result = await self._store_call(
            True,
            lambda: self._store.revoke_capture(
                RevokeCaptureInput(
                    scope=scope,
                    capture_id=capture_id,
                    now=self._now(),
                    retention_ms=self._tombstone_retention_ms,
                    fence_absent=False,
                )
            ),
        )
        if kind == "invalid":
            return ("invariant", None)
        if kind != "ok":
            return ("unavailable", None)
        outcome = getattr(result, "outcome", None)
        entries = getattr(result, "entries", 0)
        if outcome == "not-found":
            return ("ok", RevokeResult(outcome="not-found", entries=0))
        if outcome in ("revoked", "already-revoked") and type(entries) is int and entries >= 0:
            return ("ok", RevokeResult(outcome=outcome, entries=entries))
        return ("invariant", None)

    async def _revoke(self, request: LifecycleRequest) -> RevokeResult:
        resolved, capture, scope, capture_id, fail, done = await self._lifecycle_start("revoke", request)
        code = VaultServerErrorCode
        if capture is None:
            return done(RevokeResult(outcome="not-found", entries=0), 0)
        kind, result = await self._revoke_in_store(scope, capture_id)
        if kind == "unavailable":
            raise fail(code.STORE_UNAVAILABLE)
        if kind != "ok":
            raise fail(code.INVARIANT_VIOLATION)
        return done(result, result.entries)

    async def _delete(self, request: LifecycleRequest) -> DeleteCiphertextResult:
        resolved, capture, scope, capture_id, fail, done = await self._lifecycle_start("delete-ciphertext", request)
        code = VaultServerErrorCode
        not_found = DeleteCiphertextResult(outcome="not-found", entries=0)
        if capture is None:
            return done(not_found, 0)
        kind, revoked = await self._revoke_in_store(scope, capture_id)
        if kind == "unavailable":
            raise fail(code.STORE_UNAVAILABLE)
        if kind != "ok":
            raise fail(code.INVARIANT_VIOLATION)
        if revoked.outcome == "not-found":
            return done(not_found, 0)
        kind, deleted = await self._store_call(
            True,
            lambda: self._store.delete_ciphertext(
                DeleteCiphertextInput(scope=scope, capture_id=capture_id, now=self._now())
            ),
        )
        if kind != "ok":
            raise fail(code.INVARIANT_VIOLATION if kind == "invalid" else code.STORE_UNAVAILABLE)
        outcome = getattr(deleted, "outcome", None)
        entries = getattr(deleted, "entries", None)
        if outcome == "deleted" and type(entries) is int and entries >= 0:
            return done(DeleteCiphertextResult(outcome="deleted", entries=entries), entries)
        reason = getattr(deleted, "reason", None) if outcome == "rejected" else None
        if reason == "not-found":
            return done(not_found, 0)
        if reason == "clock-skew":
            raise fail(code.CLOCK_SKEW)
        # "live" after a successful revoke means the store contradicted itself.
        raise fail(code.INVARIANT_VIOLATION)

    async def _resolve_attempt(self, request: ResolveAttemptRequest) -> ResolveAttemptResult:
        self._open_check()
        code = VaultServerErrorCode
        parsed = self._parse_restore(request)
        if parsed.attempt_id is None or parsed.invalid or parsed.malformed:
            raise _stop(code.INVALID_ARGUMENT)
        at = self._now()
        request_id, attempt_id = parsed.request_id, parsed.attempt_id
        who: _Resolved | None = None

        def fail(error: VaultServerErrorCode) -> _Stop:
            self._audit(
                operation=ServerAuditOperation.RESOLVE_ATTEMPT,
                outcome="denied" if error == code.LIFECYCLE_DENIED else "failed",
                at=at,
                principal_id=None if who is None else who.principal.id,
                tenant=None if who is None else who.tenant,
                code=error.value,
                attempt_id=attempt_id,
                request_id=request_id,
            )
            return _stop(error)

        who = await self._resolve(parsed.context)
        if who is None:
            raise fail(code.LIFECYCLE_DENIED)
        resolved = who
        allowed = await self._lifecycle(
            operation="resolve-attempt",
            principal=resolved.principal,
            tenant=resolved.tenant,
            session_id=resolved.session_id,
            requested_at=at,
        )
        if not allowed:
            raise fail(code.LIFECYCLE_DENIED)
        # The same bound a restore has: no attempt over it could have committed.
        if len(parsed.uses) > self._capabilities.max_restore_entries:
            raise fail(code.INVALID_ARGUMENT)
        uses: dict[str, _Use] = {}
        derive_failed = False
        try:
            for token, (count, paths) in parsed.uses.items():
                entry_id = derive_entry_id(self._namespace, resolved.tenant, token)
                uses[entry_id] = _Use(token=token, entry_id=entry_id, count=count, paths=dict(paths))
        except RecordCryptoError:
            derive_failed = True
        if derive_failed:
            raise _stop(code.INVALID_ARGUMENT)
        digest = self._request_digest(resolved, parsed, uses)
        if digest is None:
            raise _stop(code.INVALID_ARGUMENT)
        scope = StoreScope(namespace=self._namespace, tenant=resolved.tenant)
        kind, inspected = await self._store_call(
            False, lambda: self._store.inspect_attempt(InspectAttemptInput(scope=scope, attempt_id=attempt_id))
        )
        if kind != "ok":
            raise fail(code.INVARIANT_VIOLATION if kind == "invalid" else code.STORE_UNAVAILABLE)
        state = getattr(inspected, "state", None)
        if state == "absent":
            result = ResolveAttemptResult(state="absent")
        elif (
            state == "committed"
            and isinstance(getattr(inspected, "request_digest", None), bytes)
            and is_timestamp(getattr(inspected, "committed_at", None))
        ):
            if _equal_tags(inspected.request_digest.hex(), digest.hex()):
                result = ResolveAttemptResult(state="committed", committed_at=inspected.committed_at)
            else:
                result = ResolveAttemptResult(state="attempt-mismatch")
        else:
            raise fail(code.INVARIANT_VIOLATION)
        self._audit(
            operation=ServerAuditOperation.RESOLVE_ATTEMPT,
            outcome="committed",
            at=at,
            principal_id=resolved.principal.id,
            tenant=resolved.tenant,
            attempt_id=attempt_id,
            request_id=request_id,
        )
        return result

    # ------------------------------------------------------------------- parsing

    def _parse_restore(self, request: PersistentRestoreRequest) -> _Parsed:
        """Shape validation and the field snapshot (section 7.2 step 1). Programming errors are ``INVALID_ARGUMENT``;
        anything a model's output could cause is recorded and denied by the caller after the principal is known."""

        code = VaultServerErrorCode
        # A request is read by attribute only: a ``tenant`` or ``session_id`` on it is never looked at.
        context = getattr(request, "context", None)
        sink = getattr(request, "sink", None)
        purpose = getattr(request, "purpose", None)
        captures = getattr(request, "captures", None)
        fields = getattr(request, "fields", None)
        attempt_id = getattr(request, "attempt_id", None)
        request_id = getattr(request, "request_id", None)
        if request is None or not is_identifier(sink):
            raise _stop(code.INVALID_ARGUMENT)
        if (
            type(purpose) is not str
            or not is_well_formed(purpose)
            or _utf8_length(purpose) > _limits.PURPOSE_MAX_BYTES
            or count_markers(purpose) > 0
        ):
            raise _stop(code.INVALID_ARGUMENT)
        if attempt_id is not None and not is_attempt_id(attempt_id):
            raise _stop(code.INVALID_ARGUMENT)
        if not _is_request_id(request_id):
            raise _stop(code.INVALID_ARGUMENT)
        if (
            not isinstance(captures, (tuple, list))
            or len(captures) == 0
            or len(captures) > self._capabilities.max_restore_captures
        ):
            raise _stop(code.INVALID_ARGUMENT)
        sources: dict[str, None] = {}
        for capture_id in captures:
            if not is_capture_id(capture_id):
                raise _stop(code.INVALID_ARGUMENT)
            sources[capture_id] = None
        if not isinstance(fields, Mapping):
            raise _stop(code.INVALID_ARGUMENT)

        parsed = _Parsed(
            context=context,
            sink=sink,
            purpose=purpose,
            sources=tuple(sources),
            attempt_id=attempt_id,
            request_id=request_id,
            snapshot=[],
            uses={},
        )
        keys = list(fields.keys())
        if len(keys) > self._limits["max_restore_fields"]:
            parsed.invalid = True
            return parsed
        for path in keys:
            text = fields[path]
            if (
                not is_identifier(path)
                or type(text) is not str
                or _utf8_length(text) > self._limits["max_restore_field_bytes"]
            ):
                parsed.invalid = True
                return parsed
            parsed.snapshot.append((path, text))
        for path, text in parsed.snapshot:
            tokens = TOKEN_PATTERN.findall(text)
            if count_markers(text) != len(tokens):
                parsed.malformed = True
                return parsed
            for token in tokens:
                count, paths = parsed.uses.get(token, (0, {}))
                paths[path] = paths.get(path, 0) + 1
                parsed.uses[token] = (count + 1, paths)
        return parsed


# ------------------------------------------------------------------------- helpers


def _zero_all(buffers: list[bytearray]) -> None:
    for buffer in buffers:
        _buffers.zero(buffer)


async def _swallow(awaitable: Awaitable[Any]) -> None:
    try:
        await awaitable
    except Exception:
        return


def _equal_tags(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("ascii", "replace"), b.encode("ascii", "replace"))


def _is_payload(payload: object) -> bool:
    if (
        not isinstance(payload, RecordPayload)
        or not isinstance(payload.value, bytearray)
        or type(payload.type) is not str
    ):
        return False
    if payload.policy_revision is not None and type(payload.policy_revision) is not str:
        return False
    if type(payload.grants) is not tuple:
        return False
    for grant in payload.grants:
        if not isinstance(grant, Grant) or type(grant.sink) is not str or type(grant.paths) is not tuple:
            return False
        if any(type(path) is not str for path in grant.paths):
            return False
    return True


def _inspect_read(
    read: object, uses: dict[str, _Use]
) -> tuple[Any, dict[str, StoredEntry], dict[str, StoredCapture]] | None:
    """Checks what a store returned from ``read_entries`` before any of it is used. A faulty or hostile store must not
    make the server act on an entry it did not ask for, an entry without its capture, or a malformed number. ``None``
    when the result is not usable; the caller fails closed."""

    if not isinstance(read, ReadEntriesResult):
        return None
    recovery, entries, captures = read.recovery, read.entries, read.captures
    if (
        type(recovery.state) is not str
        or type(recovery.epoch) is not int
        or not 0 <= recovery.epoch <= _limits.MAX_TIMESTAMP
    ):
        return None
    if type(entries) is not tuple or type(captures) is not tuple:
        return None

    def positive(value: object) -> bool:
        return type(value) is int and 1 <= value <= _limits.MAX_TIMESTAMP

    capture_map: dict[str, StoredCapture] = {}
    for capture in captures:
        if (
            not isinstance(capture, StoredCapture)
            or not is_capture_id(capture.capture_id)
            or capture.capture_id in capture_map
        ):
            return None
        if capture.state not in ("live", "revoked"):
            return None
        if (
            not positive(capture.generation)
            or not is_timestamp(capture.created_at)
            or not is_timestamp(capture.expires_at)
        ):
            return None
        if capture.session_tag is not None and not is_session_tag(capture.session_tag):
            return None
        if capture.state == "live":
            if (
                not is_key_ref(capture.key_ref)
                or not isinstance(capture.wrapped_key, bytes)
                or len(capture.wrapped_key) == 0
            ):
                return None
            # A lower epoch must already read as revoked (section 5.1); a live one from another epoch contradicts it.
            if capture.epoch != recovery.epoch:
                return None
        capture_map[capture.capture_id] = capture

    entry_map: dict[str, StoredEntry] = {}
    used_captures: set[str] = set()
    for entry in entries:
        if not isinstance(entry, StoredEntry) or not is_entry_id(entry.entry_id):
            return None
        if entry.entry_id not in uses or entry.entry_id in entry_map:
            return None
        if not is_capture_id(entry.capture_id) or entry.capture_id not in capture_map:
            return None
        if not positive(entry.max_uses) or entry.max_uses > _limits.MAX_USES:
            return None
        if type(entry.used) is not int or not 0 <= entry.used <= _limits.MAX_TIMESTAMP:
            return None
        if not positive(entry.lifecycle_revision) or not positive(entry.ciphertext_revision):
            return None
        if not isinstance(entry.envelope, bytes) or not 0 < len(entry.envelope) <= _limits.MAX_ENVELOPE_BYTES:
            return None
        entry_map[entry.entry_id] = entry
        used_captures.add(entry.capture_id)
    # Only the captures of returned entries are considered.
    return recovery, entry_map, {key: value for key, value in capture_map.items() if key in used_captures}
