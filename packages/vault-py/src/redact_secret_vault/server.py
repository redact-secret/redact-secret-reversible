"""``InMemoryVaultServer``: capture plus the S1 restore-authority contract.

Capture (an in-memory analogue of ``@redact-secret/vault``'s whole-input
capture, packages/vault/src/vault.ts) is this package's own extension — the
S1 ADR is explicitly restore-only. ``restore`` implements the ADR's exact
nine-step preflight order (section 3):

1. Resolve principal -> ``unauthenticated``
2. Marker/grammar and known-entry -> ``malformed-token`` / ``unknown-token``
   (or ``revoked`` when a revocation tombstone is live)
3. Source binding -> ``source``
4. Tenant match -> ``tenant-mismatch``
5. Expiry -> ``expired``
6. Sink/path grant -> ``sink-or-path``
7. Purpose presence -> ``missing-purpose``
8. Budget -> ``budget``
9. ``ServerReleasePolicy`` -> ``policy`` or a more specific reason

Every occurrence of every path is checked before any plaintext or budget
change is visible; one denial fails the whole request (all-or-nothing,
mirroring decision-define-restore-transaction-boundary.md).
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, NoReturn

from .capture_plan import CAPTURE_DEFAULT_LIMITS, CAPTURE_LIMIT_CEILINGS, plan_capture
from .core_client import CoreClient
from .errors import ServerDenialReason, VaultServerError, VaultServerErrorCode
from .token import TOKEN_PATTERN, count_markers, find_tokens, new_capture_id
from .types import (
    CaptureOptions,
    CaptureResult,
    IssuedToken,
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

DEFAULT_LIMITS: Mapping[str, int] = {
    **CAPTURE_DEFAULT_LIMITS,
    # Server-only addition (ADR section 4): how long a revoked token's
    # capture/tenant is remembered so a later restore attempt can report
    # "revoked" rather than "unknown-token". Not part of the in-memory vault.
    "revocation_tombstone_ttl_ms": 5 * 60 * 1000,
}

_LIMIT_CEILINGS: Mapping[str, int] = {
    **CAPTURE_LIMIT_CEILINGS,
    "revocation_tombstone_ttl_ms": 24 * 60 * 60 * 1000,
}

_MAX_IDENTIFIER_LENGTH = 256
_MAX_GRANTS = 64
_TOKEN_ATTEMPTS = 4


def _is_identifier(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= _MAX_IDENTIFIER_LENGTH


def _utf8_length(text: str) -> int:
    return len(text.encode("utf-8"))


@dataclass
class _Entry:
    value: str
    type: str
    capture_id: str
    issued_tenant: str
    grants: dict[str, set[str]]
    max_uses: int
    used: int
    expires_at: int
    bytes: int


@dataclass
class _Tombstone:
    capture_id: str
    issued_tenant: str
    expires_at: int


class InMemoryVaultServer:
    """Server-side, in-memory implementation of the S1 authority contract.

    Storage is a plain process-local dict, matching
    ``@redact-secret/vault``'s in-memory model and threat boundary: values
    are retained in this process's memory only, for as long as an entry's
    TTL, with no persistence, no encryption-at-rest, and no cross-process
    coordination. A qualified persistent store is #19's scope, not this
    package's.
    """

    def __init__(
        self,
        *,
        core_client: CoreClient,
        principal_resolver: PrincipalResolver | None = None,
        release_policy: ServerReleasePolicy | None = None,
        on_audit: ServerAuditHook | None = None,
        limits: Mapping[str, int] | None = None,
        now: Callable[[], float] | None = None,
        policy_timeout_s: float = 5.0,
    ) -> None:
        self._core = core_client
        self._principal_resolver = principal_resolver
        self._release_policy = release_policy
        self._on_audit = on_audit
        self._limits = self._resolve_limits(limits)
        self._now = now or _default_clock()
        self._policy_timeout_s = policy_timeout_s

        self._entries: dict[str, _Entry] = {}
        self._captures: dict[str, set[str]] = {}
        self._tombstones: dict[str, _Tombstone] = {}
        self._retained_bytes = 0
        self._disposed = False
        self._busy = False
        # Monotonic: a clock moving backwards cannot extend any lifetime.
        # Mirrors `createVault`'s `latest = Math.max(latest, value)` wrapper
        # (packages/vault/src/vault.ts:L199-L213), applied to *every* read of
        # `now`, not only the ones on the `_run`/`_run_async` operation
        # boundary.
        self._latest = float("-inf")
        self._created_at = self._now_or_raise()
        self._expires_at = self._created_at + self._limits["vault_ttl_ms"]

    @staticmethod
    def _resolve_limits(partial: Mapping[str, int] | None) -> dict[str, int]:
        resolved = dict(DEFAULT_LIMITS)
        for key, value in (partial or {}).items():
            if key not in DEFAULT_LIMITS:
                raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
            if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= _LIMIT_CEILINGS[key]):
                raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
            resolved[key] = value
        return resolved

    # -- clock ---------------------------------------------------------

    def _now_raw(self) -> float:
        try:
            value = self._now()
        except Exception as exc:
            raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT) from exc
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
        if value != value or value in (float("inf"), float("-inf")):  # NaN check
            raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
        return value

    def _now_or_raise(self) -> int:
        value = self._now_raw()
        if value > self._latest:
            self._latest = value
        return int(self._latest)

    def _now_or_nan(self) -> float:
        try:
            return self._now_or_raise()
        except VaultServerError:
            return float("nan")

    # -- audit -----------------------------------------------------------

    def _audit(self, event: ServerAuditEvent) -> None:
        if self._on_audit is None:
            return
        try:
            self._on_audit(event)
        except Exception:
            pass  # An audit hook's failure never changes an operation's outcome.

    # -- operation boundary -----------------------------------------------

    def _run(self, body: Callable[[int], Any]) -> Any:
        if self._busy:
            raise VaultServerError(VaultServerErrorCode.BUSY)
        if self._disposed:
            raise VaultServerError(VaultServerErrorCode.DISPOSED)
        self._busy = True
        try:
            at = self._now_or_raise()
            if at >= self._expires_at:
                self._dispose_all()
                raise VaultServerError(VaultServerErrorCode.DISPOSED)
            return body(at)
        finally:
            self._busy = False

    async def _run_async(self, body: Callable[[int], Any]) -> Any:
        if self._busy:
            raise VaultServerError(VaultServerErrorCode.BUSY)
        if self._disposed:
            raise VaultServerError(VaultServerErrorCode.DISPOSED)
        self._busy = True
        try:
            at = self._now_or_raise()
            if at >= self._expires_at:
                self._dispose_all()
                raise VaultServerError(VaultServerErrorCode.DISPOSED)
            try:
                return await body(at)
            except VaultServerError as error:
                if error.code != VaultServerErrorCode.DISPOSED:
                    self._audit(
                        ServerAuditEvent(
                            operation=ServerAuditOperation.RESTORE,
                            outcome="denied" if error.code == VaultServerErrorCode.RESTORE_DENIED else "failed",
                            at=at,
                            code=error.code.value,
                            reason=error.reason,
                        )
                    )
                raise
        finally:
            self._busy = False

    # -- entry/capture bookkeeping -----------------------------------------

    def _issue_capture_id(self) -> str:
        for _ in range(_TOKEN_ATTEMPTS):
            capture_id = new_capture_id()
            if capture_id not in self._captures:
                return capture_id
        raise VaultServerError(VaultServerErrorCode.TOKEN_GENERATION_FAILED)

    def _remove_entry(self, token: str, entry: _Entry) -> None:
        self._entries.pop(token, None)
        self._retained_bytes -= entry.bytes
        entry.value = ""
        tokens = self._captures.get(entry.capture_id)
        if tokens is not None:
            tokens.discard(token)
            if not tokens:
                self._captures.pop(entry.capture_id, None)

    def _remove_capture(self, capture_id: str, at: int, *, tombstone: bool) -> int:
        tokens = self._captures.get(capture_id)
        if tokens is None:
            return 0
        removed = 0
        for token in list(tokens):
            entry = self._entries.get(token)
            if entry is not None:
                issued_tenant = entry.issued_tenant
                self._remove_entry(token, entry)
                removed += 1
                if tombstone:
                    self._tombstones[token] = _Tombstone(
                        capture_id=capture_id,
                        issued_tenant=issued_tenant,
                        expires_at=at + self._limits["revocation_tombstone_ttl_ms"],
                    )
        self._captures.pop(capture_id, None)
        return removed

    def _sweep(self, at: int) -> None:
        for token, entry in list(self._entries.items()):
            if at >= entry.expires_at:
                self._remove_entry(token, entry)
        for token, tombstone in list(self._tombstones.items()):
            if at >= tombstone.expires_at:
                self._tombstones.pop(token, None)

    def _dispose_all(self) -> int:
        removed = len(self._entries)
        for entry in self._entries.values():
            entry.value = ""
        self._entries.clear()
        self._captures.clear()
        self._tombstones.clear()
        self._retained_bytes = 0
        self._disposed = True
        return removed

    # -- public API: capture ------------------------------------------------

    def capture(self, input_text: str, options: CaptureOptions) -> CaptureResult:
        """Scan ``input_text`` through the qualified core boundary, retain
        eligible ``redact`` findings under issued tokens, and return
        redacted text. Never calls ``on_audit``: capture is outside the S1
        ADR's audit vocabulary (``resolve-principal``/``restore``/``revoke``/
        ``policy-error``), which is restore-only by design.
        """

        return self._run(lambda at: self._capture(input_text, options, at))

    def _capture(self, input_text: str, options: CaptureOptions, at: int) -> CaptureResult:
        if not isinstance(input_text, str):
            raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
        if not _is_identifier(options.issued_tenant):
            raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)

        def budget() -> tuple[int, int]:
            # Read once by the plan, after its input checks and before the core scan.
            self._sweep(at)
            return len(self._entries), self._retained_bytes

        # Everything a capture decides before it retains anything is the shared capture plan
        # (redact_secret_vault.capture_plan), which the persistent server profile also runs.
        plan = plan_capture(
            self._core,
            input_text,
            options,
            self._limits,
            budget=budget,
            is_taken=lambda token: token in self._entries,
        )

        capture_id = self._issue_capture_id()
        expires_at = at + self._limits["entry_ttl_ms"]
        tokens: list[IssuedToken] = []
        capture_tokens: set[str] = set()
        for planned in plan.retained:
            value = plan.value_of(input_text, planned)
            self._entries[planned.token] = _Entry(
                value=value,
                type=planned.type,
                capture_id=capture_id,
                issued_tenant=options.issued_tenant,
                grants={grant.sink: set(grant.paths) for grant in plan.grants},
                max_uses=plan.max_uses,
                used=0,
                expires_at=expires_at,
                bytes=_utf8_length(value),
            )
            self._retained_bytes += _utf8_length(value)
            capture_tokens.add(planned.token)
            tokens.append(IssuedToken(token=planned.token, type=planned.type))
        if capture_tokens:
            self._captures[capture_id] = capture_tokens

        return CaptureResult(
            capture_id=capture_id,
            text=plan.text,
            tokens=tuple(tokens),
            passed_through=plan.passed_through,
            passed_through_types=plan.passed_through_types,
            unrestorable=plan.unrestorable,
            expires_at=expires_at,
        )

    # -- public API: restore -------------------------------------------------

    async def restore(self, request: RestoreRequest) -> RestoreResult:
        return await self._run_async(lambda at: self._restore(request, at))

    async def _resolve_principal(self, context: Any, at: int) -> Principal | None:
        if self._principal_resolver is None:
            self._audit(
                ServerAuditEvent(
                    operation=ServerAuditOperation.RESOLVE_PRINCIPAL,
                    outcome="failed",
                    at=at,
                    reason=ServerDenialReason.UNAUTHENTICATED,
                )
            )
            return None
        try:
            result = self._principal_resolver(context)
            if inspect.isawaitable(result):
                result = await result
            if not isinstance(result, Principal):
                raise TypeError("PrincipalResolver returned a non-Principal value")
            return result
        except Exception:
            self._audit(
                ServerAuditEvent(
                    operation=ServerAuditOperation.RESOLVE_PRINCIPAL,
                    outcome="failed",
                    at=at,
                    reason=ServerDenialReason.UNAUTHENTICATED,
                )
            )
            return None

    async def _restore(self, request: RestoreRequest, at: int) -> RestoreResult:
        # Structural validation -> INVALID_ARGUMENT, mirroring vault.ts's
        # `#restore` checks before its `deny` closure exists.
        if not _is_identifier(request.sink):
            raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
        if not isinstance(request.fields, Mapping):
            raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
        if not request.captures or len(request.captures) > _MAX_GRANTS * 16:
            raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
        sources: set[str] = set()
        for capture_id in request.captures:
            if not _is_identifier(capture_id):
                raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
            sources.add(capture_id)
        if not isinstance(request.purpose, str):
            raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)

        def deny(reason: ServerDenialReason) -> NoReturn:
            self._sweep(at)
            raise VaultServerError(VaultServerErrorCode.RESTORE_DENIED, reason=reason)

        # Field-shape and size limits -> RESTORE_DENIED("invalid-request"),
        # not INVALID_ARGUMENT: these describe the caller-supplied fields
        # dict, not the call's own shape, matching vault.ts's
        # `deny("invalid-request")` for the same checks
        # (packages/vault/src/vault.ts:L552-L562).
        keys = list(request.fields.keys())
        if len(keys) > self._limits["max_restore_fields"]:
            deny(ServerDenialReason.INVALID_REQUEST)
        snapshot: list[tuple[str, str]] = []
        for path in keys:
            text = request.fields[path]
            if not _is_identifier(path) or not isinstance(text, str):
                deny(ServerDenialReason.INVALID_REQUEST)
            if _utf8_length(text) > self._limits["max_restore_field_bytes"]:
                deny(ServerDenialReason.INVALID_REQUEST)
            snapshot.append((path, text))

        # Step 1: resolve principal.
        principal = await self._resolve_principal(request.context, at)
        if principal is None:
            deny(ServerDenialReason.UNAUTHENTICATED)
        tenant = request.tenant if request.tenant is not None else principal.tenant

        # Step 2: marker/grammar and known-entry.
        uses: dict[str, dict[str, Any]] = {}
        occurrences = 0
        for path, text in snapshot:
            tokens_found = find_tokens(text)
            if count_markers(text) != len(tokens_found):
                deny(ServerDenialReason.MALFORMED_TOKEN)
            for token in tokens_found:
                entry = self._entries.get(token)
                if entry is None:
                    tombstone = self._tombstones.get(token)
                    if tombstone is not None and at < tombstone.expires_at:
                        deny(ServerDenialReason.REVOKED)
                    deny(ServerDenialReason.UNKNOWN_TOKEN)
                use = uses.setdefault(token, {"entry": entry, "count": 0, "paths": {}})
                use["count"] += 1
                use["paths"][path] = use["paths"].get(path, 0) + 1
                occurrences += 1

        # Step 3: source binding.
        for use in uses.values():
            if use["entry"].capture_id not in sources:
                deny(ServerDenialReason.SOURCE)

        # Step 4: tenant match.
        for use in uses.values():
            if tenant != use["entry"].issued_tenant:
                deny(ServerDenialReason.TENANT_MISMATCH)

        # Step 5: expiry.
        for use in uses.values():
            if at >= use["entry"].expires_at:
                deny(ServerDenialReason.EXPIRED)

        # Step 6: sink/path grant.
        for use in uses.values():
            allowed = use["entry"].grants.get(request.sink)
            for path in use["paths"]:
                if allowed is None or path not in allowed:
                    deny(ServerDenialReason.SINK_OR_PATH)

        # Step 7: purpose presence.
        if not request.purpose:
            deny(ServerDenialReason.MISSING_PURPOSE)

        # Step 8: budget.
        for use in uses.values():
            entry = use["entry"]
            if entry.used + use["count"] > entry.max_uses:
                deny(ServerDenialReason.BUDGET)

        # Step 9: ServerReleasePolicy — fresh per occurrence of every path,
        # fail-closed with no configured policy.
        for use in uses.values():
            entry = use["entry"]
            for path, count in use["paths"].items():
                decision_input = RestoreDecisionInput(
                    principal=principal,
                    tenant=tenant,
                    source=RestoreSource(
                        capture_id=entry.capture_id,
                        issued_tenant=entry.issued_tenant,
                        session_id=request.session_id,
                    ),
                    sink=request.sink,
                    path=path,
                    purpose=request.purpose,
                    type=entry.type,
                    occurrences=count,
                    total_occurrences=use["count"],
                    used=entry.used,
                    max_uses=entry.max_uses,
                    requested_at=at,
                    policy_revision=request.policy_revision,
                )
                if self._release_policy is None:
                    deny(ServerDenialReason.POLICY)
                try:
                    decision = self._release_policy(decision_input)
                    if inspect.isawaitable(decision):
                        decision = await asyncio.wait_for(decision, timeout=self._policy_timeout_s)
                    if not isinstance(decision, PolicyDecision):
                        raise TypeError("ServerReleasePolicy returned a non-conforming value")
                except Exception:
                    self._audit(
                        ServerAuditEvent(
                            operation=ServerAuditOperation.POLICY_ERROR,
                            outcome="failed",
                            at=at,
                            principal_id=principal.id,
                            tenant=tenant,
                            sink=request.sink,
                            path=path,
                            purpose=request.purpose,
                            reason=ServerDenialReason.POLICY_EVALUATION_ERROR,
                            policy_revision=request.policy_revision,
                            request_id=request.request_id,
                        )
                    )
                    deny(ServerDenialReason.POLICY_EVALUATION_ERROR)
                if not decision.allow:
                    deny(decision.reason or ServerDenialReason.POLICY)

        # Commit: every occurrence of every path passed. Consume budgets,
        # then build the restored fields. No plaintext was visible before
        # this point.
        out: dict[str, str] = {}
        for path, text in snapshot:
            def _substitute(match, _uses=uses):
                return _uses[match.group(0)]["entry"].value

            out[path] = TOKEN_PATTERN.sub(_substitute, text)
        for token, use in uses.items():
            entry = use["entry"]
            entry.used += use["count"]
            if entry.used >= entry.max_uses:
                self._remove_entry(token, entry)
        self._sweep(at)
        self._audit(
            ServerAuditEvent(
                operation=ServerAuditOperation.RESTORE,
                outcome="committed",
                at=at,
                entries=len(uses),
                sink=request.sink,
                tenant=tenant,
                principal_id=principal.id,
                purpose=request.purpose,
                policy_revision=request.policy_revision,
                request_id=request.request_id,
            )
        )
        return RestoreResult(fields=out, restored=occurrences)

    # -- public API: revoke / dispose / stats --------------------------------

    def revoke(self, capture_id: str) -> int:
        """Removes every live entry of one capture and records a
        short-lived revocation tombstone for each removed token, so a
        subsequent restore attempt against it denies with ``"revoked"``
        rather than ``"unknown-token"`` (ADR section 4)."""

        if self._disposed:
            return 0

        def body(at: int) -> int:
            if not isinstance(capture_id, str):
                raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
            removed = self._remove_capture(capture_id, at, tombstone=True)
            self._audit(
                ServerAuditEvent(operation=ServerAuditOperation.REVOKE, outcome="committed", at=at, entries=removed)
            )
            return removed

        return self._run(body)

    def dispose(self) -> None:
        if self._disposed:
            return
        if self._busy:
            raise VaultServerError(VaultServerErrorCode.BUSY)
        self._busy = True
        try:
            self._dispose_all()
        finally:
            self._busy = False

    def stats(self) -> VaultServerStats:
        if not self._disposed and not self._busy:
            self._busy = True
            try:
                at = self._now_or_nan()
                if at == at:  # not NaN
                    at = int(at)
                    if at >= self._expires_at:
                        self._dispose_all()
                    else:
                        self._sweep(at)
            except Exception:
                pass
            finally:
                self._busy = False
        return VaultServerStats(
            entries=len(self._entries),
            retained_bytes=self._retained_bytes,
            captures=len(self._captures),
            disposed=self._disposed,
            expires_at=self._expires_at,
        )


def _default_clock() -> Callable[[], float]:
    import time

    base = time.time() * 1000 - time.monotonic() * 1000

    def clock() -> float:
        return base + time.monotonic() * 1000

    return clock


async def create_vault_server(
    *,
    core_client: CoreClient,
    principal_resolver: PrincipalResolver | None = None,
    release_policy: ServerReleasePolicy | None = None,
    on_audit: ServerAuditHook | None = None,
    limits: Mapping[str, int] | None = None,
    now: Callable[[], float] | None = None,
    policy_timeout_s: float = 5.0,
) -> InMemoryVaultServer:
    """Async factory mirroring ``createVault`` (packages/vault/src/vault.ts).
    A plain constructor call works identically; this exists for symmetry
    with the JS async factory and for future async setup (for example,
    verifying the core bridge is reachable before accepting requests)."""

    return InMemoryVaultServer(
        core_client=core_client,
        principal_resolver=principal_resolver,
        release_policy=release_policy,
        on_audit=on_audit,
        limits=limits,
        now=now,
        policy_timeout_s=policy_timeout_s,
    )
