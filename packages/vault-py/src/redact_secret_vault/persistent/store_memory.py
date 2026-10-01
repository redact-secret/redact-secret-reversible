"""Volatile reference ``Store`` in process memory. Standard library only.

A ciphertext-only, non-durable, single-process store (docs/specs/persistent-vault.md
section 5), the Python counterpart of ``@redact-secret/store-memory``. It holds
envelopes, wrapped keys, counters, and receipts in memory. It never decrypts,
never holds a key, never resolves a principal, and never evaluates a policy.
Everything is lost when the process exits.

**Python persistence is not implemented and not supported.** This module is the
reference the schedule corpus and the persistent server profile are first run
against; it says nothing about a database adapter, and it is not durability.

Concurrency (docs/plans/python-persistence-parity.md section 3.7): the reference
store holds a ``threading.Lock`` for the whole of each operation's atomic
section and performs no ``await`` while holding it. The lock, not the GIL, is
what the store relies on, so the atomicity also holds across threads, across
event loops in one process, and on a free-threaded build. It still declares
``cross_process=False`` and ``durability="volatile"``: a lock in one process
orders nothing between processes.

The store has no hold point and no fault hook: tests that need to pause a call
or make it fail wrap or subclass the store in the test tree.
"""

from __future__ import annotations

import asyncio
import hmac
import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

from . import limits as _limits
from .contracts import (
    AttemptAbsent,
    AttemptCommitted,
    CaptureCreated,
    CaptureFenced,
    CaptureKeyRejected,
    CaptureKeyReplaced,
    CaptureNotFound,
    CaptureRejected,
    CaptureRevoked,
    CiphertextDeleted,
    CiphertextRejected,
    CommitRestoreInput,
    CommitRestoreResult,
    CreateCaptureInput,
    CreateCaptureResult,
    DeleteCiphertextInput,
    DeleteCiphertextResult,
    InitializeNamespaceResult,
    InspectAttemptInput,
    InspectAttemptResult,
    InvalidateRecoveredInput,
    InvalidateRecoveredResult,
    InvalidateRejected,
    NamespaceInitialized,
    NamespaceRejected,
    ReadCapturesInput,
    ReadEntriesInput,
    ReadEntriesResult,
    RecoveredInvalidated,
    RecoveryState,
    ReplaceCaptureKeyInput,
    ReplaceCaptureKeyResult,
    RestoreAlreadyCommitted,
    RestoreAttemptMismatch,
    RestoreCommitted,
    RestoreRejected,
    RevokeCaptureInput,
    RevokeCaptureResult,
    StoreCapabilities,
    StoredCapture,
    StoredEntry,
    StoreScope,
    SweepInput,
    SweepRejected,
    SweepResult,
    Swept,
)
from .errors import StoreError
from .validate import (
    validate_commit_restore,
    validate_create_capture,
    validate_delete_ciphertext,
    validate_initialize_namespace,
    validate_inspect_attempt,
    validate_invalidate_recovered,
    validate_namespace,
    validate_read_captures,
    validate_read_entries,
    validate_replace_capture_key,
    validate_revoke_capture,
    validate_sweep,
)

__all__ = ["MemoryStore", "create_memory_store"]

_DEFAULT_MAX_CLOCK_SKEW_MS: Final = 2000
_MAX_CLOCK_SKEW_CEILING_MS: Final = 60_000
_DEFAULT_MAX_CREATE_BYTES: Final = 16 * 1024 * 1024


@dataclass(slots=True)
class _Recovery:
    epoch: int
    state: str


@dataclass(slots=True)
class _CaptureRow:
    capture_id: str
    state: str
    generation: int
    key_revision: int
    epoch: int
    session_tag: str | None
    created_at: int
    expires_at: int
    key_ref: str
    wrapped_key: bytes
    #: A fence, or a capture whose ciphertext was deleted: it holds no key.
    keyless: bool
    #: Set by a revocation: the tombstone is kept while the store clock is at or before this.
    keep_until: int | None
    entry_ids: set[str] = field(default_factory=set)


@dataclass(slots=True)
class _EntryRow:
    entry_id: str
    capture_id: str
    max_uses: int
    used: int
    lifecycle_revision: int
    ciphertext_revision: int
    envelope: bytes


@dataclass(slots=True)
class _ReceiptRow:
    request_digest: bytes
    committed_at: int
    receipt_expires_at: int


@dataclass(slots=True)
class _TenantRows:
    captures: dict[str, _CaptureRow] = field(default_factory=dict)
    entries: dict[str, _EntryRow] = field(default_factory=dict)
    receipts: dict[str, _ReceiptRow] = field(default_factory=dict)

    def empty(self) -> bool:
        return not self.captures and not self.entries and not self.receipts


@dataclass(slots=True)
class _Namespace:
    recovery: _Recovery | None = None
    tenants: dict[str, _TenantRows] = field(default_factory=dict)


def _lowered(name: str, value: int | None, ceiling: int) -> int:
    if value is None:
        return ceiling
    if type(value) is not int or not 1 <= value <= ceiling:
        raise ValueError(f"create_memory_store: {name} must be an integer from 1 to its default")
    return value


class MemoryStore:
    """The reference ``Store``. See the module docstring.

    The decisions that a mutation control breaks (who is revoked, who is serving,
    the verdict of a commit, what a sweep may remove) are small protected methods,
    so a test can subclass the store and break exactly one. Nothing in the module
    switches a defect on.
    """

    def __init__(
        self,
        *,
        now: Callable[[], int | float] | None = None,
        max_clock_skew_ms: int = _DEFAULT_MAX_CLOCK_SKEW_MS,
        max_create_entries: int | None = None,
        max_create_bytes: int | None = None,
        max_restore_entries: int | None = None,
        max_restore_captures: int | None = None,
        max_envelope_bytes: int | None = None,
    ) -> None:
        if now is not None and not callable(now):
            raise TypeError("create_memory_store: now must be callable")
        if type(max_clock_skew_ms) is not int or not 0 <= max_clock_skew_ms <= _MAX_CLOCK_SKEW_CEILING_MS:
            raise ValueError("create_memory_store: max_clock_skew_ms must be an integer from 0 to 60000")
        self._read_clock = now if now is not None else (lambda: time.time_ns() // 1_000_000)
        self._skew = max_clock_skew_ms
        self._capabilities = StoreCapabilities(
            contract_version=1,
            adapter="store-memory-py",
            profile="process-memory",
            atomic_create=True,
            max_create_entries=_lowered("max_create_entries", max_create_entries, _limits.MAX_CREATE_ENTRIES),
            max_create_bytes=_lowered("max_create_bytes", max_create_bytes, _DEFAULT_MAX_CREATE_BYTES),
            atomic_restore=True,
            max_restore_entries=_lowered("max_restore_entries", max_restore_entries, _limits.MAX_RESTORE_ENTRIES),
            max_restore_captures=_lowered("max_restore_captures", max_restore_captures, _limits.MAX_RESTORE_CAPTURES),
            authoritative_commit=True,
            revocation_fences=True,
            attempt_receipts=True,
            store_clock=True,
            max_clock_skew_ms=max_clock_skew_ms,
            durability="volatile",
            cross_process=False,
            restore_detection="none",
            max_envelope_bytes=_lowered("max_envelope_bytes", max_envelope_bytes, _limits.MAX_ENVELOPE_BYTES),
        )
        self._namespaces: dict[str, _Namespace] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ helpers

    def capabilities(self) -> StoreCapabilities:
        return self._capabilities

    def _store_now(self) -> int:
        reading = self._read_clock()
        if type(reading) is bool or not isinstance(reading, (int, float)):
            raise StoreError("STORE_UNAVAILABLE")
        if isinstance(reading, float) and not math.isfinite(reading):
            raise StoreError("STORE_UNAVAILABLE")
        value = math.floor(reading)
        if not 0 <= value <= _limits.MAX_TIMESTAMP:
            raise StoreError("STORE_UNAVAILABLE")
        return value

    def _skewed(self, now: int, other: int) -> bool:
        return abs(now - other) > self._skew

    async def _atomic(self, apply: Callable[[int], object]) -> object:
        """Lets other tasks run once, then applies ``apply`` under the lock with no ``await`` inside.

        A call cancelled at the yield had no effect.
        """

        await asyncio.sleep(0)
        with self._lock:
            return apply(self._store_now())

    def _tenant_rows(self, scope: StoreScope) -> _TenantRows | None:
        namespace = self._namespaces.get(scope.namespace)
        return None if namespace is None else namespace.tenants.get(scope.tenant)

    def _ensure_tenant_rows(self, scope: StoreScope) -> _TenantRows:
        namespace = self._namespaces.get(scope.namespace)
        if namespace is None:
            namespace = _Namespace()
            self._namespaces[scope.namespace] = namespace
        rows = namespace.tenants.get(scope.tenant)
        if rows is None:
            rows = _TenantRows()
            namespace.tenants[scope.tenant] = rows
        return rows

    def _recovery_of(self, namespace: str) -> RecoveryState:
        record = self._namespaces[namespace].recovery if namespace in self._namespaces else None
        if record is None:
            return RecoveryState(epoch=0, state="uninitialized")
        return RecoveryState(epoch=record.epoch, state=record.state)  # type: ignore[arg-type]

    def _find_capture(self, scope: StoreScope, capture_id: str) -> _CaptureRow | None:
        rows = self._tenant_rows(scope)
        return None if rows is None else rows.captures.get(capture_id)

    def _is_revoked(self, row: _CaptureRow, namespace_epoch: int) -> bool:
        """A capture created under a lower epoch is treated as revoked by every operation (spec section 5.1)."""

        return row.state == "revoked" or row.epoch < namespace_epoch

    def _not_serving(self, namespace: str, epoch: int) -> bool:
        space = self._namespaces.get(namespace)
        record = None if space is None else space.recovery
        return record is None or record.state != "serving" or record.epoch != epoch

    def _commit_capture_verdict(self, capture: _CaptureRow | None, generation: int, epoch: int, now: int) -> str | None:
        """Step 4 of a commit for one named capture: a rejection reason, or ``None``."""

        if capture is None:
            return "unknown"
        if self._is_revoked(capture, epoch):
            return "revoked"
        if capture.generation != generation:
            return "stale"
        if now >= capture.expires_at:
            return "expired"
        return None

    def _commit_use_verdict(
        self, entry: _EntryRow | None, capture_id: str, count: int, lifecycle_revision: int, ciphertext_revision: int
    ) -> str | None:
        """Step 5 of a commit for one named entry: a rejection reason, or ``None``."""

        if entry is None or entry.capture_id != capture_id:
            return "unknown"
        if entry.lifecycle_revision != lifecycle_revision or entry.ciphertext_revision != ciphertext_revision:
            return "stale"
        if entry.used + count > entry.max_uses:
            return "budget"
        return None

    def _find_receipt(self, rows: _TenantRows | None, attempt_id: str) -> _ReceiptRow | None:
        return None if rows is None else rows.receipts.get(attempt_id)

    def _digests_match(self, stored: bytes, given: bytes) -> bool:
        return hmac.compare_digest(stored, given)

    def _receipt_sweepable(self, receipt: _ReceiptRow, now: int) -> bool:
        return now > receipt.receipt_expires_at

    def _capture_sweepable(self, capture: _CaptureRow, now: int) -> bool:
        return (now >= capture.expires_at) if capture.keep_until is None else (now > capture.keep_until)

    @staticmethod
    def _view_capture(row: _CaptureRow, revoked: bool) -> StoredCapture:
        return StoredCapture(
            capture_id=row.capture_id,
            key_ref="" if row.keyless else row.key_ref,
            wrapped_key=b"" if row.keyless else bytes(row.wrapped_key),
            state="revoked" if revoked else "live",
            generation=row.generation,
            key_revision=row.key_revision,
            epoch=row.epoch,
            session_tag=row.session_tag,
            created_at=row.created_at,
            expires_at=row.expires_at,
        )

    @staticmethod
    def _view_entry(row: _EntryRow) -> StoredEntry:
        return StoredEntry(
            entry_id=row.entry_id,
            capture_id=row.capture_id,
            max_uses=row.max_uses,
            used=row.used,
            lifecycle_revision=row.lifecycle_revision,
            ciphertext_revision=row.ciphertext_revision,
            envelope=bytes(row.envelope),
        )

    @staticmethod
    def _remove_entries(rows: _TenantRows, capture: _CaptureRow) -> int:
        removed = 0
        for entry_id in capture.entry_ids:
            if rows.entries.pop(entry_id, None) is not None:
                removed += 1
        capture.entry_ids.clear()
        return removed

    # --------------------------------------------------------------- operations

    async def create_capture(self, input: CreateCaptureInput) -> CreateCaptureResult:
        validate_create_capture(input, self._capabilities)
        scope = StoreScope(namespace=input.scope.namespace, tenant=input.scope.tenant)
        epoch, caller_now = input.epoch, input.now
        capture = input.capture
        entries = tuple((entry.entry_id, entry.max_uses, bytes(entry.envelope)) for entry in input.entries)
        key_ref, wrapped_key = capture.key_ref, bytes(capture.wrapped_key)
        session_tag, created_at, expires_at, capture_id = (
            capture.session_tag,
            capture.created_at,
            capture.expires_at,
            capture.capture_id,
        )

        def apply(now: int) -> CreateCaptureResult:
            if self._not_serving(scope.namespace, epoch):
                return CaptureRejected(reason="quarantined")
            if self._skewed(now, caller_now) or self._skewed(now, created_at):
                return CaptureRejected(reason="clock-skew")
            existing = self._tenant_rows(scope)
            present = None if existing is None else existing.captures.get(capture_id)
            if present is not None:
                return CaptureRejected(reason="fenced" if self._is_revoked(present, epoch) else "exists")
            for entry_id, _max_uses, _envelope in entries:
                if existing is not None and entry_id in existing.entries:
                    return CaptureRejected(reason="exists")
            rows = self._ensure_tenant_rows(scope)
            row = _CaptureRow(
                capture_id=capture_id,
                state="live",
                generation=1,
                key_revision=1,
                epoch=epoch,
                session_tag=session_tag,
                created_at=created_at,
                expires_at=expires_at,
                key_ref=key_ref,
                wrapped_key=wrapped_key,
                keyless=False,
                keep_until=None,
            )
            rows.captures[capture_id] = row
            for entry_id, max_uses, envelope in entries:
                row.entry_ids.add(entry_id)
                rows.entries[entry_id] = _EntryRow(
                    entry_id=entry_id,
                    capture_id=capture_id,
                    max_uses=max_uses,
                    used=0,
                    lifecycle_revision=1,
                    ciphertext_revision=1,
                    envelope=envelope,
                )
            return CaptureCreated()

        return await self._atomic(apply)  # type: ignore[return-value]

    async def read_entries(self, input: ReadEntriesInput) -> ReadEntriesResult:
        validate_read_entries(input, self._capabilities)
        scope = StoreScope(namespace=input.scope.namespace, tenant=input.scope.tenant)
        entry_ids = tuple(input.entry_ids)

        def apply(_now: int) -> ReadEntriesResult:
            recovery = self._recovery_of(scope.namespace)
            rows = self._tenant_rows(scope)
            found: list[StoredEntry] = []
            captures: dict[str, StoredCapture] = {}
            if rows is not None:
                for entry_id in entry_ids:
                    entry = rows.entries.get(entry_id)
                    if entry is None:
                        continue
                    capture = rows.captures.get(entry.capture_id)
                    if capture is None or capture.keyless:
                        continue
                    found.append(self._view_entry(entry))
                    if capture.capture_id not in captures:
                        captures[capture.capture_id] = self._view_capture(
                            capture, self._is_revoked(capture, recovery.epoch)
                        )
            return ReadEntriesResult(recovery=recovery, entries=tuple(found), captures=tuple(captures.values()))

        return await self._atomic(apply)  # type: ignore[return-value]

    async def read_captures(self, input: ReadCapturesInput) -> tuple[StoredCapture, ...]:
        validate_read_captures(input, self._capabilities)
        scope = StoreScope(namespace=input.scope.namespace, tenant=input.scope.tenant)
        capture_ids = tuple(input.capture_ids)

        def apply(_now: int) -> tuple[StoredCapture, ...]:
            epoch = self._recovery_of(scope.namespace).epoch
            rows = self._tenant_rows(scope)
            found: list[StoredCapture] = []
            if rows is not None:
                for capture_id in capture_ids:
                    capture = rows.captures.get(capture_id)
                    if capture is not None:
                        found.append(self._view_capture(capture, self._is_revoked(capture, epoch)))
            return tuple(found)

        return await self._atomic(apply)  # type: ignore[return-value]

    async def commit_restore(self, input: CommitRestoreInput) -> CommitRestoreResult:
        validate_commit_restore(input, self._capabilities)
        scope = StoreScope(namespace=input.scope.namespace, tenant=input.scope.tenant)
        epoch, caller_now = input.epoch, input.now
        attempt_id, request_digest = input.attempt.attempt_id, bytes(input.attempt.request_digest)
        receipt_expires_at = input.receipt_expires_at
        expected_captures = tuple((item.capture_id, item.generation) for item in input.captures)
        uses = tuple(
            (item.entry_id, item.capture_id, item.count, item.lifecycle_revision, item.ciphertext_revision)
            for item in input.uses
        )

        def apply(now: int) -> CommitRestoreResult:
            # Step 1.
            if self._not_serving(scope.namespace, epoch):
                return RestoreRejected(reason="quarantined")
            # Step 2.
            rows = self._tenant_rows(scope)
            receipt = self._find_receipt(rows, attempt_id)
            if receipt is not None:
                if self._digests_match(receipt.request_digest, request_digest):
                    return RestoreAlreadyCommitted()
                return RestoreAttemptMismatch()
            # Step 3.
            if self._skewed(now, caller_now):
                return RestoreRejected(reason="clock-skew")
            # Specification section 4.2: the one mechanical check that needs the store's clock,
            # after steps 1 and 2, whose order section 5.5 fixes.
            if receipt_expires_at - now > _limits.MAX_RECEIPT_HORIZON_MS:
                raise StoreError("STORE_INVALID_ARGUMENT")
            if rows is None:
                return RestoreRejected(reason="unknown")
            # Step 4.
            latest_expiry = 0
            for capture_id, generation in expected_captures:
                capture = rows.captures.get(capture_id)
                verdict = self._commit_capture_verdict(capture, generation, epoch, now)
                if verdict is not None:
                    return RestoreRejected(reason=verdict)  # type: ignore[arg-type]
                assert capture is not None
                latest_expiry = max(latest_expiry, capture.expires_at)
            # Step 5.
            targets: list[_EntryRow] = []
            for entry_id, capture_id, count, lifecycle_revision, ciphertext_revision in uses:
                entry = rows.entries.get(entry_id)
                verdict = self._commit_use_verdict(entry, capture_id, count, lifecycle_revision, ciphertext_revision)
                if verdict is not None:
                    return RestoreRejected(reason=verdict)  # type: ignore[arg-type]
                assert entry is not None
                targets.append(entry)
            # Step 6.
            if receipt_expires_at < latest_expiry:
                raise StoreError("STORE_INVALID_ARGUMENT")
            # Step 7. Nothing above wrote; nothing below can fail.
            for (_entry_id, _capture_id, count, _lifecycle, _ciphertext), entry in zip(uses, targets, strict=True):
                entry.used += count
                entry.lifecycle_revision += 1
            rows.receipts[attempt_id] = _ReceiptRow(
                request_digest=request_digest, committed_at=now, receipt_expires_at=receipt_expires_at
            )
            return RestoreCommitted()

        return await self._atomic(apply)  # type: ignore[return-value]

    async def revoke_capture(self, input: RevokeCaptureInput) -> RevokeCaptureResult:
        validate_revoke_capture(input)
        scope = StoreScope(namespace=input.scope.namespace, tenant=input.scope.tenant)
        capture_id, retention_ms, fence_absent = input.capture_id, input.retention_ms, input.fence_absent

        def apply(now: int) -> RevokeCaptureResult:
            epoch = self._recovery_of(scope.namespace).epoch
            capture = self._find_capture(scope, capture_id)
            if capture is None:
                if not fence_absent:
                    return CaptureNotFound()
                self._ensure_tenant_rows(scope).captures[capture_id] = _CaptureRow(
                    capture_id=capture_id,
                    state="revoked",
                    generation=1,
                    key_revision=1,
                    epoch=epoch,
                    session_tag=None,
                    created_at=now,
                    expires_at=now,
                    key_ref="",
                    wrapped_key=b"",
                    keyless=True,
                    keep_until=now + retention_ms,
                )
                return CaptureFenced()
            if self._is_revoked(capture, epoch):
                return CaptureRevoked(outcome="already-revoked", entries=len(capture.entry_ids))
            capture.state = "revoked"
            capture.generation += 1
            capture.keep_until = max(capture.expires_at, now) + retention_ms
            return CaptureRevoked(outcome="revoked", entries=len(capture.entry_ids))

        return await self._atomic(apply)  # type: ignore[return-value]

    async def inspect_attempt(self, input: InspectAttemptInput) -> InspectAttemptResult:
        validate_inspect_attempt(input)
        scope = StoreScope(namespace=input.scope.namespace, tenant=input.scope.tenant)
        attempt_id = input.attempt_id

        def apply(_now: int) -> InspectAttemptResult:
            rows = self._tenant_rows(scope)
            receipt = None if rows is None else rows.receipts.get(attempt_id)
            if receipt is None:
                return AttemptAbsent()
            return AttemptCommitted(request_digest=bytes(receipt.request_digest), committed_at=receipt.committed_at)

        return await self._atomic(apply)  # type: ignore[return-value]

    async def replace_capture_key(self, input: ReplaceCaptureKeyInput) -> ReplaceCaptureKeyResult:
        validate_replace_capture_key(input)
        scope = StoreScope(namespace=input.scope.namespace, tenant=input.scope.tenant)
        capture_id, expected_revision = input.capture_id, input.key_revision
        key_ref, wrapped_key = input.key_ref, bytes(input.wrapped_key)

        def apply(now: int) -> ReplaceCaptureKeyResult:
            epoch = self._recovery_of(scope.namespace).epoch
            capture = self._find_capture(scope, capture_id)
            if capture is None:
                return CaptureKeyRejected(reason="unknown")
            if capture.keyless or self._is_revoked(capture, epoch):
                return CaptureKeyRejected(reason="revoked")
            if now >= capture.expires_at:
                return CaptureKeyRejected(reason="expired")
            if capture.key_revision != expected_revision:
                return CaptureKeyRejected(reason="stale")
            capture.key_ref = key_ref
            capture.wrapped_key = wrapped_key
            capture.key_revision += 1
            return CaptureKeyReplaced(key_revision=capture.key_revision)

        return await self._atomic(apply)  # type: ignore[return-value]

    async def delete_ciphertext(self, input: DeleteCiphertextInput) -> DeleteCiphertextResult:
        validate_delete_ciphertext(input)
        scope = StoreScope(namespace=input.scope.namespace, tenant=input.scope.tenant)
        capture_id, caller_now = input.capture_id, input.now

        def apply(now: int) -> DeleteCiphertextResult:
            epoch = self._recovery_of(scope.namespace).epoch
            rows = self._tenant_rows(scope)
            capture = None if rows is None else rows.captures.get(capture_id)
            if rows is None or capture is None:
                return CiphertextRejected(reason="not-found")
            if not self._is_revoked(capture, epoch):
                # The decision rests on expiry, so the clocks must agree.
                if self._skewed(now, caller_now):
                    return CiphertextRejected(reason="clock-skew")
                if now < capture.expires_at:
                    return CiphertextRejected(reason="live")
            entries = self._remove_entries(rows, capture)
            capture.key_ref = ""
            capture.wrapped_key = b""
            capture.keyless = True
            capture.key_revision += 1
            capture.state = "revoked"
            return CiphertextDeleted(entries=entries)

        return await self._atomic(apply)  # type: ignore[return-value]

    async def sweep_expired(self, input: SweepInput) -> SweepResult:
        validate_sweep(input)
        name, caller_now, limit = input.namespace, input.now, input.limit

        def apply(now: int) -> SweepResult:
            if self._skewed(now, caller_now):
                return SweepRejected()
            namespace = self._namespaces.get(name)
            entries = captures = receipts = 0
            more = False
            if namespace is None:
                return Swept(entries=0, captures=0, receipts=0, more=False)
            for rows in namespace.tenants.values():
                for capture in rows.captures.values():
                    if now < capture.expires_at:
                        continue
                    for entry_id in tuple(capture.entry_ids):
                        if entries >= limit:
                            more = True
                            break
                        capture.entry_ids.discard(entry_id)
                        rows.entries.pop(entry_id, None)
                        entries += 1
                for capture in tuple(rows.captures.values()):
                    if not self._capture_sweepable(capture, now):
                        continue
                    # A capture row outlives its entries, so an entry never points at nothing.
                    if capture.entry_ids or captures >= limit:
                        more = True
                        continue
                    del rows.captures[capture.capture_id]
                    captures += 1
                for attempt_id, receipt in tuple(rows.receipts.items()):
                    if not self._receipt_sweepable(receipt, now):
                        continue
                    if receipts >= limit:
                        more = True
                        break
                    del rows.receipts[attempt_id]
                    receipts += 1
            for tenant, rows in tuple(namespace.tenants.items()):
                if rows.empty():
                    del namespace.tenants[tenant]
            if namespace.recovery is None and not namespace.tenants:
                del self._namespaces[name]
            return Swept(entries=entries, captures=captures, receipts=receipts, more=more)

        return await self._atomic(apply)  # type: ignore[return-value]

    async def recovery_state(self, namespace: str) -> RecoveryState:
        validate_namespace(namespace)
        name = namespace

        def apply(_now: int) -> RecoveryState:
            return self._recovery_of(name)

        return await self._atomic(apply)  # type: ignore[return-value]

    async def initialize_namespace(self, namespace: str, epoch: int) -> InitializeNamespaceResult:
        validate_initialize_namespace(namespace, epoch)
        name, new_epoch = namespace, epoch

        def apply(_now: int) -> InitializeNamespaceResult:
            existing = self._namespaces.get(name)
            if existing is not None and existing.recovery is not None:
                return NamespaceRejected(reason="exists")
            if existing is not None:
                for rows in existing.tenants.values():
                    if not rows.empty():
                        return NamespaceRejected(reason="not-empty")
            self._namespaces[name] = _Namespace(
                recovery=_Recovery(epoch=new_epoch, state="serving"),
                tenants=existing.tenants if existing is not None else {},
            )
            return NamespaceInitialized()

        return await self._atomic(apply)  # type: ignore[return-value]

    async def quarantine(self, namespace: str) -> RecoveryState:
        validate_namespace(namespace)
        name = namespace

        def apply(_now: int) -> RecoveryState:
            # Only initialize_namespace creates the record; with none there is nothing to quarantine.
            space = self._namespaces.get(name)
            record = None if space is None else space.recovery
            if record is not None:
                record.state = "quarantined"
            return self._recovery_of(name)

        return await self._atomic(apply)  # type: ignore[return-value]

    async def invalidate_recovered(self, input: InvalidateRecoveredInput) -> InvalidateRecoveredResult:
        validate_invalidate_recovered(input)
        name, new_epoch = input.namespace, input.new_epoch

        def apply(_now: int) -> InvalidateRecoveredResult:
            space = self._namespaces.get(name)
            record = None if space is None else space.recovery
            if record is None:
                return InvalidateRejected(reason="uninitialized")
            if new_epoch <= record.epoch:
                return InvalidateRejected(reason="epoch-not-greater")
            record.epoch = new_epoch
            record.state = "serving"
            return RecoveredInvalidated(recovery=self._recovery_of(name))

        return await self._atomic(apply)  # type: ignore[return-value]


def create_memory_store(
    *,
    now: Callable[[], int | float] | None = None,
    max_clock_skew_ms: int = _DEFAULT_MAX_CLOCK_SKEW_MS,
    max_create_entries: int | None = None,
    max_create_bytes: int | None = None,
    max_restore_entries: int | None = None,
    max_restore_captures: int | None = None,
    max_envelope_bytes: int | None = None,
) -> MemoryStore:
    """A new, empty store. Each bound may only be lowered from its default."""

    return MemoryStore(
        now=now,
        max_clock_skew_ms=max_clock_skew_ms,
        max_create_entries=max_create_entries,
        max_create_bytes=max_create_bytes,
        max_restore_entries=max_restore_entries,
        max_restore_captures=max_restore_captures,
        max_envelope_bytes=max_envelope_bytes,
    )
