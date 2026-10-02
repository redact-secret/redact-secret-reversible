"""Test-only: the reference store with exactly one broken decision (plan section 6.5).

Each mutant subclasses ``ScheduleStore`` and overrides one of the small protected decision methods of
``MemoryStore``, or one public operation. None is in the wheel. The suite must fail with each applied,
and fail the schedule that tests the decision.

``MUTANTS`` is ``(name, factory name, defect, [schedule ids that must fail])``. The ids are the
``id`` of cases of ``conformance/persistent/v1/schedules.json``.
"""

from __future__ import annotations

import contextvars
import copy
import dataclasses
from typing import Any

from schedule_store import ScheduleStore, current_operation

from redact_secret_vault.persistent import ReadEntriesInput, RevokeCaptureInput


class IgnoresRevocationAtCommit(ScheduleStore):
    def _commit_capture_verdict(self, capture: Any, generation: int, epoch: int, now: int) -> str | None:
        if capture is None:
            return "unknown"
        if capture.generation != generation:
            return "stale"
        if now >= capture.expires_at:
            return "expired"
        return None


class GenerationNotCompared(ScheduleStore):
    def _commit_capture_verdict(self, capture: Any, generation: int, epoch: int, now: int) -> str | None:
        if capture is None:
            return "unknown"
        if self._is_revoked(capture, epoch):
            return "revoked"
        if now >= capture.expires_at:
            return "expired"
        return None


class LifecycleRevisionNotCompared(ScheduleStore):
    def _commit_use_verdict(
        self, entry: Any, capture_id: str, count: int, lifecycle: int, ciphertext: int
    ) -> str | None:
        return super()._commit_use_verdict(
            entry, capture_id, count, entry.lifecycle_revision if entry else lifecycle, ciphertext
        )


class CiphertextRevisionNotCompared(ScheduleStore):
    def _commit_use_verdict(
        self, entry: Any, capture_id: str, count: int, lifecycle: int, ciphertext: int
    ) -> str | None:
        return super()._commit_use_verdict(
            entry, capture_id, count, lifecycle, entry.ciphertext_revision if entry else ciphertext
        )


class BudgetOffByOne(ScheduleStore):
    def _commit_use_verdict(
        self, entry: Any, capture_id: str, count: int, lifecycle: int, ciphertext: int
    ) -> str | None:
        if entry is not None and entry.capture_id == capture_id and entry.used + count == entry.max_uses + 1:
            return None if entry.lifecycle_revision == lifecycle else "stale"
        return super()._commit_use_verdict(entry, capture_id, count, lifecycle, ciphertext)


class BudgetNotChecked(ScheduleStore):
    def _commit_use_verdict(
        self, entry: Any, capture_id: str, count: int, lifecycle: int, ciphertext: int
    ) -> str | None:
        verdict = super()._commit_use_verdict(entry, capture_id, count, lifecycle, ciphertext)
        return None if verdict == "budget" else verdict


class ReceiptLookupSkipped(ScheduleStore):
    """Receipts are written and inspectable, but a commit never consults them."""

    def _find_receipt(self, rows: Any, attempt_id: str) -> Any:
        return None if current_operation() == "commit_restore" else super()._find_receipt(rows, attempt_id)


class DigestNotCompared(ScheduleStore):
    def _digests_match(self, stored: bytes, given: bytes) -> bool:
        return True


class EpochNotCompared(ScheduleStore):
    def _not_serving(self, namespace: str, epoch: int) -> bool:
        space = self._namespaces.get(namespace)
        record = None if space is None else space.recovery
        return record is None or record.state != "serving"


class EarlierEpochStaysLive(ScheduleStore):
    def _is_revoked(self, row: Any, namespace_epoch: int) -> bool:
        return row.state == "revoked"


_CALLER_NOW: contextvars.ContextVar[int | None] = contextvars.ContextVar("rsv_mutant_caller_now", default=None)


class ExpiryJudgedOnCallerClock(ScheduleStore):
    async def commit_restore(self, input: Any) -> Any:
        token = _CALLER_NOW.set(input.now)
        try:
            return await super().commit_restore(input)
        finally:
            _CALLER_NOW.reset(token)

    def _commit_capture_verdict(self, capture: Any, generation: int, epoch: int, now: int) -> str | None:
        caller = _CALLER_NOW.get()
        return super()._commit_capture_verdict(capture, generation, epoch, now if caller is None else caller)


class NoSkewCheckAtCommit(ScheduleStore):
    async def commit_restore(self, input: Any) -> Any:
        return await super().commit_restore(dataclasses.replace(input, now=self._store_now()))


class SweepsReceiptsEarly(ScheduleStore):
    def _receipt_sweepable(self, receipt: Any, now: int) -> bool:
        return True


class SweepIgnoresTombstoneRetention(ScheduleStore):
    def _capture_sweepable(self, capture: Any, now: int) -> bool:
        return now >= capture.expires_at


_SEEN: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar("rsv_mutant_seen", default=None)


class StaleCommitRead(ScheduleStore):
    """Commit decides on the capture rows it read before a concurrent revocation (specification section 5.2)."""

    async def commit_restore(self, input: Any) -> Any:
        rows = self._tenant_rows(input.scope)
        seen = {}
        if rows is not None:
            for item in input.captures:
                row = rows.captures.get(item.capture_id)
                if row is not None:
                    seen[item.capture_id] = copy.copy(row)
        token = _SEEN.set(seen)
        try:
            return await super().commit_restore(input)
        finally:
            _SEEN.reset(token)

    def _commit_capture_verdict(self, capture: Any, generation: int, epoch: int, now: int) -> str | None:
        stale = (_SEEN.get() or {}).get(getattr(capture, "capture_id", ""))
        return super()._commit_capture_verdict(stale if stale is not None else capture, generation, epoch, now)


_BLOCKED: contextvars.ContextVar[bool | None] = contextvars.ContextVar("rsv_mutant_blocked", default=None)


class StaleCreateRead(ScheduleStore):
    """Create reads the recovery record without conflicting with a concurrent quarantine (specification section 5.2)."""

    async def create_capture(self, input: Any) -> Any:
        token = _BLOCKED.set(self._not_serving(input.scope.namespace, input.epoch))
        try:
            return await super().create_capture(input)
        finally:
            _BLOCKED.reset(token)

    def _not_serving(self, namespace: str, epoch: int) -> bool:
        stale = _BLOCKED.get()
        return super()._not_serving(namespace, epoch) if stale is None else stale


class CreateOverwrites(ScheduleStore):
    async def create_capture(self, input: Any) -> Any:
        rows = self._tenant_rows(input.scope)
        present = None if rows is None else rows.captures.get(input.capture.capture_id)
        if present is not None and not self._is_revoked(present, input.epoch):
            self._remove_entries(rows, present)
            del rows.captures[input.capture.capture_id]
        return await super().create_capture(input)


class TenantScopeIgnoredOnRead(ScheduleStore):
    def _tenant_rows(self, scope: Any) -> Any:
        if current_operation() == "read_entries":
            namespace = self._namespaces.get(scope.namespace)
            if namespace is not None:
                for rows in namespace.tenants.values():
                    return rows
        return super()._tenant_rows(scope)


class RevokeKeepsGeneration(ScheduleStore):
    async def revoke_capture(self, input: RevokeCaptureInput) -> Any:
        result = await super().revoke_capture(input)
        if result.outcome == "revoked":
            self._find_capture(input.scope, input.capture_id).generation -= 1
        return result


class DeleteKeepsKey(ScheduleStore):
    async def delete_ciphertext(self, input: Any) -> Any:
        capture = self._find_capture(input.scope, input.capture_id)
        kept = None if capture is None else (capture.key_ref, capture.wrapped_key, capture.keyless)
        result = await super().delete_ciphertext(input)
        if result.outcome == "deleted" and capture is not None and kept is not None:
            capture.key_ref, capture.wrapped_key, capture.keyless = kept
        return result


class FencesWithoutBeingAsked(ScheduleStore):
    async def revoke_capture(self, input: RevokeCaptureInput) -> Any:
        if self._find_capture(input.scope, input.capture_id) is None and not input.fence_absent:
            await super().revoke_capture(dataclasses.replace(input, fence_absent=True))
            return await super().revoke_capture(input)
        return await super().revoke_capture(input)


class RekeyResetsUsed(ScheduleStore):
    async def replace_capture_key(self, input: Any) -> Any:
        result = await super().replace_capture_key(input)
        if result.outcome == "replaced":
            rows = self._tenant_rows(input.scope)
            for entry_id in self._find_capture(input.scope, input.capture_id).entry_ids:
                rows.entries[entry_id].used = 0
        return result


_ = ReadEntriesInput  # imported for readers of this module: the read mutants act on read_entries

#: (name, class, defect, ids of the schedules that must fail with it applied)
MUTANTS: tuple[tuple[str, type[ScheduleStore], str, tuple[str, ...]], ...] = (
    (
        "ignores-revocation-at-commit",
        IgnoresRevocationAtCommit,
        "commit does not check capture state (revoked ignored)",
        ("commit.rejects-revoked-after-a-revocation-with-the-generation-read-before-or-after-it",),
    ),
    (
        "generation-not-compared",
        GenerationNotCompared,
        "commit does not compare the capture generation",
        ("commit.rejects-stale-for-a-different-lifecyclerevision-ciphertextrevision-or-generation",),
    ),
    (
        "lifecycle-revision-not-compared",
        LifecycleRevisionNotCompared,
        "commit does not compare the entry's lifecycle revision",
        ("commit.rejects-stale-for-a-different-lifecyclerevision-ciphertextrevision-or-generation",),
    ),
    (
        "ciphertext-revision-not-compared",
        CiphertextRevisionNotCompared,
        "commit does not compare the entry's ciphertext revision",
        ("commit.rejects-stale-for-a-different-lifecyclerevision-ciphertextrevision-or-generation",),
    ),
    (
        "budget-off-by-one",
        BudgetOffByOne,
        "budget check allows maxUses + 1",
        ("commit.accepts-a-budget-exactly-at-maxuses-and-rejects-one-over",),
    ),
    (
        "budget-not-checked",
        BudgetNotChecked,
        "budget is not checked at commit",
        (
            "commit.accepts-a-budget-exactly-at-maxuses-and-rejects-one-over",
            "concurrency.parallel-restores-of-one-entry-with-maxuses-7-retried-on-stale-exactly-seven-commit",
        ),
    ),
    (
        "receipt-lookup-skipped",
        ReceiptLookupSkipped,
        "no receipt uniqueness: the same attempt commits twice",
        ("commit.answers-already-committed-for-the-same-attempt-and-digest-and-changes-nothing",),
    ),
    (
        "digest-not-compared",
        DigestNotCompared,
        "the request digest is not compared with the receipt's",
        ("commit.answers-attempt-mismatch-for-the-same-attempt-with-another-digest-and-changes-nothing",),
    ),
    (
        "epoch-not-compared",
        EpochNotCompared,
        "the epoch is not compared at create or commit",
        ("commit.rejects-quarantined-for-an-uninitialized-namespace-and-for-an-epoch-that-differs",),
    ),
    (
        "earlier-epoch-stays-live",
        EarlierEpochStaysLive,
        "a capture of an earlier epoch is not treated as revoked",
        ("recovery.every-capture-of-an-earlier-epoch-is-treated-as-revoked-by-every-operation",),
    ),
    (
        "expiry-on-caller-clock",
        ExpiryJudgedOnCallerClock,
        "expiry is judged on the caller's now, not the store clock",
        ("commit.judges-expiry-on-the-store-s-clock-live-one-millisecond-before-expiresat-expired-exactly-at-it",),
    ),
    (
        "no-skew-check-at-commit",
        NoSkewCheckAtCommit,
        "the caller's now replaces the clock-skew comparison at commit",
        ("commit.rejects-clock-skew-when-the-caller-s-now-is-outside-the-bound-and-applies-nothing",),
    ),
    (
        "sweeps-receipts-early",
        SweepsReceiptsEarly,
        "sweep removes receipts before receiptExpiresAt",
        (
            "sweep.never-removes-an-unexpired-capture-its-entries-a-revoked-capture-s-unexpired-entries-or-an-unexpired-receipt",
        ),
    ),
    (
        "tombstone-retention-ignored",
        SweepIgnoresTombstoneRetention,
        "sweep removes a tombstone at expiry, ignoring retention",
        (
            "sweep.keeps-a-revocation-tombstone-until-the-capture-s-expiry-plus-retention-and-it-fences-creation-meanwhile",
        ),
    ),
    (
        "stale-commit-read",
        StaleCommitRead,
        "commit reads the capture without conflicting with a concurrent revoke (specification section 5.2)",
        ("interleave.a-revocation-committed-between-a-restore-s-read-and-its-commit-the-restore-does-not-commit",),
    ),
    (
        "stale-create-read",
        StaleCreateRead,
        "create reads the recovery record without conflicting with a concurrent quarantine (specification section 5.2)",
        ("interleave.a-quarantine-committed-between-a-creation-s-check-and-its-commit-the-creation-does-not-succeed",),
    ),
    (
        "create-overwrites",
        CreateOverwrites,
        "createCapture overwrites an existing capture",
        ("create.rejects-exists-for-a-live-capture-identifier-and-overwrites-nothing",),
    ),
    (
        "tenant-scope-ignored-on-read",
        TenantScopeIgnoredOnRead,
        "the tenant scope is ignored on read",
        ("read.another-tenant-s-identifiers-return-nothing",),
    ),
    (
        "revoke-keeps-generation",
        RevokeKeepsGeneration,
        "revoke does not increment the generation",
        ("revoke.revokes-a-live-capture-increments-its-generation-and-reports-its-entry-count",),
    ),
    (
        "delete-keeps-key",
        DeleteKeepsKey,
        "deleteCiphertext keeps the stored key",
        ("delete.deletes-a-revoked-capture-s-ciphertext-whatever-the-clocks-say",),
    ),
    (
        "fence-without-being-asked",
        FencesWithoutBeingAsked,
        "revoke of an absent capture writes a tombstone without fenceAbsent",
        ("revoke.answers-not-found-for-an-absent-capture-and-writes-nothing",),
    ),
    (
        "rekey-resets-used",
        RekeyResetsUsed,
        "replaceCaptureKey resets used",
        ("rekey.a-restore-prepared-before-the-re-wrap-still-commits-and-its-use-is-kept",),
    ),
)
