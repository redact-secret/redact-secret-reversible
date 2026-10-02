"""PostgreSQL ``Store`` over ``psycopg`` 3, against the schema of ``@redact-secret/store-postgres``.

A ciphertext-only store (docs/specs/persistent-vault.md section 5): it holds ciphertext, wrapped keys, counters,
and receipts, never decrypts, holds no key, and evaluates no policy. It is the Python counterpart of
``packages/store-postgres/src/store.ts`` and runs against the same tables. It creates no table and runs no
migration: the schema is owned by that package (``migrate`` and ``grantStatements`` there), and the serving role of
this adapter needs only the privileges those grants give.

**Python persistence is not supported.** This module is an implementation under qualification; support is stated only
by ``docs/research/qualification-python-persistence-0.1.0b3.md``, cell by cell.

Connection ownership (docs/plans/python-persistence-parity.md section 4.1). The application creates and closes the
pool and passes it in. A pool is any object whose ``connection()`` returns an async context manager yielding a
``psycopg.AsyncConnection`` (``psycopg_pool.AsyncConnectionPool`` is one). The adapter never opens a connection from a
URL or the environment, never closes the pool, and sets only transaction-local settings. A connection whose state it
cannot vouch for (a failed ``COMMIT``, a failed ``ROLLBACK``, a cancelled statement) is closed before it is handed back,
so a pool discards it. Construct the store after ``os.fork()``; a store used from another process than the one that
created it raises ``STORE_CLOSED``.

Installing: the ``postgres`` extra names plain ``psycopg``, which cannot be imported at all without a system ``libpq``.
Either install ``libpq`` or ``psycopg[binary]`` (the variant the qualification record tested) beside it.

Errors. Every failure is a sanitized ``StoreError``: no driver message, SQLSTATE detail, parameter, or row value leaves
the adapter, and ``__cause__`` and ``__context__`` are both ``None``. A failure before ``COMMIT`` is sent leaves nothing
applied (``STORE_UNAVAILABLE``, or ``stale`` for a lock wait, deadlock, or serialization failure). A failure of
``COMMIT`` itself, or a ``COMMIT`` that PostgreSQL completed with a warning, has an unknown outcome and is
``STORE_AMBIGUOUS``; the adapter never retries it. ``asyncio.CancelledError`` is never converted: the connection is
closed and the cancellation propagates.
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any, Final, Literal

from .._extras import require_extra

require_extra("redact_secret_vault.stores.postgres", "psycopg", "postgres")

from psycopg import pq  # noqa: E402

from ..persistent import limits as _limits  # noqa: E402
from ..persistent.contracts import (  # noqa: E402
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
    SweepInput,
    SweepRejected,
    SweepResult,
    Swept,
)
from ..persistent.errors import StoreError  # noqa: E402
from ..persistent.validate import (  # noqa: E402
    is_capture_id,
    is_entry_id,
    is_key_ref,
    is_session_tag,
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

__all__ = ["PostgresStore", "SCHEMA_VERSION", "create_postgres_store"]

#: Equals ``SCHEMA_VERSION`` of ``packages/store-postgres/src/schema.ts``; a test compares the two files.
SCHEMA_VERSION: Final = 1

_DEFAULT_SCHEMA: Final = "rsv"
_DEFAULT_MAX_CLOCK_SKEW_MS: Final = 2000
_MAX_CLOCK_SKEW_CEILING_MS: Final = 60_000
_DEFAULT_STATEMENT_TIMEOUT_MS: Final = 5000
_DEFAULT_LOCK_TIMEOUT_MS: Final = 2000
_TIMEOUT_CEILING_MS: Final = 600_000
_DEFAULT_MAX_CREATE_BYTES: Final = 64 * 1024 * 1024
_MAX_CREATE_BYTES_CEILING: Final = 256 * 1024 * 1024

_NOW_MS: Final = "(extract(epoch from clock_timestamp()) * 1000)::bigint"

#: The timeline this primary writes WAL on (the first eight hexadecimal digits of the current WAL file name).
#: NULL on a standby.
_TIMELINE_SQL: Final = (
    "CASE WHEN pg_is_in_recovery() THEN NULL "
    "ELSE ('x' || substr(pg_walfile_name(pg_current_wal_insert_lsn()), 1, 8))::bit(32)::int END"
)

#: serialization_failure, deadlock_detected, lock_not_available: nothing was applied.
_CONTENTION_SQLSTATES: Final = frozenset({"40001", "40P01", "55P03"})

_SCHEMA_NAME_CHARS: Final = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_")

Mode = Literal["write", "read"]


def _is_schema_name(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 63
        and value[0] not in "0123456789"
        and all(char in _SCHEMA_NAME_CHARS for char in value)
    )


class _Rollback(Exception):  # noqa: N818 - a control-flow signal inside a transaction body
    """Raised inside a body to roll back and return ``value``."""

    def __init__(self, value: object) -> None:
        super().__init__()
        self.value = value


class _Contended:
    """The sentinel a transaction returns when a lock wait, deadlock, or serialization failure applied nothing."""


CONTENDED: Final = _Contended()


class _Head:
    __slots__ = ("now", "system_identifier", "timeline_id")

    def __init__(self, now: int, system_identifier: str, timeline_id: int) -> None:
        self.now = now
        self.system_identifier = system_identifier
        self.timeline_id = timeline_id


class _Namespace:
    __slots__ = ("epoch", "state")

    def __init__(self, epoch: int, state: str) -> None:
        self.epoch = epoch
        self.state = state


# ----------------------------------------------------------------------------- row checks
#
# A row is data from a database the adapter does not control. Anything outside the contract is a
# ``STORE_UNAVAILABLE`` and never reaches a caller (docs/plans/python-persistence-parity.md section 3.6).


def _int(value: object, *, low: int = 0) -> int:
    if type(value) is not int or not low <= value <= _limits.MAX_TIMESTAMP:
        raise StoreError("STORE_UNAVAILABLE")
    return value


def _bytes(value: object, low: int, high: int) -> bytes:
    if type(value) is not bytes or not low <= len(value) <= high:
        raise StoreError("STORE_UNAVAILABLE")
    return value


def _check(condition: bool) -> None:
    if not condition:
        raise StoreError("STORE_UNAVAILABLE")


class _Notices:
    """Counts the server warnings of one transaction, so a ``COMMIT`` completed with a warning is not taken as clean."""

    __slots__ = ("warnings",)

    def __init__(self) -> None:
        self.warnings = 0

    def __call__(self, diagnostic: Any) -> None:
        state = getattr(diagnostic, "sqlstate", None)
        # Class 00 is a plain NOTICE. Anything else, or a message without a code, is a warning.
        if type(state) is not str or not state.startswith("00"):
            self.warnings += 1


class PostgresStore:
    """The ``Store`` over PostgreSQL. Build it with :func:`create_postgres_store`."""

    #: The SQL expression of the store clock. A test subclass replaces it to run the time-dependent cases
    #: against real transactions with a clock it can move; production code always reads the database clock.
    _NOW_SQL: str = _NOW_MS

    def __init__(
        self,
        pool: Any,
        schema: str,
        capabilities: StoreCapabilities,
        synchronous_commit: str,
        require_standby: bool,
        statement_timeout_ms: int,
        lock_timeout_ms: int,
    ) -> None:
        self._pool = pool
        self._t_ns = f'"{schema}".rsv_namespace'
        self._t_capture = f'"{schema}".rsv_capture'
        self._t_entry = f'"{schema}".rsv_entry'
        self._t_receipt = f'"{schema}".rsv_receipt'
        self._capabilities = capabilities
        self._synchronous_commit = synchronous_commit
        self._require_standby = require_standby
        self._statement_timeout_ms = statement_timeout_ms
        self._lock_timeout_ms = lock_timeout_ms
        self._closed = False
        self._pid = os.getpid()

    # ------------------------------------------------------------------ housekeeping

    def capabilities(self) -> StoreCapabilities:
        return self._capabilities

    def close(self) -> None:
        """Marks this adapter closed. The pool stays open: the application owns it."""

        self._closed = True

    def _ensure_usable(self) -> None:
        # A pool and its connections are not process-safe: a store used after ``os.fork()`` fails closed.
        if self._closed or os.getpid() != self._pid:
            raise StoreError("STORE_CLOSED")

    async def _guarded(self, operation: Callable[..., Awaitable[Any]], *arguments: Any) -> Any:
        """Runs one operation and re-raises any sanitized failure as a new error from this frame.

        The traceback a caller receives then starts here and holds no frame of the transaction, whose locals hold
        rows and parameters (docs/plans/python-persistence-parity.md section 3.4).
        """

        code: str | None = None
        try:
            return await operation(*arguments)
        except StoreError as error:
            code = error.code
        del operation, arguments
        raise StoreError(code)  # type: ignore[arg-type]

    # ------------------------------------------------------------------ transactions

    def _clock_sql(self) -> str:
        return self._NOW_SQL

    async def _transaction(
        self,
        mode: Mode,
        body: Callable[[Any, _Head], Awaitable[Any]],
        *,
        on_contention: object = None,
    ) -> Any:
        """One transaction on one connection.

        A failure before ``COMMIT`` is sent leaves nothing applied. A failure of ``COMMIT`` itself has an unknown
        outcome when the transaction wrote: ``STORE_AMBIGUOUS``, and it is never retried. A lock wait, deadlock, or
        serialization failure returns ``on_contention`` (or ``STORE_UNAVAILABLE`` when none is given).
        """

        self._ensure_usable()
        connection_manager: Any = None
        connection: Any = None
        try:
            connection_manager = self._pool.connection()
            connection = await connection_manager.__aenter__()
        except Exception:  # noqa: BLE001 - a driver failure is never carried
            connection = None
        if connection is None:
            raise StoreError("STORE_UNAVAILABLE")

        notices = _Notices()
        noticing = False
        kind = "STORE_UNAVAILABLE"
        value: Any = None
        destroy = False
        commit_sent = False
        cursor: Any = None
        warnings_before = 0
        try:
            try:
                connection.add_notice_handler(notices)
                noticing = True
            except Exception:  # noqa: BLE001
                noticing = False
            cursor = connection.cursor()
            if connection.info.transaction_status != pq.TransactionStatus.IDLE:
                raise StoreError("STORE_UNAVAILABLE")
            isolation = "READ COMMITTED READ WRITE" if mode == "write" else "REPEATABLE READ READ ONLY"
            if connection.autocommit:
                await cursor.execute(f"BEGIN ISOLATION LEVEL {isolation}")
            else:
                # psycopg has just issued its own BEGIN; this is the first statement of the transaction.
                await cursor.execute(f"SET TRANSACTION ISOLATION LEVEL {isolation}")
            await cursor.execute(
                "SELECT set_config('statement_timeout', %s, true), set_config('lock_timeout', %s, true), "
                "set_config('synchronous_commit', %s, true)",
                (str(self._statement_timeout_ms), str(self._lock_timeout_ms), self._synchronous_commit),
            )
            await cursor.execute(
                f"SELECT {self._clock_sql()} AS now, pg_is_in_recovery() AS standby, "
                "current_setting('synchronous_standby_names') AS standbys, "
                "(SELECT system_identifier::text FROM pg_control_system()) AS sysid, "
                f"{_TIMELINE_SQL} AS timeline"
            )
            facts = await cursor.fetchone()
            _check(facts is not None and len(facts) == 5)
            now, standby, standbys, system_identifier, timeline = facts
            # A connection that has landed on a standby is not the authority.
            if standby is not False or type(system_identifier) is not str:
                raise StoreError("STORE_UNAVAILABLE")
            # The profile this store declared needs a synchronous standby; a primary that stopped naming one is not it.
            if self._require_standby and (type(standbys) is not str or standbys.strip() == ""):
                raise StoreError("STORE_UNAVAILABLE")
            head = _Head(_int(now), system_identifier, _int(timeline))
            value = await body(cursor, head)
            warnings_before = notices.warnings
            commit_sent = True
            await cursor.execute("COMMIT")
            completed = cursor.statusmessage
            commit_sent = False
            # PostgreSQL answers COMMIT on a failed transaction with the tag ROLLBACK and no error. Every
            # statement error already left through the handlers below, so this is a second guard.
            if completed != "COMMIT":
                kind = "STORE_UNAVAILABLE"
            elif mode == "write" and notices.warnings != warnings_before:
                # COMMIT completed with a warning (a wait for the synchronous standby was cancelled): committed
                # here, possibly missing there. Not the durability this store declares.
                kind = "STORE_AMBIGUOUS"
            else:
                kind = "ok"
        except _Rollback as signal:
            value = signal.value
            kind = "rollback"
        except StoreError as error:
            kind = error.code
        except Exception as error:  # noqa: BLE001 - classified by SQLSTATE only; nothing of it is carried
            if commit_sent:
                kind = "STORE_AMBIGUOUS" if mode == "write" else "STORE_UNAVAILABLE"
                destroy = True
            elif getattr(error, "sqlstate", None) in _CONTENTION_SQLSTATES:
                kind = "contention"
            else:
                kind = "STORE_UNAVAILABLE"
        except BaseException:
            # Cancellation or an interrupt: the transaction state is unknown, so the connection is not reused.
            await self._discard(connection, connection_manager, notices if noticing else None)
            raise

        if not destroy and kind not in ("ok", "STORE_AMBIGUOUS"):
            # Nothing was committed on this path: roll back, and discard the connection if that fails.
            destroy = not await self._rollback(cursor)
        if destroy:
            await self._discard(connection, connection_manager, notices if noticing else None)
        else:
            await self._release(connection, connection_manager, notices if noticing else None)

        if kind in ("ok", "rollback"):
            return value
        if kind == "contention":
            if on_contention is not None:
                return on_contention
            kind = "STORE_UNAVAILABLE"
        raise StoreError(kind)  # type: ignore[arg-type]

    @staticmethod
    async def _rollback(cursor: Any) -> bool:
        """ROLLBACK on the connection; ``False`` when it fails, so the connection is discarded."""

        try:
            if cursor is None:
                return False
            await cursor.execute("ROLLBACK")
        except Exception:  # noqa: BLE001
            return False
        return True

    @staticmethod
    async def _release(connection: Any, manager: Any, notices: _Notices | None) -> None:
        try:
            if notices is not None:
                connection.remove_notice_handler(notices)
        except Exception:  # noqa: BLE001
            pass
        try:
            await manager.__aexit__(None, None, None)
        except Exception:  # noqa: BLE001 - the outcome of the transaction is already decided
            pass

    @staticmethod
    async def _discard(connection: Any, manager: Any, notices: _Notices | None) -> None:
        """Closes the connection before handing it back, so a pool drops it."""

        try:
            await connection.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            await manager.__aexit__(None, None, None)
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------ shared reads

    async def _namespace(
        self, cursor: Any, head: _Head, namespace: str, lock: Literal["share", "update", "none"]
    ) -> _Namespace:
        """The recovery record under a lock: shared for operations that conflict with quarantine and invalidation
        (spec section 5.2), exclusive for those two. A database whose identity differs from the recorded one reads as
        quarantined whatever the stored state says."""

        suffix = " FOR SHARE" if lock == "share" else " FOR UPDATE" if lock == "update" else ""
        await cursor.execute(
            f"SELECT epoch, state, system_identifier, timeline_id FROM {self._t_ns} WHERE namespace = %s{suffix}",
            (namespace,),
        )
        row = await cursor.fetchone()
        if row is None:
            return _Namespace(0, "uninitialized")
        epoch, state, system_identifier, timeline_id = row
        epoch = _int(epoch, low=1)
        timeline_id = _int(timeline_id)
        _check(state in ("serving", "quarantined"))
        same = system_identifier == head.system_identifier and timeline_id == head.timeline_id
        return _Namespace(epoch, "serving" if same and state == "serving" else "quarantined")

    async def _clock(self, cursor: Any) -> int:
        await cursor.execute(f"SELECT {self._clock_sql()} AS now")
        row = await cursor.fetchone()
        _check(row is not None)
        return _int(row[0])

    def _skewed(self, head: _Head, now: int) -> bool:
        return abs(head.now - now) > self._capabilities.max_clock_skew_ms

    async def _captures(
        self,
        cursor: Any,
        namespace: str,
        tenant: str,
        capture_ids: tuple[str, ...] | list[str],
        epoch: int,
        lock: Literal["", " FOR SHARE", " FOR UPDATE"],
    ) -> list[StoredCapture]:
        """Capture rows in identifier order (the lock order). A capture created under a lower epoch reads as revoked."""

        await cursor.execute(
            "SELECT capture_id, state, generation, key_revision, epoch, session_tag, created_at, expires_at, "
            f"key_ref, wrapped_key FROM {self._t_capture} "
            f"WHERE namespace = %s AND tenant = %s AND capture_id = ANY(%s::text[]) ORDER BY capture_id{lock}",
            (namespace, tenant, list(capture_ids)),
        )
        found: list[StoredCapture] = []
        for row in await cursor.fetchall():
            capture_id, state, generation, key_revision, capture_epoch, session_tag, created_at, expires_at = row[:8]
            key_ref, wrapped_key = row[8], row[9]
            _check(is_capture_id(capture_id) and state in ("live", "revoked"))
            _check(session_tag is None or is_session_tag(session_tag))
            _check(type(key_ref) is str)
            wrapped = _bytes(wrapped_key, 0, _limits.WRAPPED_KEY_MAX_BYTES)
            # A capture that holds a key holds a well-formed one. A fence or a deleted capture holds none.
            _check((key_ref == "" and wrapped == b"") or (is_key_ref(key_ref) and len(wrapped) > 0))
            _check(state == "revoked" or key_ref != "")
            epoch_of = _int(capture_epoch, low=1)
            found.append(
                StoredCapture(
                    capture_id=capture_id,
                    state="live" if state == "live" and epoch_of == epoch else "revoked",
                    generation=_int(generation, low=1),
                    key_revision=_int(key_revision, low=1),
                    epoch=epoch_of,
                    session_tag=session_tag,
                    created_at=_int(created_at),
                    expires_at=_int(expires_at),
                    key_ref=key_ref,
                    wrapped_key=wrapped,
                )
            )
        return found

    # ------------------------------------------------------------------ operations

    def create_capture(self, input: CreateCaptureInput) -> Coroutine[Any, Any, CreateCaptureResult]:
        return self._guarded(self._create_capture, input)

    async def _create_capture(self, input: CreateCaptureInput) -> CreateCaptureResult:
        validate_create_capture(input, self._capabilities)
        scope, capture, entries = input.scope, input.capture, input.entries

        async def body(cursor: Any, head: _Head) -> CreateCaptureResult:
            ns = await self._namespace(cursor, head, scope.namespace, "share")
            if ns.state != "serving" or ns.epoch != input.epoch:
                raise _Rollback(CaptureRejected(reason="quarantined"))
            if self._skewed(head, input.now) or self._skewed(head, capture.created_at):
                raise _Rollback(CaptureRejected(reason="clock-skew"))
            await cursor.execute(
                f"INSERT INTO {self._t_capture} "
                "(namespace, tenant, capture_id, state, generation, key_revision, epoch, session_tag, "
                "created_at, expires_at, key_ref, wrapped_key, has_ciphertext, retain_until) "
                "VALUES (%s, %s, %s, 'live', 1, 1, %s::bigint, %s, %s::bigint, %s::bigint, %s, %s, true, %s::bigint) "
                "ON CONFLICT (namespace, tenant, capture_id) DO NOTHING",
                (
                    scope.namespace,
                    scope.tenant,
                    capture.capture_id,
                    input.epoch,
                    capture.session_tag,
                    capture.created_at,
                    capture.expires_at,
                    capture.key_ref,
                    bytes(capture.wrapped_key),
                    capture.expires_at,
                ),
            )
            if cursor.rowcount != 1:
                [existing] = await self._captures(
                    cursor, scope.namespace, scope.tenant, [capture.capture_id], ns.epoch, ""
                ) or [None]
                # Revoked, fenced, or created under an earlier epoch: the identifier is fenced.
                fenced = existing is not None and existing.state != "live"
                raise _Rollback(CaptureRejected(reason="fenced" if fenced else "exists"))
            await cursor.execute(
                f"INSERT INTO {self._t_entry} "
                "(namespace, tenant, entry_id, capture_id, max_uses, used, lifecycle_revision, ciphertext_revision, "
                "envelope, expires_at) "
                "SELECT %s, %s, e.entry_id, %s, e.max_uses, 0, 1, 1, e.envelope, %s::bigint "
                "FROM unnest(%s::text[], %s::int[], %s::bytea[]) AS e(entry_id, max_uses, envelope) "
                "ON CONFLICT (namespace, tenant, entry_id) DO NOTHING",
                (
                    scope.namespace,
                    scope.tenant,
                    capture.capture_id,
                    capture.expires_at,
                    [entry.entry_id for entry in entries],
                    [entry.max_uses for entry in entries],
                    [bytes(entry.envelope) for entry in entries],
                ),
            )
            # Any entry identifier already present: nothing is created, nothing overwritten.
            if cursor.rowcount != len(entries):
                raise _Rollback(CaptureRejected(reason="exists"))
            return CaptureCreated()

        return await self._transaction(  # type: ignore[no-any-return]
            "write", body, on_contention=CaptureRejected(reason="stale")
        )

    def read_entries(self, input: ReadEntriesInput) -> Coroutine[Any, Any, ReadEntriesResult]:
        return self._guarded(self._read_entries, input)

    async def _read_entries(self, input: ReadEntriesInput) -> ReadEntriesResult:
        validate_read_entries(input, self._capabilities)
        scope = input.scope
        requested = tuple(input.entry_ids)

        async def body(cursor: Any, head: _Head) -> ReadEntriesResult:
            # REPEATABLE READ gives the reads one snapshot (spec section 5.4).
            ns = await self._namespace(cursor, head, scope.namespace, "none")
            await cursor.execute(
                "SELECT e.entry_id, e.capture_id, e.max_uses, e.used, e.lifecycle_revision, "
                f"e.ciphertext_revision, e.envelope FROM {self._t_entry} e "
                "WHERE e.namespace = %s AND e.tenant = %s AND e.entry_id = ANY(%s::text[])",
                (scope.namespace, scope.tenant, list(requested)),
            )
            found: dict[str, StoredEntry] = {}
            for row in await cursor.fetchall():
                entry_id, capture_id, max_uses, used, lifecycle_revision, ciphertext_revision, envelope = row
                _check(is_entry_id(entry_id) and is_capture_id(capture_id) and entry_id in requested)
                max_uses = _int(max_uses, low=1)
                used = _int(used)
                _check(max_uses <= _limits.MAX_USES and used <= max_uses)
                found[entry_id] = StoredEntry(
                    entry_id=entry_id,
                    capture_id=capture_id,
                    max_uses=max_uses,
                    used=used,
                    lifecycle_revision=_int(lifecycle_revision, low=1),
                    ciphertext_revision=_int(ciphertext_revision, low=1),
                    envelope=_bytes(envelope, 1, self._capabilities.max_envelope_bytes),
                )
            entries = tuple(found[entry_id] for entry_id in dict.fromkeys(requested) if entry_id in found)
            capture_ids = list(dict.fromkeys(entry.capture_id for entry in entries))
            captures: list[StoredCapture] = []
            if capture_ids:
                by_id = {
                    capture.capture_id: capture
                    for capture in await self._captures(
                        cursor, scope.namespace, scope.tenant, capture_ids, ns.epoch, ""
                    )
                }
                _check(all(capture_id in by_id for capture_id in capture_ids))
                captures = [by_id[capture_id] for capture_id in capture_ids]
            return ReadEntriesResult(
                recovery=RecoveryState(epoch=ns.epoch, state=ns.state),  # type: ignore[arg-type]
                entries=entries,
                captures=tuple(captures),
            )

        return await self._transaction("read", body)  # type: ignore[no-any-return]

    def read_captures(self, input: ReadCapturesInput) -> Coroutine[Any, Any, tuple[StoredCapture, ...]]:
        return self._guarded(self._read_captures, input)

    async def _read_captures(self, input: ReadCapturesInput) -> tuple[StoredCapture, ...]:
        validate_read_captures(input, self._capabilities)
        scope = input.scope
        requested = tuple(input.capture_ids)

        async def body(cursor: Any, head: _Head) -> tuple[StoredCapture, ...]:
            ns = await self._namespace(cursor, head, scope.namespace, "none")
            rows = await self._captures(cursor, scope.namespace, scope.tenant, requested, ns.epoch, "")
            by_id = {capture.capture_id: capture for capture in rows}
            _check(all(capture_id in requested for capture_id in by_id))
            return tuple(by_id[capture_id] for capture_id in dict.fromkeys(requested) if capture_id in by_id)

        return await self._transaction("read", body)  # type: ignore[no-any-return]

    def commit_restore(self, input: CommitRestoreInput) -> Coroutine[Any, Any, CommitRestoreResult]:
        return self._guarded(self._commit_restore, input)

    async def _commit_restore(self, input: CommitRestoreInput) -> CommitRestoreResult:
        validate_commit_restore(input, self._capabilities)
        scope, attempt = input.scope, input.attempt
        digest = bytes(attempt.request_digest)

        async def body(cursor: Any, head: _Head) -> CommitRestoreResult:
            # Lock order: recovery record, receipt, captures by identifier, entries by identifier.
            # 1. Shared lock on the recovery record: conflicts with quarantine and invalidation.
            ns = await self._namespace(cursor, head, scope.namespace, "share")
            if ns.state != "serving" or ns.epoch != input.epoch:
                raise _Rollback(RestoreRejected(reason="quarantined"))

            # 2. The receipt is claimed first. A concurrent transaction for the same attempt waits here until
            # this one ends, then sees the conflict.
            await cursor.execute(
                f"INSERT INTO {self._t_receipt} "
                "(namespace, tenant, attempt_id, request_digest, committed_at, expires_at) "
                "VALUES (%s, %s, %s, %s, %s::bigint, %s::bigint) "
                "ON CONFLICT (namespace, tenant, attempt_id) DO NOTHING",
                (scope.namespace, scope.tenant, attempt.attempt_id, digest, head.now, input.receipt_expires_at),
            )
            if cursor.rowcount != 1:
                await cursor.execute(
                    f"SELECT request_digest FROM {self._t_receipt} "
                    "WHERE namespace = %s AND tenant = %s AND attempt_id = %s",
                    (scope.namespace, scope.tenant, attempt.attempt_id),
                )
                existing = await cursor.fetchone()
                # Swept between the conflict and the read: nothing known, nothing applied.
                if existing is None:
                    raise _Rollback(RestoreRejected(reason="stale"))
                stored = _bytes(existing[0], _limits.REQUEST_DIGEST_BYTES, _limits.REQUEST_DIGEST_BYTES)
                same = stored == digest
                raise _Rollback(RestoreAlreadyCommitted() if same else RestoreAttemptMismatch())

            # 3. Skew.
            if self._skewed(head, input.now):
                raise _Rollback(RestoreRejected(reason="clock-skew"))
            if input.receipt_expires_at > head.now + _limits.MAX_RECEIPT_HORIZON_MS:
                raise StoreError("STORE_INVALID_ARGUMENT")

            # 4. Captures, share-locked: a revocation of any of them now waits for this transaction, and one that
            # already committed is visible here.
            captures = await self._captures(
                cursor,
                scope.namespace,
                scope.tenant,
                [item.capture_id for item in input.captures],
                ns.epoch,
                " FOR SHARE",
            )
            by_id = {capture.capture_id: capture for capture in captures}
            latest_expiry = 0
            for expected in input.captures:
                capture = by_id.get(expected.capture_id)
                if capture is None:
                    raise _Rollback(RestoreRejected(reason="unknown"))
                if capture.state != "live":
                    raise _Rollback(RestoreRejected(reason="revoked"))
                if capture.generation != expected.generation:
                    raise _Rollback(RestoreRejected(reason="stale"))
                if head.now >= capture.expires_at:
                    raise _Rollback(RestoreRejected(reason="expired"))
                latest_expiry = max(latest_expiry, capture.expires_at)

            # 5. Entries, locked for update in identifier order.
            await cursor.execute(
                "SELECT entry_id, capture_id, max_uses, used, lifecycle_revision, ciphertext_revision "
                f"FROM {self._t_entry} WHERE namespace = %s AND tenant = %s AND entry_id = ANY(%s::text[]) "
                "ORDER BY entry_id FOR UPDATE",
                (scope.namespace, scope.tenant, [use.entry_id for use in input.uses]),
            )
            rows = {row[0]: row for row in await cursor.fetchall()}
            for use in input.uses:
                row = rows.get(use.entry_id)
                if row is None or row[1] != use.capture_id:
                    raise _Rollback(RestoreRejected(reason="unknown"))
                max_uses, used = _int(row[2], low=1), _int(row[3])
                if _int(row[4], low=1) != use.lifecycle_revision or _int(row[5], low=1) != use.ciphertext_revision:
                    raise _Rollback(RestoreRejected(reason="stale"))
                if used + use.count > max_uses:
                    raise _Rollback(RestoreRejected(reason="budget"))

            # Expiry is judged again now that every lock is held: the time spent waiting for them must not let a
            # capture be restored past its expiry.
            locked_at = await self._clock(cursor)
            for capture in captures:
                if locked_at >= capture.expires_at:
                    raise _Rollback(RestoreRejected(reason="expired"))

            # 6. A receipt must outlive every capture it covers.
            if input.receipt_expires_at < latest_expiry:
                raise StoreError("STORE_INVALID_ARGUMENT")

            # 7. Apply every use in one statement.
            await cursor.execute(
                f"UPDATE {self._t_entry} e SET used = e.used + u.count, lifecycle_revision = e.lifecycle_revision + 1 "
                "FROM unnest(%s::text[], %s::int[]) AS u(entry_id, count) "
                "WHERE e.namespace = %s AND e.tenant = %s AND e.entry_id = u.entry_id",
                (
                    [use.entry_id for use in input.uses],
                    [use.count for use in input.uses],
                    scope.namespace,
                    scope.tenant,
                ),
            )
            if cursor.rowcount != len(input.uses):
                raise StoreError("STORE_UNAVAILABLE")
            return RestoreCommitted()

        return await self._transaction(  # type: ignore[no-any-return]
            "write", body, on_contention=RestoreRejected(reason="stale")
        )

    def revoke_capture(self, input: RevokeCaptureInput) -> Coroutine[Any, Any, RevokeCaptureResult]:
        return self._guarded(self._revoke_capture, input)

    async def _revoke_capture(self, input: RevokeCaptureInput) -> RevokeCaptureResult:
        validate_revoke_capture(input)
        scope, capture_id = input.scope, input.capture_id

        async def body(cursor: Any, head: _Head) -> RevokeCaptureResult:
            # Revocation works in a quarantined namespace; the record is read for its epoch only.
            ns = await self._namespace(cursor, head, scope.namespace, "share")
            found = await self._captures(cursor, scope.namespace, scope.tenant, [capture_id], ns.epoch, " FOR UPDATE")
            if not found:
                if not input.fence_absent:
                    return CaptureNotFound()
                await cursor.execute(
                    f"INSERT INTO {self._t_capture} "
                    "(namespace, tenant, capture_id, state, generation, key_revision, epoch, session_tag, "
                    "created_at, expires_at, key_ref, wrapped_key, has_ciphertext, retain_until) "
                    "VALUES (%s, %s, %s, 'revoked', 1, 1, %s::bigint, NULL, %s::bigint, %s::bigint, "
                    "'', ''::bytea, false, %s::bigint) "
                    "ON CONFLICT (namespace, tenant, capture_id) DO NOTHING",
                    (
                        scope.namespace,
                        scope.tenant,
                        capture_id,
                        max(ns.epoch, 1),
                        head.now,
                        head.now,
                        head.now + input.retention_ms,
                    ),
                )
                # A creation won the race: run again and revoke what now exists.
                if cursor.rowcount != 1:
                    raise _Rollback(CONTENDED)
                return CaptureFenced()
            capture = found[0]
            await cursor.execute(
                f"SELECT count(*)::int AS entries FROM {self._t_entry} "
                "WHERE namespace = %s AND tenant = %s AND capture_id = %s",
                (scope.namespace, scope.tenant, capture_id),
            )
            counted = await cursor.fetchone()
            _check(counted is not None)
            entries = _int(counted[0])
            if capture.state != "live":
                return CaptureRevoked(outcome="already-revoked", entries=entries)
            await cursor.execute(
                f"UPDATE {self._t_capture} SET state = 'revoked', generation = generation + 1, "
                "retain_until = GREATEST(expires_at, %s::bigint) + %s::bigint "
                "WHERE namespace = %s AND tenant = %s AND capture_id = %s",
                (head.now, input.retention_ms, scope.namespace, scope.tenant, capture_id),
            )
            return CaptureRevoked(outcome="revoked", entries=entries)

        # One more try after a lock wait or a lost create/fence race. Nothing was applied by the first.
        for _attempt in range(2):
            result = await self._transaction("write", body, on_contention=CONTENDED)
            if result is not CONTENDED:
                return result  # type: ignore[no-any-return]
        raise StoreError("STORE_UNAVAILABLE")

    def inspect_attempt(self, input: InspectAttemptInput) -> Coroutine[Any, Any, InspectAttemptResult]:
        return self._guarded(self._inspect_attempt, input)

    async def _inspect_attempt(self, input: InspectAttemptInput) -> InspectAttemptResult:
        validate_inspect_attempt(input)
        scope = input.scope

        async def body(cursor: Any, head: _Head) -> InspectAttemptResult:
            # A read on the primary (the transaction head refuses a standby): authoritative.
            await cursor.execute(
                f"SELECT request_digest, committed_at FROM {self._t_receipt} "
                "WHERE namespace = %s AND tenant = %s AND attempt_id = %s",
                (scope.namespace, scope.tenant, input.attempt_id),
            )
            row = await cursor.fetchone()
            if row is None:
                return AttemptAbsent()
            return AttemptCommitted(
                request_digest=_bytes(row[0], _limits.REQUEST_DIGEST_BYTES, _limits.REQUEST_DIGEST_BYTES),
                committed_at=_int(row[1]),
            )

        return await self._transaction("read", body)  # type: ignore[no-any-return]

    def replace_capture_key(self, input: ReplaceCaptureKeyInput) -> Coroutine[Any, Any, ReplaceCaptureKeyResult]:
        return self._guarded(self._replace_capture_key, input)

    async def _replace_capture_key(self, input: ReplaceCaptureKeyInput) -> ReplaceCaptureKeyResult:
        validate_replace_capture_key(input)
        scope, capture_id = input.scope, input.capture_id

        async def body(cursor: Any, head: _Head) -> ReplaceCaptureKeyResult:
            ns = await self._namespace(cursor, head, scope.namespace, "share")
            found = await self._captures(cursor, scope.namespace, scope.tenant, [capture_id], ns.epoch, " FOR UPDATE")
            if not found:
                return CaptureKeyRejected(reason="unknown")
            capture = found[0]
            if capture.state != "live":
                return CaptureKeyRejected(reason="revoked")
            if (await self._clock(cursor)) >= capture.expires_at:
                return CaptureKeyRejected(reason="expired")
            if capture.key_revision != input.key_revision:
                return CaptureKeyRejected(reason="stale")
            # Only the stored key changes: no envelope, counter, state, epoch, or time.
            await cursor.execute(
                f"UPDATE {self._t_capture} SET key_ref = %s, wrapped_key = %s, key_revision = key_revision + 1 "
                "WHERE namespace = %s AND tenant = %s AND capture_id = %s",
                (input.key_ref, bytes(input.wrapped_key), scope.namespace, scope.tenant, capture_id),
            )
            return CaptureKeyReplaced(key_revision=input.key_revision + 1)

        return await self._transaction(  # type: ignore[no-any-return]
            "write", body, on_contention=CaptureKeyRejected(reason="stale")
        )

    def delete_ciphertext(self, input: DeleteCiphertextInput) -> Coroutine[Any, Any, DeleteCiphertextResult]:
        return self._guarded(self._delete_ciphertext, input)

    async def _delete_ciphertext(self, input: DeleteCiphertextInput) -> DeleteCiphertextResult:
        validate_delete_ciphertext(input)
        scope, capture_id = input.scope, input.capture_id

        async def body(cursor: Any, head: _Head) -> DeleteCiphertextResult:
            ns = await self._namespace(cursor, head, scope.namespace, "share")
            found = await self._captures(cursor, scope.namespace, scope.tenant, [capture_id], ns.epoch, " FOR UPDATE")
            if not found:
                return CiphertextRejected(reason="not-found")
            capture = found[0]
            if capture.state == "live":
                # The decision rests on expiry, so the clocks must agree.
                if self._skewed(head, input.now):
                    return CiphertextRejected(reason="clock-skew")
                if head.now < capture.expires_at:
                    return CiphertextRejected(reason="live")
            await cursor.execute(
                f"DELETE FROM {self._t_entry} WHERE namespace = %s AND tenant = %s AND capture_id = %s",
                (scope.namespace, scope.tenant, capture_id),
            )
            removed = cursor.rowcount
            await cursor.execute(
                f"UPDATE {self._t_capture} SET state = 'revoked', key_ref = '', wrapped_key = ''::bytea, "
                "has_ciphertext = false, key_revision = key_revision + 1 "
                "WHERE namespace = %s AND tenant = %s AND capture_id = %s",
                (scope.namespace, scope.tenant, capture_id),
            )
            return CiphertextDeleted(entries=_int(removed))

        return await self._transaction("write", body)  # type: ignore[no-any-return]

    def sweep_expired(self, input: SweepInput) -> Coroutine[Any, Any, SweepResult]:
        return self._guarded(self._sweep_expired, input)

    async def _sweep_expired(self, input: SweepInput) -> SweepResult:
        validate_sweep(input)
        namespace, limit = input.namespace, input.limit

        async def body(cursor: Any, head: _Head) -> SweepResult:
            if self._skewed(head, input.now):
                return SweepRejected()
            # Rows another transaction holds are skipped, never waited for: cleanup yields to restores.
            await cursor.execute(
                f"DELETE FROM {self._t_entry} WHERE ctid IN ("
                f"SELECT ctid FROM {self._t_entry} WHERE namespace = %s AND expires_at <= %s::bigint "
                "LIMIT %s FOR UPDATE SKIP LOCKED)",
                (namespace, head.now, limit),
            )
            entries = _int(cursor.rowcount)
            await cursor.execute(
                f"DELETE FROM {self._t_capture} WHERE ctid IN ("
                f"SELECT ctid FROM {self._t_capture} x "
                "WHERE x.namespace = %s AND x.expires_at <= %s::bigint "
                "AND (x.state = 'live' OR x.retain_until < %s::bigint) "
                f"AND NOT EXISTS (SELECT 1 FROM {self._t_entry} e "
                "WHERE e.namespace = x.namespace AND e.tenant = x.tenant AND e.capture_id = x.capture_id) "
                "LIMIT %s FOR UPDATE SKIP LOCKED)",
                (namespace, head.now, head.now, limit),
            )
            captures = _int(cursor.rowcount)
            await cursor.execute(
                f"DELETE FROM {self._t_receipt} WHERE ctid IN ("
                f"SELECT ctid FROM {self._t_receipt} WHERE namespace = %s AND expires_at < %s::bigint "
                "LIMIT %s FOR UPDATE SKIP LOCKED)",
                (namespace, head.now, limit),
            )
            receipts = _int(cursor.rowcount)
            return Swept(
                entries=entries,
                captures=captures,
                receipts=receipts,
                more=any(count >= limit for count in (entries, captures, receipts)),
            )

        return await self._transaction("write", body)  # type: ignore[no-any-return]

    def recovery_state(self, namespace: str) -> Coroutine[Any, Any, RecoveryState]:
        return self._guarded(self._recovery_state, namespace)

    async def _recovery_state(self, namespace: str) -> RecoveryState:
        validate_namespace(namespace)

        async def body(cursor: Any, head: _Head) -> RecoveryState:
            ns = await self._namespace(cursor, head, namespace, "none")
            return RecoveryState(epoch=ns.epoch, state=ns.state)  # type: ignore[arg-type]

        return await self._transaction("read", body)  # type: ignore[no-any-return]

    def initialize_namespace(self, namespace: str, epoch: int) -> Coroutine[Any, Any, InitializeNamespaceResult]:
        return self._guarded(self._initialize_namespace, namespace, epoch)

    async def _initialize_namespace(self, namespace: str, epoch: int) -> InitializeNamespaceResult:
        validate_initialize_namespace(namespace, epoch)

        async def body(cursor: Any, head: _Head) -> InitializeNamespaceResult:
            # Serializes initializations of one namespace, so the emptiness check and the insert are one step.
            await cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"rsv-namespace:{namespace}",))
            await cursor.execute(f"SELECT 1 FROM {self._t_ns} WHERE namespace = %s", (namespace,))
            if await cursor.fetchone() is not None:
                return NamespaceRejected(reason="exists")
            await cursor.execute(
                f"SELECT EXISTS (SELECT 1 FROM {self._t_capture} WHERE namespace = %s) "
                f"OR EXISTS (SELECT 1 FROM {self._t_entry} WHERE namespace = %s) "
                f"OR EXISTS (SELECT 1 FROM {self._t_receipt} WHERE namespace = %s) AS occupied",
                (namespace, namespace, namespace),
            )
            occupied = await cursor.fetchone()
            if occupied is None or occupied[0] is not False:
                return NamespaceRejected(reason="not-empty")
            await cursor.execute(
                f"INSERT INTO {self._t_ns} (namespace, epoch, state, system_identifier, timeline_id) "
                "VALUES (%s, %s::bigint, 'serving', %s, %s::bigint)",
                (namespace, epoch, head.system_identifier, head.timeline_id),
            )
            return NamespaceInitialized()

        return await self._transaction("write", body)  # type: ignore[no-any-return]

    def quarantine(self, namespace: str) -> Coroutine[Any, Any, RecoveryState]:
        return self._guarded(self._quarantine, namespace)

    async def _quarantine(self, namespace: str) -> RecoveryState:
        validate_namespace(namespace)

        async def body(cursor: Any, head: _Head) -> RecoveryState:
            # Exclusive: waits for in-flight commits and creates, and blocks new ones until it commits.
            ns = await self._namespace(cursor, head, namespace, "update")
            if ns.state == "uninitialized":
                return RecoveryState(epoch=0, state="uninitialized")
            await cursor.execute(f"UPDATE {self._t_ns} SET state = 'quarantined' WHERE namespace = %s", (namespace,))
            return RecoveryState(epoch=ns.epoch, state="quarantined")

        return await self._transaction("write", body)  # type: ignore[no-any-return]

    def invalidate_recovered(self, input: InvalidateRecoveredInput) -> Coroutine[Any, Any, InvalidateRecoveredResult]:
        return self._guarded(self._invalidate_recovered, input)

    async def _invalidate_recovered(self, input: InvalidateRecoveredInput) -> InvalidateRecoveredResult:
        validate_invalidate_recovered(input)

        async def body(cursor: Any, head: _Head) -> InvalidateRecoveredResult:
            ns = await self._namespace(cursor, head, input.namespace, "update")
            if ns.state == "uninitialized":
                return InvalidateRejected(reason="uninitialized")
            if input.new_epoch <= ns.epoch:
                return InvalidateRejected(reason="epoch-not-greater")
            # Every capture stamped with an earlier epoch is revoked from here on; the database's present
            # identity becomes the recorded one.
            await cursor.execute(
                f"UPDATE {self._t_ns} SET epoch = %s::bigint, state = 'serving', system_identifier = %s, "
                "timeline_id = %s::bigint WHERE namespace = %s",
                (input.new_epoch, head.system_identifier, head.timeline_id, input.namespace),
            )
            return RecoveredInvalidated(recovery=RecoveryState(epoch=input.new_epoch, state="serving"))

        return await self._transaction("write", body)  # type: ignore[no-any-return]

    def acknowledge_identity_change(self, namespace: str) -> Coroutine[Any, Any, RecoveryState]:
        """Records the database's current identity for a namespace without changing its epoch, after the operator
        established that the change lost no acknowledged commit (promotion of a synchronous standby). It accepts a
        new timeline of the same cluster and nothing else; a changed system identifier is refused."""

        return self._guarded(self._acknowledge_identity_change, namespace)

    async def _acknowledge_identity_change(self, namespace: str) -> RecoveryState:
        validate_namespace(namespace)

        async def body(cursor: Any, head: _Head) -> RecoveryState:
            ns = await self._namespace(cursor, head, namespace, "update")
            if ns.state == "uninitialized":
                return RecoveryState(epoch=0, state="uninitialized")
            await cursor.execute(f"SELECT system_identifier FROM {self._t_ns} WHERE namespace = %s", (namespace,))
            recorded = await cursor.fetchone()
            _check(recorded is not None)
            # A promoted standby keeps its cluster's system identifier. A different one is another cluster: a
            # restore, never a promotion. ``invalidate_recovered`` is the way out.
            if recorded[0] != head.system_identifier:
                return RecoveryState(epoch=ns.epoch, state="quarantined")
            await cursor.execute(
                f"UPDATE {self._t_ns} SET system_identifier = %s, timeline_id = %s::bigint WHERE namespace = %s",
                (head.system_identifier, head.timeline_id, namespace),
            )
            after = await self._namespace(cursor, head, namespace, "none")
            return RecoveryState(epoch=after.epoch, state=after.state)  # type: ignore[arg-type]

        return await self._transaction("write", body)  # type: ignore[no-any-return]


def _bounded(name: str, value: int | None, default: int, ceiling: int) -> int:
    resolved = default if value is None else value
    if type(resolved) is not int or not 1 <= resolved <= ceiling:
        raise ValueError(f"create_postgres_store: {name} must be an integer from 1 to {ceiling}")
    return resolved


async def create_postgres_store(
    *,
    pool: Any,
    schema: str = _DEFAULT_SCHEMA,
    max_clock_skew_ms: int = _DEFAULT_MAX_CLOCK_SKEW_MS,
    synchronous_commit: Literal["on", "remote_apply"] = "on",
    require_synchronous_standby: bool = False,
    statement_timeout_ms: int | None = None,
    lock_timeout_ms: int | None = None,
    max_create_entries: int | None = None,
    max_create_bytes: int | None = None,
    max_restore_entries: int | None = None,
    max_restore_captures: int | None = None,
    max_envelope_bytes: int | None = None,
    store_class: type[PostgresStore] = PostgresStore,
) -> PostgresStore:
    """Opens the store after verifying the deployment it is pointed at: the schema version, that the server is a
    primary, that ``fsync`` is on, and that the required commit durability can be set. It raises ``STORE_CAPABILITY``
    when a check fails and ``STORE_UNAVAILABLE`` when it cannot connect. It creates no table.

    Each size bound may only be lowered from its default. ``store_class`` is for a test subclass.
    """

    connection = getattr(pool, "connection", None)
    if not callable(connection):
        raise StoreError("STORE_INVALID_ARGUMENT")
    if not _is_schema_name(schema):
        raise StoreError("STORE_INVALID_ARGUMENT")
    if synchronous_commit not in ("on", "remote_apply"):
        raise StoreError("STORE_INVALID_ARGUMENT")
    if type(require_synchronous_standby) is not bool:
        raise StoreError("STORE_INVALID_ARGUMENT")
    if type(max_clock_skew_ms) is not int or not 0 <= max_clock_skew_ms <= _MAX_CLOCK_SKEW_CEILING_MS:
        raise StoreError("STORE_INVALID_ARGUMENT")
    try:
        statement_ms = _bounded(
            "statement_timeout_ms", statement_timeout_ms, _DEFAULT_STATEMENT_TIMEOUT_MS, _TIMEOUT_CEILING_MS
        )
        lock_ms = _bounded("lock_timeout_ms", lock_timeout_ms, _DEFAULT_LOCK_TIMEOUT_MS, _TIMEOUT_CEILING_MS)
        max_entries = _bounded(
            "max_create_entries", max_create_entries, _limits.MAX_CREATE_ENTRIES, _limits.MAX_CREATE_ENTRIES
        )
        max_bytes = _bounded("max_create_bytes", max_create_bytes, _DEFAULT_MAX_CREATE_BYTES, _MAX_CREATE_BYTES_CEILING)
        restore_entries = _bounded(
            "max_restore_entries", max_restore_entries, _limits.MAX_RESTORE_ENTRIES, _limits.MAX_RESTORE_ENTRIES
        )
        restore_captures = _bounded(
            "max_restore_captures", max_restore_captures, _limits.MAX_RESTORE_CAPTURES, _limits.MAX_RESTORE_CAPTURES
        )
        envelope_bytes = _bounded(
            "max_envelope_bytes", max_envelope_bytes, _limits.MAX_ENVELOPE_BYTES, _limits.MAX_ENVELOPE_BYTES
        )
    except ValueError:
        # No driver text here, but the bound that failed is the caller's own argument name, not a secret.
        invalid = True
    else:
        invalid = False
    if invalid:
        raise StoreError("STORE_INVALID_ARGUMENT")

    standby_names = await _verify_deployment(pool, schema, synchronous_commit, require_synchronous_standby)

    capabilities = StoreCapabilities(
        contract_version=1,
        adapter="store-postgres-py",
        profile=(
            f"postgres-single-primary/synchronous_commit={synchronous_commit}"
            if standby_names.strip() == ""
            else f"postgres-primary-with-synchronous-standby/synchronous_commit={synchronous_commit}"
        ),
        atomic_create=True,
        max_create_entries=max_entries,
        max_create_bytes=max_bytes,
        atomic_restore=True,
        max_restore_entries=restore_entries,
        max_restore_captures=restore_captures,
        authoritative_commit=True,
        revocation_fences=True,
        attempt_receipts=True,
        store_clock=True,
        max_clock_skew_ms=max_clock_skew_ms,
        durability="durable",
        cross_process=True,
        restore_detection="postgres-system-identifier-and-timeline",
        max_envelope_bytes=envelope_bytes,
    )
    return store_class(
        pool,
        schema,
        capabilities,
        synchronous_commit,
        require_synchronous_standby or synchronous_commit == "remote_apply",
        statement_ms,
        lock_ms,
    )


async def _verify_deployment(pool: Any, schema: str, synchronous_commit: str, require_standby: bool) -> str:
    """Schema version, primary, ``fsync``, and standby configuration. Returns ``synchronous_standby_names``."""

    code: str | None = None
    names = ""
    manager: Any = None
    connection: Any = None
    try:
        manager = pool.connection()
        connection = await manager.__aenter__()
    except Exception:  # noqa: BLE001
        connection = None
    if connection is None:
        raise StoreError("STORE_UNAVAILABLE")
    try:
        async with connection.cursor() as cursor:
            if connection.autocommit is False and connection.info.transaction_status != pq.TransactionStatus.IDLE:
                raise StoreError("STORE_UNAVAILABLE")
            await cursor.execute(f'SELECT version FROM "{schema}".rsv_schema')
            versions = await cursor.fetchall()
            if len(versions) != 1 or versions[0][0] != SCHEMA_VERSION:
                raise StoreError("STORE_CAPABILITY")
            await cursor.execute(
                "SELECT pg_is_in_recovery() AS standby, current_setting('fsync') AS fsync, "
                "current_setting('synchronous_standby_names') AS standbys"
            )
            facts = await cursor.fetchone()
            if facts is None or facts[0] is not False or facts[1] != "on":
                raise StoreError("STORE_CAPABILITY")
            names = facts[2] if type(facts[2]) is str else ""
            if (require_standby or synchronous_commit == "remote_apply") and names.strip() == "":
                raise StoreError("STORE_CAPABILITY")
            await connection.rollback()
    except StoreError as error:
        code = error.code
    except Exception:  # noqa: BLE001
        code = "STORE_UNAVAILABLE"
    except BaseException:
        await PostgresStore._discard(connection, manager, None)
        raise
    if code is not None:
        await PostgresStore._discard(connection, manager, None)
        raise StoreError(code)  # type: ignore[arg-type]
    await PostgresStore._release(connection, manager, None)
    return names
