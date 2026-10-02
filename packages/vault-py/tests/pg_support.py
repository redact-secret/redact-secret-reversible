"""Test-only support for the PostgreSQL adapter (``redact_secret_vault.stores.postgres``).

Nothing here is in the wheel. It supplies:

* the database location, from ``RSV_PG_APP_URL`` (the serving role) and ``RSV_PG_ADMIN_URL`` (a role that may corrupt
  rows and terminate sessions, used only by tests that need to). Without them every test that needs a database is
  skipped with the reason, and a run with ``RSV_REQUIRE_POSTGRES=1`` fails instead: a run without a database proves
  nothing and must not look like a pass. The schema is applied by ``tests/pg_prepare.mjs`` from the JavaScript
  package, which owns it.
* ``Pool``: the smallest pool the adapter accepts (``connection()`` yields a ``psycopg.AsyncConnection``), with a
  bound on open connections and counters, so a test sees which connections the adapter discarded.
* ``HookedPool``: a pool whose connections pause before ``COMMIT`` (the hold point ``before-commit``) and fail in
  named ways (the fault vocabulary of ``conformance/persistent/v1/SCHEDULES.md``), through the real adapter and the
  real driver. The hooks are armed per task with context variables, so concurrent calls do not see each other's.
* ``DbClock``: a store clock a test can move, kept in a test-only table, read by a subclass of the adapter. The
  same transactions, locks, isolation, and commits run; only the clock expression differs.
"""

from __future__ import annotations

import asyncio
import contextvars
import os
import secrets
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

ENV_APP = "RSV_PG_APP_URL"
ENV_ADMIN = "RSV_PG_ADMIN_URL"
ENV_SCHEMA = "RSV_PG_SCHEMA"
ENV_REQUIRE = "RSV_REQUIRE_POSTGRES"

APP_URL = os.environ.get(ENV_APP)
ADMIN_URL = os.environ.get(ENV_ADMIN)
SCHEMA = os.environ.get(ENV_SCHEMA, "rsv")
HAVE_DATABASE = bool(APP_URL) and bool(ADMIN_URL)
REQUIRED = os.environ.get(ENV_REQUIRE) == "1"
SKIP_REASON = f"{ENV_APP} and {ENV_ADMIN} are not set (no database; nothing was run)"

CLOCK_START_MS = 1_800_000_000_000


def require_database() -> None:
    """Call at module level: skip, or fail when the run insists on a database."""

    if HAVE_DATABASE:
        return
    if REQUIRED:
        raise RuntimeError(f"{ENV_REQUIRE}=1 but {SKIP_REASON}")


needs_database = pytest.mark.skipif(not HAVE_DATABASE and not REQUIRED, reason=SKIP_REASON)


def random_name(prefix: str = "t") -> str:
    return f"{prefix}-{secrets.token_hex(6)}"


class Pool:
    """A pool of fresh connections, closed on exit; at most ``size`` open at once."""

    def __init__(self, dsn: str | None = None, size: int = 40) -> None:
        self.dsn = dsn or APP_URL or ""
        self.size = size
        self.opened = 0
        self.closed = 0
        self.discarded = 0
        self._gate: asyncio.Semaphore | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    def connection(self) -> Any:
        return _Lease(self)

    def _semaphore(self) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        if self._gate is None or self._loop is not loop:
            self._gate, self._loop = asyncio.Semaphore(self.size), loop
        return self._gate

    async def _open(self) -> Any:
        import psycopg

        return await psycopg.AsyncConnection.connect(self.dsn)

    def _wrap(self, connection: Any) -> Any:
        return connection


class _Lease:
    def __init__(self, pool: Pool) -> None:
        self._pool = pool
        self._connection: Any = None
        self._held = False

    async def __aenter__(self) -> Any:
        await self._pool._semaphore().acquire()
        self._held = True
        try:
            raw = await self._pool._open()
        except BaseException:
            self._pool._semaphore().release()
            self._held = False
            raise
        self._pool.opened += 1
        self._connection = raw
        return self._pool._wrap(raw)

    async def __aexit__(self, *_exc: object) -> None:
        raw = self._connection
        try:
            if raw is not None:
                if raw.closed or raw.broken:
                    self._pool.discarded += 1
                await raw.close()
                self._pool.closed += 1
        finally:
            if self._held:
                self._pool._semaphore().release()
                self._held = False


# ------------------------------------------------------------------------- hold and fault hooks

#: ``async def pause()``: awaited immediately before the next ``COMMIT`` sent by the calling task, once.
HOLD: contextvars.ContextVar[Callable[[], Awaitable[None]] | None] = contextvars.ContextVar("rsv_pg_hold", default=None)
#: A fault applied to the calling task's next call.
FAULT: contextvars.ContextVar[str | None] = contextvars.ContextVar("rsv_pg_fault", default=None)

#: A process-wide queue of pauses (``async def pause()``): the next write transaction, in whatever task, awaits one
#: before its ``COMMIT``. For a worker process that is driven by messages and has no task of its own to arm.
HOLD_NEXT: list[Callable[[], Awaitable[None]]] = []

FAULT_MARKER = "SENTINEL-SYNTHETIC-DRIVER-FAILURE"


class _Cursor:
    """A cursor whose ``execute`` consults the hooks of the calling task."""

    def __init__(self, inner: Any, connection: _Connection) -> None:
        self._inner = inner
        self._connection = connection

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def __aenter__(self) -> _Cursor:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self._inner.close()

    async def execute(self, query: Any, params: Any = None, **kwargs: Any) -> Any:
        import psycopg

        text = query if isinstance(query, str) else ""
        fault = FAULT.get()
        if text.startswith(("SET TRANSACTION", "BEGIN ISOLATION")):
            self._connection.writing = "READ WRITE" in text
        if text == "COMMIT":
            pause = HOLD.get()
            if pause is None and self._connection.writing and HOLD_NEXT:
                pause = HOLD_NEXT.pop(0)
            if pause is not None:
                HOLD.set(None)
                await pause()
            if fault in ("after-commit-before-ack", "drop-connection"):
                FAULT.set(None)
                # The commit is durable on the server; the caller sees a lost connection.
                await self._inner.execute(text)
                await self._connection.inner.close()
                raise psycopg.OperationalError(FAULT_MARKER)
        elif fault == "before-first-write" and text.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE")):
            FAULT.set(None)
            await self._connection.inner.close()
            raise psycopg.OperationalError(FAULT_MARKER)
        return await self._inner.execute(query, params, **kwargs)


class _Connection:
    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.writing = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def cursor(self, *args: Any, **kwargs: Any) -> _Cursor:
        return _Cursor(self.inner.cursor(*args, **kwargs), self)


class HookedPool(Pool):
    """A ``Pool`` whose connections honour ``HOLD`` and ``FAULT``."""

    def connection(self) -> Any:
        if FAULT.get() == "unavailable":
            FAULT.set(None)
            raise _unavailable()
        return super().connection()

    def _wrap(self, connection: Any) -> Any:
        return _Connection(connection)


def _unavailable() -> Exception:
    import psycopg

    return psycopg.OperationalError(FAULT_MARKER)


# ---------------------------------------------------------------------------------- clock


class DbClock:
    """A store clock in a test-only table: one row per clock, moved by the test, read by ``clocked_store_class``."""

    def __init__(self, dsn: str | None = None, start: int = CLOCK_START_MS) -> None:
        self.dsn = dsn or APP_URL or ""
        self.id = random_name("clock")
        self.ms = start
        self._ready = False

    def now(self) -> int:
        return self.ms

    async def push(self) -> None:
        import psycopg

        async with await psycopg.AsyncConnection.connect(self.dsn, autocommit=True) as connection:
            if not self._ready:
                await connection.execute(
                    f'INSERT INTO "{SCHEMA}".rsv_test_clock (id, now_ms) VALUES (%s, %s)', (self.id, self.ms)
                )
                self._ready = True
            else:
                await connection.execute(
                    f'UPDATE "{SCHEMA}".rsv_test_clock SET now_ms = %s WHERE id = %s', (self.ms, self.id)
                )

    async def dispose(self) -> None:
        import psycopg

        if not self._ready:
            return
        async with await psycopg.AsyncConnection.connect(self.dsn, autocommit=True) as connection:
            await connection.execute(f'DELETE FROM "{SCHEMA}".rsv_test_clock WHERE id = %s', (self.id,))
        self._ready = False

    def sql(self) -> str:
        return f"(SELECT now_ms FROM \"{SCHEMA}\".rsv_test_clock WHERE id = '{self.id}')"


async def open_store(
    pool: Pool,
    *,
    clock: DbClock | None = None,
    schema: str | None = None,
    **options: Any,
) -> Any:
    """The adapter over ``pool``; with ``clock``, a subclass that reads the store clock from it."""

    from redact_secret_vault.stores.postgres import PostgresStore, create_postgres_store

    store_class: type[PostgresStore] = PostgresStore
    if clock is not None:
        await clock.push()
        expression = clock.sql()

        class ClockedStore(PostgresStore):
            _NOW_SQL = expression

        store_class = ClockedStore
    defaults: dict[str, Any] = {"lock_timeout_ms": 10_000, "max_clock_skew_ms": 30_000}
    if clock is not None:
        defaults["max_clock_skew_ms"] = 2000
    defaults.update(options)
    return await create_postgres_store(pool=pool, schema=schema or SCHEMA, store_class=store_class, **defaults)


# ----------------------------------------------------------------------------- admin access


async def admin_execute(sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    """One statement as the admin role (autocommit). Rows, or an empty list for a statement that returns none."""

    import psycopg

    async with await psycopg.AsyncConnection.connect(ADMIN_URL or "", autocommit=True) as connection:
        cursor = await connection.execute(sql, params)
        return await cursor.fetchall() if cursor.description is not None else []


# ------------------------------------------------------------------- a network the test can cut


class CuttableProxy:
    """A TCP relay between the adapter and PostgreSQL that cuts a connection at a chosen client message.

    ``arm(pattern, forward=True)``: the next client message containing ``pattern`` is forwarded to the server first
    (``forward``), or not at all, and then both sockets are closed without relaying anything the server answers. With
    ``forward=True`` and the simple-query ``COMMIT`` this is a real lost acknowledgement: the commit is durable and the
    client sees the connection end. With ``forward=False`` the server never saw the ``COMMIT`` and rolls the
    transaction back when the session ends, while the client cannot tell the two apart.
    """

    COMMIT = b"Q\x00\x00\x00\x0bCOMMIT\x00"

    def __init__(self, target: str | None = None) -> None:
        from urllib.parse import urlsplit

        parts = urlsplit(target or APP_URL or "")
        self._upstream = (parts.hostname or "127.0.0.1", parts.port or 5432)
        self._parts = parts
        self._armed: list[tuple[bytes, bool]] = []
        self._server: asyncio.AbstractServer | None = None
        self.port = 0
        self.cuts = 0

    async def start(self) -> CuttableProxy:
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    @property
    def dsn(self) -> str:
        netloc = self._parts.netloc.rsplit("@", 1)
        auth = netloc[0] + "@" if len(netloc) == 2 else ""
        return f"{self._parts.scheme}://{auth}127.0.0.1:{self.port}{self._parts.path}"

    def arm(self, pattern: bytes, *, forward: bool = True) -> None:
        self._armed.append((pattern, forward))

    async def _serve(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(*self._upstream)
        except OSError:
            client_writer.close()
            return
        cut = asyncio.Event()

        async def pipe_down() -> None:
            while not cut.is_set():
                chunk = await upstream_reader.read(65536)
                if not chunk or cut.is_set():
                    break
                client_writer.write(chunk)
                await client_writer.drain()

        async def pipe_up() -> None:
            while True:
                chunk = await client_reader.read(65536)
                if not chunk:
                    break
                for index, (pattern, forward) in enumerate(self._armed):
                    if pattern in chunk:
                        self._armed.pop(index)
                        self.cuts += 1
                        # From here on nothing the server answers reaches the client.
                        cut.set()
                        if forward:
                            upstream_writer.write(chunk)
                            await upstream_writer.drain()
                            # Let the server act on it before the connection ends.
                            await asyncio.sleep(0.3)
                        return
                upstream_writer.write(chunk)
                await upstream_writer.drain()

        tasks = [asyncio.ensure_future(pipe_down()), asyncio.ensure_future(pipe_up())]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in tasks:
            task.cancel()
        for writer in (client_writer, upstream_writer):
            writer.close()
