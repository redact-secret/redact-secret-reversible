"""The PostgreSQL adapter (``redact_secret_vault.stores.postgres``) against a real PostgreSQL server.

What this file covers (docs/plans/python-persistence-parity.md handoff 8, gates G3 and G6 for this adapter):

* the language-neutral schedule corpus (``conformance/persistent/v1/schedules.json``) through the Python driver with
  the PostgreSQL backend: with a controllable store clock, with the database clock, with and without holds, every
  case run or skipped with its reason;
* a disconnect before and after ``COMMIT``, over a real TCP connection that is cut;
* malicious rows: a value JavaScript cannot represent, a wrong length, a malformed identifier;
* cancellation of a call that is paused before ``COMMIT``;
* a real ``psycopg_pool`` pool, an ``autocommit`` connection, and the deployment checks of ``create_postgres_store``;
* a leak test with ``logging`` at ``DEBUG`` for every logger, ``warnings`` as errors, and a marker planted in the
  driver's failures: none of a sentinel may reach an error, a traceback, a log record, or a stream.

The two-process cases are in ``test_stores_postgres_processes.py``. Skipped, with the reason, when ``RSV_PG_APP_URL``
and ``RSV_PG_ADMIN_URL`` are not set; a run with ``RSV_REQUIRE_POSTGRES=1`` fails instead.
"""

from __future__ import annotations

import ast
import asyncio
import dataclasses
import logging
import re
import sys
import traceback
import warnings
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

pytest.importorskip("psycopg")

import pg_support  # noqa: E402
from schedule_support import have_orchestrator, load_corpus, run_schedules  # noqa: E402

from redact_secret_vault.persistent import (  # noqa: E402
    Attempt,
    CaptureGeneration,
    CommitRestoreInput,
    CreateCaptureInput,
    EntryUse,
    InspectAttemptInput,
    NewCapture,
    NewEntry,
    ReadCapturesInput,
    ReadEntriesInput,
    RevokeCaptureInput,
    StoreError,
    StoreScope,
    SweepInput,
    missing_capabilities,
)
from redact_secret_vault.persistent.contracts import Store  # noqa: E402

pytestmark = [
    pg_support.needs_database,
    pytest.mark.skipif(sys.version_info < (3, 11), reason="the persistent modules need Python 3.11"),
]
pg_support.require_database()

REPO = Path(__file__).resolve().parents[3]
STORE_SOURCE = Path(__file__).resolve().parents[1] / "src" / "redact_secret_vault" / "stores" / "postgres.py"
TENANT = "tenant-synthetic-a"
HOUR = 3_600_000


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def now_ms() -> int:
    import time

    return time.time_ns() // 1_000_000


def capture_id() -> str:
    import secrets

    return "cap_" + "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(26))


def entry_id() -> str:
    import secrets

    return secrets.token_hex(32)


class Fixture:
    """One synthetic capture of one entry, with the inputs that create, commit, and revoke it."""

    def __init__(
        self,
        namespace: str,
        *,
        envelope: bytes = b"\x22" * 24,
        wrapped_key: bytes = b"\x11" * 40,
        key_ref: str = "synthetic-key:v1",
        session_tag: str | None = None,
        max_uses: int = 1,
        now: int | None = None,
        entries: int = 1,
    ) -> None:
        self.scope = StoreScope(namespace=namespace, tenant=TENANT)
        self.capture_id = capture_id()
        self.entry_ids = tuple(entry_id() for _ in range(entries))
        self.now = now_ms() if now is None else now
        self.envelope, self.wrapped_key, self.key_ref = envelope, wrapped_key, key_ref
        self.session_tag, self.max_uses = session_tag, max_uses

    def create(self) -> CreateCaptureInput:
        return CreateCaptureInput(
            scope=self.scope,
            epoch=1,
            now=self.now,
            capture=NewCapture(
                capture_id=self.capture_id,
                key_ref=self.key_ref,
                wrapped_key=self.wrapped_key,
                session_tag=self.session_tag,
                created_at=self.now,
                expires_at=self.now + HOUR,
            ),
            entries=tuple(
                NewEntry(entry_id=entry, max_uses=self.max_uses, envelope=self.envelope) for entry in self.entry_ids
            ),
        )

    def commit(self, attempt: str = "attempt-synthetic-1", digest: bytes = b"\x33" * 32) -> CommitRestoreInput:
        return CommitRestoreInput(
            scope=self.scope,
            epoch=1,
            now=self.now,
            attempt=Attempt(attempt_id=attempt, request_digest=digest),
            receipt_expires_at=self.now + 2 * HOUR,
            captures=(CaptureGeneration(capture_id=self.capture_id, generation=1),),
            uses=(
                EntryUse(
                    entry_id=self.entry_ids[0],
                    capture_id=self.capture_id,
                    count=1,
                    lifecycle_revision=1,
                    ciphertext_revision=1,
                ),
            ),
        )

    def revoke(self) -> RevokeCaptureInput:
        return RevokeCaptureInput(
            scope=self.scope, capture_id=self.capture_id, now=self.now, retention_ms=HOUR, fence_absent=False
        )

    def read(self) -> ReadEntriesInput:
        return ReadEntriesInput(scope=self.scope, entry_ids=self.entry_ids)


async def serving(store: Any, namespace: str) -> None:
    result = await store.initialize_namespace(namespace, 1)
    assert result.outcome == "initialized"


def namespace() -> str:
    return pg_support.random_name("adapter")


def raised(coro: Any) -> StoreError:
    with pytest.raises(StoreError) as caught:
        run(coro)
    error = caught.value
    assert error.__cause__ is None and error.__context__ is None
    assert not hasattr(error, "__notes__")
    return error


# ------------------------------------------------------------------------------ static


def test_the_schema_version_equals_the_one_the_javascript_package_owns() -> None:
    from redact_secret_vault.stores.postgres import SCHEMA_VERSION

    source = (REPO / "packages" / "store-postgres" / "src" / "schema.ts").read_text(encoding="utf-8")
    match = re.search(r"export const SCHEMA_VERSION = (\d+);", source)
    assert match is not None and int(match.group(1)) == SCHEMA_VERSION


def test_the_adapter_creates_no_table_and_runs_no_ddl() -> None:
    source = STORE_SOURCE.read_text(encoding="utf-8")
    code = "\n".join(re.findall(r'"([^"\n]*)"', source))
    assert not re.search(r"\b(CREATE|ALTER|DROP|TRUNCATE|GRANT)\s", code, re.IGNORECASE)


def test_the_production_module_has_no_hold_point_and_no_fault_hook() -> None:
    tree = ast.parse(STORE_SOURCE.read_text(encoding="utf-8"))
    identifiers: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            identifiers.add(node.name)
        elif isinstance(node, ast.Name):
            identifiers.add(node.id)
        elif isinstance(node, ast.Attribute):
            identifiers.add(node.attr)
        elif isinstance(node, ast.arg):
            identifiers.add(node.arg)
    banned = {"hold", "holds", "fault", "faults", "pause", "mutant"}
    words = {name: set(re.split(r"_|(?<=[a-z])(?=[A-Z])", name.lower())) for name in identifiers}
    assert sorted(name for name, parts in words.items() if parts & banned) == []


def test_the_adapter_imports_only_psycopg_and_the_persistent_modules() -> None:
    tree = ast.parse(STORE_SOURCE.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    assert roots <= {"__future__", "collections", "os", "typing", "psycopg"}, roots


# ------------------------------------------------------------------------- the corpus


@pytest.mark.skipif(not have_orchestrator(), reason="node and the orchestrator are needed")
def test_the_store_level_schedules_pass_with_a_controllable_clock_and_none_is_skipped() -> None:
    report = run_schedules(level="store", store_options={"backend": "postgres"}, parallelism=100, timeout=900)
    store_cases = [case for case in load_corpus()["cases"] if case["level"] == "store"]
    counts = report["counts"]
    failures = [(row["id"], row.get("detail")) for row in report["results"] if row["status"] == "failed"]
    assert failures == []
    assert counts["failed"] == 0 and counts["skipped"] == 0
    assert counts["passed"] == len(store_cases)
    print(f"store-level schedules, controlled clock, holds: {counts['passed']} passed, 0 skipped")


@pytest.mark.skipif(not have_orchestrator(), reason="node and the orchestrator are needed")
def test_with_the_database_clock_and_holds_only_the_time_travel_cases_are_skipped_with_that_reason() -> None:
    report = run_schedules(
        level="store",
        store_options={"backend": "postgres", "realClock": True, "maxClockSkewMs": 30000},
        parallelism=16,
        timeout=900,
    )
    skipped = [row for row in report["results"] if row["status"] == "skipped"]
    assert report["counts"]["failed"] == 0
    assert skipped, "a clock the harness cannot move skips the time-travel cases"
    assert all("testClock" in str(row.get("detail")) for row in skipped), [row.get("detail") for row in skipped]
    print(f"store-level schedules, database clock: {report['counts']['passed']} passed, {len(skipped)} skipped")


@pytest.mark.skipif(not have_orchestrator(), reason="node and the orchestrator are needed")
def test_without_holds_the_two_connection_schedules_are_skipped_and_never_passed() -> None:
    report = run_schedules(
        level="store",
        store_options={"backend": "postgres", "realClock": True, "noHolds": True, "maxClockSkewMs": 30000},
        parallelism=16,
        timeout=900,
    )
    interleave = [row for row in report["results"] if row["id"].startswith("interleave.")]
    assert report["counts"]["failed"] == 0
    assert interleave and all(row["status"] == "skipped" for row in interleave)
    print(
        f"store-level schedules, database clock, no holds: {report['counts']['passed']} passed, "
        f"{report['counts']['skipped']} skipped"
    )


@pytest.mark.skipif(not have_orchestrator(), reason="node and the orchestrator are needed")
def test_the_store_level_schedules_pass_with_every_bound_lowered() -> None:
    bounds = {
        "backend": "postgres",
        "maxCreateEntries": 8,
        "maxCreateBytes": 64 * 1024,
        "maxRestoreEntries": 8,
        "maxRestoreCaptures": 4,
        "maxEnvelopeBytes": 4096,
    }
    report = run_schedules(level="store", store_options=bounds, parallelism=16, timeout=900)
    failures = [(row["id"], row.get("detail")) for row in report["results"] if row["status"] == "failed"]
    assert failures == []


@pytest.mark.skipif(not have_orchestrator(), reason="node and the orchestrator are needed")
def test_the_server_level_schedules_pass_with_the_persistent_server_over_this_store() -> None:
    """The Python persistent server, the local key provider, and this adapter over a real database."""

    report = run_schedules(level="server", store_options={"backend": "postgres"}, parallelism=16, timeout=900)
    server_cases = [case for case in load_corpus()["cases"] if case["level"] == "server"]
    failures = [(row["id"], row.get("detail")) for row in report["results"] if row["status"] == "failed"]
    assert failures == []
    assert report["counts"]["skipped"] == 0 and report["counts"]["passed"] == len(server_cases)
    print(f"server-level schedules over PostgreSQL: {report['counts']['passed']} passed, 0 skipped")


# ------------------------------------------------------------------------ the store


def test_the_store_declares_what_it_is_and_what_it_is_not() -> None:
    async def scenario() -> None:
        store = await pg_support.open_store(pg_support.Pool())
        assert isinstance(store, Store)
        capabilities = store.capabilities()
        assert missing_capabilities(capabilities) == ()
        assert capabilities.durability == "durable" and capabilities.cross_process is True
        assert capabilities.restore_detection == "postgres-system-identifier-and-timeline"
        assert capabilities.adapter == "store-postgres-py"
        assert capabilities.profile.startswith("postgres-single-primary/")

    run(scenario())


def test_a_round_trip_through_every_operation() -> None:
    async def scenario() -> None:
        store = await pg_support.open_store(pg_support.Pool())
        space = namespace()
        await serving(store, space)
        fixture = Fixture(space, max_uses=2)
        assert (await store.create_capture(fixture.create())).outcome == "created"
        seen = await store.read_entries(fixture.read())
        assert seen.recovery.state == "serving" and [e.used for e in seen.entries] == [0]
        assert seen.entries[0].envelope == fixture.envelope and seen.captures[0].wrapped_key == fixture.wrapped_key
        assert (await store.commit_restore(fixture.commit())).outcome == "committed"
        assert (await store.commit_restore(fixture.commit())).outcome == "already-committed"
        inspected = await store.inspect_attempt(
            InspectAttemptInput(scope=fixture.scope, attempt_id="attempt-synthetic-1")
        )
        assert inspected.state == "committed" and inspected.request_digest == b"\x33" * 32
        found = await store.read_captures(ReadCapturesInput(scope=fixture.scope, capture_ids=(fixture.capture_id,)))
        assert found[0].state == "live" and found[0].generation == 1
        assert (await store.revoke_capture(fixture.revoke())).outcome == "revoked"
        swept = await store.sweep_expired(SweepInput(namespace=space, now=now_ms(), limit=10))
        assert swept.outcome == "swept"

    run(scenario())


def test_a_store_that_is_closed_fails_closed_and_leaves_the_pool_open() -> None:
    async def scenario() -> None:
        pool = pg_support.Pool()
        store = await pg_support.open_store(pool)
        store.close()
        with pytest.raises(StoreError) as caught:
            await store.recovery_state("closed-synthetic")
        assert caught.value.code == "STORE_CLOSED"
        # The pool is the application's: still usable.
        other = await pg_support.open_store(pool)
        assert (await other.recovery_state("closed-synthetic")).state == "uninitialized"

    run(scenario())


def test_arguments_are_validated_before_any_connection_is_made() -> None:
    from redact_secret_vault.stores.postgres import create_postgres_store

    pool = pg_support.Pool()
    cases: list[dict[str, Any]] = [
        {"pool": object()},
        {"pool": pool, "schema": "Bad-Name"},
        {"pool": pool, "schema": "1bad"},
        {"pool": pool, "schema": ""},
        {"pool": pool, "synchronous_commit": "off"},
        {"pool": pool, "max_clock_skew_ms": 60_001},
        {"pool": pool, "max_clock_skew_ms": True},
        {"pool": pool, "statement_timeout_ms": 0},
        {"pool": pool, "max_create_entries": 2000},
        {"pool": pool, "max_envelope_bytes": 2**30},
        {"pool": pool, "require_synchronous_standby": "yes"},
    ]
    for arguments in cases:
        error = raised(create_postgres_store(**arguments))
        assert error.code == "STORE_INVALID_ARGUMENT", arguments
    assert pool.opened == 0


def test_a_database_without_a_synchronous_standby_refuses_a_profile_that_needs_one() -> None:
    from redact_secret_vault.stores.postgres import create_postgres_store

    for arguments in ({"require_synchronous_standby": True}, {"synchronous_commit": "remote_apply"}):
        error = raised(create_postgres_store(pool=pg_support.Pool(), schema=pg_support.SCHEMA, **arguments))
        assert error.code == "STORE_CAPABILITY"


def test_a_schema_of_another_version_or_none_is_refused_without_a_driver_message() -> None:
    from redact_secret_vault.stores.postgres import create_postgres_store

    async def scenario() -> None:
        schema = "rsv_wrongversion"
        await pg_support.admin_execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await pg_support.admin_execute(f'CREATE SCHEMA "{schema}"')
        await pg_support.admin_execute(f'CREATE TABLE "{schema}".rsv_schema (singleton boolean, version integer)')
        await pg_support.admin_execute(f'INSERT INTO "{schema}".rsv_schema VALUES (true, 2)')
        role = (pg_support.APP_URL or "").split("//")[1].split(":")[0]
        await pg_support.admin_execute(f'GRANT USAGE ON SCHEMA "{schema}" TO "{role}"')
        await pg_support.admin_execute(f'GRANT SELECT ON "{schema}".rsv_schema TO "{role}"')
        try:
            with pytest.raises(StoreError) as wrong:
                await create_postgres_store(pool=pg_support.Pool(), schema=schema)
            assert wrong.value.code == "STORE_CAPABILITY"
            with pytest.raises(StoreError) as missing:
                await create_postgres_store(pool=pg_support.Pool(), schema="rsv_does_not_exist")
            assert missing.value.code == "STORE_UNAVAILABLE"
            for error in (wrong.value, missing.value):
                assert error.__cause__ is None and error.__context__ is None
                assert "rsv_" not in str(error)
        finally:
            await pg_support.admin_execute(f'DROP SCHEMA "{schema}" CASCADE')

    run(scenario())


def test_an_unreachable_database_is_unavailable_and_the_error_names_no_address() -> None:
    from redact_secret_vault.stores.postgres import create_postgres_store

    pool = pg_support.Pool(
        dsn="postgres://rsv_app:SENTINEL-UNREACHABLE-PASSWORD@127.0.0.1:1/postgres?connect_timeout=2"
    )
    error = raised(create_postgres_store(pool=pool, schema=pg_support.SCHEMA))
    assert error.code == "STORE_UNAVAILABLE"
    assert "SENTINEL" not in repr(error) and "127.0.0.1" not in repr(error)


def test_the_adapter_works_on_an_autocommit_connection() -> None:
    class AutocommitPool(pg_support.Pool):
        async def _open(self) -> Any:
            import psycopg

            return await psycopg.AsyncConnection.connect(self.dsn, autocommit=True)

    async def scenario() -> None:
        store = await pg_support.open_store(AutocommitPool())
        space = namespace()
        await serving(store, space)
        fixture = Fixture(space)
        assert (await store.create_capture(fixture.create())).outcome == "created"
        assert (await store.commit_restore(fixture.commit())).outcome == "committed"
        assert [e.used for e in (await store.read_entries(fixture.read())).entries] == [1]

    run(scenario())


def test_a_real_psycopg_pool_keeps_working_after_the_adapter_discards_a_connection() -> None:
    pytest.importorskip("psycopg_pool")
    from psycopg_pool import AsyncConnectionPool

    async def scenario() -> None:
        pool = AsyncConnectionPool(pg_support.APP_URL or "", min_size=1, max_size=4, open=False)
        await pool.open()
        try:
            hooked = _FaultingPoolView(pool)
            store = await pg_support.open_store(hooked)
            space = namespace()
            await serving(store, space)
            fixture = Fixture(space, max_uses=2)
            assert (await store.create_capture(fixture.create())).outcome == "created"
            pg_support.FAULT.set("after-commit-before-ack")
            with pytest.raises(StoreError) as lost:
                await store.commit_restore(fixture.commit())
            assert lost.value.code == "STORE_AMBIGUOUS"
            # The discarded connection is gone from the pool; the next call gets a working one.
            resolved = await store.inspect_attempt(
                InspectAttemptInput(scope=fixture.scope, attempt_id="attempt-synthetic-1")
            )
            assert resolved.state == "committed"
            assert [e.used for e in (await store.read_entries(fixture.read())).entries] == [1]
        finally:
            await pool.close()

    run(scenario())


class _FaultingPoolView:
    """A real ``AsyncConnectionPool`` whose leases honour the test hooks."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    def connection(self) -> Any:
        return _HookedLease(self._pool.connection())


class _HookedLease:
    def __init__(self, inner: Any) -> None:
        self._inner = inner

    async def __aenter__(self) -> Any:
        return pg_support._Connection(await self._inner.__aenter__())

    async def __aexit__(self, *exc: object) -> Any:
        return await self._inner.__aexit__(*exc)


# ------------------------------------------------------------- disconnect around COMMIT


def test_a_connection_lost_after_the_commit_reached_the_server_is_ambiguous_and_the_receipt_resolves_it() -> None:
    async def scenario() -> None:
        proxy = await pg_support.CuttableProxy().start()
        try:
            direct = await pg_support.open_store(pg_support.Pool())
            through = await pg_support.open_store(pg_support.Pool(dsn=proxy.dsn))
            space = namespace()
            await serving(direct, space)
            fixture = Fixture(space)
            assert (await direct.create_capture(fixture.create())).outcome == "created"
            proxy.arm(proxy.COMMIT, forward=True)
            with pytest.raises(StoreError) as lost:
                await through.commit_restore(fixture.commit())
            assert lost.value.code == "STORE_AMBIGUOUS"
            assert lost.value.__cause__ is None and lost.value.__context__ is None
            assert proxy.cuts == 1, "the COMMIT was seen and the connection cut"
            # The commit is durable: the receipt exists and the counter moved.
            resolved = await direct.inspect_attempt(
                InspectAttemptInput(scope=fixture.scope, attempt_id="attempt-synthetic-1")
            )
            assert resolved.state == "committed"
            assert [e.used for e in (await direct.read_entries(fixture.read())).entries] == [1]
            # The adapter never retries it: a second submission is a replay, not a second use.
            assert (await direct.commit_restore(fixture.commit())).outcome == "already-committed"
        finally:
            await proxy.stop()

    run(scenario())


def test_a_connection_lost_before_the_commit_reached_the_server_applies_nothing() -> None:
    async def scenario() -> None:
        proxy = await pg_support.CuttableProxy().start()
        try:
            direct = await pg_support.open_store(pg_support.Pool())
            through = await pg_support.open_store(pg_support.Pool(dsn=proxy.dsn))
            space = namespace()
            await serving(direct, space)
            fixture = Fixture(space)
            assert (await direct.create_capture(fixture.create())).outcome == "created"
            proxy.arm(proxy.COMMIT, forward=False)
            with pytest.raises(StoreError) as lost:
                await through.commit_restore(fixture.commit())
            # The caller cannot tell this from the lost acknowledgement, so it is told the same.
            assert lost.value.code == "STORE_AMBIGUOUS"
            await asyncio.sleep(0.3)
            resolved = await direct.inspect_attempt(
                InspectAttemptInput(scope=fixture.scope, attempt_id="attempt-synthetic-1")
            )
            assert resolved.state == "absent"
            assert [e.used for e in (await direct.read_entries(fixture.read())).entries] == [0]
            assert (await direct.commit_restore(fixture.commit())).outcome == "committed"
        finally:
            await proxy.stop()

    run(scenario())


def test_a_connection_lost_in_the_middle_of_a_transaction_is_unavailable_and_applies_nothing() -> None:
    async def scenario() -> None:
        proxy = await pg_support.CuttableProxy().start()
        try:
            direct = await pg_support.open_store(pg_support.Pool())
            through = await pg_support.open_store(pg_support.Pool(dsn=proxy.dsn))
            space = namespace()
            await serving(direct, space)
            fixture = Fixture(space)
            proxy.arm(b"INSERT INTO", forward=False)
            with pytest.raises(StoreError) as lost:
                await through.create_capture(fixture.create())
            assert lost.value.code == "STORE_UNAVAILABLE"
            assert (await direct.read_entries(fixture.read())).entries == ()
            assert (await direct.create_capture(fixture.create())).outcome == "created"
        finally:
            await proxy.stop()

    run(scenario())


def test_a_backend_terminated_during_a_held_transaction_is_unavailable_and_applies_nothing() -> None:
    async def scenario() -> None:
        pool = pg_support.HookedPool()
        store = await pg_support.open_store(pool)
        space = namespace()
        await serving(store, space)
        fixture = Fixture(space)
        assert (await store.create_capture(fixture.create())).outcome == "created"
        paused = asyncio.Event()
        release = asyncio.Event()

        async def pause() -> None:
            paused.set()
            await release.wait()

        async def held_commit() -> Any:
            pg_support.HOLD.set(pause)
            return await store.commit_restore(fixture.commit())

        task = asyncio.ensure_future(held_commit())
        await asyncio.wait_for(paused.wait(), 10)
        # The session of the held transaction is ended from outside, as a failover or an operator would.
        killed = await pg_support.admin_execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE usename = %s AND pid <> pg_backend_pid() AND state = 'idle in transaction'",
            ((pg_support.APP_URL or "").split("//")[1].split(":")[0],),
        )
        assert killed and all(row[0] for row in killed)
        release.set()
        with pytest.raises(StoreError) as lost:
            await task
        # COMMIT had not been sent when the session ended, but it could not be sent after: an unknown outcome
        # from the caller's side, never reported as nothing happening.
        assert lost.value.code in ("STORE_UNAVAILABLE", "STORE_AMBIGUOUS")
        assert [e.used for e in (await store.read_entries(fixture.read())).entries] == [0]
        assert (await store.commit_restore(fixture.commit())).outcome == "committed"

    run(scenario())


# ------------------------------------------------------------------------ cancellation


def test_a_call_cancelled_while_paused_before_commit_closes_its_connection_and_applies_nothing() -> None:
    async def scenario() -> None:
        pool = pg_support.HookedPool()
        store = await pg_support.open_store(pool)
        space = namespace()
        await serving(store, space)
        fixture = Fixture(space)
        assert (await store.create_capture(fixture.create())).outcome == "created"
        paused = asyncio.Event()

        async def pause() -> None:
            paused.set()
            await asyncio.sleep(3600)

        async def held() -> Any:
            pg_support.HOLD.set(pause)
            return await store.commit_restore(fixture.commit())

        before = pool.closed
        task = asyncio.ensure_future(held())
        await asyncio.wait_for(paused.wait(), 10)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        # Not converted into a store error, and the connection of the interrupted transaction was closed.
        assert pool.closed == before + 1
        assert [e.used for e in (await store.read_entries(fixture.read())).entries] == [0]
        assert (await store.commit_restore(fixture.commit())).outcome == "committed"

    run(scenario())


# --------------------------------------------------------------------- malicious rows


async def _corrupt(sql: str, params: tuple[Any, ...] = ()) -> None:
    await pg_support.admin_execute(sql, params)


def _prepared(**options: Any) -> tuple[Any, Fixture, str]:
    async def build() -> tuple[Any, Fixture, str]:
        store = await pg_support.open_store(pg_support.Pool())
        space = namespace()
        await serving(store, space)
        fixture = Fixture(space, **options)
        assert (await store.create_capture(fixture.create())).outcome == "created"
        return store, fixture, space

    return run(build())


CAPTURE_CORRUPTIONS = [
    ("created_at beyond 2^53 - 1", "UPDATE rsv_capture SET created_at = %s WHERE capture_id = %s", (2**53,)),
    ("expires_at beyond 2^53 - 1", "UPDATE rsv_capture SET expires_at = %s WHERE capture_id = %s", (2**62,)),
    ("negative created_at", "UPDATE rsv_capture SET created_at = %s WHERE capture_id = %s", (-1,)),
    ("epoch beyond 2^53 - 1", "UPDATE rsv_capture SET epoch = %s WHERE capture_id = %s", (2**60,)),
    (
        "wrapped key longer than the limit",
        "UPDATE rsv_capture SET wrapped_key = %s WHERE capture_id = %s",
        (b"\x01" * 5000,),
    ),
    ("empty wrapped key on a live capture", "UPDATE rsv_capture SET wrapped_key = %s WHERE capture_id = %s", (b"",)),
    ("empty key reference on a live capture", "UPDATE rsv_capture SET key_ref = %s WHERE capture_id = %s", ("",)),
    ("key reference longer than the limit", "UPDATE rsv_capture SET key_ref = %s WHERE capture_id = %s", ("k" * 600,)),
    ("session tag that is not a tag", "UPDATE rsv_capture SET session_tag = %s WHERE capture_id = %s", ("not-a-tag",)),
]


@pytest.mark.parametrize(("name", "statement", "values"), CAPTURE_CORRUPTIONS, ids=[c[0] for c in CAPTURE_CORRUPTIONS])
def test_a_capture_row_outside_the_contract_is_unavailable_and_never_returned(
    name: str, statement: str, values: tuple[Any, ...]
) -> None:
    store, fixture, _space = _prepared()
    schema = pg_support.SCHEMA
    qualified = statement.replace("rsv_capture", f'"{schema}".rsv_capture')
    run(_corrupt(qualified, (*values, fixture.capture_id)))
    error = raised(store.read_captures(ReadCapturesInput(scope=fixture.scope, capture_ids=(fixture.capture_id,))))
    assert error.code == "STORE_UNAVAILABLE", name
    assert str(error) == "The store was unavailable; the operation had no effect."


ENTRY_CORRUPTIONS = [
    (
        "envelope longer than the store's limit",
        "UPDATE rsv_entry SET envelope = %s WHERE entry_id = %s",
        (b"\x07" * 1_200_000,),
    ),
    ("empty envelope", "UPDATE rsv_entry SET envelope = %s WHERE entry_id = %s", (b"",)),
]


@pytest.mark.parametrize(("name", "statement", "values"), ENTRY_CORRUPTIONS, ids=[c[0] for c in ENTRY_CORRUPTIONS])
def test_an_entry_row_outside_the_contract_is_unavailable_and_never_returned(
    name: str, statement: str, values: tuple[Any, ...]
) -> None:
    store, fixture, _space = _prepared()
    qualified = statement.replace("rsv_entry", f'"{pg_support.SCHEMA}".rsv_entry')
    run(_corrupt(qualified, (*values, fixture.entry_ids[0])))
    error = raised(store.read_entries(fixture.read()))
    assert error.code == "STORE_UNAVAILABLE", name


def test_a_receipt_whose_digest_is_not_thirty_two_bytes_is_unavailable_to_inspect_and_to_replay() -> None:
    store, fixture, space = _prepared(max_uses=2)
    assert run(store.commit_restore(fixture.commit())).outcome == "committed"
    schema = pg_support.SCHEMA
    run(
        _corrupt(
            f'UPDATE "{schema}".rsv_receipt SET request_digest = %s WHERE namespace = %s',
            (b"\x00" * 31, space),
        )
    )
    inspect = InspectAttemptInput(scope=fixture.scope, attempt_id="attempt-synthetic-1")
    assert raised(store.inspect_attempt(inspect)).code == "STORE_UNAVAILABLE"
    assert raised(store.commit_restore(fixture.commit())).code == "STORE_UNAVAILABLE"
    assert [e.used for e in run(store.read_entries(fixture.read())).entries] == [1]


def test_a_recovery_record_with_an_epoch_beyond_what_javascript_can_represent_is_unavailable() -> None:
    store, fixture, space = _prepared()
    schema = pg_support.SCHEMA
    run(_corrupt(f'UPDATE "{schema}".rsv_namespace SET epoch = %s WHERE namespace = %s', (2**60, space)))
    assert raised(store.recovery_state(space)).code == "STORE_UNAVAILABLE"
    assert raised(store.read_entries(fixture.read())).code == "STORE_UNAVAILABLE"


def test_a_namespace_recorded_by_another_database_identity_reads_as_quarantined() -> None:
    store, fixture, space = _prepared()
    schema = pg_support.SCHEMA
    run(_corrupt(f"UPDATE \"{schema}\".rsv_namespace SET system_identifier = '1' WHERE namespace = %s", (space,)))
    assert run(store.recovery_state(space)).state == "quarantined"
    assert run(store.commit_restore(fixture.commit())).reason == "quarantined"  # type: ignore[union-attr]
    assert run(store.create_capture(Fixture(space).create())).reason == "quarantined"  # type: ignore[union-attr]


# ---------------------------------------------------------------------------- leaks

MARKER = pg_support.FAULT_MARKER
PASSWORD = urlsplit(pg_support.APP_URL or "").password or "SENTINEL-DB-PASSWORD-7d1c"
ENVELOPE = b"SENTINEL-ENVELOPE-8e2a-0123456789ab"
WRAPPED = b"SENTINEL-WRAPPED-KEY-4f6b-0123456789abcdef"
KEY_REF = "sentinel-key-ref:9a1e"
DIGEST = bytes.fromhex("5e17d1c0a9b84f3e6d2c1b0a99887766554433221100ffeeddccbbaa99887766"[:64])


def _forms(raw: bytes) -> set[str]:
    import base64

    forms = {raw.hex(), base64.b64encode(raw).decode(), repr(raw)}
    try:
        forms.add(raw.decode("utf-8"))
    except UnicodeDecodeError:
        pass
    return {item for item in forms if len(item) >= 8}


def _sentinels() -> set[str]:
    found = {MARKER, PASSWORD, KEY_REF}
    for raw in (ENVELOPE, WRAPPED, DIGEST):
        found |= _forms(raw)
    return found


def _walk(value: Any, depth: int = 0) -> str:
    if depth > 4:
        return ""
    if isinstance(value, (bytes, bytearray)):
        return repr(bytes(value)) + bytes(value).hex()
    if isinstance(value, str):
        return value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return "|".join(_walk(getattr(value, f.name), depth + 1) for f in dataclasses.fields(value))
    if isinstance(value, (tuple, list, set, frozenset)):
        return "|".join(_walk(item, depth + 1) for item in value)
    if isinstance(value, dict):
        return "|".join(_walk(k, depth + 1) + _walk(v, depth + 1) for k, v in value.items())
    return repr(value)


def _error_texts(error: BaseException) -> list[str]:
    texts = [str(error), repr(error), _walk(error.args), _walk(getattr(error, "__dict__", {}))]
    for name in getattr(type(error), "__slots__", ()):
        texts.append(_walk(getattr(error, name, None)))
    texts.append("".join(traceback.format_exception(error)))
    tb = error.__traceback__
    while tb is not None:
        frame = tb.tb_frame
        if "redact_secret_vault" in frame.f_code.co_filename:
            texts.extend(f"{name}={_walk(value)}" for name, value in frame.f_locals.items())
        tb = tb.tb_next
    return texts


def test_nothing_secret_reaches_an_error_a_traceback_a_log_a_warning_or_a_stream(
    capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    sentinels = _sentinels()
    outcomes: list[Any] = []
    errors: list[BaseException] = []

    async def scenario() -> None:
        pool = pg_support.HookedPool()
        store = await pg_support.open_store(pool)
        space = namespace()
        await serving(store, space)
        fixture = Fixture(space, envelope=ENVELOPE, wrapped_key=WRAPPED, key_ref=KEY_REF, max_uses=3)
        outcomes.append(await store.create_capture(fixture.create()))
        outcomes.append(await store.read_entries(fixture.read()))
        outcomes.append(await store.commit_restore(fixture.commit(digest=DIGEST)))
        # Every named failure, and the real driver's failure with the marker in its text, attribute, and cause.
        for fault in ("unavailable", "before-first-write", "drop-connection", "after-commit-before-ack"):
            for operation in (
                lambda: store.commit_restore(fixture.commit(attempt="attempt-synthetic-2", digest=DIGEST)),
                lambda: store.create_capture(
                    Fixture(space, envelope=ENVELOPE, wrapped_key=WRAPPED, key_ref=KEY_REF).create()
                ),
                lambda: store.revoke_capture(fixture.revoke()),
                lambda: store.read_entries(fixture.read()),
            ):
                pg_support.FAULT.set(fault)
                try:
                    await operation()
                except StoreError as error:
                    errors.append(error)
                finally:
                    pg_support.FAULT.set(None)
        # A malformed row, a closed store, and an invalid argument.
        await pg_support.admin_execute(
            f'UPDATE "{pg_support.SCHEMA}".rsv_capture SET created_at = %s WHERE capture_id = %s',
            (2**60, fixture.capture_id),
        )
        for operation in (
            lambda: store.read_captures(ReadCapturesInput(scope=fixture.scope, capture_ids=(fixture.capture_id,))),
            lambda: store.recovery_state("bad namespace with spaces"),
        ):
            try:
                await operation()
            except StoreError as error:
                errors.append(error)
        store.close()
        try:
            await store.recovery_state(space)
        except StoreError as error:
            errors.append(error)

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        root = logging.getLogger()
        previous = root.level
        root.setLevel(logging.DEBUG)
        names = ("psycopg", "psycopg.pool", "psycopg.pq", "asyncio")
        saved = {name: logging.getLogger(name).level for name in names}
        for name in names:
            logging.getLogger(name).setLevel(logging.DEBUG)
        try:
            with caplog.at_level(logging.DEBUG):
                run(scenario())
        finally:
            root.setLevel(previous)
            for name, level in saved.items():
                logging.getLogger(name).setLevel(level)

    assert len(errors) >= 15, "every fault and malformed path raised"
    assert {error.code for error in errors} >= {
        "STORE_UNAVAILABLE",
        "STORE_AMBIGUOUS",
        "STORE_CLOSED",
        "STORE_INVALID_ARGUMENT",
    }
    for error in errors:
        assert error.__cause__ is None and error.__context__ is None
        assert not hasattr(error, "__notes__")
        for text in _error_texts(error):
            for sentinel in sentinels:
                assert sentinel not in text, f"{sentinel[:8]}... in an error of {error.code}"
    streams = capsys.readouterr()
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    for text in (streams.out, streams.err, log_text):
        for sentinel in sentinels:
            assert sentinel not in text
    # What psycopg logs at DEBUG is the connection's address and state, never a statement or a parameter.
    assert "rsv_capture" not in log_text and "INSERT" not in log_text and "SELECT" not in log_text
    for result in outcomes:
        assert PASSWORD not in repr(result) and MARKER not in repr(result)
    # Whatever the libraries log at DEBUG is recorded for the qualification note, not asserted away.
    print(f"log records at DEBUG during the run: {len(caplog.records)} from {sorted({r.name for r in caplog.records})}")


def test_the_contract_objects_the_adapter_returns_print_lengths_not_bytes() -> None:
    store, fixture, _space = _prepared(envelope=ENVELOPE, wrapped_key=WRAPPED)
    seen = run(store.read_entries(fixture.read()))
    for text in (repr(seen), str(seen), repr(seen.entries[0]), repr(seen.captures[0])):
        for sentinel in _forms(ENVELOPE) | _forms(WRAPPED):
            assert sentinel not in text
