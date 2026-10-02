"""The two-process cases of the plan (docs/plans/python-persistence-parity.md section 6.1) against real PostgreSQL.

Every case starts at least two operating-system processes (``schedule_driver.py`` with the PostgreSQL backend), each its
own interpreter with its own connections, and a test process that only conducts. They share the database and nothing
else. Time is the database's: the caller's ``now`` is this machine's clock, and a caller whose clock is far off is
simulated by the ``now`` it sends.

Skipped, with the reason, when ``RSV_PG_APP_URL`` and ``RSV_PG_ADMIN_URL`` are not set; a run with
``RSV_REQUIRE_POSTGRES=1`` fails instead.
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

pytest.importorskip("psycopg")

import pg_support  # noqa: E402
from pg_processes import (  # noqa: E402
    Capture,
    DriverProcess,
    attempt_id,
    capture_id,
    namespace_name,
    real_now,
    restore_with_retry,
    scope,
)

pytestmark = [
    pg_support.needs_database,
    pytest.mark.skipif(sys.version_info < (3, 11), reason="the persistent modules need Python 3.11"),
]
pg_support.require_database()

REAL_CLOCK = {"realClock": True}


def run(coro: Awaitable[Any]) -> Any:
    return asyncio.run(coro)  # type: ignore[arg-type]


async def with_processes(count: int, body: Callable[..., Awaitable[None]], store: dict[str, Any] | None = None) -> None:
    started: list[DriverProcess] = []
    try:
        for index in range(count):
            process = DriverProcess(f"p{index}")
            await process.start({**REAL_CLOCK, **(store or {})})
            started.append(process)
        pids = {process.pid for process in started} | {os.getpid()}
        assert len(pids) == count + 1, "every actor is its own operating-system process"
        await body(*started)
    finally:
        await asyncio.gather(*(process.stop() for process in started))


async def initialized(process: DriverProcess, namespace: str, epoch: int = 1) -> None:
    reply = await process.call("initializeNamespace", input={"namespace": namespace, "epoch": epoch})
    assert reply["result"] == {"outcome": "initialized"}, reply


async def created(process: DriverProcess, capture: Capture) -> None:
    reply = await process.call("createCapture", input=capture.create_input())
    assert reply["result"] == {"outcome": "created"}, reply


async def entries(process: DriverProcess, capture: Capture) -> list[dict[str, Any]]:
    reply = await process.call("readEntries", input={"scope": capture.scope, "entryIds": capture.entry_ids})
    return reply["result"]["entries"]


async def read(process: DriverProcess, capture: Capture) -> dict[str, Any]:
    return (await process.call("readEntries", input={"scope": capture.scope, "entryIds": capture.entry_ids}))["result"]


# ----------------------------------------------------------- revoke against restore


def test_a_revoke_committed_before_a_commit_starts_denies_the_restore() -> None:
    async def body(a: DriverProcess, b: DriverProcess) -> None:
        namespace = namespace_name()
        await initialized(a, namespace)
        capture = Capture(namespace, max_uses=2)
        await created(a, capture)
        # A read the entries, and the generation it will commit against.
        seen = await read(a, capture)
        generation = seen["captures"][0]["generation"]
        revoked = await b.call("revokeCapture", input=capture.revoke_input())
        assert revoked["result"]["outcome"] == "revoked"
        reply = await a.call("commitRestore", input=capture.commit_input(generation=generation))
        assert reply["result"]["outcome"] == "rejected" and reply["result"]["reason"] in ("revoked", "stale")
        assert [row["used"] for row in await entries(a, capture)] == [0]

    run(with_processes(2, body))


def test_a_revoke_held_open_across_a_commit_attempt_then_committed_denies_the_restore() -> None:
    async def body(a: DriverProcess, b: DriverProcess) -> None:
        namespace = namespace_name()
        await initialized(a, namespace)
        capture = Capture(namespace, max_uses=2)
        await created(a, capture)
        generation = (await read(a, capture))["captures"][0]["generation"]
        # B's transaction has executed its statements and waits before COMMIT, holding the capture row.
        held = b.send("revokeCapture", input=capture.revoke_input(), hold="before-commit", holdId="h1")
        await b.held("h1")
        commit = a.send("commitRestore", input=capture.commit_input(generation=generation))
        await asyncio.sleep(1.0)
        # A needed the capture row B holds: it waits for B, it does not read around it.
        assert not commit.done(), "the commit must wait for the open revocation, not pass it"
        await b.release("h1")
        assert (await held)["result"]["outcome"] == "revoked"
        reply = await commit
        assert reply["result"]["outcome"] == "rejected" and reply["result"]["reason"] in ("revoked", "stale")
        assert [row["used"] for row in await entries(a, capture)] == [0]

    run(with_processes(2, body))


def test_a_commit_that_won_the_race_is_not_undone_by_a_late_revoke() -> None:
    async def body(a: DriverProcess, b: DriverProcess) -> None:
        namespace = namespace_name()
        await initialized(a, namespace)
        capture = Capture(namespace, max_uses=2)
        await created(a, capture)
        held = a.send("commitRestore", input=capture.commit_input(), hold="before-commit", holdId="h1")
        await a.held("h1")
        revoke = b.send("revokeCapture", input=capture.revoke_input())
        await asyncio.sleep(1.0)
        assert not revoke.done(), "the revoke must wait for the commit that holds the capture share lock"
        await a.release("h1")
        assert (await held)["result"]["outcome"] == "committed"
        assert (await revoke)["result"]["outcome"] == "revoked"
        assert [row["used"] for row in await entries(a, capture)] == [1]

    run(with_processes(2, body))


# --------------------------------------------------------- quarantine against create


@pytest.mark.parametrize("operation", ["quarantine", "invalidateRecovered"])
def test_a_creation_that_passed_its_recovery_check_is_ordered_against_a_recovery_operation(operation: str) -> None:
    async def body(a: DriverProcess, b: DriverProcess) -> None:
        namespace = namespace_name()
        await initialized(a, namespace)
        capture = Capture(namespace)
        held = a.send("createCapture", input=capture.create_input(), hold="before-commit", holdId="h1")
        await a.held("h1")
        recovery_input = (
            {"namespace": namespace} if operation == "quarantine" else {"namespace": namespace, "newEpoch": 2}
        )
        recovery = b.send(operation, input=recovery_input)
        await asyncio.sleep(1.0)
        assert not recovery.done(), "the recovery operation must wait for the open creation"
        await a.release("h1")
        # The creation committed before the recovery operation took effect; it is not the one that is rejected.
        assert (await held)["result"] == {"outcome": "created"}
        answer = (await recovery)["result"]
        if operation == "quarantine":
            assert answer == {"epoch": 1, "state": "quarantined"}
        else:
            assert answer["outcome"] == "invalidated"
        # After either, a creation under the old epoch is not served.
        later = Capture(namespace)
        reply = await a.call("createCapture", input=later.create_input())
        assert reply["result"] == {"outcome": "rejected", "reason": "quarantined"}

    run(with_processes(2, body))


def test_a_creation_after_a_committed_quarantine_is_rejected() -> None:
    async def body(a: DriverProcess, b: DriverProcess) -> None:
        namespace = namespace_name()
        await initialized(a, namespace)
        capture = Capture(namespace)
        assert (await b.call("quarantine", input={"namespace": namespace}))["result"]["state"] == "quarantined"
        reply = await a.call("createCapture", input=capture.create_input())
        assert reply["result"] == {"outcome": "rejected", "reason": "quarantined"}
        assert await entries(a, capture) == []

    run(with_processes(2, body))


# ------------------------------------------------------------------------- budget


def test_a_hundred_concurrent_restores_from_two_processes_commit_exactly_max_uses() -> None:
    max_uses = 7

    async def body(a: DriverProcess, b: DriverProcess) -> None:
        namespace = namespace_name()
        await initialized(a, namespace)
        capture = Capture(namespace, max_uses=max_uses)
        await created(a, capture)
        entry = capture.entry_ids[0]
        outcomes = await asyncio.gather(
            *(
                restore_with_retry(a if index % 2 == 0 else b, capture, entry, attempt_id(), tries=400)
                for index in range(100)
            )
        )
        committed = outcomes.count("committed")
        assert committed == max_uses, outcomes
        # Every other attempt is the budget (or, when it gave up on a hot row, a conflict); none is anything else.
        assert all(outcome in ("committed", "budget", "exhausted") for outcome in outcomes), set(outcomes)
        assert [row["used"] for row in await entries(a, capture)] == [max_uses]

    run(with_processes(2, body))


# ------------------------------------------------------- whole-request atomicity


def test_a_restore_naming_several_entries_where_one_fails_changes_nothing_and_writes_no_receipt() -> None:
    async def body(a: DriverProcess, b: DriverProcess) -> None:
        namespace = namespace_name()
        await initialized(a, namespace)
        capture = Capture(namespace, entries=3, max_uses=1)
        await created(a, capture)
        # B uses up the second entry.
        spent = await b.call("commitRestore", input=capture.commit_input(entries=[capture.entry_ids[1]]))
        assert spent["result"]["outcome"] == "committed"
        before = {row["entryId"]: row for row in await entries(a, capture)}
        # A asks for all three. Its read is current; the second entry is out of budget at commit.
        seen = await read(a, capture)
        revisions = {row["entryId"]: row["lifecycleRevision"] for row in seen["entries"]}
        request = capture.commit_input(entries=capture.entry_ids, attempt=attempt_id())
        for use in request["uses"]:
            use["lifecycleRevision"] = revisions[use["entryId"]]
        reply = await a.call("commitRestore", input=request)
        assert reply["result"] == {"outcome": "rejected", "reason": "budget"}
        after = {row["entryId"]: row for row in await entries(a, capture)}
        assert after == before, "no counter or revision moved"
        receipt = await a.call(
            "inspectAttempt", input={"scope": capture.scope, "attemptId": request["attempt"]["attemptId"]}
        )
        assert receipt["result"] == {"state": "absent"}

    run(with_processes(2, body))


# ---------------------------------------------------------------------- receipts


def test_one_attempt_submitted_by_two_processes_commits_once_and_the_other_is_already_committed() -> None:
    async def body(a: DriverProcess, b: DriverProcess) -> None:
        namespace = namespace_name()
        await initialized(a, namespace)
        capture = Capture(namespace, max_uses=3)
        await created(a, capture)
        request = capture.commit_input(attempt=attempt_id())
        first, second = await asyncio.gather(
            a.call("commitRestore", input=request), b.call("commitRestore", input=request)
        )
        kinds = sorted(reply["result"]["outcome"] for reply in (first, second))
        assert kinds == ["already-committed", "committed"], kinds
        assert [row["used"] for row in await entries(a, capture)] == [1]
        # The same attempt with a different request is a mismatch, from either process.
        changed = capture.commit_input(attempt=request["attempt"]["attemptId"], digest="44" * 32)
        assert (await b.call("commitRestore", input=changed))["result"] == {"outcome": "attempt-mismatch"}
        assert (await a.call("commitRestore", input=request))["result"] == {"outcome": "already-committed"}

    run(with_processes(2, body))


def test_an_ambiguous_commit_is_resolved_by_the_other_process_and_a_new_attempt_is_denied() -> None:
    async def body(a: DriverProcess, b: DriverProcess) -> None:
        namespace = namespace_name()
        await initialized(a, namespace)
        capture = Capture(namespace, max_uses=1)
        await created(a, capture)
        request = capture.commit_input(attempt=attempt_id())
        # The commit is durable and A sees the connection fail before the acknowledgement.
        lost = await a.call("commitRestore", input=request, fault="after-commit-before-ack")
        assert lost == {"id": lost["id"], "error": "STORE_AMBIGUOUS"}
        resolved = await b.call(
            "inspectAttempt", input={"scope": capture.scope, "attemptId": request["attempt"]["attemptId"]}
        )
        assert resolved["result"]["state"] == "committed"
        assert resolved["result"]["requestDigest"] == request["attempt"]["requestDigest"]
        fresh = capture.commit_input(attempt=attempt_id(), lifecycle_revision=2)
        assert (await b.call("commitRestore", input=fresh))["result"] == {"outcome": "rejected", "reason": "budget"}

    run(with_processes(2, body))


# ------------------------------------------------------------- create against fence


def test_a_delayed_creation_after_a_fence_is_fenced() -> None:
    async def body(a: DriverProcess, b: DriverProcess) -> None:
        namespace = namespace_name()
        await initialized(a, namespace)
        capture = Capture(namespace)
        fenced = await b.call("revokeCapture", input=capture.revoke_input(fence_absent=True))
        assert fenced["result"] == {"outcome": "fenced"}
        reply = await a.call("createCapture", input=capture.create_input())
        assert reply["result"] == {"outcome": "rejected", "reason": "fenced"}

    run(with_processes(2, body))


# ------------------------------------------------------------------------ restart


def test_a_process_captures_and_exits_and_a_new_process_restores() -> None:
    async def scenario() -> None:
        namespace = namespace_name()
        capture = Capture(namespace, max_uses=2)
        first = DriverProcess("first")
        await first.start(REAL_CLOCK)
        await initialized(first, namespace)
        await created(first, capture)
        first_pid = first.pid
        await first.stop()
        second = DriverProcess("second")
        await second.start(REAL_CLOCK)
        try:
            assert second.pid != first_pid
            seen = await read(second, capture)
            assert [row["used"] for row in seen["entries"]] == [0]
            reply = await second.call("commitRestore", input=capture.commit_input())
            assert reply["result"] == {"outcome": "committed"}
        finally:
            await second.stop()

    run(scenario())


def test_a_capture_made_by_an_exited_process_and_revoked_by_another_is_denied_to_a_third() -> None:
    async def scenario() -> None:
        namespace = namespace_name()
        capture = Capture(namespace, max_uses=2)
        first = DriverProcess("first")
        await first.start(REAL_CLOCK)
        await initialized(first, namespace)
        await created(first, capture)
        generation = (await read(first, capture))["captures"][0]["generation"]
        await first.stop()
        second, third = DriverProcess("second"), DriverProcess("third")
        await second.start(REAL_CLOCK)
        await third.start(REAL_CLOCK)
        try:
            assert (await second.call("revokeCapture", input=capture.revoke_input()))["result"]["outcome"] == "revoked"
            reply = await third.call("commitRestore", input=capture.commit_input(generation=generation))
            assert reply["result"]["outcome"] == "rejected" and reply["result"]["reason"] in ("revoked", "stale")
        finally:
            await asyncio.gather(second.stop(), third.stop())

    run(scenario())


def test_a_process_killed_before_its_commit_leaves_nothing_applied() -> None:
    async def body(a: DriverProcess, b: DriverProcess) -> None:
        namespace = namespace_name()
        await initialized(a, namespace)
        capture = Capture(namespace, max_uses=2)
        await created(a, capture)
        # A's transaction has executed its statements and waits before COMMIT; then the process is killed.
        pending = a.send("commitRestore", input=capture.commit_input(), hold="before-commit", holdId="h1")
        await a.held("h1")
        a.kill()
        await asyncio.sleep(0.5)
        assert not pending.done() or "error" in pending.result()
        # B sees no use consumed and no receipt, and the row lock the dead transaction held is gone.
        assert [row["used"] for row in await entries(b, capture)] == [0]
        assert (await b.call("revokeCapture", input=capture.revoke_input()))["result"]["outcome"] == "revoked"

    run(with_processes(2, body))


# ------------------------------------------------------------------- clock skew


def test_a_process_whose_clock_is_outside_the_skew_bound_is_rejected_but_may_still_revoke() -> None:
    async def body(a: DriverProcess, b: DriverProcess) -> None:
        namespace = namespace_name()
        await initialized(a, namespace)
        good = Capture(namespace, max_uses=2)
        await created(a, good)
        hour = 3_600_000
        # B's clock runs an hour ahead of the database's.
        ahead = Capture(namespace, now=real_now() + hour)
        reply = await b.call("createCapture", input=ahead.create_input())
        assert reply["result"] == {"outcome": "rejected", "reason": "clock-skew"}
        reply = await b.call("commitRestore", input=good.commit_input(now=real_now() + hour))
        assert reply["result"] == {"outcome": "rejected", "reason": "clock-skew"}
        assert [row["used"] for row in await entries(a, good)] == [0], "the skewed commit consumed nothing"
        reply = await b.call("revokeCapture", input=good.revoke_input(now=real_now() + hour))
        assert reply["result"]["outcome"] == "revoked"

    run(with_processes(2, body, store={"maxClockSkewMs": 2000}))


# --------------------------------------------------------------------------- fork


def test_a_store_created_before_fork_is_not_used_by_the_child() -> None:
    script = (
        "import asyncio, os, sys\n"
        "sys.path.insert(0, 'tests')\n"
        "import pg_support\n"
        "from redact_secret_vault.persistent import StoreError\n"
        "async def main():\n"
        "    pool = pg_support.Pool()\n"
        "    store = await pg_support.open_store(pool)\n"
        "    await store.recovery_state('fork-synthetic')\n"
        "    opened = pool.opened\n"
        "    pid = os.fork()\n"
        "    if pid == 0:\n"
        "        code = 2\n"
        "        try:\n"
        "            await store.recovery_state('fork-synthetic')\n"
        "        except StoreError as error:\n"
        "            code = 0 if error.code == 'STORE_CLOSED' and pool.opened == opened else 3\n"
        "        os._exit(code)\n"
        "    _, status = os.waitpid(pid, 0)\n"
        "    assert os.waitstatus_to_exitcode(status) == 0, status\n"
        "    await store.recovery_state('fork-synthetic')\n"
        "asyncio.run(main())\n"
    )

    async def scenario() -> int:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            script,
            cwd=os.path.dirname(os.path.abspath(__file__)) + "/..",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return await process.wait()

    assert run(scenario()) == 0


def test_the_actors_are_distinct_processes_with_distinct_clocks() -> None:
    async def body(a: DriverProcess, b: DriverProcess) -> None:
        assert a.pid != b.pid
        namespace = namespace_name()
        await initialized(a, namespace)
        assert (await b.call("recoveryState", input={"namespace": namespace}))["result"] == {
            "epoch": 1,
            "state": "serving",
        }
        assert scope(namespace)["namespace"] == namespace and capture_id().startswith("cap_")

    run(with_processes(2, body))
