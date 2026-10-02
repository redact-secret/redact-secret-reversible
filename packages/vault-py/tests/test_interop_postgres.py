"""Cross-language interoperation through one real PostgreSQL database (docs/plans/python-persistence-parity.md section
5.4, and the mixed-language variants of section 6.1; gate G2).

Two persistent server processes, one JavaScript (``@redact-secret/vault-server/persistent`` over ``store-postgres``) and
one Python (the persistent server profile over ``redact_secret_vault.stores.postgres``), each its own operating-system
process with its own pool, its own core, and its own key provider, share the database and the key material the test
generates for the run, and nothing else. The database schema is the one the JavaScript package owns; neither side
creates a table.

Every value is synthetic. A restored value is compared in memory and never logged. Skipped, with the reason, when
``RSV_PG_APP_URL`` and ``RSV_PG_ADMIN_URL`` are not set (a run with ``RSV_REQUIRE_POSTGRES=1`` fails instead), or when
``node`` or the JavaScript build is missing.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import shutil
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("psycopg")
pytest.importorskip("cryptography")

import pg_support  # noqa: E402
from pg_processes import Capture, Worker, attempt_id, namespace_name  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
HARNESS = REPO / "packages" / "store-postgres" / "qualification" / "lib" / "harness.mjs"
BUILT = (REPO / "packages" / "store-postgres" / "dist" / "index.js").is_file()
HAVE_NODE = shutil.which("node") is not None

pytestmark = [
    pg_support.needs_database,
    pytest.mark.skipif(sys.version_info < (3, 11), reason="the persistent modules need Python 3.11"),
    pytest.mark.skipif(
        not HAVE_NODE or not BUILT, reason="node and a built JavaScript workspace are needed (npm run build)"
    ),
]
pg_support.require_database()

PAIRS = [("js", "py"), ("py", "js")]
#: A deliberately contended run (100 restores of one entry from two processes): the lock and statement waits, the store
#: deadline of the server, and the pool are sized so that waiting for a row lock or a connection is not what is
#: measured. The first run of this case in a Linux container, with the defaults (2 s lock wait, 10 s store deadline, a
#: pool of 20), had a restore end ``COMMIT_AMBIGUOUS`` or ``STORE_UNAVAILABLE`` after waiting too long, which is what
#: those codes mean.
CONTENDED: dict[str, Any] = {
    "poolMax": 40,
    "storeOptions": {"lockTimeoutMs": 10_000, "statementTimeoutMs": 30_000},
    "vaultOptions": {"storeTimeoutMs": 60_000},
}
TENANT = "tenant-synthetic-a"
RELEASE = [{"sink": "sink-a", "paths": ["body", "subject"]}]


def run(coro: Awaitable[Any]) -> Any:
    return asyncio.run(coro)  # type: ignore[arg-type]


def secret(index: int) -> str:
    """Unmistakably synthetic values the core detects (AGENTS.md security boundary). Never a real credential."""

    return f"ghp_SYNTHETICxREVOKEDxTESTx{index:013d}"


def synthetic_text(count: int, offset: int = 0) -> tuple[str, list[str]]:
    values = [secret(offset + index) for index in range(count)]
    return "\n".join(f"field {index}: {value}" for index, value in enumerate(values)), values


def keys() -> dict[str, str]:
    return {"keyHex": secrets.token_hex(32), "digestHex": secrets.token_hex(32)}


def context(*, session: str | None = None, tenant: str = TENANT, principal: str = "user-synthetic-1") -> dict[str, str]:
    value = {"principal": principal, "tenant": tenant}
    if session is not None:
        value["session"] = session
    return value


def restore_request(
    capture: dict[str, Any],
    ctx: dict[str, str],
    *,
    attempt: str | None = None,
    purpose: str = "qualification",
    repeat: int = 1,
) -> dict[str, Any]:
    tokens = [item["token"] for item in capture["tokens"]]
    request: dict[str, Any] = {
        "context": ctx,
        "sink": "sink-a",
        "purpose": purpose,
        "captures": [capture["captureId"]],
        "fields": {"body": "| ".join(f"{token} " * repeat for token in tokens)},
    }
    if attempt is not None:
        request["attemptId"] = attempt
    return request


def expected_body(values: list[str], repeat: int = 1) -> str:
    return "| ".join(f"{value} " * repeat for value in values)


async def make_worker(language: str, namespace: str, shared: dict[str, str], **override: str) -> Worker:
    config = {
        "url": pg_support.APP_URL,
        "schema": pg_support.SCHEMA,
        "namespace": namespace,
        "epoch": 1,
        "poolMax": 20,
        **shared,
        **override,
    }
    return await Worker(language, config).start()


async def pair(
    first: str,
    second: str,
    body: Callable[[Worker, Worker, str], Awaitable[None]],
    *,
    override: dict[str, str] | None = None,
    both: dict[str, Any] | None = None,
) -> None:
    """Two processes of two languages over one namespace. ``override`` applies to the second one only."""

    namespace = namespace_name("interop")
    shared = keys()
    # The parent of the server processes creates the namespace recovery record once, as an operator would.
    store = await pg_support.open_store(pg_support.Pool(), lock_timeout_ms=2000, max_clock_skew_ms=2000)
    assert (await store.initialize_namespace(namespace, 1)).outcome == "initialized"
    store.close()
    a = await make_worker(first, namespace, shared, **(both or {}))
    b = await make_worker(second, namespace, shared, **{**(both or {}), **(override or {})})
    try:
        assert a.pid != b.pid != os.getpid()
        assert a.language != b.language
        await body(a, b, namespace)
    finally:
        await asyncio.gather(a.stop(), b.stop())


async def captured(
    worker: Worker, ctx: dict[str, str], *, count: int = 1, max_uses: int = 1, offset: int = 0
) -> tuple[dict[str, Any], list[str]]:
    text, values = synthetic_text(count, offset)
    reply = await worker.call("capture", text=text, context=ctx, maxUses=max_uses, release=RELEASE)
    assert reply["ok"] is True, reply
    capture = reply["value"]
    assert len(capture["tokens"]) == count
    for value in values:
        assert value not in capture["text"], "the redacted text carries no value"
    return capture, values


def denied(reply: dict[str, Any], reason: str) -> bool:
    return reply["ok"] is False and reply["code"] == "RESTORE_DENIED" and reply["reason"] == reason


def short(reply: dict[str, Any]) -> str:
    return f"ok={reply.get('ok')} code={reply.get('code')} reason={reply.get('reason')}"


# ---------------------------------------------------------------------------- seal in one, open in the other


@pytest.mark.parametrize(("sealer", "opener"), PAIRS)
def test_a_capture_sealed_by_one_language_is_restored_by_the_other(sealer: str, opener: str) -> None:
    async def body(a: Worker, b: Worker, namespace: str) -> None:
        ctx = context()
        capture, values = await captured(a, ctx, count=3, max_uses=2)
        reply = await b.call("restore", request=restore_request(capture, ctx, repeat=2))
        assert reply["ok"] is True, short(reply)
        assert reply["value"]["fields"] == {"body": expected_body(values, 2)}
        assert reply["value"]["restored"] == 6
        # The sealer can open it too: the budget of 2 is shared, one use each.
        again = await a.call("restore", request=restore_request(capture, ctx))
        assert again["ok"] is False and again["reason"] == "budget", short(again)

    run(pair(sealer, opener, body))


@pytest.mark.parametrize(("sealer", "opener"), PAIRS)
def test_every_capture_of_a_batch_sealed_by_one_language_opens_in_the_other(sealer: str, opener: str) -> None:
    async def body(a: Worker, b: Worker, namespace: str) -> None:
        ctx = context()
        made = [await captured(a, ctx, count=2, offset=10 * index) for index in range(4)]
        for capture, values in made:
            reply = await b.call("restore", request=restore_request(capture, ctx))
            assert reply["ok"] is True, short(reply)
            assert reply["value"]["fields"] == {"body": expected_body(values)}

    run(pair(sealer, opener, body))


# ------------------------------------------------------------------------ lifecycle across languages


@pytest.mark.parametrize(("maker", "other"), PAIRS)
def test_a_capture_revoked_by_the_other_language_is_denied_revoked_by_both(maker: str, other: str) -> None:
    async def body(a: Worker, b: Worker, namespace: str) -> None:
        ctx = context()
        capture, _values = await captured(a, ctx, max_uses=3)
        revoked = await b.call("revoke", context=ctx, captureId=capture["captureId"])
        assert revoked["ok"] is True and revoked["value"]["outcome"] == "revoked", short(revoked)
        for worker in (a, b):
            reply = await worker.call("restore", request=restore_request(capture, ctx))
            assert denied(reply, "revoked"), short(reply)

    run(pair(maker, other, body))


@pytest.mark.parametrize(("first", "second"), PAIRS)
def test_a_restore_committed_by_one_language_is_already_committed_to_the_other_and_a_changed_request_mismatches(
    first: str, second: str
) -> None:
    async def body(a: Worker, b: Worker, namespace: str) -> None:
        ctx = context()
        capture, values = await captured(a, ctx, count=2, max_uses=2)
        attempt = attempt_id()
        request = restore_request(capture, ctx, attempt=attempt)
        done = await a.call("restore", request=request)
        assert done["ok"] is True and done["value"]["fields"] == {"body": expected_body(values)}, short(done)
        # The same attempt and the same request: the other language's request digest agrees with the first's.
        replay = await b.call("restore", request=request)
        assert denied(replay, "attempt-already-committed"), short(replay)
        # A changed request under the same attempt identifier.
        changed = await b.call(
            "restore", request=restore_request(capture, ctx, attempt=attempt, purpose="another-purpose")
        )
        assert denied(changed, "attempt-mismatch"), short(changed)
        resolved = await b.call("resolveAttempt", request=request)
        assert resolved["ok"] is True and resolved["value"]["state"] == "committed", short(resolved)
        # And from the language that committed.
        changed_here = await a.call(
            "restore", request=restore_request(capture, ctx, attempt=attempt, purpose="another-purpose")
        )
        assert denied(changed_here, "attempt-mismatch"), short(changed_here)

    run(pair(first, second, body))


@pytest.mark.parametrize(("maker", "other"), PAIRS)
def test_a_session_bound_capture_is_denied_source_under_another_session_and_restored_under_the_same(
    maker: str, other: str
) -> None:
    async def body(a: Worker, b: Worker, namespace: str) -> None:
        bound = context(session="session-synthetic-one")
        capture, values = await captured(a, bound, max_uses=3)
        wrong = await b.call("restore", request=restore_request(capture, context(session="session-synthetic-two")))
        assert denied(wrong, "source"), short(wrong)
        none = await b.call("restore", request=restore_request(capture, context()))
        assert denied(none, "source"), short(none)
        right = await b.call("restore", request=restore_request(capture, bound))
        assert right["ok"] is True and right["value"]["fields"] == {"body": expected_body(values)}, short(right)
        # The session tags agree in the other direction too.
        wrong_here = await a.call("restore", request=restore_request(capture, context(session="session-synthetic-two")))
        assert denied(wrong_here, "source"), short(wrong_here)

    run(pair(maker, other, body))


@pytest.mark.parametrize(("first", "second"), PAIRS)
def test_an_exhausted_budget_is_denied_budget_to_both(first: str, second: str) -> None:
    async def body(a: Worker, b: Worker, namespace: str) -> None:
        ctx = context()
        capture, _values = await captured(a, ctx, max_uses=1)
        assert (await a.call("restore", request=restore_request(capture, ctx)))["ok"] is True
        for worker in (a, b):
            reply = await worker.call("restore", request=restore_request(capture, ctx))
            assert denied(reply, "budget"), short(reply)

    run(pair(first, second, body))


# -------------------------------------------------------------------------------- negative runs


@pytest.mark.parametrize(("maker", "other"), PAIRS)
def test_with_a_different_digest_key_a_session_bound_restore_is_denied_source(maker: str, other: str) -> None:
    async def body(a: Worker, b: Worker, namespace: str) -> None:
        bound = context(session="session-synthetic-one")
        capture, _values = await captured(a, bound, max_uses=2)
        reply = await b.call("restore", request=restore_request(capture, bound))
        assert denied(reply, "source"), short(reply)
        # Nothing was consumed: the maker, with the right digest key, still restores.
        ok = await a.call("restore", request=restore_request(capture, bound))
        assert ok["ok"] is True, short(ok)

    run(pair(maker, other, body, override={"digestHex": secrets.token_hex(32)}))


@pytest.mark.parametrize(("maker", "other"), PAIRS)
def test_with_different_key_material_the_restore_is_denied_and_nothing_is_consumed(maker: str, other: str) -> None:
    async def body(a: Worker, b: Worker, namespace: str) -> None:
        ctx = context()
        capture, values = await captured(a, ctx, max_uses=1)
        reply = await b.call("restore", request=restore_request(capture, ctx))
        assert reply["ok"] is False and reply["code"] == "RESTORE_DENIED", short(reply)
        assert reply["reason"] in ("key-unavailable", "integrity-failure"), short(reply)
        # A single-use value that the wrong key could not open is still there for the right one.
        ok = await a.call("restore", request=restore_request(capture, ctx))
        assert ok["ok"] is True and ok["value"]["fields"] == {"body": expected_body(values)}, short(ok)

    run(pair(maker, other, body, override={"keyHex": secrets.token_hex(32)}))


# ------------------------------------------------------------------ mixed-language two-process cases


@pytest.mark.parametrize(("restorer", "revoker"), PAIRS)
def test_a_revoke_held_open_by_one_language_across_a_restore_by_the_other_denies_the_restore(
    restorer: str, revoker: str
) -> None:
    async def body(a: Worker, b: Worker, namespace: str) -> None:
        ctx = context()
        capture, _values = await captured(a, ctx, max_uses=2)
        await b.hold_next("h1")
        held = b.send("revoke", context=ctx, captureId=capture["captureId"])
        await b.held("h1")
        pending = a.send("restore", request=restore_request(capture, ctx))
        await asyncio.sleep(1.0)
        assert not pending.done(), "the restore must wait for the open revocation, not read around it"
        await b.release("h1")
        assert (await held)["ok"] is True
        reply = await pending
        assert reply["ok"] is False and reply["reason"] == "revoked", short(reply)

    run(pair(restorer, revoker, body))


@pytest.mark.parametrize(("restorer", "revoker"), PAIRS)
def test_a_revoke_committed_before_a_restore_by_the_other_language_denies_it(restorer: str, revoker: str) -> None:
    async def body(a: Worker, b: Worker, namespace: str) -> None:
        ctx = context()
        capture, _values = await captured(a, ctx, max_uses=2)
        assert (await b.call("revoke", context=ctx, captureId=capture["captureId"]))["ok"] is True
        reply = await a.call("restore", request=restore_request(capture, ctx))
        assert denied(reply, "revoked"), short(reply)

    run(pair(restorer, revoker, body))


@pytest.mark.parametrize(("creator", "quarantiner"), PAIRS)
def test_a_creation_held_open_in_one_language_is_ordered_against_a_quarantine_in_the_other(
    creator: str, quarantiner: str
) -> None:
    async def body(a: Worker, b: Worker, namespace: str) -> None:
        fixture = Capture(namespace, entries=2)
        await a.hold_next("h1")
        held = a.send("store", method="createCapture", input=fixture.create_input())
        await a.held("h1")
        quarantine = b.send("store", method="quarantine", input={"namespace": namespace})
        await asyncio.sleep(1.0)
        assert not quarantine.done(), "the quarantine must wait for the open creation"
        await a.release("h1")
        assert (await held)["result"] == {"outcome": "created"}
        assert (await quarantine)["result"] == {"epoch": 1, "state": "quarantined"}
        later = Capture(namespace)
        reply = await a.store("createCapture", later.create_input())
        assert reply["result"] == {"outcome": "rejected", "reason": "quarantined"}

    run(pair(creator, quarantiner, body))


@pytest.mark.parametrize(("first", "second"), PAIRS)
def test_a_hundred_concurrent_restores_from_the_two_languages_commit_exactly_max_uses(first: str, second: str) -> None:
    max_uses = 7

    async def body(a: Worker, b: Worker, namespace: str) -> None:
        ctx = context()
        capture, values = await captured(a, ctx, max_uses=max_uses)
        requests = [restore_request(capture, ctx, attempt=attempt_id()) for _ in range(100)]
        replies = await asyncio.gather(
            a.call("burst", requests=requests[::2]), b.call("burst", requests=requests[1::2])
        )
        outcomes = [reply for batch in replies for reply in batch]
        committed = [reply for reply in outcomes if reply["ok"]]
        assert len(committed) == max_uses, [short(reply) for reply in outcomes if not reply["ok"]][:5]
        for reply in committed:
            assert reply["value"]["fields"] == {"body": expected_body(values)}
        for reply in outcomes:
            if not reply["ok"]:
                assert (
                    reply["code"] == "RESTORE_DENIED"
                    and reply["reason"] == "budget"
                    or reply["code"] == "RESTORE_CONFLICT"
                ), short(reply)
        # The database agrees: the single entry has used exactly max_uses.
        rows = await pg_support.admin_execute(
            f'SELECT used FROM "{pg_support.SCHEMA}".rsv_entry WHERE namespace = %s', (namespace,)
        )
        assert [row[0] for row in rows] == [max_uses]

    run(pair(first, second, body, both=CONTENDED))
