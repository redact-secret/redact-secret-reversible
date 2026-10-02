"""The reference store (``redact_secret_vault.persistent.store_memory``) and the schedule corpus.

The language-neutral corpus (``conformance/persistent/v1/schedules.json``) is the oracle: this file runs it
through the Python driver (``schedule_driver.py``) and applies the store-level mutation controls of the plan,
section 6.5. Python persistence is not implemented and not supported; a pass here shows that this in-memory
store follows the Store contract on the schedules run. It says nothing about a database adapter, durability,
or the persistent server profile.
"""

from __future__ import annotations

import ast
import asyncio
import json
import re
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from schedule_support import DRIVER, have_orchestrator, load_corpus, run_schedules
from store_mutants import MUTANTS

from redact_secret_vault.persistent import (
    Attempt,
    CaptureGeneration,
    CommitRestoreInput,
    CreateCaptureInput,
    EntryUse,
    NewCapture,
    NewEntry,
    Store,
    StoreError,
    StoreScope,
    missing_capabilities,
    store_memory,
)
from redact_secret_vault.persistent.store_memory import create_memory_store

pytestmark = pytest.mark.skipif(sys.version_info < (3, 11), reason="the persistent modules need Python 3.11")

needs_orchestrator = pytest.mark.skipif(
    not have_orchestrator(), reason="needs node and the repository's conformance directory"
)

SCOPE = StoreScope(namespace="ns-synthetic", tenant="tenant-acme-synthetic")
START = 1_800_000_000_000
CAPTURE = "cap_" + "a" * 26
ENTRY = "0" * 63 + "1"


class _Clock:
    def __init__(self) -> None:
        self.ms = START

    def now(self) -> int:
        return self.ms


def _new_capture(clock: _Clock, *, max_uses: int = 1) -> CreateCaptureInput:
    return CreateCaptureInput(
        scope=SCOPE,
        epoch=1,
        now=clock.ms,
        capture=NewCapture(
            capture_id=CAPTURE,
            key_ref="synthetic-key:v1",
            wrapped_key=b"\x11" * 40,
            session_tag=None,
            created_at=clock.ms,
            expires_at=clock.ms + 3_600_000,
        ),
        entries=(NewEntry(entry_id=ENTRY, max_uses=max_uses, envelope=b"\x22" * 24),),
    )


def _commit(clock: _Clock, attempt: str) -> CommitRestoreInput:
    return CommitRestoreInput(
        scope=SCOPE,
        epoch=1,
        now=clock.ms,
        attempt=Attempt(attempt_id=attempt, request_digest=b"\x33" * 32),
        receipt_expires_at=clock.ms + 2 * 3_600_000,
        captures=(CaptureGeneration(capture_id=CAPTURE, generation=1),),
        uses=(EntryUse(entry_id=ENTRY, capture_id=CAPTURE, count=1, lifecycle_revision=1, ciphertext_revision=1),),
    )


# ------------------------------------------------------------------------ the store itself


def test_the_store_declares_what_it_is_and_what_it_is_not() -> None:
    store = create_memory_store()
    assert isinstance(store, Store)
    capabilities = store.capabilities()
    assert missing_capabilities(capabilities) == ()
    assert capabilities.durability == "volatile"
    assert capabilities.cross_process is False
    assert capabilities.restore_detection == "none"


def test_the_production_module_has_no_hold_point_and_no_fault_hook() -> None:
    """No identifier of the module names a hold, a pause, a fault, or a mutant (comments and docstrings may say so)."""

    tree = ast.parse(Path(store_memory.__file__).read_text(encoding="utf-8"))
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
    banned = {"hold", "holds", "fault", "faults", "pause", "mutant", "release"}
    words = {name: set(re.split(r"_|(?<=[a-z])(?=[A-Z])", name.lower())) for name in identifiers}
    assert sorted(name for name, parts in words.items() if parts & banned) == []
    assert not hasattr(create_memory_store(), "hold")


def test_bounds_may_only_be_lowered() -> None:
    assert create_memory_store(max_create_entries=8).capabilities().max_create_entries == 8
    for bad in (0, -1, 2000, True, 1.5):
        with pytest.raises(ValueError, match="max_create_entries"):
            create_memory_store(max_create_entries=bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="max_clock_skew_ms"):
        create_memory_store(max_clock_skew_ms=60_001)


def test_a_clock_that_cannot_be_read_is_unavailable_and_changes_nothing() -> None:
    bad: list[object] = [True, float("nan"), float("inf"), -1, 2**53, "now", None]
    for reading in bad:
        store = create_memory_store(now=lambda reading=reading: reading)  # type: ignore[misc]
        with pytest.raises(StoreError) as raised:
            asyncio.run(store.recovery_state("ns-synthetic"))
        assert raised.value.code == "STORE_UNAVAILABLE"
        assert raised.value.__cause__ is None and raised.value.__context__ is None


def test_a_float_clock_is_floored() -> None:
    store = create_memory_store(now=lambda: START + 0.9)
    assert asyncio.run(store.initialize_namespace("ns-synthetic", 1)).outcome == "initialized"


def test_errors_carry_no_cause_and_no_context() -> None:
    store = create_memory_store()
    with pytest.raises(StoreError) as raised:
        asyncio.run(store.read_entries(None))  # type: ignore[arg-type]
    assert raised.value.code == "STORE_INVALID_ARGUMENT"
    assert raised.value.__cause__ is None and raised.value.__context__ is None


def test_one_use_is_granted_once_across_threads_and_event_loops() -> None:
    """The store relies on its lock, not the GIL: threads with their own event loops still commit exactly once."""

    clock = _Clock()
    store = create_memory_store(now=clock.now)
    asyncio.run(store.initialize_namespace(SCOPE.namespace, 1))
    assert asyncio.run(store.create_capture(_new_capture(clock))).outcome == "created"
    outcomes: list[str] = []
    guard = threading.Lock()
    barrier = threading.Barrier(8)

    def worker(index: int) -> None:
        barrier.wait()
        result = asyncio.run(store.commit_restore(_commit(clock, f"attempt-synthetic-{index}")))
        with guard:
            outcomes.append(result.outcome if result.outcome != "rejected" else f"rejected:{result.reason}")

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert outcomes.count("committed") == 1
    assert all(item in ("committed", "rejected:budget", "rejected:stale") for item in outcomes)


def test_a_cancelled_call_before_its_atomic_section_has_no_effect() -> None:
    clock = _Clock()
    store = create_memory_store(now=clock.now)

    async def scenario() -> str:
        await store.initialize_namespace(SCOPE.namespace, 1)
        task = asyncio.ensure_future(store.create_capture(_new_capture(clock)))
        await asyncio.sleep(0)  # the call is at its yield point, before its atomic section
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        rows = await store.read_captures(
            __import__("redact_secret_vault.persistent", fromlist=["ReadCapturesInput"]).ReadCapturesInput(
                scope=SCOPE, capture_ids=(CAPTURE,)
            )
        )
        return "present" if rows else "absent"

    assert asyncio.run(scenario()) == "absent"


# --------------------------------------------------------------------------- restart


def _talk(process: subprocess.Popen[str], message: dict[str, object]) -> dict[str, object]:
    assert process.stdin is not None and process.stdout is not None
    process.stdin.write(json.dumps(message) + "\n")
    process.stdin.flush()
    return json.loads(process.stdout.readline())


def _start_driver() -> subprocess.Popen[str]:
    return subprocess.Popen(  # noqa: S603
        [sys.executable, str(DRIVER)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8"
    )


def test_a_restart_loses_everything() -> None:
    """Two processes in turn: what the first stored is not there for the second. Volatile, not persistence."""

    namespace = "conf-restart0001"
    first = _start_driver()
    try:
        assert _talk(first, {"id": 1, "op": "configure", "level": "store", "store": {}})["ok"] is True
        assert _talk(first, {"id": 2, "op": "initializeNamespace", "input": {"namespace": namespace, "epoch": 1}})[
            "result"
        ] == {"outcome": "initialized"}
        clock = int(_talk(first, {"id": 3, "op": "clock", "action": "now"})["result"]["now"])  # type: ignore[index]
        created = _talk(
            first,
            {
                "id": 4,
                "op": "createCapture",
                "input": {
                    "scope": {"namespace": namespace, "tenant": "tenant-acme-synthetic"},
                    "epoch": 1,
                    "now": clock,
                    "capture": {
                        "captureId": CAPTURE,
                        "sessionTag": None,
                        "createdAt": clock,
                        "expiresAt": clock + 3_600_000,
                        "lookupVersion": 1,
                        "keyRef": "synthetic-key:v1",
                        "wrappedKey": "11" * 40,
                    },
                    "entries": [{"entryId": ENTRY, "maxUses": 1, "envelope": "22" * 24}],
                },
            },
        )
        assert created["result"] == {"outcome": "created"}
        read = _talk(
            first,
            {
                "id": 5,
                "op": "readCaptures",
                "input": {
                    "scope": {"namespace": namespace, "tenant": "tenant-acme-synthetic"},
                    "captureIds": [CAPTURE],
                },
            },
        )
        assert len(read["result"]) == 1  # type: ignore[arg-type]
    finally:
        first.kill()
        first.wait()

    second = _start_driver()
    try:
        assert _talk(second, {"id": 1, "op": "configure", "level": "store", "store": {}})["ok"] is True
        assert _talk(second, {"id": 2, "op": "recoveryState", "input": {"namespace": namespace}})["result"] == {
            "epoch": 0,
            "state": "uninitialized",
        }
        gone = _talk(
            second,
            {
                "id": 3,
                "op": "readCaptures",
                "input": {
                    "scope": {"namespace": namespace, "tenant": "tenant-acme-synthetic"},
                    "captureIds": [CAPTURE],
                },
            },
        )
        assert gone["result"] == []
    finally:
        second.kill()
        second.wait()


# ----------------------------------------------------------------- the schedule corpus


@needs_orchestrator
def test_the_store_level_schedules_pass_and_none_is_skipped() -> None:
    report = run_schedules(level="store")
    corpus = load_corpus()
    store_cases = [case for case in corpus["cases"] if case["level"] == "store"]
    by_id = {result["id"]: result for result in report["results"]}
    assert set(by_id) == {case["id"] for case in store_cases}
    failed = [f"{result['id']}: {result.get('detail')}" for result in by_id.values() if result["status"] == "failed"]
    assert failed == []
    # Every store-level case this store's capabilities allow ran: none is skipped, so none is passed by omission.
    assert [case["id"] for case in store_cases if by_id[case["id"]]["status"] != "passed"] == []
    assert len(store_cases) >= 100
    print(f"store-level schedules: {len(store_cases)} passed, 0 skipped")


@needs_orchestrator
def test_a_driver_that_does_not_serve_a_level_skips_its_cases_with_that_reason() -> None:
    """A level the driver cannot configure is skipped, never passed: the store driver answers UNSUPPORTED_LEVEL."""

    report = run_schedules(level="server", store_options={"serveLevels": ["store"]})
    server_cases = [case for case in load_corpus()["cases"] if case["level"] == "server"]
    skipped = [r for r in report["results"] if r["status"] == "skipped"]
    assert len(skipped) == len(server_cases) > 0
    assert all("does not serve level server" in r["detail"] for r in skipped)


@needs_orchestrator
def test_a_store_with_a_clock_the_harness_cannot_move_skips_time_travel_and_never_passes_it() -> None:
    report = run_schedules(level="store", store_options={"realClock": True, "noHolds": True})
    assert [result["id"] for result in report["results"] if result["status"] == "failed"] == []
    skipped = [result for result in report["results"] if result["status"] == "skipped"]
    assert len(skipped) >= 10
    assert all(
        ("testClock" in result["detail"]) or ("hold" in result["detail"]) or ("clock" in result["detail"])
        for result in skipped
    )


@needs_orchestrator
def test_the_store_level_schedules_pass_with_every_bound_lowered() -> None:
    bounds = {
        "maxClockSkewMs": 500,
        "maxCreateEntries": 8,
        "maxCreateBytes": 4096,
        "maxRestoreEntries": 4,
        "maxRestoreCaptures": 2,
        "maxEnvelopeBytes": 1024,
    }
    report = run_schedules(level="store", store_options=bounds, parallelism=16)
    assert [f"{r['id']}: {r.get('detail')}" for r in report["results"] if r["status"] == "failed"] == []


# ---------------------------------------------------------------------- mutation controls


def _resolve(prefix: str, corpus: dict[str, object]) -> str:
    matches = [case["id"] for case in corpus["cases"] if case["id"].startswith(prefix[:70])]  # type: ignore[index]
    assert len(matches) == 1, f"{prefix!r} resolves to {matches}"
    return matches[0]


@needs_orchestrator
@pytest.mark.parametrize(
    ("name", "defect", "expected"), [(m[0], m[2], m[3]) for m in MUTANTS], ids=[m[0] for m in MUTANTS]
)
def test_mutant_is_caught(name: str, defect: str, expected: tuple[str, ...]) -> None:
    corpus = load_corpus()
    ids = tuple(_resolve(prefix, corpus) for prefix in expected)
    report = run_schedules(level="store", ids=ids, store_options={"mutant": name}, parallelism=16)
    caught = {result["id"] for result in report["results"] if result["status"] == "failed"}
    assert caught == set(ids), f"mutant {name} ({defect}): expected {sorted(ids)} to fail, failed {sorted(caught)}"


@needs_orchestrator
def test_the_same_schedules_pass_for_the_unmutated_store() -> None:
    corpus = load_corpus()
    ids = tuple(_resolve(prefix, corpus) for mutant in MUTANTS for prefix in mutant[3])
    report = run_schedules(level="store", ids=ids, parallelism=16)
    assert [r["id"] for r in report["results"] if r["status"] != "passed"] == []


@needs_orchestrator
def test_mutant_twelve_is_invisible_without_holds() -> None:
    """The write skew shows only in a two-connection schedule: without holds the case is skipped, never passed."""

    ids = tuple(_resolve(prefix, load_corpus()) for prefix in dict((m[0], m[3]) for m in MUTANTS)["stale-commit-read"])
    report = run_schedules(level="store", ids=ids, store_options={"mutant": "stale-commit-read", "noHolds": True})
    assert [r["status"] for r in report["results"]] == ["skipped"] * len(ids)
