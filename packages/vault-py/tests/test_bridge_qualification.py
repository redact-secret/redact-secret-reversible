"""The quick runs of the bridge qualification harness (``bridge_qualification.py``; gate G5).

These run the real ``boundary/core_bridge.mjs`` over the real ``@redact-secret/core``, so they need ``node`` and an
installed core and are skipped, with the reason, without them. The full runs (thousands of fuzz cases, the heavy
inputs, the memory scan on Linux) are the command-line tool; the qualification record says which were made.

Two criteria are known to be unmet. Each has a strict ``xfail`` below, so a fix flips the test and the record has to
be updated with it (CONVENTIONS.md: a status word follows the evidence).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import bridge_qualification as bq
import pytest

from redact_secret_vault import NodeCoreBridge, VaultServerError


def _core_available() -> bool:
    if shutil.which("node") is None:
        return False
    try:
        with NodeCoreBridge() as bridge:
            bridge.scan("x")
    except VaultServerError:
        return False
    return True


pytestmark = pytest.mark.skipif(not _core_available(), reason="needs node and an installed @redact-secret/core")


def _run(runner, *args, **kwargs) -> dict[str, bq.Result]:  # type: ignore[no-untyped-def]
    report = bq.Report()
    runner(report, *args, **kwargs)
    return {result.ident: result for result in report.results}


def _unmet(results: dict[str, bq.Result]) -> list[str]:
    return [f"{r.ident}: {r.numbers}" for r in results.values() if r.verdict == "NOT-MET"]


def test_adversarial_frames_are_refused_without_echo_hang_or_stderr(tmp_path: Path) -> None:
    results = _run(bq.run_protocol, tmp_path, heavy=False)
    assert _unmet(results) == []
    assert "65 cases" in results["G5.protocol"].numbers


def test_a_seeded_fuzz_run_finds_no_violation_in_the_child_or_the_client_parser() -> None:
    results = _run(bq.run_fuzz, cases=100, seed=7, parser_cases=5000)
    assert _unmet(results) == []


def test_lifetime_bounds_hold_on_the_real_core() -> None:
    results = _run(bq.run_lifetime)
    assert _unmet(results) == []
    assert results["G5.lifetime.defaults"].verdict == "INFO"


def test_a_core_that_never_returns_is_killed_and_the_bridge_recovers(tmp_path: Path) -> None:
    results = _run(bq.run_timeouts, tmp_path, runs=3)
    assert _unmet(results) == []


def test_a_waiting_caller_is_bounded_only_by_the_request_in_flight() -> None:
    """Characterization of the design (docs/specs/threat-model.md, "unbounded queuing delay"): the deadline is armed
    when a request is written, so callers queued behind the lock wait for as long as the queue is long."""

    import threading
    import time

    with NodeCoreBridge(timeout_s=60.0, node_executable=bq.NODE) as bridge:
        bridge.scan("warm")  # the first request pays for the child's start-up and the core's load
        bridge._timeout_s = 0.5  # noqa: SLF001
        lock = bridge._state.lock  # noqa: SLF001
        waited: list[float] = []

        def waiter() -> None:
            started = time.monotonic()
            bridge.scan("x")
            waited.append(time.monotonic() - started)

        with lock:  # another caller is in the middle of a request
            thread = threading.Thread(target=waiter)
            thread.start()
            time.sleep(1.5)  # three times timeout_s
        thread.join(10)
    assert waited and waited[0] >= 1.4, "the queued caller waited past timeout_s without an error"


@pytest.mark.xfail(
    strict=True,
    reason="NOT MET: an error code from the child is copied into the exception message unvalidated "
    "(core_client.py _parse); see the qualification record, G5",
)
def test_an_error_code_from_a_hostile_core_never_reaches_an_exception(tmp_path: Path) -> None:
    results = _run(bq.run_failclosed, tmp_path)
    assert results["G5.sanitization.core-error-code"].verdict == "MET"


def test_a_finding_outside_the_input_is_refused_by_the_capture_plan(tmp_path: Path) -> None:
    results = _run(bq.run_failclosed, tmp_path)
    assert results["G5.failclosed.range-outside-input"].verdict == "MET"


@pytest.mark.xfail(
    strict=True,
    reason="NOT MET: a core replaced on disk that reports the pinned version string is accepted; the bridge pins "
    "a version string and nothing else (same as the JavaScript vault); see the qualification record, G5",
)
def test_a_replaced_core_that_reports_the_pinned_version_is_detected(tmp_path: Path) -> None:
    results = _run(bq.run_failclosed, tmp_path)
    assert results["G5.failclosed.replaced-core"].verdict == "MET"
