"""The long-lived bridge process behind ``NodeCoreBridge`` (#89).

Three layers:

1. The real ``core_bridge.mjs`` against a fake ``@redact-secret/core`` that
   reports its process id as its artifact and misbehaves on request:
   process reuse, lifetime bounds, timeout, crash, malformed and oversized
   output, concurrency, shutdown, and fork.
2. ``NodeCoreBridge`` against a faked bridge process: the protocol checks
   and restart rules that need exact control over a response.
3. The real bridge against the installed core: reuse and concurrent callers.

Data is synthetic. Assertions that nothing leaks look for the synthetic
marker ``leak-synthetic``.
"""

from __future__ import annotations

import gc
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from redact_secret_vault import NodeCoreBridge, VaultServerError, VaultServerErrorCode
from redact_secret_vault import core_client as core_client_module
from redact_secret_vault.core_client import DEFAULT_BRIDGE_SCRIPT, PINNED_CORE_VERSION

# `_gone` probes with signal 0, which terminates the process on Windows.
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the process tests use POSIX process semantics")

needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node is required to run core_bridge.mjs")
posix_only = pytest.mark.skipif(os.name != "posix", reason="uses POSIX signals or fork")

ACTIVATION = "credentials=full;selectors=off;fake=1"

_FAKE_CORE = """
export const VERSION = "__PINNED_CORE_VERSION__";
export function artifact() { return { kind: "pid-" + process.pid }; }
export async function initialize() {}
export function piiActivation() { return "__ACTIVATION__"; }
export function scan(input) {
  if (input === "hang-synthetic") { for (;;) {} }
  if (input === "die-synthetic") { process.kill(process.pid, "SIGKILL"); }
  if (input === "garbage-synthetic") { process.stdout.write("not-json leak-synthetic\\n"); }
  if (input === "big-synthetic") { process.stdout.write("{" + " ".repeat(8192)); }
  if (input === "stderr-synthetic leak-synthetic") { console.error(input); process.stderr.write(input); }
  return [{ id: "finding-1", type: "fake_type", detector: "fake", confidence: "high", obfuscation: "none",
            start: 0, end: input.length, action: "redact" }];
}
"""


@pytest.fixture
def fake_core(tmp_path: Path) -> Path:
    """A ``node_modules`` holding the fake core; returns the bridge script."""
    package = tmp_path / "node_modules" / "@redact-secret" / "core"
    package.mkdir(parents=True)
    (package / "package.json").write_text(
        json.dumps({"name": "@redact-secret/core", "type": "module", "exports": "./index.js"})
    )
    source = _FAKE_CORE.replace("__PINNED_CORE_VERSION__", PINNED_CORE_VERSION).replace("__ACTIVATION__", ACTIVATION)
    (package / "index.js").write_text(source)
    script = tmp_path / "core_bridge.mjs"
    shutil.copyfile(DEFAULT_BRIDGE_SCRIPT, script)
    return script


def _pid(outcome) -> int:
    assert outcome.artifact.startswith("pid-")
    return int(outcome.artifact[len("pid-") :])


def _live_popen(bridge: NodeCoreBridge) -> subprocess.Popen:
    proc = bridge._state.proc
    assert proc is not None
    return proc.popen


def _gone(pid: int) -> bool:
    """True once ``pid`` no longer exists, zombie included (it was reaped)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


def _wait_until(predicate, timeout_s: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def _core_code(excinfo) -> str | None:
    assert excinfo.value.code == VaultServerErrorCode.CORE_FAILURE
    return excinfo.value.core_code


# -- 1. The real bridge script against a fake core -------------------------------


@needs_node
def test_sequential_scans_reuse_one_process(fake_core):
    with NodeCoreBridge(script=fake_core) as bridge:
        pids = set()
        for n in range(50):
            outcome = bridge.scan("x" * n)
            assert [f.end for f in outcome.findings] == [n]
            assert outcome.pii_activation == ACTIVATION
            pids.add(_pid(outcome))
        assert len(pids) == 1
        assert _live_popen(bridge).pid in pids


@needs_node
@posix_only
def test_timeout_kills_the_process_and_the_next_scan_restarts(fake_core):
    with NodeCoreBridge(script=fake_core, timeout_s=1.0) as bridge:
        first = _pid(bridge.scan("warm"))
        started = time.monotonic()
        with pytest.raises(VaultServerError) as excinfo:
            bridge.scan("hang-synthetic")
        assert _core_code(excinfo) == "BRIDGE_TIMEOUT"
        assert time.monotonic() - started < 5
        assert bridge._state.proc is None
        assert _gone(first)
        assert _pid(bridge.scan("again")) != first


@needs_node
@posix_only
def test_a_process_that_dies_mid_request_fails_closed_then_recovers(fake_core):
    with NodeCoreBridge(script=fake_core) as bridge:
        first = _pid(bridge.scan("warm"))
        with pytest.raises(VaultServerError) as excinfo:
            bridge.scan("die-synthetic")
        assert _core_code(excinfo) == "BRIDGE_PROCESS_FAILED"
        assert _gone(first)
        outcome = bridge.scan("after")
        assert _pid(outcome) != first
        assert [f.end for f in outcome.findings] == [len("after")]


@needs_node
@posix_only
def test_a_process_killed_while_idle_is_replaced_before_the_next_request(fake_core):
    with NodeCoreBridge(script=fake_core) as bridge:
        first = _pid(bridge.scan("warm"))
        popen = _live_popen(bridge)
        os.kill(first, signal.SIGKILL)
        assert _wait_until(lambda: popen.poll() is not None)
        # No request was in flight, so nothing fails: the next scan simply
        # starts a new process.
        assert _pid(bridge.scan("after")) != first


@needs_node
def test_malformed_output_fails_closed_without_echoing_it_then_recovers(fake_core):
    with NodeCoreBridge(script=fake_core) as bridge:
        first = _pid(bridge.scan("warm"))
        with pytest.raises(VaultServerError) as excinfo:
            bridge.scan("garbage-synthetic")
        assert _core_code(excinfo) == "BRIDGE_BAD_OUTPUT"
        assert "leak-synthetic" not in str(excinfo.value)
        assert "leak-synthetic" not in repr(excinfo.value.__cause__)
        assert _pid(bridge.scan("after")) != first


@needs_node
def test_oversized_output_fails_closed(fake_core, monkeypatch):
    monkeypatch.setattr(core_client_module, "MAX_RESPONSE_FRAME_BYTES", 4096)
    with NodeCoreBridge(script=fake_core) as bridge:
        first = _pid(bridge.scan("warm"))
        with pytest.raises(VaultServerError) as excinfo:
            bridge.scan("big-synthetic")
        assert _core_code(excinfo) == "BRIDGE_BAD_OUTPUT"
        assert _pid(bridge.scan("after")) != first


@needs_node
def test_an_oversized_request_is_refused_before_it_is_sent(fake_core, monkeypatch):
    with NodeCoreBridge(script=fake_core) as bridge:
        first = _pid(bridge.scan("warm"))
        monkeypatch.setattr(core_client_module, "MAX_REQUEST_FRAME_BYTES", 1024)
        with pytest.raises(VaultServerError) as excinfo:
            bridge.scan("y" * 2048)
        assert excinfo.value.code == VaultServerErrorCode.LIMIT_EXCEEDED
        # The process was never involved, so it is kept.
        assert _pid(bridge.scan("after")) == first


@needs_node
def test_bridge_stderr_is_discarded(fake_core, capfd):
    with NodeCoreBridge(script=fake_core) as bridge:
        bridge.scan("stderr-synthetic leak-synthetic")
    out, err = capfd.readouterr()
    assert "leak-synthetic" not in out
    assert "leak-synthetic" not in err


@needs_node
def test_process_is_retired_at_max_scans(fake_core):
    with NodeCoreBridge(script=fake_core, max_scans_per_process=3) as bridge:
        pids = [_pid(bridge.scan("x")) for _ in range(3)]
        # Killed right after its last scan, not left holding that input.
        assert bridge._state.proc is None
        assert _gone(pids[0])
        pids += [_pid(bridge.scan("x")) for _ in range(4)]
    assert pids[0] == pids[1] == pids[2]
    assert pids[3] == pids[4] == pids[5]
    assert pids[6] not in (pids[0], pids[3])
    assert pids[0] != pids[3]
    assert _gone(pids[0]) and _gone(pids[3])


@needs_node
def test_process_is_replaced_after_max_age(fake_core):
    with NodeCoreBridge(script=fake_core, max_process_age_s=0.3) as bridge:
        first = _pid(bridge.scan("x"))
        assert _pid(bridge.scan("x")) == first
        time.sleep(0.4)
        assert _pid(bridge.scan("x")) != first


@needs_node
def test_an_idle_process_exits_on_its_own_and_is_replaced(fake_core):
    with NodeCoreBridge(script=fake_core, idle_timeout_s=0.5) as bridge:
        first = _pid(bridge.scan("x"))
        popen = _live_popen(bridge)
        assert _wait_until(lambda: popen.poll() is not None)
        assert popen.returncode == 0
        assert _pid(bridge.scan("x")) != first


@needs_node
def test_threads_sharing_one_bridge_are_serialized_on_one_process(fake_core):
    errors: list[BaseException] = []
    pids: set[int] = set()
    lock = threading.Lock()

    with NodeCoreBridge(script=fake_core) as bridge:

        def worker(length: int) -> None:
            try:
                for _ in range(25):
                    outcome = bridge.scan("t" * length)
                    # Each caller gets the findings for its own input.
                    assert [f.end for f in outcome.findings] == [length]
                    with lock:
                        pids.add(_pid(outcome))
            except BaseException as exc:  # noqa: BLE001 - reported below
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n + 1,)) for n in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert errors == []
    assert len(pids) == 1


@needs_node
def test_separate_bridges_use_separate_processes_concurrently(fake_core):
    results: dict[int, set[int]] = {0: set(), 1: set()}
    errors: list[BaseException] = []
    bridges = [NodeCoreBridge(script=fake_core), NodeCoreBridge(script=fake_core)]

    def worker(index: int) -> None:
        try:
            for n in range(20):
                outcome = bridges[index].scan("c" * (index * 100 + n))
                assert [f.end for f in outcome.findings] == [index * 100 + n]
                results[index].add(_pid(outcome))
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in (0, 1)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    for bridge in bridges:
        bridge.close()
    assert errors == []
    assert len(results[0]) == len(results[1]) == 1
    assert results[0] != results[1]


@needs_node
def test_close_kills_and_reaps_the_process_and_refuses_later_scans(fake_core):
    bridge = NodeCoreBridge(script=fake_core)
    pid = _pid(bridge.scan("x"))
    bridge.close()
    assert _gone(pid)
    bridge.close()  # idempotent
    with pytest.raises(VaultServerError) as excinfo:
        bridge.scan("x")
    assert _core_code(excinfo) == "BRIDGE_CLOSED"


@needs_node
def test_context_manager_closes(fake_core):
    with NodeCoreBridge(script=fake_core) as bridge:
        pid = _pid(bridge.scan("x"))
    assert _gone(pid)


@needs_node
def test_garbage_collecting_the_bridge_reaps_the_process(fake_core):
    bridge = NodeCoreBridge(script=fake_core)
    pid = _pid(bridge.scan("x"))
    del bridge
    gc.collect()
    assert _gone(pid)


def test_close_before_any_scan_starts_nothing():
    bridge = NodeCoreBridge(node_executable="node-fake-synthetic")
    bridge.close()
    with pytest.raises(VaultServerError) as excinfo:
        bridge.scan("x")
    assert _core_code(excinfo) == "BRIDGE_CLOSED"


@needs_node
@posix_only
@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_a_forked_child_never_uses_the_parents_process(fake_core):
    with NodeCoreBridge(script=fake_core) as bridge:
        parent_pid = _pid(bridge.scan("x"))
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:  # pragma: no cover - runs in the forked child
            code = 1
            try:
                os.close(read_fd)
                child_bridge_pid = _pid(bridge.scan("child"))
                os.write(write_fd, str(child_bridge_pid).encode())
                bridge.close()
                code = 0
            finally:
                os._exit(code)
        os.close(write_fd)
        with os.fdopen(read_fd, "rb") as reader:
            reported = reader.read()
        _, status = os.waitpid(child, 0)
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
        child_bridge_pid = int(reported)
        assert child_bridge_pid != parent_pid
        assert _gone(child_bridge_pid)
        # The parent's process was neither used nor disturbed by the child.
        assert _pid(bridge.scan("x")) == parent_pid


@needs_node
def test_the_bridge_exits_when_its_stdin_closes(fake_core):
    proc = subprocess.Popen(
        ["node", str(fake_core)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    request = {"id": 1, "input": "x", "pii": [], "nodeModules": str(fake_core.parent / "node_modules")}
    proc.stdin.write(json.dumps(request).encode() + b"\n")
    proc.stdin.flush()
    assert json.loads(proc.stdout.readline())["id"] == 1
    proc.stdin.close()
    assert proc.wait(timeout=10) == 0
    proc.stdout.close()


def _raw_session(script: Path, lines: list[bytes], args: tuple[str, ...] = ()) -> tuple[list[dict], int]:
    proc = subprocess.run(
        ["node", str(script), *args], input=b"".join(lines), capture_output=True, timeout=10, check=False
    )
    return [json.loads(line) for line in proc.stdout.splitlines()], proc.returncode


def _request(script: Path, request_id, **extra) -> bytes:
    body = {"id": request_id, "input": "leak-synthetic", "pii": [], "nodeModules": str(script.parent / "node_modules")}
    body.update(extra)
    return json.dumps(body).encode() + b"\n"


@needs_node
@pytest.mark.parametrize("request_id", [0, 2, "1", None, 1.5])
def test_the_bridge_refuses_an_out_of_sequence_id_and_exits(fake_core, request_id):
    replies, code = _raw_session(fake_core, [_request(fake_core, request_id)])
    assert replies == [{"id": None, "error": {"message": "request.id out of sequence"}}]
    assert code == 1


@needs_node
def test_the_bridge_refuses_a_changed_configuration_and_exits(fake_core):
    proc = subprocess.Popen(["node", str(fake_core)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    proc.stdin.write(_request(fake_core, 1))
    proc.stdin.flush()
    assert "findings" in json.loads(proc.stdout.readline())
    proc.stdin.write(_request(fake_core, 2, pii=["pii"]))
    proc.stdin.flush()
    reply = json.loads(proc.stdout.readline())
    assert reply == {"id": 2, "error": {"message": "request configuration changed"}}
    assert proc.wait(timeout=10) == 1
    proc.stdin.close()
    proc.stdout.close()


@needs_node
@pytest.mark.parametrize(
    "args", [("--idle-exit-ms=0",), ("--idle-exit-ms=x",), ("--other",), ("--idle-exit-ms=99999999999",)]
)
def test_the_bridge_refuses_malformed_arguments(fake_core, args):
    replies, code = _raw_session(fake_core, [_request(fake_core, 1)], args)
    assert replies == [{"id": None, "error": {"message": "invalid bridge arguments"}}]
    assert code == 1


@needs_node
@pytest.mark.parametrize("line", [b"leak-synthetic\n", b"[1]\n", b"null\n"])
def test_the_bridge_refuses_a_malformed_frame_without_echoing_it(fake_core, line):
    replies, code = _raw_session(fake_core, [line])
    assert len(replies) == 1 and replies[0]["id"] is None and set(replies[0]) == {"id", "error"}
    assert "leak-synthetic" not in json.dumps(replies)
    assert code == 1


# -- 2. NodeCoreBridge against a faked bridge process ---------------------------


class _FakePopen:
    """A bridge process whose every response line is scripted by the test."""

    instances: list[_FakePopen] = []
    script: list = []

    def __init__(self, args, **_kwargs) -> None:
        self.args = args
        self.pid = 90000 + len(_FakePopen.instances)
        self.returncode = None
        self.requests: list[dict] = []
        self.stdin = self
        self.stdout = self
        self._pending: list[bytes] = []
        _FakePopen.instances.append(self)

    # stdin
    def write(self, data: bytes) -> int:
        request = json.loads(data)
        self.requests.append(request)
        action = _FakePopen.script.pop(0)
        if callable(action):
            action = action(request)
        if action is not None:
            self._pending.append(action if isinstance(action, bytes) else json.dumps(action).encode() + b"\n")
        return len(data)

    def flush(self) -> None:
        pass

    # stdout
    def readline(self, _limit: int = -1) -> bytes:
        return self._pending.pop(0) if self._pending else b""

    def close(self) -> None:
        pass

    def poll(self):
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


def _ok(request: dict, activation: str | None = ACTIVATION) -> dict:
    return {
        "id": request["id"],
        "findings": [],
        "coreVersion": PINNED_CORE_VERSION,
        "artifact": "fake",
        "piiActivation": activation,
    }


@pytest.fixture
def scripted(monkeypatch):
    _FakePopen.instances = []
    _FakePopen.script = []
    monkeypatch.setattr(core_client_module.subprocess, "Popen", _FakePopen)

    def install(*actions) -> list[_FakePopen]:
        _FakePopen.script = list(actions)
        return _FakePopen.instances

    return install


def _fake_bridge(**kwargs) -> NodeCoreBridge:
    return NodeCoreBridge(node_executable="node-fake-synthetic", **kwargs)


def test_one_scan_per_process_leaves_no_process_between_scans(scripted):
    processes = scripted(_ok, _ok)
    bridge = _fake_bridge(max_scans_per_process=1)
    bridge.scan("x")
    assert bridge._state.proc is None and processes[0].returncode == -9
    bridge.scan("x")
    assert len(processes) == 2


def test_request_ids_count_up_per_process(scripted):
    processes = scripted(_ok, _ok, _ok, _ok)
    bridge = _fake_bridge(max_scans_per_process=3)
    for _ in range(4):
        bridge.scan("x")
    assert [r["id"] for r in processes[0].requests] == [1, 2, 3]
    assert [r["id"] for r in processes[1].requests] == [1]
    assert processes[0].args[-1] == "--idle-exit-ms=60000"


@pytest.mark.parametrize(
    "reply",
    [
        lambda r: {**_ok(r), "id": r["id"] + 1},
        lambda r: {**_ok(r), "id": str(r["id"])},
        lambda r: {**_ok(r), "id": True},
        lambda r: {k: v for k, v in _ok(r).items() if k != "id"},
        lambda r: {"id": None, "error": {"message": "invalid request JSON"}},
        lambda r: {"id": r["id"], "error": {"code": "X"}, "findings": []},
        lambda r: b'{"id": 1, "findings": [' * 2000 + b"\n",
        lambda r: b"\xff\xfe\n",
    ],
)
def test_a_response_for_another_request_or_malformed_frame_fails_closed(scripted, reply):
    processes = scripted(reply, _ok)
    bridge = _fake_bridge()
    with pytest.raises(VaultServerError) as excinfo:
        bridge.scan("x")
    assert _core_code(excinfo) == "BRIDGE_BAD_OUTPUT"
    assert processes[0].returncode == -9
    bridge.scan("x")
    assert len(processes) == 2


def test_a_bridge_error_response_discards_the_process(scripted):
    def error(request):
        return {"id": request["id"], "error": {"message": "core scan failed", "code": "X_SYNTHETIC"}}

    processes = scripted(error, _ok)
    bridge = _fake_bridge()
    with pytest.raises(VaultServerError) as excinfo:
        bridge.scan("x")
    assert _core_code(excinfo) == "X_SYNTHETIC"
    bridge.scan("x")
    assert len(processes) == 2 and processes[0].returncode == -9


@pytest.mark.parametrize(
    "code",
    [
        "leak-synthetic",
        "LEAK synthetic",
        "lower_case",
        "1_STARTS_WITH_A_DIGIT",
        "_STARTS_WITH_UNDERSCORE",
        "A" * 65,
        "TRAILING_NEWLINE\n",
        "E\u00c9",
        "",
        "X" + "\u0000",
        "SECRET=leak-synthetic",
    ],
)
def test_an_error_code_of_the_wrong_shape_is_bad_output_with_a_fixed_message(scripted, code):
    """A code the child reports is passed on only if it matches ``[A-Z][A-Z0-9_]{0,63}``; otherwise the response is
    ``BRIDGE_BAD_OUTPUT`` and nothing the child wrote reaches the exception."""

    def error(request):
        return {"id": request["id"], "error": {"message": "leak-synthetic", "code": code}}

    processes = scripted(error, _ok)
    bridge = _fake_bridge()
    with pytest.raises(VaultServerError) as excinfo:
        bridge.scan("x")
    assert _core_code(excinfo) == "BRIDGE_BAD_OUTPUT"
    shown = f"{excinfo.value!s}{excinfo.value!r}{excinfo.value.args}{excinfo.value.core_code}"
    assert "leak" not in shown.lower() and "synthetic" not in shown.lower() and "\n" not in shown
    assert excinfo.value.__cause__ is None
    assert processes[0].returncode == -9
    bridge.scan("x")


@pytest.mark.parametrize("code", ["A", "X_SYNTHETIC", "PII_SELECTOR_INVALID", "A" + "9" * 63, None])
def test_an_error_code_of_the_right_shape_is_passed_on(scripted, code):
    error_body = {"message": "core scan failed"} if code is None else {"message": "m", "code": code}
    scripted(lambda request: {"id": request["id"], "error": error_body})
    with pytest.raises(VaultServerError) as excinfo:
        _fake_bridge().scan("x")
    assert _core_code(excinfo) == code


_GOOD_FINDING = {
    "id": "finding-1",
    "type": "github_token",
    "detector": "github-token",
    "confidence": "high",
    "obfuscation": "none",
    "start": 0,
    "end": 1,
    "action": "redact",
}


@pytest.mark.parametrize(
    "patch",
    [
        {"id": "leak synthetic"},
        {"id": ""},
        {"id": "f" * 129},
        {"type": "leak\nsynthetic"},
        {"type": "a b"},
        {"type": "\u00e9"},
        {"detector": "x" * 200},
        {"confidence": "leak-synthetic"},
        {"obfuscation": "leak-synthetic"},
        {"action": "leak-synthetic"},
        {"action": "REDACT"},
        {"start": True},
        {"end": 1.0},
    ],
)
def test_a_finding_field_of_the_wrong_shape_is_bad_output(scripted, patch):
    scripted(lambda request: {**_ok(request), "findings": [{**_GOOD_FINDING, **patch}]})
    with pytest.raises(VaultServerError) as excinfo:
        _fake_bridge().scan("x")
    assert _core_code(excinfo) == "BRIDGE_BAD_OUTPUT"
    assert "leak" not in repr(excinfo.value).lower()


def test_a_finding_of_the_expected_shape_is_accepted(scripted):
    second = {**_GOOD_FINDING, "id": "finding-2", "type": "pii_email"}
    scripted(lambda request: {**_ok(request), "findings": [_GOOD_FINDING, second]})
    outcome = _fake_bridge().scan("x")
    assert [f.id for f in outcome.findings] == ["finding-1", "finding-2"]


@pytest.mark.parametrize(
    "patch",
    [
        {"coreVersion": "leak synthetic"},
        {"coreVersion": "9" * 65},
        {"coreVersion": ""},
        {"artifact": "leak synthetic"},
        {"artifact": "Addon"},
        {"artifact": "a" * 33},
        {"artifact": ""},
        {"piiActivation": "leak synthetic"},
        {"piiActivation": "x\ny"},
        {"piiActivation": "\u00e9"},
        {"piiActivation": "a" * 513},
    ],
)
def test_a_version_artifact_or_activation_of_the_wrong_shape_is_bad_output(scripted, patch):
    scripted(lambda request: {**_ok(request), **patch})
    with pytest.raises(VaultServerError) as excinfo:
        _fake_bridge().scan("x")
    assert _core_code(excinfo) == "BRIDGE_BAD_OUTPUT"


def test_a_restarted_process_is_rechecked_against_the_pinned_activation(scripted):
    other = "credentials=full;selectors=pii:global;fake=2"
    processes = scripted(_ok, lambda r: _ok(r, other), lambda r: _ok(r, other))
    bridge = _fake_bridge(max_scans_per_process=1)
    assert bridge.scan("x").pii_activation == ACTIVATION
    with pytest.raises(VaultServerError) as excinfo:
        bridge.scan("x")
    assert excinfo.value.code == VaultServerErrorCode.PII_ACTIVATION_MISMATCH
    with pytest.raises(VaultServerError):
        bridge.scan("x")
    assert len(processes) == 3


def test_a_restarted_process_is_rechecked_against_the_expected_activation(scripted):
    processes = scripted(_ok, lambda r: _ok(r, None))
    bridge = _fake_bridge(max_scans_per_process=1, expected_pii_activation=ACTIVATION)
    bridge.scan("x")
    with pytest.raises(VaultServerError) as excinfo:
        bridge.scan("x")
    assert excinfo.value.code == VaultServerErrorCode.PII_UNAVAILABLE
    assert len(processes) == 2


def test_eof_mid_request_is_process_failed(scripted):
    processes = scripted(None, _ok)
    bridge = _fake_bridge()
    with pytest.raises(VaultServerError) as excinfo:
        bridge.scan("x")
    assert _core_code(excinfo) == "BRIDGE_PROCESS_FAILED"
    bridge.scan("x")
    assert len(processes) == 2


def test_a_partial_line_before_eof_is_process_failed(scripted):
    scripted(lambda r: b'{"id": 1, "find')
    with pytest.raises(VaultServerError) as excinfo:
        _fake_bridge().scan("x")
    assert _core_code(excinfo) == "BRIDGE_PROCESS_FAILED"


def test_an_interrupted_request_discards_the_process(scripted):
    def interrupt(_request):
        raise KeyboardInterrupt

    processes = scripted(interrupt, _ok)
    bridge = _fake_bridge()
    with pytest.raises(KeyboardInterrupt):
        bridge.scan("x")
    assert processes[0].returncode == -9
    bridge.scan("x")
    assert len(processes) == 2


def test_a_broken_pipe_is_process_failed(scripted):
    def broken(_request):
        raise BrokenPipeError

    scripted(broken)
    with pytest.raises(VaultServerError) as excinfo:
        _fake_bridge().scan("x")
    assert _core_code(excinfo) == "BRIDGE_PROCESS_FAILED"


def test_a_process_that_cannot_start_is_spawn_failed(tmp_path):
    bridge = NodeCoreBridge(node_executable=str(tmp_path / "missing-node-synthetic"))
    with pytest.raises(VaultServerError) as excinfo:
        bridge.scan("leak-synthetic")
    assert _core_code(excinfo) == "BRIDGE_SPAWN_FAILED"
    assert "leak-synthetic" not in str(excinfo.value)


def test_an_unserializable_policy_is_invalid_argument(scripted):
    processes = scripted()
    with pytest.raises(VaultServerError) as excinfo:
        _fake_bridge().scan("x", policy={"github_token": object()})
    assert excinfo.value.code == VaultServerErrorCode.INVALID_ARGUMENT
    with pytest.raises(VaultServerError) as excinfo:
        _fake_bridge().scan("x", limits={"maxInputBytes": float("nan")})
    assert excinfo.value.code == VaultServerErrorCode.INVALID_ARGUMENT
    assert processes == []


def test_non_ascii_and_lone_surrogates_are_escaped_on_one_line(scripted):
    processes = scripted(_ok)
    _fake_bridge().scan("café \ud800 line\nbreak  ")
    assert processes[0].requests[0]["input"] == "café \ud800 line\nbreak  "


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout_s": 0},
        {"timeout_s": -1},
        {"timeout_s": float("nan")},
        {"timeout_s": float("inf")},
        {"timeout_s": True},
        {"timeout_s": "10"},
        {"max_scans_per_process": 0},
        {"max_scans_per_process": 1.5},
        {"max_scans_per_process": True},
        {"max_process_age_s": 0},
        {"idle_timeout_s": 0},
        {"idle_timeout_s": 24 * 60 * 60 + 1},
    ],
)
def test_malformed_lifetime_settings_are_invalid_argument(kwargs):
    with pytest.raises(VaultServerError) as excinfo:
        _fake_bridge(**kwargs)
    assert excinfo.value.code == VaultServerErrorCode.INVALID_ARGUMENT


def test_watchdog_kills_only_while_armed():
    watchdog = core_client_module._Watchdog()

    class Target:
        killed = 0

        def kill(self):
            Target.killed += 1

    target = Target()
    watchdog.arm(target, 10.0)
    assert watchdog.disarm() is False
    watchdog.arm(target, 0.05)
    assert _wait_until(lambda: Target.killed == 1, 2.0)
    assert watchdog.disarm() is True
    time.sleep(0.1)
    assert Target.killed == 1
    watchdog.stop()


# -- 3. The real bridge against the installed core ------------------------------

REPO_NODE_MODULES = Path(__file__).resolve().parents[3] / "node_modules"
TOKEN = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000"

needs_real_core = pytest.mark.skipif(
    shutil.which("node") is None or not (REPO_NODE_MODULES / "@redact-secret" / "core").is_dir(),
    reason="needs node and @redact-secret/core installed at the repository root (npm ci)",
)


@needs_real_core
def test_real_core_reuses_one_process_across_scans():
    with NodeCoreBridge() as bridge:
        pid = None
        for n in range(20):
            outcome = bridge.scan(" " * n + TOKEN)
            assert [(f.type, f.start, f.id) for f in outcome.findings] == [("github_token", n, "finding-1")]
            current = _live_popen(bridge).pid
            assert pid in (None, current)
            pid = current


@needs_real_core
def test_real_core_concurrent_callers_get_their_own_findings():
    errors: list[BaseException] = []
    with NodeCoreBridge() as bridge:

        def worker(offset: int) -> None:
            try:
                for _ in range(10):
                    outcome = bridge.scan("p" * offset + " " + TOKEN)
                    assert [f.start for f in outcome.findings] == [offset + 1]
            except BaseException as exc:  # noqa: BLE001 - reported below
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i * 7,)) for i in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert errors == []


@needs_real_core
def test_real_core_error_then_recovery_keeps_scanning():
    with NodeCoreBridge() as bridge:
        bridge.scan(TOKEN)
        first = _live_popen(bridge).pid
        with pytest.raises(VaultServerError) as excinfo:
            bridge.scan(TOKEN, limits={"maxInputBytes": 4, "maxFindings": 10})
        assert _core_code(excinfo) == "INPUT_LIMIT_EXCEEDED"
        assert bridge.scan(TOKEN).findings[0].start == 0
        assert _live_popen(bridge).pid != first
