"""Bridge qualification harness for the persistent profile (docs/plans/python-persistence-parity.md section 6.2, gate
G5, and the three gaps that docs/decisions/limit-python-persistence-claim-to-a-supplied-core-client.md names).

Not part of the wheel. A command-line tool and a library for ``test_bridge_qualification.py``. It runs the real
``boundary/core_bridge.mjs`` over the real ``@redact-secret/core`` and reports numbers, one line per result:

    RESULT <id> <MET|NOT-MET|INFO> <what> | <numbers>

Sections (``--section``): ``protocol`` (adversarial frames, raw), ``fuzz`` (seeded frame fuzzing of the child's parser
and of the client's parser), ``lifetime`` (process bounds), ``heap`` (plaintext left in the child's memory),
``timeouts``, ``concurrency``, ``limits`` (input sizes, memory), ``failclosed`` (hostile or replaced cores).

Every value is synthetic. A "secret" below is a ``ghp_SYNTHETIC...`` string the core detects; a "plaintext marker" is
a free-text string the core does not detect. Nothing prints an input, a frame, or a child's output: results are
counts, durations, and identifiers of the cases.

    python tests/bridge_qualification.py --section protocol --section fuzz --fuzz-cases 2000 --seed 1
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent / "src"))

from redact_secret_vault import NodeCoreBridge, VaultServerError  # noqa: E402
from redact_secret_vault.core_client import (  # noqa: E402
    DEFAULT_BRIDGE_SCRIPT,
    DEFAULT_IDLE_TIMEOUT_S,
    DEFAULT_MAX_PROCESS_AGE_S,
    DEFAULT_MAX_SCANS_PER_PROCESS,
    MAX_REQUEST_FRAME_BYTES,
    MAX_RESPONSE_FRAME_BYTES,
    PINNED_CORE_VERSION,
)

NODE = shutil.which("node") or "node"
SCRIPT = str(DEFAULT_BRIDGE_SCRIPT)
PLAINTEXT_MARKER = "SYNTHETIC-PLAINTEXT-MARKER-NOT-DETECTED-4471"
LIMITS = {"maxInputBytes": 1 << 26, "maxFindings": 50_000}
#: How long a case may take before it counts as a hang. Generous: a loaded host starts Node.js slowly.
CASE_TIMEOUT_S = float(os.environ.get("RSV_BRIDGE_QUAL_TIMEOUT_S", "30"))


def secret(index: int) -> str:
    return f"ghp_SYNTHETICxREVOKEDxTESTx{index:013d}"


@dataclass
class Result:
    ident: str
    verdict: str  # MET, NOT-MET, INFO
    what: str
    numbers: str = ""

    def line(self) -> str:
        return f"RESULT {self.ident} {self.verdict} {self.what} | {self.numbers}"


@dataclass
class Report:
    results: list[Result] = field(default_factory=list)

    def add(self, ident: str, ok: bool | None, what: str, numbers: str = "") -> None:
        verdict = "INFO" if ok is None else ("MET" if ok else "NOT-MET")
        result = Result(ident, verdict, what, numbers)
        self.results.append(result)
        print(result.line(), flush=True)

    def failed(self) -> list[Result]:
        return [r for r in self.results if r.verdict == "NOT-MET"]


# ------------------------------------------------------------------------------------------------ raw child


class Raw:
    """The child process driven directly: the harness is the bridge's owner and reads stdout and stderr itself."""

    def __init__(self, args: tuple[str, ...] = (), *, script: str = SCRIPT, node: str = NODE) -> None:
        self.p = subprocess.Popen(
            [node, script, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0
        )
        self.out = bytearray()
        self.err = bytearray()
        self._cond = threading.Condition()
        self._threads = [
            threading.Thread(target=self._pump, args=(self.p.stdout, self.out), daemon=True),
            threading.Thread(target=self._pump, args=(self.p.stderr, self.err), daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    def _pump(self, stream: Any, sink: bytearray) -> None:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            with self._cond:
                sink.extend(chunk)
                self._cond.notify_all()
        with self._cond:
            self._cond.notify_all()

    def send(self, data: bytes, *, chunk: int | None = None) -> bool:
        try:
            assert self.p.stdin is not None
            if chunk is None:
                self.p.stdin.write(data)
            else:
                for index in range(0, len(data), chunk):
                    self.p.stdin.write(data[index : index + chunk])
            return True
        except (BrokenPipeError, OSError, ValueError):
            return False

    def close_stdin(self) -> None:
        try:
            assert self.p.stdin is not None
            self.p.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            pass

    def wait_lines(self, count: int, timeout: float) -> list[bytes]:
        deadline = time.monotonic() + timeout
        with self._cond:
            while self.out.count(b"\n") < count and self.p.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._cond.wait(remaining)
        if self.p.poll() is not None:
            # The child exited: the reader threads may not have appended its last chunk yet.
            for thread in self._threads:
                thread.join(5)
        with self._cond:
            return bytes(self.out).split(b"\n")[:count] if self.out.count(b"\n") >= count else []

    def finish(self, timeout: float = 8.0) -> tuple[int | None, bytes, bytes, bool]:
        """Closes stdin, waits for the exit, and kills a child that does not. Returns code, out, err, hung."""

        self.close_stdin()
        hung = False
        try:
            self.p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            hung = True
            self.p.kill()
            self.p.wait()
        for thread in self._threads:
            thread.join(2)
        return self.p.returncode, bytes(self.out), bytes(self.err), hung


def frame(id_: Any, text: Any = "x", pii: Any = (), **extra: Any) -> bytes:
    body: dict[str, Any] = {"id": id_, "input": text, "pii": list(pii) if isinstance(pii, tuple) else pii}
    body.update(extra)
    return json.dumps(body, separators=(",", ":")).encode("ascii") + b"\n"


def inspect_output(out: bytes, err: bytes, needles: tuple[bytes, ...]) -> list[str]:
    """Violations of what the protocol allows the child to write. Never returns the text it inspected."""

    problems: list[str] = []
    if err:
        problems.append(f"stderr not empty ({len(err)} bytes)")
    for needle in needles:
        if needle and (needle in out or needle in err):
            problems.append("a planted marker reached the child's output")
    if out and not out.endswith(b"\n"):
        problems.append("stdout ends without a newline")
    for raw in out.split(b"\n")[:-1] if out else []:
        try:
            data = json.loads(raw)
        except ValueError:
            problems.append("a stdout line is not JSON")
            continue
        if type(data) is not dict or "id" not in data:
            problems.append("a stdout frame has no id")
            continue
        keys = set(data) - {"id"}
        if keys not in ({"findings", "coreVersion", "artifact", "piiActivation", "integrity"}, {"error"}):
            problems.append("a stdout frame has unexpected keys")
        if "error" in data and (type(data["error"]) is not dict or set(data["error"]) - {"message", "code"}):
            problems.append("an error frame has unexpected keys")
    return problems


# ------------------------------------------------------------------------------------------------ protocol


def _fake_core(root: Path, *, manifest: dict[str, Any] | None = None, source: str | None = None) -> str:
    package = root / "node_modules" / "@redact-secret" / "core"
    package.mkdir(parents=True)
    (package / "package.json").write_text(
        json.dumps(
            manifest
            or {"name": "@redact-secret/core", "version": PINNED_CORE_VERSION, "type": "module", "main": "index.js"}
        )
    )
    (package / "index.js").write_text(
        source
        or f"""export const VERSION = {json.dumps(PINNED_CORE_VERSION)};
export async function initialize() {{}}
export function scan() {{ return []; }}
export function artifact() {{ return {{ kind: "synthetic" }}; }}
"""
    )
    return str(root / "node_modules")


@dataclass
class Case:
    name: str
    frames: list[bytes]
    expect: str  # "success" | "error" | "silent" (no frame, clean exit) | "either"
    args: tuple[str, ...] = ()
    chunk: int | None = None
    needles: tuple[bytes, ...] = ()
    frames_expected: int | None = None


def run_case(case: Case, *, timeout: float = CASE_TIMEOUT_S) -> list[str]:
    child = Raw(case.args)
    problems: list[str] = []
    started = time.monotonic()
    for data in case.frames:
        if not child.send(data, chunk=case.chunk):
            break
    want = case.frames_expected if case.frames_expected is not None else (0 if case.expect == "silent" else 1)
    lines = child.wait_lines(want, timeout) if want else []
    code, out, err, hung = child.finish(timeout=timeout)
    elapsed = time.monotonic() - started
    if hung:
        problems.append("the child did not exit")
    problems += inspect_output(out, err, case.needles)
    frames = [json.loads(x) for x in out.split(b"\n")[:-1]] if not problems else []
    got_error = any("error" in f for f in frames)
    got_success = any("findings" in f for f in frames)
    if case.expect == "success" and not got_success:
        problems.append("expected a success frame")
    if case.expect == "error":
        if not got_error:
            problems.append("expected an error frame")
        if code != 1:
            problems.append(f"expected exit code 1 after an error, got {code}")
    if case.expect == "silent" and out:
        problems.append("expected no frame")
    if case.expect == "silent" and code != 0:
        problems.append(f"expected exit code 0, got {code}")
    if got_error and len(lines) == 0 and want:
        problems.append("no response line arrived in time")
    if elapsed > timeout:
        problems.append("slow")
    return problems


def protocol_cases(workdir: Path) -> list[Case]:
    needle = PLAINTEXT_MARKER.encode()
    ok = frame(1, f"a {secret(1)} b {PLAINTEXT_MARKER}")
    huge_sel = ["s" * 129]
    cases: list[Case] = [
        Case("valid request", [ok], "success", needles=(needle,)),
        Case("valid request, one byte per write", [ok], "success", chunk=1, needles=(needle,)),
        Case("two requests in one write", [ok + frame(2, "y")], "success", frames_expected=2, needles=(needle,)),
        Case("CRLF line ending", [ok[:-1] + b"\r\n"], "success", needles=(needle,)),
        Case("blank line", [b"\n"], "error"),
        Case("not JSON", [b"not json " + needle + b"\n"], "error", needles=(needle,)),
        Case("truncated JSON", [ok[: len(ok) // 2] + b"\n"], "error", needles=(needle,)),
        Case("trailing garbage after the object", [ok[:-1] + b" garbage\n"], "error", needles=(needle,)),
        Case("array instead of object", [b"[1,2,3]\n"], "error"),
        Case("string instead of object", [b'"' + needle + b'"\n'], "error", needles=(needle,)),
        Case("null", [b"null\n"], "error"),
        Case("number", [b"1\n"], "error"),
        Case("deep nesting (100000 levels)", [b"[" * 100_000 + b"]" * 100_000 + b"\n"], "error"),
        Case("id 0", [frame(0, "x")], "error"),
        Case("id 2 first", [frame(2, "x")], "error"),
        Case("id as string", [frame("1", "x")], "error"),
        Case("id negative", [frame(-1, "x")], "error"),
        Case("id null", [frame(None, "x")], "error"),
        Case("id missing", [b'{"input":"x","pii":[]}\n'], "error"),
        Case("id repeated", [frame(1, "x") + frame(1, "y")], "either", frames_expected=2),
        # The core integrity pins (the "integrity" field of the first request): a malformed one is refused as a
        # request error before the core is touched, and a wrong one is refused as CORE_INTEGRITY_MISMATCH.
        Case("integrity null", [frame(1, "x", integrity=None)], "error"),
        Case("integrity an array", [frame(1, "x", integrity=[])], "error"),
        Case("integrity a string", [frame(1, "x", integrity=needle.decode())], "error", needles=(needle,)),
        Case("integrity an empty object", [frame(1, "x", integrity={})], "error"),
        Case("integrity name outside the scope", [frame(1, "x", integrity={"evil/pkg": "0" * 64})], "error"),
        Case(
            "integrity name carrying a marker",
            [frame(1, "x", integrity={"@redact-secret/" + PLAINTEXT_MARKER: "0" * 64})],
            "error",
            needles=(needle,),
        ),
        Case("integrity digest in upper case", [frame(1, "x", integrity={"@redact-secret/core": "A" * 64})], "error"),
        Case("integrity digest of 63 characters", [frame(1, "x", integrity={"@redact-secret/core": "0" * 63})], "error"),
        Case("integrity digest a number", [frame(1, "x", integrity={"@redact-secret/core": 7})], "error"),
        Case(
            "integrity with 33 packages",
            [frame(1, "x", integrity={f"@redact-secret/p{i}": "0" * 64 for i in range(33)})],
            "error",
        ),
        Case(
            "integrity pins that do not match the installed core",
            [frame(1, "x", integrity={"@redact-secret/core": "0" * 64, "@redact-secret/wasm": "1" * 64})],
            "error",
            needles=(needle,),
        ),
        Case(
            "integrity pinning the core only (no WebAssembly package)",
            [frame(1, "x", integrity={"@redact-secret/core": "0" * 64})],
            "error",
        ),
        Case(
            "integrity repeated on a second request",
            [ok, frame(2, "y", integrity={"@redact-secret/core": "0" * 64, "@redact-secret/wasm": "1" * 64})],
            "either",
            frames_expected=2,
            needles=(needle,),
        ),
        Case("id fractional", [b'{"id":1.5,"input":"x","pii":[]}\n'], "error"),
        Case("id huge", [b'{"id":1e999,"input":"x","pii":[]}\n'], "error"),
        Case("input missing", [b'{"id":1,"pii":[]}\n'], "error"),
        Case("input null", [frame(1, None)], "error"),
        Case("input number", [frame(1, 7)], "error"),
        Case("input object", [frame(1, {"a": needle.decode()})], "error", needles=(needle,)),
        Case("input array", [frame(1, [needle.decode()])], "error", needles=(needle,)),
        Case("pii missing", [b'{"id":1,"input":"x"}\n'], "error"),
        Case("pii string", [frame(1, "x", pii=needle.decode())], "error", needles=(needle,)),
        Case("pii holds a number", [frame(1, "x", pii=[1])], "error"),
        Case("pii holds an empty string", [frame(1, "x", pii=[""])], "error"),
        Case("pii selector over 128 characters", [frame(1, "x", pii=huge_sel)], "error"),
        Case("pii with 65 selectors", [frame(1, "x", pii=["pii"] * 65)], "error"),
        Case("pii selector the core rejects", [frame(1, "x", pii=[needle.decode()])], "error", needles=(needle,)),
        Case("nodeModules a number", [frame(1, "x", nodeModules=7)], "error"),
        Case("nodeModules relative", [frame(1, "x", nodeModules="node_modules")], "error"),
        Case("nodeModules empty", [frame(1, "x", nodeModules="")], "error"),
        Case("nodeModules with a NUL", [frame(1, "x", nodeModules="/tmp/\u0000x")], "error"),
        Case("nodeModules over 4096 characters", [frame(1, "x", nodeModules="/" + "a" * 5000)], "error"),
        Case(
            "nodeModules without the core (path carries a marker)",
            [frame(1, "x", nodeModules=f"/nonexistent/{PLAINTEXT_MARKER}")],
            "error",
            needles=(needle,),
        ),
        Case("policy an array", [frame(1, "x", policy=[needle.decode()])], "either", needles=(needle,)),
        Case(
            "policy with an unknown action",
            [frame(1, secret(2), policy={"default": needle.decode()})],
            "error",
            needles=(needle,),
        ),
        Case(
            "policy with a prototype key",
            [frame(1, secret(2), policy={"__proto__": "block", "constructor": "block"})],
            "either",
        ),
        Case("limits negative", [frame(1, "x", limits={"maxInputBytes": -1, "maxFindings": -1})], "either"),
        Case("limits a string", [frame(1, "x", limits=needle.decode())], "either", needles=(needle,)),
        Case(
            "limits smaller than the input",
            [frame(1, secret(3) * 20, limits={"maxInputBytes": 8, "maxFindings": 1})],
            "error",
        ),
        Case(
            "limits fewer findings than present",
            [frame(1, (secret(4) + " ") * 5, limits={"maxInputBytes": 1 << 20, "maxFindings": 1})],
            "error",
        ),
        Case("__proto__ key in the request", [b'{"__proto__":{"input":"p"},"id":1,"input":"x","pii":[]}\n'], "success"),
        Case("duplicate keys", [b'{"id":1,"input":"x","input":"y","pii":[]}\n'], "success"),
        Case(
            "raw UTF-8 split across writes", ['{"id":1,"input":"é€\U0001f600","pii":[]}\n'.encode()], "success", chunk=1
        ),
        Case("invalid UTF-8 bytes in the input", [b'{"id":1,"input":"\xff\xfe\xc3","pii":[]}\n'], "success"),
        Case("NUL and control characters in the input", [frame(1, "a\u0000b\u0001c d e")], "success"),
        Case("lone surrogate escape (the core refuses it)", [b'{"id":1,"input":"\\ud800 tail","pii":[]}\n'], "error"),
        Case("EOF in the middle of a frame", [ok[:20]], "silent"),
        Case("EOF with no input", [], "silent"),
        Case("config changed: pii", [frame(1, "x", pii=[]) + frame(2, "x", pii=["pii"])], "success", frames_expected=2),
        Case("unknown argument", [], "error", args=("--bogus",)),
        Case("idle flag zero", [], "error", args=("--idle-exit-ms=0",)),
        Case("idle flag not a number", [], "error", args=("--idle-exit-ms=abc",)),
        Case("idle flag over a day", [], "error", args=("--idle-exit-ms=999999999",)),
        Case("idle flag twice", [], "error", args=("--idle-exit-ms=100", "--idle-exit-ms=200")),
    ]
    # The core location cases need directories.
    wrong = workdir / "wrong-name"
    nm = _fake_core(wrong, manifest={"name": "not-the-core", "version": "1.0.0", "main": "index.js"})
    cases.append(Case("nodeModules holds another package", [frame(1, "x", nodeModules=nm)], "error"))
    escape = workdir / "escape"
    nm = _fake_core(
        escape, manifest={"name": "@redact-secret/core", "version": "1", "exports": "../../../../outside.js"}
    )
    cases.append(Case("package entry that leaves the package directory", [frame(1, "x", nodeModules=nm)], "error"))
    broken = workdir / "broken"
    nm = _fake_core(broken, source="throw new Error('SYNTHETIC-LOAD-FAILURE-MARKER');")
    cases.append(
        Case(
            "core that throws on load (message carries a marker)",
            [frame(1, "x", nodeModules=nm)],
            "error",
            needles=(b"SYNTHETIC-LOAD-FAILURE-MARKER",),
        )
    )
    throws = workdir / "throws"
    nm = _fake_core(
        throws,
        source=f"""export const VERSION = {json.dumps(PINNED_CORE_VERSION)};
export async function initialize() {{}}
export function scan(text) {{ const e = new Error("scan failed for " + text); e.code = "SYNTHETIC_CODE"; throw e; }}
export function artifact() {{ return {{ kind: "synthetic" }}; }}
""",
    )
    cases.append(
        Case(
            "core that throws on scan with the input in its message",
            [frame(1, f"input {PLAINTEXT_MARKER}", nodeModules=nm)],
            "error",
            needles=(needle,),
        )
    )
    return cases


def run_protocol(report: Report, workdir: Path, *, heavy: bool) -> None:
    cases = protocol_cases(workdir)
    failures: list[str] = []
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=4) as pool:
        for case, problems in zip(cases, pool.map(run_case, cases), strict=True):
            if problems:
                failures.append(f"{case.name}: {'; '.join(problems)}")
    report.add(
        "G5.protocol",
        not failures,
        "adversarial frames against the real child (expected outcome, exit code, empty stderr, no echo, bounded exit)",
        f"{len(cases)} cases, {len(failures)} violations, {time.monotonic() - started:.1f} s"
        + ("".join(f"; VIOLATION {f}" for f in failures)),
    )
    if heavy:
        child = Raw()
        started = time.monotonic()
        chunk = b"a" * (1 << 20)
        total = 0
        limit = MAX_REQUEST_FRAME_BYTES + 1024
        while total < limit and child.send(chunk):
            total += len(chunk)
        code, out, err, hung = child.finish()
        problems = inspect_output(out, err, ())
        got = b"BRIDGE_REQUEST_TOO_LARGE" in out
        report.add(
            "G5.oversized-request",
            got and code == 1 and not hung and not problems,
            "a request line past the frame ceiling is refused by the child itself, with no newline ever sent",
            f"sent {total >> 20} MiB, exit {code}, hung={hung}, {time.monotonic() - started:.1f} s",
        )


# ------------------------------------------------------------------------------------------------ fuzzing


def _json_pool(rng: random.Random) -> Any:
    return rng.choice(
        [
            None,
            True,
            False,
            0,
            -1,
            2**53,
            1.5,
            1e308,
            "",
            "x" * 300,
            "\u0000",
            [],
            {},
            [1, "a"],
            {"a": {"b": []}},
            "A" * 5000,
            [[[[[[]]]]]],
            "pii",
            ["pii"],
        ]
    )


def mutate_frame(rng: random.Random, base: bytes) -> bytes:
    """One mutation of a request line, byte level or JSON level. Always ends in a newline."""

    kind = rng.randrange(8)
    body = base.rstrip(b"\n")
    if kind == 0 and body:
        raw = bytearray(body)
        for _ in range(rng.randint(1, 6)):
            raw[rng.randrange(len(raw))] = rng.randrange(256) if rng.random() < 0.7 else rng.choice(b'{}[]",:\\')
        return bytes(raw).replace(b"\n", b" ") + b"\n"
    if kind == 1 and body:
        return body[: rng.randrange(len(body))] + b"\n"
    if kind == 2:
        position = rng.randrange(len(body) + 1)
        return (
            body[:position] + bytes(rng.randrange(256) for _ in range(rng.randint(1, 30))) + body[position:]
        ).replace(b"\n", b" ") + b"\n"
    if kind == 3 and body:
        start = rng.randrange(len(body))
        end = rng.randrange(start, len(body)) + 1
        return body[:end] + body[start:] + b"\n"
    if kind == 4:
        return bytes(rng.randrange(256) for _ in range(rng.randint(0, 200))).replace(b"\n", b"?") + b"\n"
    try:
        data = json.loads(body)
    except ValueError:
        return body + b"\n"
    if kind == 5 and isinstance(data, dict) and data:
        data[rng.choice(list(data))] = _json_pool(rng)
    elif kind == 6 and isinstance(data, dict) and data:
        del data[rng.choice(list(data))]
    elif isinstance(data, dict):
        data[rng.choice(["__proto__", "constructor", "policy", "limits", "nodeModules", "x", "id"])] = _json_pool(rng)
    return json.dumps(data, separators=(",", ":")).encode("ascii", "backslashreplace") + b"\n"


def fuzz_case(seed: int) -> list[str]:
    rng = random.Random(seed)
    needle = PLAINTEXT_MARKER.encode()
    first = frame(1, f"a {secret(seed % 1000)} b {PLAINTEXT_MARKER}", policy={"default": "redact"}, limits=LIMITS)
    frames: list[bytes] = []
    next_id = 1
    for index in range(rng.randint(1, 3)):
        base = frame(next_id, f"a {secret(index)} b {PLAINTEXT_MARKER}") if index else first
        frames.append(mutate_frame(rng, base) if rng.random() < 0.85 else base)
        next_id += 1
    chunk = rng.choice([None, None, 1, 7, 64, 4096])
    child = Raw(rng.choice([(), (), ("--idle-exit-ms=3000",)]))
    for data in frames:
        if not child.send(data, chunk=chunk):
            break
    time.sleep(rng.random() * 0.05)
    code, out, err, hung = child.finish(timeout=max(15.0, CASE_TIMEOUT_S))
    problems = inspect_output(out, err, (needle,))
    if hung:
        problems.append("the child did not exit after stdin closed")
    if code not in (0, 1):
        problems.append(f"unexpected exit code {code}")
    return problems


def run_fuzz(report: Report, *, cases: int, seed: int, parser_cases: int) -> None:
    started = time.monotonic()
    violations: list[str] = []
    with ThreadPoolExecutor(max_workers=6) as pool:
        for index, problems in enumerate(pool.map(fuzz_case, range(seed, seed + cases))):
            if problems:
                violations.append(f"seed {seed + index}: {'; '.join(problems)}")
    report.add(
        "G5.fuzz-child",
        not violations,
        "seeded fuzzing of the child's frame parser (bit flips, truncation, insertion, JSON value swaps, chunking)",
        f"{cases} cases from seed {seed}, {len(violations)} violations, {time.monotonic() - started:.1f} s"
        + "".join(f"; VIOLATION {v}" for v in violations[:10]),
    )
    started = time.monotonic()
    bridge = NodeCoreBridge(node_executable=NODE)
    base_finding = {
        "id": "finding-1", "type": "github_token", "detector": "d", "confidence": "high",
        "obfuscation": "none", "start": 0, "end": 5, "action": "redact",
    }  # fmt: skip
    base = (
        json.dumps(
            {
                "id": 1,
                "findings": [base_finding, base_finding],
                "coreVersion": PINNED_CORE_VERSION,
                "artifact": "wasm",
                "piiActivation": None,
                "integrity": None,
            },
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    rng = random.Random(seed)
    outcomes: dict[str, int] = {}
    bad: list[str] = []
    for index in range(parser_cases):
        line = mutate_frame(rng, base)
        try:
            outcome = bridge._parse(line, 1)  # noqa: SLF001 - the parser under test
            for finding in outcome.findings:
                assert type(finding.start) is int and type(finding.end) is int
            key = "accepted"
        except VaultServerError as error:
            key = f"refused:{error.code.value}"
        except BaseException as error:  # noqa: BLE001
            key = f"ESCAPED:{type(error).__name__}"
            bad.append(f"case {index}: {type(error).__name__}")
        outcomes[key] = outcomes.get(key, 0) + 1
    report.add(
        "G5.fuzz-client",
        not bad,
        "fuzzing of the client's response parser: only a typed refusal or a well-formed outcome may leave it",
        f"{parser_cases} cases, outcomes {json.dumps(outcomes, sort_keys=True)}, {len(bad)} escaped exceptions, {time.monotonic() - started:.1f} s"
        + "".join(f"; VIOLATION {b}" for b in bad[:5]),
    )
    run_fuzz_strings(report, seed=seed, cases=max(1000, parser_cases // 5))


_HOSTILE_STRINGS = (
    PLAINTEXT_MARKER,
    PLAINTEXT_MARKER + "\n",
    PLAINTEXT_MARKER.replace("-", " "),
    f"input {PLAINTEXT_MARKER}",
    f"SECRET={PLAINTEXT_MARKER}",
    PLAINTEXT_MARKER.lower(),
    "A" * 65,
    "a" * 4096,
    "é" * 8 + PLAINTEXT_MARKER,
    "",
    "\x00" + PLAINTEXT_MARKER,
    "\ud800" + PLAINTEXT_MARKER,
)


def _string_slots(frame: dict[str, Any]) -> list[Callable[[Any], None]]:
    """A setter for every string a response can carry."""
    slots: list[Callable[[Any], None]] = []

    def at(container: dict[str, Any], key: str) -> None:
        if isinstance(container[key], str):
            slots.append(lambda value, c=container, k=key: c.__setitem__(k, value))

    for key in list(frame):
        if key != "id":
            at(frame, key)
    if isinstance(frame.get("error"), dict):
        for key in list(frame["error"]):
            at(frame["error"], key)
    for finding in frame.get("findings") or []:
        for key in list(finding):
            at(finding, key)
    return slots


def run_fuzz_strings(report: Report, *, seed: int, cases: int) -> None:
    """Every string field of a response replaced by hostile text: a refusal must carry none of it. A string that
    passes its field's shape (a short token of the allowed alphabet) is accepted and counted, not hidden: the shapes
    bound what can come through, they do not prove that a short token is not a secret."""
    started = time.monotonic()
    bridge = NodeCoreBridge(node_executable=NODE)
    rng = random.Random(seed ^ 0x5EED)
    finding = {
        "id": "finding-1", "type": "github_token", "detector": "d", "confidence": "high",
        "obfuscation": "none", "start": 0, "end": 5, "action": "redact",
    }  # fmt: skip
    success = {
        "id": 1,
        "findings": [finding],
        "coreVersion": PINNED_CORE_VERSION,
        "artifact": "wasm",
        "piiActivation": None,
        "integrity": None,
    }
    failure = {"id": 1, "error": {"message": "core scan failed", "code": "CORE_ERROR"}}
    refused = accepted = carried = 0
    bad: list[str] = []
    needle = PLAINTEXT_MARKER.lower()
    for index in range(cases):
        frame = json.loads(json.dumps(rng.choice((success, failure))))
        slots = _string_slots(frame)
        for setter in rng.sample(slots, k=1 if rng.random() < 0.7 else rng.randint(1, len(slots))):
            setter(rng.choice(_HOSTILE_STRINGS))
        try:
            line = json.dumps(frame, separators=(",", ":")).encode("utf-8", "surrogatepass") + b"\n"
        except (TypeError, ValueError):
            continue
        try:
            outcome = bridge._parse(line, 1)  # noqa: SLF001
            accepted += 1
            if needle in repr(outcome).lower():
                carried += 1
        except VaultServerError as error:
            refused += 1
            shown = f"{error!s} {error!r} {error.args} {error.core_code} {error.__cause__!r} {error.__context__!r}"
            if needle in shown.lower() or "\n" in shown:
                bad.append(f"case {index}")
        except BaseException as error:  # noqa: BLE001
            bad.append(f"case {index}: {type(error).__name__}")
    report.add(
        "G5.fuzz-client-strings",
        not bad,
        "every string field of a response replaced by hostile text: no refusal carries any of it, and only a typed error leaves the parser",
        f"{cases} cases from seed {seed}, {refused} refused, {accepted} accepted, {carried} accepted with the marker inside a field whose alphabet allows it (a bounded token, not free text), {len(bad)} violations, {time.monotonic() - started:.1f} s"
        + "".join(f"; VIOLATION {b}" for b in bad[:5]),
    )


# ------------------------------------------------------------------------------------------------ lifetime


def _pid(bridge: NodeCoreBridge) -> int | None:
    proc = bridge._state.proc  # noqa: SLF001
    return None if proc is None else proc.popen.pid


def _alive(pid: int) -> bool:
    """Whether the process still runs. A zombie (exited, not yet reaped by its parent) does not: an orphan of a killed
    owner is reparented to the init process of the host or container, and a container whose first process does not reap
    leaves it a zombie, which is a property of that container and not of the child."""

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as stat:
            return stat.read().rpartition(")")[2].split()[0] != "Z"
    except OSError:
        return True


def _scan(bridge: NodeCoreBridge, text: str) -> int:
    return len(bridge.scan(text, policy=None, limits=LIMITS).findings)


def run_lifetime(report: Report) -> None:
    # One process per scan.
    with NodeCoreBridge(max_scans_per_process=1) as bridge:
        pids = []
        for index in range(20):
            assert _scan(bridge, f"x {secret(index)}") == 1
            pids.append(_pid(bridge))
        later = [p for p in pids if p is not None]
    report.add(
        "G5.lifetime.one-per-scan",
        all(p is None for p in pids),
        "max_scans_per_process=1 retires the child inside the call that served the scan",
        f"20 scans, children still referenced after a scan: {sum(p is not None for p in pids)}, earlier pids alive after close: {sum(_alive(p) for p in later)}",
    )
    # Retired at the scan budget.
    with NodeCoreBridge(max_scans_per_process=7) as bridge:
        starts: set[int] = set()
        for index in range(30):
            _scan(bridge, f"x {secret(index)}")
            pid = _pid(bridge)
            if pid is not None:
                starts.add(pid)
            # After the 7th, 14th, ... scan the child is retired inside the call: no pid is held.
            assert (index + 1) % 7 != 0 or pid is None
    spawned = len(starts)
    report.add(
        "G5.lifetime.scan-budget",
        spawned == 5,
        "a child is retired when it has served max_scans_per_process scans",
        f"max_scans_per_process=7, 30 scans, 5 children expected, distinct children seen {spawned}",
    )
    # Age.
    with NodeCoreBridge(max_process_age_s=1.0) as bridge:
        _scan(bridge, "x")
        first = _pid(bridge)
        time.sleep(1.2)
        _scan(bridge, "x")
        second = _pid(bridge)
    report.add(
        "G5.lifetime.age",
        first is not None and second is not None and first != second and not _alive(first),
        "a child past max_process_age_s is replaced before the next request and the old one is gone",
        f"max_process_age_s=1.0, slept 1.2 s, replaced={first != second}",
    )
    # Idle exit by itself.
    with NodeCoreBridge(idle_timeout_s=1.0) as bridge:
        _scan(bridge, "x")
        pid = _pid(bridge)
        assert pid is not None
        popen = bridge._state.proc.popen  # noqa: SLF001
        started = time.monotonic()
        while popen.poll() is None and time.monotonic() - started < 15.0:
            time.sleep(0.02)
        gone = popen.poll() is not None
        waited = time.monotonic() - started
        _scan(bridge, "x")
    report.add(
        "G5.lifetime.idle-exit",
        gone,
        "an idle child exits on its own after idle_timeout_s, before any further request",
        f"idle_timeout_s=1.0, exited by itself after {waited:.2f} s (limit 15 s), exit code {popen.returncode}",
    )
    # Owner death.
    code = (
        f"import os,signal,sys;sys.path.insert(0,{str(_HERE.parent / 'src')!r});"
        "from redact_secret_vault import NodeCoreBridge;"
        "b=NodeCoreBridge();b.scan('x');print(b._state.proc.popen.pid,flush=True);os.kill(os.getpid(),signal.SIGKILL)"
    )
    owner = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
    child_pid = int(owner.stdout.strip())
    started = time.monotonic()
    while _alive(child_pid) and time.monotonic() - started < 15.0:
        time.sleep(0.02)
    report.add(
        "G5.lifetime.owner-death",
        not _alive(child_pid),
        "the child exits when its owner is killed with SIGKILL (stdin reaches EOF)",
        f"owner exit {owner.returncode}, child gone after {time.monotonic() - started:.2f} s",
    )
    # close() kills and reaps.
    bridge = NodeCoreBridge()
    _scan(bridge, "x")
    pid = _pid(bridge)
    bridge.close()
    report.add(
        "G5.lifetime.close",
        pid is not None and not _alive(pid),
        "close() kills and reaps the child before returning",
        f"alive after close: {pid is not None and _alive(pid)}",
    )
    # One child at a time under contention.
    with NodeCoreBridge() as bridge:
        stop = threading.Event()
        seen_pids: set[int] = set()

        def sampler() -> None:
            while not stop.is_set():
                pid = _pid(bridge)
                if pid:
                    seen_pids.add(pid)
                time.sleep(0.001)

        sample = threading.Thread(target=sampler)
        sample.start()
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda i: _scan(bridge, f"x {secret(i)}"), range(200)))
        stop.set()
        sample.join()
    report.add(
        "G5.lifetime.one-child",
        len(seen_pids) == 1,
        "8 threads and 200 scans on one bridge use one child",
        f"distinct children seen {len(seen_pids)}",
    )
    report.add(
        "G5.lifetime.defaults",
        None,
        "default bounds of the bridge",
        f"max_scans_per_process={DEFAULT_MAX_SCANS_PER_PROCESS}, max_process_age_s={DEFAULT_MAX_PROCESS_AGE_S:g}, idle_timeout_s={DEFAULT_IDLE_TIMEOUT_S:g}",
    )


# ------------------------------------------------------------------------------------------------ heap


def _regions(pid: int) -> list[tuple[int, int, str]]:
    out: list[tuple[int, int, str]] = []
    with open(f"/proc/{pid}/maps", encoding="utf-8") as maps:
        for line in maps:
            parts = line.split(maxsplit=5)
            start, end = (int(x, 16) for x in parts[0].split("-"))
            perms = parts[1]
            name = parts[5].strip() if len(parts) > 5 else ""
            if "r" not in perms or name in ("[vvar]", "[vsyscall]", "[vdso]"):
                continue
            out.append((start, end, name or "anonymous"))
    return out


def count_in_memory(pid: int, needles: dict[str, bytes]) -> dict[str, dict[str, int]]:
    """Occurrences of each needle in every readable mapping of ``pid`` (Linux ``/proc``), by kind of mapping."""

    found: dict[str, dict[str, int]] = {label: {} for label in needles}
    overlap = max(len(n) for n in needles.values()) - 1
    step = 8 << 20
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
        for start, end, name in _regions(pid):
            kind = {"anonymous": "anonymous", "[heap]": "heap", "[stack]": "stack"}.get(name, "file")
            for position in range(start, end, step):
                try:
                    data = os.pread(mem.fileno(), min(step + overlap, end - position), position)
                except OSError:
                    break
                for label, needle in needles.items():
                    index = data.find(needle)
                    # A match that starts in the overlap belongs to the next read.
                    while index != -1 and index < step:
                        found[label][kind] = found[label].get(kind, 0) + 1
                        index = data.find(needle, index + 1)
    return found


def _wrapper(directory: Path, snapshot_dir: Path) -> str:
    script = directory / "node-with-snapshots"
    script.write_text(
        f'#!/bin/sh\nexec "{NODE}" --heapsnapshot-signal=SIGUSR2 --diagnostic-dir="{snapshot_dir}" "$@"\n'
    )
    script.chmod(0o755)
    return str(script)


def snapshot_contains(
    pid: int, snapshot_dir: Path, needles: dict[str, bytes], before: set[str]
) -> dict[str, int] | None:
    os.kill(pid, signal.SIGUSR2)
    deadline = time.monotonic() + 60
    path: Path | None = None
    while time.monotonic() < deadline:
        files = [p for p in snapshot_dir.glob("*.heapsnapshot") if p.name not in before]
        if files:
            candidate = files[0]
            size1 = candidate.stat().st_size
            time.sleep(0.5)
            if candidate.stat().st_size == size1 and size1 > 0 and not any(snapshot_dir.glob("*.tmp")):
                path = candidate
                break
        time.sleep(0.2)
    if path is None:
        return None
    data = path.read_bytes()
    result = {label: data.count(needle) for label, needle in needles.items()}
    path.unlink()
    return result


def run_heap(report: Report, workdir: Path) -> None:
    sentinel = secret(987_654_321)
    needles = {"utf8": sentinel.encode(), "utf16": sentinel.encode("utf-16-le")}
    marker = {"marker-utf8": PLAINTEXT_MARKER.encode(), "marker-utf16": PLAINTEXT_MARKER.encode("utf-16-le")}
    # Reachable heap, by V8 heap snapshot (taken after a full collection, so unreachable strings are not in it).
    snapshot_dir = workdir / "snapshots"
    snapshot_dir.mkdir()
    wrapper = _wrapper(workdir, snapshot_dir)
    with NodeCoreBridge(node_executable=wrapper) as bridge:
        text = f"before {sentinel} after {PLAINTEXT_MARKER}"
        bridge.scan(text, policy=None, limits=LIMITS)
        pid = _pid(bridge)
        assert pid is not None
        immediate = snapshot_contains(pid, snapshot_dir, {**needles, **marker}, set())
        for index in range(50):
            bridge.scan(f"filler {secret(index)}", policy=None, limits=LIMITS)
        after_more = snapshot_contains(pid, snapshot_dir, {**needles, **marker}, set())
    report.add(
        "G5.heap.snapshot",
        None,
        "V8 heap snapshot (after a full GC) of the child after one scan, and after 50 further scans",
        f"after 1 scan: {json.dumps(immediate, sort_keys=True)}; after 50 more: {json.dumps(after_more, sort_keys=True)}",
    )
    if not Path("/proc/self/mem").exists():
        report.add(
            "G5.heap.process-memory",
            None,
            "process memory scan needs Linux /proc: NOT RUN on this platform",
            f"platform {platform.system()}",
        )
        return
    # Raw process memory, including freed but not overwritten memory.
    with NodeCoreBridge() as bridge:
        text = f"before {sentinel} after {PLAINTEXT_MARKER}"
        bridge.scan(text, policy=None, limits=LIMITS)
        pid = _pid(bridge)
        assert pid is not None
        try:
            first = count_in_memory(pid, {**needles, **marker})
        except OSError as error:
            report.add(
                "G5.heap.process-memory",
                None,
                "reading the child's memory is not permitted here: NOT RUN",
                f"{type(error).__name__}",
            )
            return
        tail = {}
        for batch in (100, 1000, 5000):
            for index in range(batch):
                bridge.scan(f"filler {secret(index)} {PLAINTEXT_MARKER[:10]}{index}", policy=None, limits=LIMITS)
            tail[batch] = count_in_memory(pid, {**needles, **marker})
        time.sleep(0.5)
    report.add(
        "G5.heap.process-memory",
        None,
        "occurrences of the first input's secret and undetected text in the child's whole memory (/proc/<pid>/mem), by mapping",
        f"after 1 scan: {json.dumps(first, sort_keys=True)}; after +100 scans: {json.dumps(tail[100], sort_keys=True)}; "
        f"after +1100: {json.dumps(tail[1000], sort_keys=True)}; after +6100: {json.dumps(tail[5000], sort_keys=True)}",
    )
    with NodeCoreBridge(max_scans_per_process=1) as bridge:
        bridge.scan(f"before {sentinel} after", policy=None, limits=LIMITS)
        gone = _pid(bridge) is None
    report.add(
        "G5.heap.one-per-scan",
        gone,
        "with max_scans_per_process=1 no child holds the input once the call returns",
        f"no child referenced after the scan: {gone}",
    )


# ------------------------------------------------------------------------------------------------ timeouts


HANG_CORE = f"""export const VERSION = {json.dumps(PINNED_CORE_VERSION)};
export async function initialize() {{}}
export function piiActivation() {{ return "credentials=full;selectors=off;families=;vocabulary=pii-context/v2"; }}
export function scan(text) {{ if (text.includes("HANG")) {{ for (;;) {{}} }} return []; }}
export function artifact() {{ return {{ kind: "synthetic" }}; }}
"""


def run_timeouts(report: Report, workdir: Path, *, runs: int = 20) -> None:
    # A core that never returns (a busy loop that blocks the child's event loop), through the real child script.
    nm = _fake_core(workdir / "hang", source=HANG_CORE)
    overshoot: list[float] = []
    timeouts = restarted = 0
    for _ in range(runs):
        with NodeCoreBridge(node_modules=nm, timeout_s=20.0, expected_core_integrity=None) as bridge:
            bridge.scan(
                "warm", policy=None, limits=LIMITS
            )  # a running child: what is measured is the deadline and the kill
            first = _pid(bridge)
            bridge._timeout_s = 0.2  # noqa: SLF001 - the same bridge continues
            started = time.monotonic()
            try:
                bridge.scan("HANG", policy=None, limits=LIMITS)
                outcome = "completed"
            except VaultServerError as error:
                outcome = error.core_code or error.code.value
            overshoot.append(time.monotonic() - started - 0.2)
            timeouts += outcome == "BRIDGE_TIMEOUT"
            bridge._timeout_s = 20.0  # noqa: SLF001
            try:
                bridge.scan("again", policy=None, limits=LIMITS)
                restarted += _pid(bridge) not in (None, first)
            except VaultServerError:
                pass
    overshoot.sort()
    report.add(
        "G5.timeout.fires-and-restarts",
        timeouts == runs and restarted == runs,
        "a core that never returns is killed at timeout_s (BRIDGE_TIMEOUT) and the next scan on the same bridge runs on a new child",
        f"{runs} runs, timeout_s 0.2: {timeouts} BRIDGE_TIMEOUT, {restarted} next scans on a new child, "
        f"time past the deadline p50 {overshoot[runs // 2] * 1000:.0f} ms, max {overshoot[-1] * 1000:.0f} ms",
    )
    # An external kill in the middle of a request.
    with NodeCoreBridge(node_modules=nm, timeout_s=60.0, expected_core_integrity=None) as bridge:
        bridge.scan("warm", policy=None, limits=LIMITS)
        pid = _pid(bridge)
        assert pid is not None
        result: dict[str, str] = {}

        def long_scan() -> None:
            try:
                bridge.scan("HANG", policy=None, limits=LIMITS)
                result["r"] = "completed"
            except VaultServerError as error:
                result["r"] = error.core_code or error.code.value

        thread = threading.Thread(target=long_scan)
        thread.start()
        time.sleep(0.5)
        os.kill(pid, signal.SIGKILL)
        thread.join(30)
        try:
            recovered = _scan(bridge, "again") == 0
        except VaultServerError:
            recovered = False
    report.add(
        "G5.timeout.kill-mid-request",
        result.get("r") == "BRIDGE_PROCESS_FAILED" and recovered,
        "a child killed from outside in the middle of a scan fails the call closed (BRIDGE_PROCESS_FAILED) and the next scan recovers",
        f"call ended {result.get('r')}, next scan ok {recovered}",
    )
    # What the first request after a spawn costs: the child's start-up, the core's load, and the scan.
    cold: list[float] = []
    warm: list[float] = []
    for _ in range(10):
        with NodeCoreBridge(timeout_s=120.0) as bridge:
            started = time.monotonic()
            bridge.scan("x", policy=None, limits=LIMITS)
            cold.append(time.monotonic() - started)
            started = time.monotonic()
            bridge.scan("x", policy=None, limits=LIMITS)
            warm.append(time.monotonic() - started)
    cold.sort()
    warm.sort()
    report.add(
        "G5.timeout.cold-start",
        None,
        "the first scan on a new child (spawn, core load, scan) against the next scan: timeout_s covers both",
        f"10 runs, first scan p50 {cold[5] * 1000:.0f} ms max {cold[-1] * 1000:.0f} ms; second scan p50 {warm[5] * 1000:.1f} ms max {warm[-1] * 1000:.1f} ms",
    )
    # A core that cannot load: repeated start failures are backed off (two in a row, then a capped, jittered
    # exponential delay in which a request fails at once with the same code and no process is spawned).
    import redact_secret_vault.core_client as core_client_module

    real_popen = core_client_module.subprocess.Popen
    spawned = 0

    def counting(*args: Any, **kwargs: Any) -> Any:
        nonlocal spawned
        spawned += 1
        return real_popen(*args, **kwargs)

    results: dict[str, str] = {}
    with tempfile.TemporaryDirectory() as empty:
        core_client_module.subprocess.Popen = counting  # type: ignore[misc]
        try:
            with NodeCoreBridge(node_modules=empty) as bridge:
                started = time.monotonic()
                codes: dict[str, int] = {}
                for _ in range(30):
                    try:
                        bridge.scan("x", policy=None, limits=LIMITS)
                    except VaultServerError as error:
                        codes[error.core_code or "?"] = codes.get(error.core_code or "?", 0) + 1
                results["burst"] = (
                    f"30 back-to-back requests: {spawned} spawns, codes {json.dumps(codes, sort_keys=True)}, "
                    f"{(time.monotonic() - started) * 1000:.0f} ms in all"
                )
            spawned = 0
            with NodeCoreBridge(node_modules=empty) as bridge:
                started = time.monotonic()
                longest = 0.0
                refused_fast = 0
                requests = 0
                while time.monotonic() - started < 6.0:
                    t0 = time.monotonic()
                    spawns_before = spawned
                    try:
                        bridge.scan("x", policy=None, limits=LIMITS)
                    except VaultServerError:
                        pass
                    took = time.monotonic() - t0
                    longest = max(longest, took)
                    refused_fast += spawned == spawns_before
                    requests += 1
                    time.sleep(0.05)
                results["paced"] = (
                    f"one request every 50 ms for 6 s: {requests} requests, {spawned} spawns, "
                    f"{refused_fast} refused without a spawn, slowest request {longest * 1000:.0f} ms"
                )
        finally:
            core_client_module.subprocess.Popen = real_popen  # type: ignore[misc]
    paced_spawns = int(results["paced"].split(", ")[1].split()[0])
    report.add(
        "G5.timeout.restart-storm",
        paced_spawns <= 12,
        "a core that cannot load: repeated start failures back off (capped, jittered exponential), failing closed at once with no spawn and no waiting",
        f"{results['burst']}; {results['paced']} (unbacked, that is one spawn per request)",
    )


# ------------------------------------------------------------------------------------------------ concurrency


def run_concurrency(report: Report) -> None:
    text = f"synthetic ticket body {secret(7)} and some more text " * 20

    def rate(bridges: int, threads: int, seconds: float = 3.0) -> tuple[float, float, float]:
        pool_bridges = [NodeCoreBridge() for _ in range(bridges)]
        for bridge in pool_bridges:
            _scan(bridge, "warm")
        latencies: list[float] = []
        lock = threading.Lock()
        stop = time.monotonic() + seconds

        def work(index: int) -> None:
            bridge = pool_bridges[index % bridges]
            mine: list[float] = []
            while time.monotonic() < stop:
                t0 = time.monotonic()
                bridge.scan(text, policy=None, limits=LIMITS)
                mine.append(time.monotonic() - t0)
            with lock:
                latencies.extend(mine)

        with ThreadPoolExecutor(max_workers=threads) as pool:
            list(pool.map(work, range(threads)))
        for bridge in pool_bridges:
            bridge.close()
        latencies.sort()
        return len(latencies) / seconds, latencies[len(latencies) // 2], latencies[int(len(latencies) * 0.99)]

    rows = []
    for bridges, threads in ((1, 1), (1, 4), (1, 16), (1, 64), (4, 4), (4, 16)):
        per_second, p50, p99 = rate(bridges, threads)
        rows.append(
            f"{bridges} bridge x {threads} threads: {per_second:.0f} scans/s, p50 {p50 * 1000:.1f} ms, p99 {p99 * 1000:.1f} ms"
        )
    report.add(
        "G5.concurrency.ceiling",
        None,
        "throughput of 1 and 4 bridges (a 1.1 KiB input with one secret)",
        "; ".join(rows),
    )
    # Waiting behind the lock: timeout_s is end to end, so no caller waits longer than it, whatever the queue.
    big = "z " * 6_000_000  # about 12 MB: one scan takes a noticeable time
    with NodeCoreBridge(timeout_s=60.0) as bridge:
        _scan(bridge, "warm")  # the first request pays for the start-up
        bridge._timeout_s = 5.0  # noqa: SLF001
        t0 = time.monotonic()
        _scan(bridge, big)
        one = time.monotonic() - t0
        elapsed: list[float] = []
        completed = 0
        errors: dict[str, int] = {}
        lock = threading.Lock()
        # Enough callers that the last one would wait several times timeout_s behind scans that each finish in time.
        callers = min(64, max(12, int(3 * 5.0 / max(one, 0.01)) + 2))

        def waiter(_: int) -> None:
            nonlocal completed
            start = time.monotonic()
            try:
                _scan(bridge, big)
                ok, code = True, ""
            except VaultServerError as error:
                ok, code = False, error.core_code or error.code.value
            took = time.monotonic() - start
            with lock:
                elapsed.append(took)
                completed += ok
                if code:
                    errors[code] = errors.get(code, 0) + 1

        with ThreadPoolExecutor(max_workers=callers) as pool:
            list(pool.map(waiter, range(callers)))
    elapsed.sort()
    longest = elapsed[-1] if elapsed else 0.0
    report.add(
        "G5.concurrency.bounded-queue",
        completed > 0 and longest <= 5.0 * 1.5 and set(errors) <= {"BRIDGE_TIMEOUT"},
        "a caller waiting for the bridge lock is bounded by timeout_s end to end (lock wait included), failing closed with BRIDGE_TIMEOUT",
        f"one scan {one:.2f} s, timeout_s 5.0, {callers} callers: {completed} completed, longest call {longest:.2f} s (limit 7.50: timeout_s and the kill of a scan past its deadline on a loaded host), errors {json.dumps(errors, sort_keys=True)}",
    )


def run_server_concurrency(report: Report) -> None:
    """The persistent server over the reference store and one real bridge: captures per second at growing concurrency,
    and what a pile of queued captures does to ``asyncio.to_thread`` for the rest of the application."""

    if sys.version_info < (3, 11):
        report.add(
            "G5.concurrency.server", None, "the persistent server needs Python 3.11: NOT RUN", sys.version.split()[0]
        )
        return
    import asyncio

    from server_support import make_rig

    async def scenario() -> list[str]:
        out: list[str] = []
        bridge = NodeCoreBridge()
        probe = await asyncio.to_thread(bridge.scan, "", policy=None, limits=LIMITS)
        rig = await make_rig(core=bridge, expected_pii_activation=probe.pii_activation or "")  # type: ignore[arg-type]
        text = f"ticket {secret(11)} body " + "x " * 500
        import os

        workers = min(32, (os.cpu_count() or 1) + 4)
        for concurrency in (1, 8, 32, 128):
            started = time.monotonic()
            await asyncio.gather(*(rig.capture(text) for _ in range(concurrency)))
            elapsed = time.monotonic() - started
            out.append(f"{concurrency} concurrent captures: {concurrency / elapsed:.0f}/s, {elapsed:.2f} s")
        # An unrelated to_thread behind 128 queued captures of a larger input.
        big = f"ticket {secret(12)} body " + "x " * 250_000
        captures = [asyncio.ensure_future(rig.capture(big)) for _ in range(128)]
        await asyncio.sleep(0.2)
        started = time.monotonic()
        await asyncio.to_thread(lambda: None)
        starved = time.monotonic() - started
        results = await asyncio.gather(*captures, return_exceptions=True)
        failed: dict[str, int] = {}
        for result in results:
            if isinstance(result, BaseException):
                code = getattr(result, "core_code", None) or type(result).__name__
                failed[code] = failed.get(code, 0) + 1
        out.append(
            f"an unrelated asyncio.to_thread behind 128 queued 0.5 MB captures waited {starved:.2f} s "
            f"(default executor: {workers} threads; the scans run on the bridge's own {2} threads); "
            f"{128 - sum(failed.values())} of the 128 completed, failures {json.dumps(failed, sort_keys=True)}"
        )
        bridge.close()
        out.append(f"STARVED={starved:.3f}")
        return out

    lines = asyncio.run(scenario())
    starved = float(lines.pop().split("=")[1])
    report.add(
        "G5.concurrency.server",
        starved < 2.0,
        "capture throughput of one persistent server over one bridge (reference store), and whether queued scans starve the default executor (an unrelated asyncio.to_thread must not wait for them)",
        "; ".join(lines),
    )


# ------------------------------------------------------------------------------------------------ limits


def _ru_maxrss_mib() -> float:
    value = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return value / (1 << 20) if sys.platform == "darwin" else value / 1024


def _size_run(kind: str, mib: int) -> None:
    """Child-of-the-harness: one bridge, one scan, print duration and the child process's peak memory."""

    size = mib << 20
    text = {"plain": "a" * size, "control": "\u0001" * size, "secrets": (secret(5) + " ") * (size // 41)}[kind]
    with NodeCoreBridge(timeout_s=600.0) as bridge:
        started = time.monotonic()
        try:
            outcome = bridge.scan(text, policy=None, limits={"maxInputBytes": size + 1024, "maxFindings": 50_000})
            result = f"ok:findings={len(outcome.findings)}"
        except VaultServerError as error:
            result = f"{error.code.value}:{error.core_code}"
        elapsed = time.monotonic() - started
    print(f"SIZE {kind} {mib} {result} {elapsed:.2f} {_ru_maxrss_mib():.0f}")


def run_limits(report: Report, *, heavy: bool) -> None:
    sizes = [(k, m) for k in ("plain",) for m in (1, 8, 32)]
    if heavy:
        sizes += [("plain", 64), ("control", 64), ("secrets", 16)]
    rows = []
    default_timeout_fail: list[str] = []
    for kind, mib in sizes:
        done = subprocess.run(
            [sys.executable, __file__, "--size-run", f"{kind}:{mib}"], capture_output=True, text=True, timeout=900
        )
        line = next((x for x in done.stdout.splitlines() if x.startswith("SIZE ")), "SIZE ? ? failed 0 0")
        _, k, m, result, seconds, rss = (line.split() + ["?"] * 6)[:6]
        rows.append(f"{k} {m} MiB: {result}, {seconds} s, child peak {rss} MiB")
        if float(seconds) > 10.0 if seconds.replace(".", "").isdigit() else True:
            default_timeout_fail.append(f"{k}:{m}")
    report.add(
        "G5.limits.input-size",
        None,
        "one scan at growing input sizes: time and the child's peak resident memory (default timeout_s is 10 s)",
        "; ".join(rows)
        + (f"; over the 10 s default: {default_timeout_fail}" if default_timeout_fail else "; none over 10 s"),
    )
    report.add(
        "G5.limits.frames",
        None,
        "frame ceilings",
        f"request {MAX_REQUEST_FRAME_BYTES >> 20} MiB (before send), response {MAX_RESPONSE_FRAME_BYTES >> 20} MiB (BRIDGE_BAD_OUTPUT above)",
    )


# ------------------------------------------------------------------------------------------------ fail closed


def run_failclosed(report: Report, workdir: Path) -> None:
    marker = PLAINTEXT_MARKER

    def hostile(name: str, source: str) -> str:
        return _fake_core(workdir / name, source=source)

    base = f"""export const VERSION = {json.dumps(PINNED_CORE_VERSION)};
export async function initialize() {{}}
export function artifact() {{ return {{ kind: "synthetic" }}; }}
"""
    # A core that puts the input into the error code it reports, for several shapes of input.
    nm = hostile(
        "echo-code", base + """export function scan(text) { const e = new Error("x"); e.code = text; throw e; }"""
    )
    hostile_inputs = (
        f"input {marker}",
        marker,
        marker.lower(),
        f"{marker}\n{marker}",
        "A" * 65,
        "É" * 4,
    )
    leaked = False
    wrong_code = 0
    detail = "no error"
    for text in hostile_inputs:
        try:
            NodeCoreBridge(node_modules=nm, expected_core_integrity=None).scan(text, policy=None, limits=LIMITS)
        except VaultServerError as error:
            shown = f"{error!s}{error!r}{error.args}{error.core_code or ''}"
            leaked = leaked or marker.lower() in shown.lower()
            if error.core_code != "BRIDGE_BAD_OUTPUT":
                wrong_code += 1
            detail = error.code.value
    report.add(
        "G5.sanitization.core-error-code",
        not leaked and wrong_code == 0,
        "an error code reported by a (compromised or buggy) core is not copied into the exception unvalidated: only [A-Z][A-Z0-9_]{0,63} passes, anything else is BRIDGE_BAD_OUTPUT with a fixed message",
        f"{len(hostile_inputs)} hostile codes through the real child; the input marker reached an exception: {leaked}; refused with a code other than BRIDGE_BAD_OUTPUT: {wrong_code} ({detail})",
    )
    run_integrity(report, workdir)
    # A core that returns a finding outside the input.
    nm = hostile(
        "range",
        base
        + """export function scan() { return [{ id: "f", type: "github_token", detector: "d", confidence: "high", obfuscation: "none", start: 5, end: 99999, action: "redact" }]; }""",
    )
    from redact_secret_vault import CaptureGrant, CaptureOptions, InMemoryVaultServer

    client_result = "accepted"
    try:
        NodeCoreBridge(node_modules=nm, expected_core_integrity=None).scan("short", policy=None, limits=LIMITS)
    except VaultServerError as error:
        client_result = error.code.value
    server_result = "accepted"
    with NodeCoreBridge(node_modules=nm, expected_core_integrity=None) as bridge:
        try:
            InMemoryVaultServer(core_client=bridge).capture(
                "short",
                CaptureOptions(issued_tenant="tenant-synthetic", release=(CaptureGrant(sink="sink", paths=("body",)),)),
            )
        except VaultServerError as error:
            server_result = error.code.value
    report.add(
        "G5.failclosed.range-outside-input",
        server_result != "accepted",
        "a core that reports a finding outside the input: the client parser passes it on, the capture plan must refuse it",
        f"NodeCoreBridge.scan: {client_result}; InMemoryVaultServer.capture: {server_result}",
    )


# ------------------------------------------------------------------------------------------------ core integrity


def _core_integrity_module() -> Any:
    """``scripts/core-integrity.py``, the reference implementation of the digest and the writer of the pin."""
    import importlib.util

    path = _HERE.parents[2] / "scripts" / "core-integrity.py"
    spec = importlib.util.spec_from_file_location("core_integrity_reference", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _real_node_modules() -> Path | None:
    from redact_secret_vault.core_client import _resolve_node_modules  # noqa: PLC0415

    candidates = [_resolve_node_modules(None), str(_HERE.parents[2] / "node_modules")]
    for candidate in candidates:
        if candidate and (Path(candidate) / "@redact-secret" / "core" / "package.json").is_file():
            return Path(candidate)
    return None


def _copy_core(real: Path, target: Path, *, addon: bool = True) -> Path:
    """A node_modules holding a copy of the installed core, its wasm package, and (optionally) this host's addon."""
    scope = target / "node_modules" / "@redact-secret"
    scope.mkdir(parents=True)
    for source in sorted((real / "@redact-secret").iterdir()):
        name = source.name
        if name in ("core", "wasm") or (addon and name.startswith("node-")):
            shutil.copytree(source, scope / name, symlinks=True)
    return target / "node_modules"


def _flip(path: Path) -> None:
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0x01
    path.write_bytes(bytes(data))


def run_integrity(report: Report, workdir: Path) -> None:
    from redact_secret_vault.core_client import PINNED_CORE_INTEGRITY  # noqa: PLC0415

    real = _real_node_modules()
    if real is None:
        report.add("G5.failclosed.replaced-core", None, "NOT RUN: no installed @redact-secret/core to copy", "")
        return
    reference = _core_integrity_module()
    marker = PLAINTEXT_MARKER
    root = workdir / "integrity"
    addon_names = sorted(p.name for p in (real / "@redact-secret").iterdir() if p.name.startswith("node-"))

    def attempt(nm: Path, *, env: dict[str, str] | None = None, pins: Any = PINNED_CORE_INTEGRITY) -> tuple[str, str]:
        """``(outcome, artifact)``: ``accepted`` with the artifact the child used, or the refusal's ``core_code``."""
        saved = {key: os.environ.get(key) for key in (env or {})}
        os.environ.update(env or {})
        try:
            with NodeCoreBridge(node_modules=str(nm), expected_core_integrity=pins, timeout_s=60.0) as bridge:
                outcome = bridge.scan(f"input {secret(1)} {marker}", policy=None, limits=LIMITS)
                return ("accepted" if outcome.findings else "accepted-nothing-found", outcome.artifact)
        except VaultServerError as error:
            shown = f"{error!s}{error!r}{error.args}"
            assert marker not in shown and str(nm) not in shown, "an integrity failure echoed the input or a path"
            return (str(error.core_code), "")
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    refused = "CORE_INTEGRITY_MISMATCH"
    results: list[tuple[str, bool, str]] = []

    def case(name: str, expected: str, nm: Path, **kwargs: Any) -> None:
        got, artifact = attempt(nm, **kwargs)
        results.append((name, got == expected, f"{got}{'/' + artifact if artifact else ''}"))

    # Positive controls: the installed core is accepted, with its addon and with the WebAssembly fallback.
    nm = _copy_core(real, root / "pristine")
    case("pristine copy, addon", "accepted", nm)
    nm = _copy_core(real, root / "no-addon", addon=False)
    case("pristine copy, no addon (WebAssembly fallback)", "accepted", nm)
    # Every kind of change to a pinned package is refused before the core runs.
    core_dir = lambda nm: nm / "@redact-secret" / "core"  # noqa: E731
    nm = _copy_core(real, root / "core-byte")
    _flip(core_dir(nm) / "dist" / "index.js")
    case("one bit of the core's dist/index.js flipped", refused, nm)
    nm = _copy_core(real, root / "core-extra")
    (core_dir(nm) / "dist" / "extra.js").write_text("export {};\n")
    case("a file added to the core", refused, nm)
    nm = _copy_core(real, root / "core-removed")
    (core_dir(nm) / "dist" / "formatters.d.ts").unlink()
    case("a file removed from the core", refused, nm)
    nm = _copy_core(real, root / "core-symlink")
    (core_dir(nm) / "dist" / "version.d.ts").unlink()
    (core_dir(nm) / "dist" / "version.d.ts").symlink_to(core_dir(nm) / "dist" / "version.js")
    case("a file of the core replaced by a symbolic link", refused, nm)
    nm = _copy_core(real, root / "core-manifest")
    manifest = core_dir(nm) / "package.json"
    manifest.write_text(manifest.read_text().replace('"MIT"', '"MIT "', 1))
    case("the core's package.json changed", refused, nm)
    nm = _copy_core(real, root / "wasm-byte")
    _flip(next((nm / "@redact-secret" / "wasm").glob("*.wasm")))
    case("one bit of the WebAssembly package flipped", refused, nm)
    nm = _copy_core(real, root / "wasm-missing")
    shutil.rmtree(nm / "@redact-secret" / "wasm")
    case("the WebAssembly package missing", refused, nm)
    for name in addon_names:
        nm = _copy_core(real, root / f"addon-byte-{name}")
        _flip(next((nm / "@redact-secret" / name).glob("*.node")))
        case(f"one bit of the native addon ({name}) flipped", refused, nm)
    # An addon that Node.js would find outside the verified places (NODE_PATH) is refused, not loaded and trusted.
    if addon_names:
        planted = root / "node-path"
        shutil.copytree(real / "@redact-secret" / addon_names[0], planted / "@redact-secret" / addon_names[0])
        nm = _copy_core(real, root / "addon-elsewhere", addon=False)
        control = attempt(nm, env={"NODE_PATH": str(planted)}, pins=None)
        results.append(("control: that addon is the one Node.js loads when nothing is pinned", control[1] == "addon", control[0] + "/" + control[1]))
        case("a native addon found through NODE_PATH, not beside the core", refused, nm, env={"NODE_PATH": str(planted)})
    # A replaced core that reports the pinned version, and runs code when it is imported.
    base = f"""import {{ writeFileSync }} from "node:fs";
writeFileSync({json.dumps(str(root / "ran"))}, "imported");
export const VERSION = {json.dumps(PINNED_CORE_VERSION)};
export async function initialize() {{}}
export function artifact() {{ return "addon"; }}
export function scan() {{ return []; }}
"""
    fake = _fake_core(root / "replaced", source=base)
    case("a replacement core that reports the pinned version and finds nothing", refused, Path(fake))
    results.append(("the replacement core's code never ran (hashed before it was imported)", not (root / "ran").exists(), "marker absent" if not (root / "ran").exists() else "MARKER PRESENT"))
    # The child's digest is the reference function's: pins computed by the reference for a tampered copy are accepted.
    nm = _copy_core(real, root / "agree")
    _flip(core_dir(nm) / "dist" / "index.js")
    pins = {"@redact-secret/core": reference.tree_digest_of_dir(core_dir(nm)), "@redact-secret/wasm": reference.tree_digest_of_dir(nm / "@redact-secret" / "wasm")}
    for name in addon_names:
        pins[f"@redact-secret/{name}"] = reference.tree_digest_of_dir(nm / "@redact-secret" / name)
    case("the reference digest of a modified copy is accepted by the child (the two functions agree)", "accepted", nm, pins=pins)
    wrong = sum(1 for _name, ok, _got in results if not ok)
    report.add(
        "G5.failclosed.replaced-core",
        wrong == 0,
        "a core replaced on disk that reports the pinned version string is detected: the packages the child is about to load are hashed against the pin before the core runs, and a difference is CORE_INTEGRITY_MISMATCH with a fixed message",
        f"{len(results)} cases, {wrong} unexpected"
        + "".join(f"; UNEXPECTED {name}: {got}" for name, ok, got in results if not ok),
    )
    report.add(
        "G5.failclosed.integrity-cases",
        None,
        "each case of the integrity check and its outcome",
        "; ".join(f"{name} -> {got}" for name, _ok, got in results),
    )
    # What the check costs: the first scan of a new child with and without the pin.
    nm = _copy_core(real, root / "cost")
    timings: dict[str, list[float]] = {"pinned": [], "unpinned": []}
    for _ in range(10):
        for label, pins in (("pinned", PINNED_CORE_INTEGRITY), ("unpinned", None)):
            with NodeCoreBridge(node_modules=str(nm), expected_core_integrity=pins, timeout_s=60.0) as bridge:
                started = time.monotonic()
                bridge.scan("x", policy=None, limits=LIMITS)
                timings[label].append(time.monotonic() - started)
    pinned, unpinned = sorted(timings["pinned"]), sorted(timings["unpinned"])
    # The cost of the one setting that leaves no live process holding an input: a new child for every scan.
    per_scan: dict[str, float] = {}
    for label, pins in (("pinned", PINNED_CORE_INTEGRITY), ("unpinned", None)):
        with NodeCoreBridge(
            node_modules=str(nm), expected_core_integrity=pins, timeout_s=60.0, max_scans_per_process=1
        ) as bridge:
            started = time.monotonic()
            for _ in range(20):
                bridge.scan("x", policy=None, limits=LIMITS)
            per_scan[label] = 20 / (time.monotonic() - started)
    report.add(
        "G5.integrity.cost",
        None,
        "the first scan of a new child with and without the integrity pin (the pin is verified once per child), and the rate at max_scans_per_process=1 (a new child for every scan)",
        f"10 runs each: with the pin p50 {pinned[5] * 1000:.0f} ms max {pinned[-1] * 1000:.0f} ms; without p50 {unpinned[5] * 1000:.0f} ms max {unpinned[-1] * 1000:.0f} ms; "
        f"max_scans_per_process=1, 20 scans: {per_scan['pinned']:.1f} scans/s with the pin, {per_scan['unpinned']:.1f} without",
    )


# ------------------------------------------------------------------------------------------------ main

SECTIONS = ("protocol", "fuzz", "lifetime", "heap", "timeouts", "concurrency", "limits", "failclosed")


def environment_line() -> str:
    node = subprocess.run([NODE, "--version"], capture_output=True, text=True).stdout.strip()
    try:
        load = ", load average " + "/".join(f"{value:.1f}" for value in os.getloadavg()) + f" on {os.cpu_count()} CPUs"
    except OSError:
        load = ""
    return (
        f"python {platform.python_version()} ({platform.python_implementation()}), node {node}, {platform.system()} "
        f"{platform.machine()}, core {PINNED_CORE_VERSION}{load}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--section", action="append", choices=SECTIONS, help="repeat; default: all but the heavy runs")
    parser.add_argument("--fuzz-cases", type=int, default=300)
    parser.add_argument("--parser-cases", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--heavy", action="store_true", help="448 MiB request line, 64 MiB inputs")
    parser.add_argument("--size-run", help=argparse.SUPPRESS)
    options = parser.parse_args(argv)
    if options.size_run:
        kind, mib = options.size_run.split(":")
        _size_run(kind, int(mib))
        return 0
    print(f"ENVIRONMENT {environment_line()}", flush=True)
    report = Report()
    sections: list[str] = options.section or list(SECTIONS)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        steps: dict[str, Callable[[], None]] = {
            "protocol": lambda: run_protocol(report, work / "protocol", heavy=options.heavy),
            "fuzz": lambda: run_fuzz(
                report, cases=options.fuzz_cases, seed=options.seed, parser_cases=options.parser_cases
            ),
            "lifetime": lambda: run_lifetime(report),
            "heap": lambda: run_heap(report, work / "heap"),
            "timeouts": lambda: run_timeouts(report, work / "timeouts"),
            "concurrency": lambda: (run_concurrency(report), run_server_concurrency(report)),
            "limits": lambda: run_limits(report, heavy=options.heavy),
            "failclosed": lambda: run_failclosed(report, work / "failclosed"),
        }
        for name in sections:
            (work / name).mkdir()
            steps[name]()
    print(f"SUMMARY {len(report.results)} results, {len(report.failed())} not met", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
