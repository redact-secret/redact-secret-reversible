"""Client for the qualified service boundary to ``@redact-secret/core``.

See ``boundary/core_bridge.mjs`` and the "Python core bridge" section of
docs/specs/threat-model.md for why this boundary exists: no native Python
distribution of the core is published (verified against the
``redact-secret/redact-secret`` GitHub organization), so this package must not
reimplement detection (AGENTS.md, CONVENTIONS.md). Detection happens entirely
in the pinned ``@redact-secret/core`` JavaScript package, run in a long-lived
Node.js process that the bridge owns; this module only parses the safe
finding metadata (id/type/detector/confidence/obfuscation/start/end/action)
that the core's public ``scan`` API returns, never a matched value.

``CoreClient`` is a ``Protocol`` so a caller may substitute a fake in unit
tests (see ``tests/test_server_authority.py``) or, in the future, a
differently-qualified boundary (an HTTP microservice fronting the same core,
for example) without changing ``InMemoryVaultServer``.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
import threading
import time
import weakref
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import IO, Any, Protocol, runtime_checkable

from ._core_pin import CORE_PACKAGES
from .errors import VaultServerError, VaultServerErrorCode
from .pii import MAX_PII_ACTIVATION_LENGTH, resolve_expected_pii_activation, resolve_pii_selection

DEFAULT_BRIDGE_SCRIPT = Path(__file__).parent / "boundary" / "core_bridge.mjs"

# The exact core release this boundary is qualified against, matching the
# pin in this repository's root package.json. A response reporting a
# different version is treated as CORE_FAILURE rather than silently trusted.
PINNED_CORE_VERSION = "0.1.0-beta.12"

#: The integrity pin of that release: the "rsv-tree-v1" digest of each package directory the core needs (the core,
#: its WebAssembly package, and the addon package of each platform it publishes). The bridge process hashes the
#: directories it is about to load before it imports the core and refuses on any difference
#: (``CORE_INTEGRITY_MISMATCH``). Generated into ``_core_pin.py`` by ``scripts/core-integrity.py``, which CI re-runs
#: against ``package.json``, ``package-lock.json``, and the published tarballs.
PINNED_CORE_INTEGRITY: Mapping[str, str] = MappingProxyType({name: pin["tree"] for name, pin in CORE_PACKAGES.items()})
_INTEGRITY_CORE = "@redact-secret/core"
_INTEGRITY_WASM = "@redact-secret/wasm"

#: Environment variable ``NodeCoreBridge`` reads when ``node_modules`` is not
#: passed: the ``node_modules`` directory that holds ``@redact-secret/core``.
NODE_MODULES_ENV = "REDACT_SECRET_VAULT_NODE_MODULES"

#: Largest request frame sent to the bridge process, in bytes (requests are
#: ASCII JSON, so bytes equal characters). Equals ``MAX_REQUEST_CHARS`` in
#: ``core_bridge.mjs``. It admits the server's largest ``max_input_bytes``
#: (64 MiB) even when every character needs a six-byte JSON escape. A larger
#: request raises ``LIMIT_EXCEEDED`` before anything is sent.
MAX_REQUEST_FRAME_BYTES = 448 * 1024 * 1024
#: Largest response frame read back, in bytes. ``max_findings`` is at most
#: 50,000 and each projected finding is a few hundred bytes. A longer line is
#: ``BRIDGE_BAD_OUTPUT``, and the process is replaced.
MAX_RESPONSE_FRAME_BYTES = 32 * 1024 * 1024

#: Defaults for the bridge process lifetime (see ``NodeCoreBridge``).
DEFAULT_MAX_SCANS_PER_PROCESS = 10_000
DEFAULT_MAX_PROCESS_AGE_S = 600.0
DEFAULT_IDLE_TIMEOUT_S = 60.0
# Upper bounds for the lifetime settings; the idle bound matches
# MAX_IDLE_EXIT_MS in core_bridge.mjs.
_MAX_SECONDS = 24 * 60 * 60.0
_MAX_SCANS_PER_PROCESS = 10_000_000
# How long to wait for a killed bridge process to be reaped.
_REAP_TIMEOUT_S = 5.0


def _resolve_node_modules(value: str | os.PathLike[str] | None) -> str | None:
    """The absolute ``node_modules`` directory to load the core from, or
    ``None`` for the bridge script's own resolution.

    An explicit argument wins; otherwise a non-empty
    ``REDACT_SECRET_VAULT_NODE_MODULES`` is used. A relative path is made
    absolute once, here, so later scans never depend on the working
    directory. Whether the directory holds the core is checked by each bridge
    process when it starts (``CORE_FAILURE`` / ``BRIDGE_CORE_NOT_FOUND``).
    """
    if value is None:
        value = os.environ.get(NODE_MODULES_ENV) or None
        if value is None:
            return None
    try:
        raw = os.fspath(value)
    except TypeError:
        raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT) from None
    if type(raw) is not str or not raw or "\x00" in raw:
        raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
    return os.path.abspath(raw)


_PACKAGE_NAME = re.compile(r"@redact-secret/[a-z0-9][a-z0-9-]{0,63}")
_TREE_DIGEST = re.compile(r"[0-9a-f]{64}")


def _resolve_integrity(value: Mapping[str, str] | None) -> dict[str, str] | None:
    """The package digests to pin, or ``None`` for no integrity check (a caller that loads a core other than the
    pinned release, as the test fixtures do, and says so)."""
    if value is None:
        return None
    if not isinstance(value, Mapping) or not 0 < len(value) <= 32:
        raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
    pins: dict[str, str] = {}
    for name, digest in value.items():
        if (
            type(name) is not str
            or type(digest) is not str
            or _PACKAGE_NAME.fullmatch(name) is None
            or _TREE_DIGEST.fullmatch(digest) is None
        ):
            raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
        pins[name] = digest
    if _INTEGRITY_CORE not in pins or _INTEGRITY_WASM not in pins:
        raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
    return pins


def _resolve_seconds(value: Any) -> float:
    """A finite duration in (0, 24 h], or ``INVALID_ARGUMENT``."""
    if type(value) not in (int, float) or not math.isfinite(value) or not (0 < value <= _MAX_SECONDS):
        raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
    return float(value)


def _resolve_count(value: Any) -> int:
    if type(value) is not int or not (1 <= value <= _MAX_SCANS_PER_PROCESS):
        raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
    return value


@dataclass(frozen=True, slots=True)
class CoreFinding:
    """Mirrors the core's public ``SecretFinding`` (safe metadata only — no
    matched value, ever)."""

    id: str
    type: str
    detector: str
    confidence: str
    obfuscation: str
    start: int
    end: int
    action: str


@dataclass(frozen=True, slots=True)
class CoreScanOutcome:
    findings: Sequence[CoreFinding]
    core_version: str
    artifact: str
    # The core's canonical PII activation identity for the realm that ran
    # this scan, or ``None`` when that core has no PII surface (beta.9).
    # ``InMemoryVaultServer`` refuses a capture's ``pii`` retention unless
    # this reports active PII detection, so a ``CoreClient`` that never sets
    # it can never have PII retained (fail closed).
    pii_activation: str | None = None


@runtime_checkable
class CoreClient(Protocol):
    def scan(
        self,
        text: str,
        *,
        policy: Mapping[str, str] | None = None,
        limits: Mapping[str, int] | None = None,
    ) -> CoreScanOutcome: ...


_FINDING_STR_FIELDS = ("id", "type", "detector", "confidence", "obfuscation", "action")
_FINDING_KEYS = frozenset((*_FINDING_STR_FIELDS, "start", "end"))
_SUCCESS_KEYS = frozenset(("findings", "coreVersion", "artifact", "piiActivation", "integrity"))
_ERROR_KEYS = frozenset(("error",))
_UNPINNED: Any = object()

# Every string the child process reports is checked against a fixed shape before it is used, and a response that
# breaks one is ``BRIDGE_BAD_OUTPUT`` with a fixed message that carries none of the child's text. The shapes are
# deliberately narrow: they bound what a buggy or compromised core can smuggle into an exception, a log line, an audit
# field or a stored payload (a short token of the allowed alphabet, never free text or the input). They cannot prove
# that a short token of that alphabet is not a secret: a core that reports one is still a core that cannot be trusted.
#: The ``code`` of an error frame; ``core_code`` and the exception message carry it.
_CORE_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
#: A finding's ``id``, ``type`` and ``detector`` (``finding-3``, ``aws_access_key_id``, ``github-token``,
#: ``pii_email``); 128 is the longest PII type (``pii_`` and 124 characters).
_FINDING_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
#: ``coreVersion`` (``0.1.0-beta.12``) and ``artifact`` (``addon`` or ``wasm``).
_VERSION_TEXT = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,63}")
_ARTIFACT_TEXT = re.compile(r"[a-z][a-z0-9_-]{0,31}")
#: ``piiActivation`` is a canonical identity such as ``credentials=full;selectors=off;families=;vocabulary=...``:
#: printable ASCII without a space, at most ``MAX_PII_ACTIVATION_LENGTH`` characters.
_ACTIVATION_TEXT = re.compile(rf"[\x21-\x7e]{{1,{MAX_PII_ACTIVATION_LENGTH}}}")
_CONFIDENCE = frozenset(("high", "medium", "low"))
_OBFUSCATION = frozenset(("none", "invisible-characters"))
_ACTION = frozenset(("redact", "block", "warn", "allow"))


def _core_failure(core_code: str) -> VaultServerError:
    return VaultServerError(VaultServerErrorCode.CORE_FAILURE, core_code=core_code)


def _bad_output() -> VaultServerError:
    return _core_failure("BRIDGE_BAD_OUTPUT")


def _parse_finding(raw: Any) -> CoreFinding:
    if type(raw) is not dict or raw.keys() != _FINDING_KEYS:
        raise _bad_output()
    if not all(type(raw[key]) is str for key in _FINDING_STR_FIELDS):
        raise _bad_output()
    if not all(_FINDING_NAME.fullmatch(raw[key]) for key in ("id", "type", "detector")):
        raise _bad_output()
    if raw["confidence"] not in _CONFIDENCE or raw["obfuscation"] not in _OBFUSCATION or raw["action"] not in _ACTION:
        raise _bad_output()
    if type(raw["start"]) is not int or type(raw["end"]) is not int:
        raise _bad_output()
    return CoreFinding(
        id=raw["id"],
        type=raw["type"],
        detector=raw["detector"],
        confidence=raw["confidence"],
        obfuscation=raw["obfuscation"],
        start=raw["start"],
        end=raw["end"],
        action=raw["action"],
    )


class _Watchdog:
    """Kills the armed bridge process when its request passes its deadline.

    One daemon thread per bridge, started on first use, so a request costs a
    lock round trip rather than a new timer thread. Killing the process
    unblocks the requesting thread's pipe write or read, which then sees
    ``disarm()`` report that the watchdog fired.
    """

    def __init__(self) -> None:
        self._cond = threading.Condition(threading.Lock())
        self._target: subprocess.Popen[bytes] | None = None
        self._deadline = 0.0
        self._waiting_until = math.inf
        self._fired = False
        self._stopped = False
        self._thread: threading.Thread | None = None

    def arm(self, target: subprocess.Popen[bytes], timeout_s: float) -> None:
        with self._cond:
            self._target = target
            self._deadline = time.monotonic() + timeout_s
            self._fired = False
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run, name="redact-secret-vault-bridge-watchdog", daemon=True
                )
                self._thread.start()
            elif self._deadline < self._waiting_until:
                self._cond.notify()

    def disarm(self) -> bool:
        """Disarms, and reports whether the watchdog killed the target."""
        with self._cond:
            self._target = None
            fired, self._fired = self._fired, False
            return fired

    def stop(self) -> None:
        with self._cond:
            self._stopped = True
            self._target = None
            self._cond.notify()

    def _run(self) -> None:
        with self._cond:
            while not self._stopped:
                if self._target is None:
                    self._waiting_until = math.inf
                    self._cond.wait()
                    continue
                remaining = self._deadline - time.monotonic()
                if remaining > 0:
                    self._waiting_until = self._deadline
                    self._cond.wait(remaining)
                    continue
                target, self._target = self._target, None
                self._fired = True
                try:
                    target.kill()
                except OSError:
                    pass


class _BridgeProcess:
    """One running ``core_bridge.mjs`` and its bookkeeping."""

    __slots__ = ("popen", "owner_pid", "started_at", "last_used", "served", "next_id")

    def __init__(self, popen: subprocess.Popen[bytes]) -> None:
        self.popen = popen
        self.owner_pid = os.getpid()
        self.started_at = self.last_used = time.monotonic()
        self.served = 0
        self.next_id = 1

    @property
    def stdin(self) -> IO[bytes]:
        assert self.popen.stdin is not None
        return self.popen.stdin

    @property
    def stdout(self) -> IO[bytes]:
        assert self.popen.stdout is not None
        return self.popen.stdout

    def terminate(self) -> None:
        """Kills and reaps the process. Nothing it holds needs a graceful
        shutdown, and killing first means closing the pipes never blocks."""
        popen = self.popen
        if popen.poll() is None:
            try:
                popen.kill()
            except OSError:
                pass
        self._close_pipes()
        try:
            popen.wait(timeout=_REAP_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            pass

    def abandon(self) -> None:
        """In a forked child: drop this handle without signalling a process
        that belongs to the parent."""
        self._close_pipes()

    def _close_pipes(self) -> None:
        for stream in (self.popen.stdin, self.popen.stdout):
            if stream is None:
                continue
            try:
                stream.close()
            except (OSError, ValueError):
                pass


class _BridgeState:
    """Process-lifetime state, held apart from ``NodeCoreBridge`` so that its
    finalizer and the fork hook never keep the bridge itself alive."""

    __slots__ = ("lock", "proc", "closed", "watchdog", "__weakref__")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.proc: _BridgeProcess | None = None
        self.closed = False
        self.watchdog = _Watchdog()

    def discard(self) -> None:
        proc, self.proc = self.proc, None
        if proc is not None:
            proc.terminate()

    def shutdown(self) -> None:
        self.closed = True
        self.discard()
        self.watchdog.stop()

    def after_fork_in_child(self) -> None:
        # The child must never write to the parent's bridge process: two
        # writers on one pipe would interleave frames and could hand one
        # caller's findings to another. The lock may have been held by a
        # thread that does not exist in the child.
        self.lock = threading.Lock()
        if self.proc is not None:
            self.proc.abandon()
        self.proc = None
        self.watchdog = _Watchdog()


_LIVE_STATES: weakref.WeakSet[_BridgeState] = weakref.WeakSet()


def _reset_after_fork() -> None:
    for state in list(_LIVE_STATES):
        state.after_fork_in_child()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_after_fork)


class NodeCoreBridge:
    """Calls the real ``@redact-secret/core`` in a long-lived Node.js process.

    Threat boundary: this class trusts the local ``node`` executable and the
    npm-installed ``@redact-secret/core`` (or a caller-supplied
    script/executable).

    Core location: ``node_modules`` (or, when it is ``None``, the
    ``REDACT_SECRET_VAULT_NODE_MODULES`` environment variable) names the
    ``node_modules`` directory the application installed the core into, for
    example with ``npm install @redact-secret/core@<PINNED_CORE_VERSION>``.
    The bridge then loads ``<node_modules>/@redact-secret/core`` and nothing
    else: no parent directories and never the working directory. With
    neither set, the bridge script resolves the core relative to its own
    location, which works in this repository and when the virtualenv lives
    inside the project that installed the core, but not for a
    ``pip``-installed package whose site-packages is elsewhere. A directory
    that does not hold the core raises ``CORE_FAILURE`` with ``core_code``
    ``BRIDGE_CORE_NOT_FOUND`` (``BRIDGE_CORE_LOAD_FAILED`` if it is found but
    fails to load); so does a missing core without either setting. It is a
    server-side, same-host integration only, not qualified for
    browser/Worker/CSP contexts. It never passes a fixture, secret, or
    matched value back to the caller; the core's ``scan`` API structurally
    cannot return one, and the bridge script projects each finding to its
    eight safe metadata fields.

    Process lifetime (#89): each bridge owns at most one Node.js process at
    a time, started on the first ``scan`` and reused by later ones. Requests
    and responses are newline-delimited JSON frames with a per-process
    request id that the response must echo. A lock admits one request at a
    time, so threads sharing a bridge are serialized and each waits for the
    one ahead of it; separate bridges own separate processes. The process is
    killed as soon as it has served ``max_scans_per_process`` scans
    (``1`` gives one process per scan), and replaced before a request once
    it is ``max_process_age_s`` old or has been idle for half of
    ``idle_timeout_s`` (the process exits on its own after the full idle
    time, so a request never races that exit). It is killed and discarded
    after any request that does not end in a well-formed success response,
    including a timeout, a crash, a malformed or oversized frame, a
    bridge-reported error, a version or PII-activation mismatch, and an
    interrupted call. The next ``scan`` starts a new process. ``close()``,
    the context manager, garbage collection of the bridge, and interpreter
    exit each kill and reap the process; the process also exits when its
    stdin closes, so it never outlives the Python process. After a
    ``fork()``, the child never uses the parent's process and starts its
    own. The process's stderr is discarded.

    Core integrity: ``expected_core_integrity`` (default ``PINNED_CORE_INTEGRITY``) pins the "rsv-tree-v1" digest of
    the package directories the bridge is about to load: ``@redact-secret/core``, ``@redact-secret/wasm``, and the
    platform addon package that Node.js finds beside them. The first request of each process carries the pins; the
    process hashes those directories before it imports the core, so a core that was replaced or modified never runs and
    never sees an input, and any difference (a changed, added, removed or symlinked file) is ``CORE_FAILURE`` with
    ``core_code`` ``CORE_INTEGRITY_MISMATCH``. The response reports the digests it verified and this class checks them
    against the pin again. What it covers: every file of those directories, and that a native addon the core chose was
    one of them (an addon found through ``NODE_PATH`` or a global folder is refused). What it does not cover: the
    ``node`` executable, the bridge script, other directories on Node.js's module path, and a change made between the
    hash and the import by someone who can write those files. ``None`` switches the check off, as
    ``expected_core_version=None`` does the version check; a core other than the pinned release needs both.

    PII activation (docs/decisions/decide-pii-retention-and-activation-ownership.md
    §3 "Python bridge"): each bridge process is a realm with no other
    initializer, so ``pii`` is the only selection and omission means PII
    off. ``pii`` is forwarded verbatim to the core's ``initialize({ pii })``
    when a process starts; the core owns selector grammar and its
    ``PII_SELECTOR_*`` rejections surface as ``CORE_FAILURE`` with
    ``core_code``. A non-empty ``pii`` on a core without a PII surface
    (beta.9) raises ``PII_UNAVAILABLE``. Every response, from every process
    this bridge starts, reports ``piiActivation`` and is compared with
    ``expected_pii_activation`` when that is set (``PII_UNAVAILABLE`` if the
    core reports none). Otherwise the identity from the first successful
    response is pinned and every later response must match, so a replacement
    process that came up under a different core fails. A difference raises
    ``PII_ACTIVATION_MISMATCH``.

    Failure behavior: a malformed ``pii``, ``expected_pii_activation``,
    ``timeout_s``, or lifetime setting raises ``INVALID_ARGUMENT`` and a
    missing ``node`` executable raises ``UNSUPPORTED_RUNTIME``, both at
    construction. A request frame over ``MAX_REQUEST_FRAME_BYTES`` raises
    ``LIMIT_EXCEEDED`` before it is sent. A request that passes
    ``timeout_s`` (``BRIDGE_TIMEOUT``), a process that cannot start
    (``BRIDGE_SPAWN_FAILED``) or exits mid-request
    (``BRIDGE_PROCESS_FAILED``), a malformed, oversized, or out-of-sequence
    response (``BRIDGE_BAD_OUTPUT``), and a core-version mismatch
    (``CORE_VERSION_MISMATCH``), and a core that is not the pinned release byte for byte
    (``CORE_INTEGRITY_MISMATCH``) each raise ``VaultServerError(CORE_FAILURE)``
    — fail-closed, never a partial or best-effort finding list. A ``scan``
    after ``close()`` raises ``CORE_FAILURE`` with ``BRIDGE_CLOSED``. No
    error carries the input, a selector, a path, or process output.

    Residual risk: a compromised local ``node`` binary or a supply-chain
    compromise of the installed ``@redact-secret/core`` package would affect
    this boundary exactly as it would affect the JS vault. A process now
    serves many requests, possibly from different callers sharing the
    bridge, over its lifetime; see the threat model's "Python core bridge"
    section for why no request can observe another's input or findings.
    """

    def __init__(
        self,
        *,
        node_executable: str | None = None,
        script: Path = DEFAULT_BRIDGE_SCRIPT,
        timeout_s: float = 10.0,
        expected_core_version: str | None = PINNED_CORE_VERSION,
        expected_core_integrity: Mapping[str, str] | None = PINNED_CORE_INTEGRITY,
        pii: Sequence[str] = (),
        expected_pii_activation: str | None = None,
        node_modules: str | os.PathLike[str] | None = None,
        max_scans_per_process: int = DEFAULT_MAX_SCANS_PER_PROCESS,
        max_process_age_s: float = DEFAULT_MAX_PROCESS_AGE_S,
        idle_timeout_s: float = DEFAULT_IDLE_TIMEOUT_S,
    ) -> None:
        selection = resolve_pii_selection(pii)
        resolved_node_modules = _resolve_node_modules(node_modules)
        expected_activation = resolve_expected_pii_activation(expected_pii_activation)
        self._timeout_s = _resolve_seconds(timeout_s)
        self._max_scans = _resolve_count(max_scans_per_process)
        self._max_age_s = _resolve_seconds(max_process_age_s)
        self._idle_timeout_s = _resolve_seconds(idle_timeout_s)
        resolved_node = node_executable or shutil.which("node")
        if resolved_node is None:
            raise VaultServerError(VaultServerErrorCode.UNSUPPORTED_RUNTIME)
        self._node = resolved_node
        self._script = script
        self._node_modules = resolved_node_modules
        self._expected_version = expected_core_version
        self._expected_integrity = _resolve_integrity(expected_core_integrity)
        # Sent with the first request of each process: `"integrity":{...},`
        self._integrity_field = b""
        if self._expected_integrity is not None:
            pins = json.dumps(self._expected_integrity, separators=(",", ":"), sort_keys=True).encode("ascii")
            self._integrity_field = b'"integrity":' + pins + b","
        self._pii = selection
        self._expected_pii_activation = expected_activation
        self._pinned_pii_activation: Any = _UNPINNED
        self._state = _BridgeState()
        _LIVE_STATES.add(self._state)
        self._finalizer = weakref.finalize(self, self._state.shutdown)

    def close(self) -> None:
        """Kills and reaps the bridge process. Idempotent. Waits for a
        request in progress on another thread to finish first. A later
        ``scan`` raises ``CORE_FAILURE`` with ``BRIDGE_CLOSED``."""
        with self._state.lock:
            self._finalizer()

    def __enter__(self) -> NodeCoreBridge:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def scan(
        self,
        text: str,
        *,
        policy: Mapping[str, str] | None = None,
        limits: Mapping[str, int] | None = None,
    ) -> CoreScanOutcome:
        if not isinstance(text, str):
            raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
        request: dict[str, Any] = {"input": text, "pii": list(self._pii), "policy": policy, "limits": limits}
        if self._node_modules is not None:
            request["nodeModules"] = self._node_modules
        try:
            # ASCII (non-ASCII and lone surrogates are \u-escaped), no raw
            # newline, and never NaN/Infinity, which JSON.parse rejects.
            body = json.dumps(request, allow_nan=False, separators=(",", ":")).encode("ascii")
        except (TypeError, ValueError):
            raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT) from None
        # `{"id":N,` is prepended once the process assigns N.
        if len(body) + len(self._integrity_field) + 32 > MAX_REQUEST_FRAME_BYTES:
            raise VaultServerError(VaultServerErrorCode.LIMIT_EXCEEDED)

        state = self._state
        with state.lock:
            if state.closed:
                raise _core_failure("BRIDGE_CLOSED")
            proc = self._ready_process(state)
            request_id = proc.next_id
            proc.next_id += 1
            # The integrity pins go with the first request of a process, which verifies them before it loads the core.
            first = request_id == 1
            pins = self._integrity_field if first else b""
            try:
                line = self._exchange(state, proc, b'{"id":%d,' % request_id + pins + body[1:] + b"\n")
                outcome = self._parse(line, request_id, first=first)
            except BaseException:
                # Whatever went wrong, this process is never asked again.
                state.discard()
                raise
            proc.served += 1
            proc.last_used = time.monotonic()
            if proc.served >= self._max_scans:
                # Retire it now rather than at the next request, so no
                # process outlives its scan budget holding the last input.
                state.discard()
            return outcome

    def _ready_process(self, state: _BridgeState) -> _BridgeProcess:
        """The process for the next request, replacing one that is exited,
        inherited across ``fork()``, or past a lifetime bound."""
        proc = state.proc
        if proc is not None:
            now = time.monotonic()
            if proc.owner_pid != os.getpid():
                proc.abandon()
                state.proc = proc = None
            elif (
                proc.popen.poll() is not None
                or now - proc.started_at >= self._max_age_s
                or now - proc.last_used >= self._idle_timeout_s / 2
            ):
                state.discard()
                proc = None
        if proc is None:
            idle_exit_ms = max(1, round(self._idle_timeout_s * 1000))
            try:
                popen = subprocess.Popen(
                    [self._node, str(self._script), f"--idle-exit-ms={idle_exit_ms}"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
            except (OSError, ValueError) as exc:
                raise _core_failure("BRIDGE_SPAWN_FAILED") from exc
            proc = state.proc = _BridgeProcess(popen)
        return proc

    def _exchange(self, state: _BridgeState, proc: _BridgeProcess, frame: bytes) -> bytes:
        """Writes one request frame and reads one response line, under the
        watchdog's deadline."""
        limit = MAX_RESPONSE_FRAME_BYTES
        line: bytes | None = None
        state.watchdog.arm(proc.popen, self._timeout_s)
        try:
            try:
                proc.stdin.write(frame)
                proc.stdin.flush()
                line = proc.stdout.readline(limit + 1)
            except (OSError, ValueError):
                line = None
        finally:
            fired = state.watchdog.disarm()
        if fired:
            raise _core_failure("BRIDGE_TIMEOUT")
        if line is not None and len(line) > limit:
            raise _bad_output()
        if not line or not line.endswith(b"\n"):
            raise _core_failure("BRIDGE_PROCESS_FAILED")
        return line

    def _parse(self, line: bytes, request_id: int, *, first: bool = False) -> CoreScanOutcome:
        try:
            data = json.loads(line)
        except (ValueError, RecursionError) as exc:
            raise _bad_output() from exc
        if type(data) is not dict:
            raise _bad_output()
        response_id = data.pop("id", None)
        if type(response_id) is not int or response_id != request_id:
            raise _bad_output()

        if "error" in data:
            error = data["error"]
            if data.keys() != _ERROR_KEYS or type(error) is not dict:
                raise _bad_output()
            code = error.get("code")
            # Only a code of the fixed shape is passed on; `message` is never read.
            if code is not None and (type(code) is not str or _CORE_CODE.fullmatch(code) is None):
                raise _bad_output()
            if code == "PII_UNAVAILABLE":
                raise VaultServerError(VaultServerErrorCode.PII_UNAVAILABLE)
            raise VaultServerError(VaultServerErrorCode.CORE_FAILURE, core_code=code)

        if data.keys() != _SUCCESS_KEYS:
            raise _bad_output()
        core_version = data["coreVersion"]
        artifact = data["artifact"]
        activation = data["piiActivation"]
        raw_findings = data["findings"]
        if type(core_version) is not str or type(artifact) is not str or type(raw_findings) is not list:
            raise _bad_output()
        if _VERSION_TEXT.fullmatch(core_version) is None or _ARTIFACT_TEXT.fullmatch(artifact) is None:
            raise _bad_output()
        if activation is not None and (type(activation) is not str or _ACTIVATION_TEXT.fullmatch(activation) is None):
            raise _bad_output()
        self._check_integrity(data["integrity"], artifact, first)
        if self._expected_version is not None and core_version != self._expected_version:
            raise _core_failure("CORE_VERSION_MISMATCH")

        findings = tuple(_parse_finding(raw) for raw in raw_findings)
        self._check_pii_activation(activation)
        return CoreScanOutcome(
            findings=findings,
            core_version=core_version,
            artifact=artifact,
            pii_activation=activation,
        )

    def _check_integrity(self, reported: Any, artifact: str, first: bool) -> None:
        """The child reports, with the response to the first request of a process, the digest of every pinned package
        it found and verified before it loaded the core. The child already refuses a difference; this is the check
        that it did verify (a bridge script that ignores the field, or a different one, is not accepted)."""
        expected = self._expected_integrity
        if expected is None or not first:
            if reported is not None:
                raise _bad_output()
            return
        if type(reported) is not dict or not reported or len(reported) > len(expected):
            raise _bad_output()
        for name, digest in reported.items():
            if type(name) is not str or type(digest) is not str or name not in expected:
                raise _bad_output()
            if digest != expected[name]:
                raise _core_failure("CORE_INTEGRITY_MISMATCH")
        if _INTEGRITY_CORE not in reported or _INTEGRITY_WASM not in reported:
            raise _core_failure("CORE_INTEGRITY_MISMATCH")
        # A native addon that was not among the verified packages was found somewhere this check did not look.
        if artifact == "addon" and len(reported) <= 2:
            raise _core_failure("CORE_INTEGRITY_MISMATCH")

    def _check_pii_activation(self, activation: str | None) -> None:
        # Called with the bridge lock held, so pinning is not racy.
        if self._expected_pii_activation is not None:
            if activation is None:
                # An expected identity on a core with no PII surface, as
                # `createVault({ expectPiiActivation })` does on beta.9.
                raise VaultServerError(VaultServerErrorCode.PII_UNAVAILABLE)
            if activation != self._expected_pii_activation:
                raise VaultServerError(VaultServerErrorCode.PII_ACTIVATION_MISMATCH)
            return
        if self._pinned_pii_activation is _UNPINNED:
            self._pinned_pii_activation = activation
        elif activation != self._pinned_pii_activation:
            raise VaultServerError(VaultServerErrorCode.PII_ACTIVATION_MISMATCH)
