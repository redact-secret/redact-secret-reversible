"""Python driver for the schedule orchestrator (docs/plans/python-persistence-parity.md section 6.3).

Serves ``redact_secret_vault.persistent.store_memory`` over the line protocol described in
``conformance/persistent/v1/SCHEDULES.md``: one JSON request per line on standard input, one
response per line on standard output.

A test tool. It lives in the test tree and is not in the wheel, accepts only synthetic fixtures, and
answers with result structures and error codes only. The hold and fault hooks live here and in
``schedule_store.py``, outside the package's production API.

    python tests/schedule_driver.py            # serves standard input and output
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import re
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

# Run as a script from a checkout: make the package and the sibling test modules importable.
_HERE = Path(__file__).resolve().parent
for _path in (_HERE, _HERE.parent / "src"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from schedule_store import ScheduleStore  # noqa: E402

from redact_secret_vault.persistent import (  # noqa: E402
    Attempt,
    CaptureGeneration,
    CommitRestoreInput,
    CreateCaptureInput,
    DeleteCiphertextInput,
    EntryUse,
    InspectAttemptInput,
    InvalidateRecoveredInput,
    NewCapture,
    NewEntry,
    ReadCapturesInput,
    ReadEntriesInput,
    ReplaceCaptureKeyInput,
    RevokeCaptureInput,
    StoreError,
    StoreScope,
    SweepInput,
)

CLOCK_START_MS = 1_800_000_000_000
HOLD_POINTS = ("before-commit",)
FAULTS = ("unavailable", "before-first-write", "drop-connection", "after-commit-before-ack")

_HEX = re.compile(r"(?:[0-9a-f]{2})*")
_BYTES_FIELDS = frozenset({"envelope", "wrappedKey", "requestDigest"})

#: wire operation name -> the ``Store`` method that serves it
_STORE_METHODS = {
    "createCapture": "create_capture",
    "readEntries": "read_entries",
    "readCaptures": "read_captures",
    "commitRestore": "commit_restore",
    "revokeCapture": "revoke_capture",
    "inspectAttempt": "inspect_attempt",
    "replaceCaptureKey": "replace_capture_key",
    "deleteCiphertext": "delete_ciphertext",
    "sweepExpired": "sweep_expired",
    "recoveryState": "recovery_state",
    "initializeNamespace": "initialize_namespace",
    "quarantine": "quarantine",
    "invalidateRecovered": "invalidate_recovered",
}

_SERVER_OPERATIONS = frozenset({"capture", "restore", "revoke", "deleteCaptureCiphertext", "resolveAttempt"})

_BOUNDS = {
    "maxClockSkewMs": "max_clock_skew_ms",
    "maxCreateEntries": "max_create_entries",
    "maxCreateBytes": "max_create_bytes",
    "maxRestoreEntries": "max_restore_entries",
    "maxRestoreCaptures": "max_restore_captures",
    "maxEnvelopeBytes": "max_envelope_bytes",
}


# ---------------------------------------------------------------- wire conversion


def _bytes(value: Any) -> Any:
    """Hexadecimal or a byte run to ``bytes``. Anything else is left alone, so a validator rejects it."""

    if type(value) is str and _HEX.fullmatch(value) is not None:
        return bytes.fromhex(value)
    if isinstance(value, dict) and type(value.get("$fill")) is int and type(value.get("length")) is int:
        return bytes([value["$fill"]]) * value["length"]
    return value


def _scope(value: Any) -> Any:
    if isinstance(value, dict):
        return StoreScope(namespace=value.get("namespace"), tenant=value.get("tenant"))  # type: ignore[arg-type]
    return value


def _tuple(value: Any, build: Callable[[Any], Any] = lambda item: item) -> Any:
    return tuple(build(item) for item in value) if isinstance(value, list) else value


def _create_capture(data: dict[str, Any]) -> CreateCaptureInput:
    capture = data["capture"]
    return CreateCaptureInput(
        scope=_scope(data["scope"]),
        epoch=data["epoch"],
        now=data["now"],
        capture=NewCapture(
            capture_id=capture["captureId"],
            key_ref=capture["keyRef"],
            wrapped_key=_bytes(capture["wrappedKey"]),
            session_tag=capture["sessionTag"],
            created_at=capture["createdAt"],
            expires_at=capture["expiresAt"],
            lookup_version=capture["lookupVersion"],
        ),
        entries=_tuple(
            data["entries"],
            lambda entry: NewEntry(
                entry_id=entry["entryId"], max_uses=entry["maxUses"], envelope=_bytes(entry["envelope"])
            ),
        ),
    )


def _commit_restore(data: dict[str, Any]) -> CommitRestoreInput:
    attempt = data["attempt"]
    return CommitRestoreInput(
        scope=_scope(data["scope"]),
        epoch=data["epoch"],
        now=data["now"],
        attempt=Attempt(attempt_id=attempt["attemptId"], request_digest=_bytes(attempt["requestDigest"])),
        receipt_expires_at=data["receiptExpiresAt"],
        captures=_tuple(
            data["captures"],
            lambda item: CaptureGeneration(capture_id=item["captureId"], generation=item["generation"]),
        ),
        uses=_tuple(
            data["uses"],
            lambda item: EntryUse(
                entry_id=item["entryId"],
                capture_id=item["captureId"],
                count=item["count"],
                lifecycle_revision=item["lifecycleRevision"],
                ciphertext_revision=item["ciphertextRevision"],
            ),
        ),
    )


def _call(store: ScheduleStore, operation: str, data: dict[str, Any]) -> Any:
    """The coroutine of one store operation, built from its wire input."""

    method = getattr(store, _STORE_METHODS[operation])
    if operation == "createCapture":
        return method(_create_capture(data))
    if operation == "readEntries":
        return method(ReadEntriesInput(scope=_scope(data["scope"]), entry_ids=_tuple(data["entryIds"])))
    if operation == "readCaptures":
        return method(ReadCapturesInput(scope=_scope(data["scope"]), capture_ids=_tuple(data["captureIds"])))
    if operation == "commitRestore":
        return method(_commit_restore(data))
    if operation == "revokeCapture":
        return method(
            RevokeCaptureInput(
                scope=_scope(data["scope"]),
                capture_id=data["captureId"],
                now=data["now"],
                retention_ms=data["retentionMs"],
                fence_absent=data["fenceAbsent"],
            )
        )
    if operation == "inspectAttempt":
        return method(InspectAttemptInput(scope=_scope(data["scope"]), attempt_id=data["attemptId"]))
    if operation == "replaceCaptureKey":
        return method(
            ReplaceCaptureKeyInput(
                scope=_scope(data["scope"]),
                capture_id=data["captureId"],
                key_revision=data["keyRevision"],
                key_ref=data["keyRef"],
                wrapped_key=_bytes(data["wrappedKey"]),
            )
        )
    if operation == "deleteCiphertext":
        return method(DeleteCiphertextInput(scope=_scope(data["scope"]), capture_id=data["captureId"], now=data["now"]))
    if operation == "sweepExpired":
        return method(SweepInput(namespace=data["namespace"], now=data["now"], limit=data["limit"]))
    if operation == "recoveryState" or operation == "quarantine":
        return method(data["namespace"])
    if operation == "initializeNamespace":
        return method(data["namespace"], data["epoch"])
    if operation == "invalidateRecovered":
        return method(InvalidateRecoveredInput(namespace=data["namespace"], new_epoch=data["newEpoch"]))
    raise KeyError(operation)


def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(part.capitalize() for part in rest)


def encode(value: Any) -> Any:
    """Contract objects to wire form: camelCase keys, bytes as lowercase hexadecimal, tuples as lists."""

    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {_camel(f.name): encode(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, (tuple, list)):
        return [encode(item) for item in value]
    if isinstance(value, Mapping):
        return {key: encode(item) for key, item in value.items()}
    return value


# ----------------------------------------------------------------------- the driver


class _Clock:
    def __init__(self) -> None:
        self.ms = CLOCK_START_MS

    def now(self) -> int:
        return self.ms


def open_store(options: dict[str, Any]) -> tuple[ScheduleStore, _Clock | None]:
    """The default store: ``ScheduleStore`` over a clock the orchestrator can move."""

    controllable = options.get("realClock") is not True
    clock = _Clock() if controllable else None
    bounds = {_BOUNDS[key]: value for key, value in options.items() if key in _BOUNDS}
    factory: type[ScheduleStore] = ScheduleStore
    if options.get("mutant") is not None:
        # A store with exactly one broken decision, for the mutation controls. Test tree only.
        from store_mutants import MUTANTS

        factory = {name: cls for name, cls, _defect, _ids in MUTANTS}[options["mutant"]]
    store = factory(now=None if clock is None else clock.now, **bounds)
    return store, clock


class Driver:
    """A driver as a function of requests. ``emit`` carries events; ``handle`` returns the response."""

    def __init__(
        self, open_store_fn: Callable[[dict[str, Any]], tuple[ScheduleStore, _Clock | None]] = open_store
    ) -> None:
        self._open = open_store_fn
        self._store: ScheduleStore | None = None
        self._clock: _Clock | None = None
        self._holds: dict[str, asyncio.Event] = {}
        self._holds_enabled = True
        self._server: Any = None

    def _reset(self) -> None:
        for event in self._holds.values():
            event.set()
        self._holds.clear()
        if self._store is not None:
            self._store.release_all()
        if self._server is not None:
            asyncio.ensure_future(self._server.vault.close())  # noqa: RUF006
        self._store = None
        self._clock = None
        self._server = None

    async def _configure_server(self, message: dict[str, Any]) -> dict[str, Any]:
        from schedule_server import FAULT_KINDS, open_server

        self._server = await open_server(message["namespace"], clock_start=CLOCK_START_MS)
        self._clock = self._server.clock
        return {
            "ok": True,
            "capabilities": encode(self._server.store.capabilities()),
            "features": {"testClock": True, "holds": [], "faults": list(FAULT_KINDS), "levels": ["server"]},
        }

    def _configure(self, message: dict[str, Any]) -> dict[str, Any]:
        self._reset()
        if message.get("level") != "store":
            return {"ok": False, "error": "UNSUPPORTED_LEVEL"}
        options = message.get("store") or {}
        self._store, self._clock = self._open(options)
        self._holds_enabled = options.get("noHolds") is not True
        return {
            "ok": True,
            "capabilities": encode(self._store.capabilities()),
            "features": {
                "testClock": self._clock is not None,
                "holds": list(HOLD_POINTS) if self._holds_enabled else [],
                "faults": list(FAULTS),
                "levels": ["store"],
            },
        }

    async def _store_call(self, message: dict[str, Any], emit: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        store = self._store
        assert store is not None
        operation = message["op"]
        fault = message.get("fault")
        if fault is not None and fault not in FAULTS:
            return {"error": "UNSUPPORTED_FAULT"}
        hold = message.get("hold")
        if hold is not None:
            if not self._holds_enabled or hold not in HOLD_POINTS:
                return {"error": "UNSUPPORTED_HOLD"}
            released = asyncio.Event()
            hold_id = message["holdId"]
            self._holds[hold_id] = released

            async def pause() -> None:
                emit({"event": "held", "holdId": hold_id})
                await released.wait()

            store.hold(_STORE_METHODS[operation], pause)
        code: str | None = None
        result: Any = None
        try:
            if fault in ("unavailable", "before-first-write"):
                raise StoreError("STORE_UNAVAILABLE")
            if fault == "drop-connection":
                raise StoreError("STORE_AMBIGUOUS")
            result = await _call(store, operation, message.get("input") or {})
            if fault == "after-commit-before-ack":
                raise StoreError("STORE_AMBIGUOUS")
        except StoreError as error:
            code = error.code
        except Exception:  # noqa: BLE001 - a foreign failure is reported by shape only
            code = "INTERNAL"
        if code is not None:
            return {"error": code}
        return {"result": encode(result)}

    async def handle(
        self, message: dict[str, Any], emit: Callable[[dict[str, Any]], None] = lambda _event: None
    ) -> dict[str, Any]:
        identifier = message.get("id")
        body = await self._dispatch(message, emit)
        return {"id": identifier, **body}

    async def _dispatch(self, message: dict[str, Any], emit: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        operation = message.get("op")
        try:
            if operation == "configure":
                served = (message.get("store") or {}).get("serveLevels")
                if served is not None and message.get("level") not in served:
                    self._reset()
                    return {"ok": False, "error": "UNSUPPORTED_LEVEL"}
                if message.get("level") == "server":
                    self._reset()
                    return await self._configure_server(message)
                return self._configure(message)
            if operation == "reset":
                self._reset()
                return {"ok": True}
            if self._server is not None and operation in _SERVER_OPERATIONS:
                from schedule_server import server_call

                return await server_call(self._server, message, _STORE_METHODS, encode)
            if self._server is not None and operation == "capabilities":
                return {"result": encode(self._server.store.capabilities())}
            if self._store is None and self._server is None:
                return {"error": "NOT_CONFIGURED"}
            if self._store is None and operation != "clock" and operation != "release":
                return {"error": "UNSUPPORTED_OPERATION"}
            if operation == "capabilities":
                return {"result": encode(self._store.capabilities())}
            if operation == "clock":
                if self._clock is None:
                    return {"error": "UNSUPPORTED_CLOCK"}
                action = message.get("action")
                if action == "advance":
                    self._clock.ms += message["ms"]
                elif action == "set":
                    self._clock.ms = message["ms"]
                elif action != "now":
                    return {"error": "UNSUPPORTED_CLOCK"}
                return {"result": {"now": self._clock.now()}}
            if operation == "release":
                event = self._holds.pop(message["holdId"], None)
                if event is not None:
                    event.set()
                return {"ok": True}
            if operation in _STORE_METHODS:
                return await self._store_call(message, emit)
            return {"error": "UNSUPPORTED_OPERATION"}
        except Exception:  # noqa: BLE001 - never carry a foreign message
            return {"error": "INTERNAL"}


# ------------------------------------------------------------------------- stdio


async def serve(driver: Driver) -> None:
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=1 << 28)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    pending: set[asyncio.Task[None]] = set()

    def write(body: dict[str, Any]) -> None:
        sys.stdout.write(json.dumps(body, separators=(",", ":")) + "\n")
        sys.stdout.flush()

    async def run(message: dict[str, Any]) -> None:
        write(await driver.handle(message, write))

    while True:
        line = await reader.readline()
        if not line:
            break
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except ValueError:
            write({"id": None, "error": "BAD_REQUEST"})
            continue
        task = asyncio.ensure_future(run(message))
        pending.add(task)
        task.add_done_callback(pending.discard)
    if pending:
        await asyncio.gather(*pending)


def main() -> None:
    asyncio.run(serve(Driver()))


if __name__ == "__main__":
    main()
