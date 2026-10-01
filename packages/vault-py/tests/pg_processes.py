"""Test-only: real operating-system processes against one PostgreSQL database (plan section 6.1).

``DriverProcess`` starts ``schedule_driver.py`` as a child process, configured for the PostgreSQL backend, and speaks
its line protocol (``conformance/persistent/v1/SCHEDULES.md``). Each child is its own interpreter with its own
connections; they share only the database. Threads or tasks in one process do not count as a second process.

The builders produce wire inputs (camelCase JSON, bytes as lowercase hexadecimal) for synthetic captures and commits.
Every value is synthetic.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any

DRIVER = Path(__file__).resolve().parent / "schedule_driver.py"

BASE32 = "abcdefghijklmnopqrstuvwxyz234567"
HOUR = 3_600_000


def real_now() -> int:
    """The caller's clock, close to the database's (both machines are this one)."""

    return time.time_ns() // 1_000_000


class DriverProcess:
    """One driver process. ``call`` sends a request and returns its response; a held call also sends ``held``."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.pid = 0
        self._process: asyncio.subprocess.Process | None = None
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._events: dict[str, asyncio.Future[None]] = {}
        self._next = 0
        self._reader: asyncio.Task[None] | None = None

    async def start(self, store: dict[str, Any] | None = None) -> dict[str, Any]:
        self._process = await asyncio.create_subprocess_exec(
            sys.executable,
            str(DRIVER),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=dict(os.environ),
            limit=1 << 26,
        )
        self._reader = asyncio.ensure_future(self._read())
        reply = await self.call("configure", level="store", store={"backend": "postgres", **(store or {})})
        assert reply.get("ok") is True, reply
        self.pid = reply["pid"]
        return reply

    async def _read(self) -> None:
        assert self._process is not None and self._process.stdout is not None
        while True:
            line = await self._process.stdout.readline()
            if not line:
                break
            message = json.loads(line)
            if message.get("event") == "held":
                event = self._event(message["holdId"])
                if not event.done():
                    event.set_result(None)
                continue
            future = self._pending.pop(message.get("id"), None)
            if future is not None and not future.done():
                future.set_result(message)

    def _event(self, hold_id: str) -> asyncio.Future[None]:
        if hold_id not in self._events:
            self._events[hold_id] = asyncio.get_running_loop().create_future()
        return self._events[hold_id]

    def send(self, op: str, **fields: Any) -> asyncio.Future[dict[str, Any]]:
        assert self._process is not None and self._process.stdin is not None
        self._next += 1
        identifier = self._next
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[identifier] = future
        self._process.stdin.write((json.dumps({"id": identifier, "op": op, **fields}) + "\n").encode())
        return future

    async def call(self, op: str, **fields: Any) -> dict[str, Any]:
        return await asyncio.wait_for(self.send(op, **fields), timeout=120)

    async def held(self, hold_id: str, timeout: float = 30) -> None:
        await asyncio.wait_for(self._event(hold_id), timeout=timeout)

    async def release(self, hold_id: str) -> None:
        await self.call("release", holdId=hold_id)

    async def clock(self, action: str, **fields: Any) -> int:
        return (await self.call("clock", action=action, **fields))["result"]["now"]

    async def stop(self) -> None:
        process = self._process
        if process is None:
            return
        try:
            if process.stdin is not None:
                process.stdin.close()
            await asyncio.wait_for(process.wait(), timeout=15)
        except (TimeoutError, ProcessLookupError):
            process.kill()
            await process.wait()
        if self._reader is not None:
            self._reader.cancel()
        self._process = None

    def kill(self) -> None:
        """SIGKILL: the process ends where it is, with whatever transaction it had open."""

        if self._process is not None:
            self._process.kill()


def namespace_name(prefix: str = "proc") -> str:
    return f"{prefix}-{secrets.token_hex(6)}"


def capture_id() -> str:
    return "cap_" + "".join(secrets.choice(BASE32) for _ in range(26))


def entry_id() -> str:
    return secrets.token_hex(32)


def attempt_id() -> str:
    return "attempt-" + secrets.token_hex(8)


def scope(namespace: str, tenant: str = "tenant-synthetic-a") -> dict[str, str]:
    return {"namespace": namespace, "tenant": tenant}


class Capture:
    """One synthetic capture: what ``createCapture`` takes and what a later ``commitRestore`` names."""

    def __init__(
        self,
        namespace: str,
        *,
        entries: int = 1,
        max_uses: int = 1,
        tenant: str = "tenant-synthetic-a",
        epoch: int = 1,
        now: int | None = None,
        lifetime: int = HOUR,
        session_tag: str | None = None,
    ) -> None:
        self.scope = scope(namespace, tenant)
        self.capture_id = capture_id()
        self.entry_ids = [entry_id() for _ in range(entries)]
        self.max_uses = max_uses
        self.epoch = epoch
        self.now = real_now() if now is None else now
        self.lifetime = lifetime
        self.session_tag = session_tag

    def create_input(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "epoch": self.epoch,
            "now": self.now,
            "capture": {
                "captureId": self.capture_id,
                "keyRef": "synthetic-key:v1",
                "wrappedKey": "11" * 40,
                "sessionTag": self.session_tag,
                "createdAt": self.now,
                "expiresAt": self.now + self.lifetime,
                "lookupVersion": 1,
            },
            "entries": [
                {"entryId": entry, "maxUses": self.max_uses, "envelope": "22" * 24} for entry in self.entry_ids
            ],
        }

    def commit_input(
        self,
        *,
        attempt: str | None = None,
        digest: str = "33" * 32,
        entries: list[str] | None = None,
        count: int = 1,
        generation: int = 1,
        lifecycle_revision: int = 1,
        now: int | None = None,
    ) -> dict[str, Any]:
        clock = self.now if now is None else now
        return {
            "scope": self.scope,
            "epoch": self.epoch,
            "now": clock,
            "attempt": {"attemptId": attempt or attempt_id(), "requestDigest": digest},
            "receiptExpiresAt": self.now + self.lifetime + HOUR,
            "captures": [{"captureId": self.capture_id, "generation": generation}],
            "uses": [
                {
                    "entryId": entry,
                    "captureId": self.capture_id,
                    "count": count,
                    "lifecycleRevision": lifecycle_revision,
                    "ciphertextRevision": 1,
                }
                for entry in (entries if entries is not None else self.entry_ids[:1])
            ],
        }

    def revoke_input(self, *, fence_absent: bool = False, now: int | None = None) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "captureId": self.capture_id,
            "now": self.now if now is None else now,
            "retentionMs": HOUR,
            "fenceAbsent": fence_absent,
        }


async def restore_with_retry(
    process: DriverProcess, capture: Capture, entry: str, attempt: str, tries: int = 60
) -> str:
    """Read, commit, and read again on ``stale``, as a server does. ``committed`` or the rejection reason."""

    for _ in range(tries):
        read = (await process.call("readEntries", input={"scope": capture.scope, "entryIds": [entry]}))["result"]
        row = read["entries"][0]
        generation = read["captures"][0]["generation"]
        reply = await process.call(
            "commitRestore",
            input=capture.commit_input(
                attempt=attempt,
                entries=[entry],
                generation=generation,
                lifecycle_revision=row["lifecycleRevision"],
            ),
        )
        if "error" in reply:
            return "error:" + reply["error"]
        result = reply["result"]
        if result["outcome"] == "committed":
            return "committed"
        if result["outcome"] == "rejected" and result["reason"] == "stale":
            continue
        return result.get("reason") or result["outcome"]
    return "exhausted"
