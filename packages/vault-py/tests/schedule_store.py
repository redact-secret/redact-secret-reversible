"""Test-only: the reference store with hold points, for the schedule driver and the mutants.

Nothing here is in the wheel (``verify-python-dist.py`` fails a wheel that contains a test file). The
package's ``MemoryStore`` has no hold point and no fault hook; ``ScheduleStore`` adds the one hold
point the corpus names, ``before-commit``, by pausing a call after its validation and before its atomic
section, which is where the JavaScript store's ``before-apply`` hook pauses. The atomic section then
reads the store's state afresh, so a competing call that ran while the call was held is seen.
"""

from __future__ import annotations

import contextvars
from collections.abc import Awaitable, Callable
from typing import Any

from redact_secret_vault.persistent.store_memory import MemoryStore

#: The store operation whose call is in progress in this task.
_OPERATION: contextvars.ContextVar[str | None] = contextvars.ContextVar("rsv_schedule_operation", default=None)

_OPERATIONS = (
    "create_capture",
    "read_entries",
    "read_captures",
    "commit_restore",
    "revoke_capture",
    "inspect_attempt",
    "replace_capture_key",
    "delete_ciphertext",
    "sweep_expired",
    "recovery_state",
    "initialize_namespace",
    "quarantine",
    "invalidate_recovered",
)


class ScheduleStore(MemoryStore):
    """``MemoryStore`` plus ``hold(operation, pause)``: the next call of ``operation`` awaits ``pause()`` first."""

    def __init__(self, **options: Any) -> None:
        super().__init__(**options)
        self._holds: dict[str, Callable[[], Awaitable[None]]] = {}

    def hold(self, operation: str, pause: Callable[[], Awaitable[None]]) -> None:
        """Pauses the next call of ``operation`` (a snake_case ``Store`` method name), once."""

        if operation not in _OPERATIONS:
            raise ValueError("unknown operation")
        self._holds[operation] = pause

    def release_all(self) -> None:
        self._holds.clear()

    async def _atomic(self, apply: Callable[[int], object]) -> object:
        operation = _OPERATION.get()
        pause = self._holds.pop(operation, None) if operation is not None else None
        if pause is not None:
            await pause()
        return await super()._atomic(apply)


def _tracked(name: str) -> Callable[..., Any]:
    base = getattr(MemoryStore, name)

    async def method(self: ScheduleStore, *args: Any, **kwargs: Any) -> Any:
        token = _OPERATION.set(name)
        try:
            return await base(self, *args, **kwargs)
        finally:
            _OPERATION.reset(token)

    method.__name__ = name
    return method


for _name in _OPERATIONS:
    setattr(ScheduleStore, _name, _tracked(_name))


def current_operation() -> str | None:
    """The operation whose call is in progress in this task (for a mutant that behaves differently per operation)."""

    return _OPERATION.get()
