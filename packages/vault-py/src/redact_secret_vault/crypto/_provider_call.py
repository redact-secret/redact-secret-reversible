"""Internal: the only way this package calls a ``KeyProvider`` (spec section 6.1).

A call is bounded by a timeout and can only end in a validated result or a
``ProviderReject`` carrying a code: a provider's own exception, its message, its
traceback, and its frames never pass through. A result that arrives after the call
was given up is overwritten by ``discard``. Task cancellation of the caller
propagates as ``asyncio.CancelledError`` and is never converted (plan section 3.7).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

from ..persistent import _buffers
from ..persistent import limits as _limits
from ..persistent.contracts import DataKey, StoredKey
from ..persistent.errors import KEY_MESSAGES, KeyProviderError, KeyProviderErrorCode
from ..persistent.validate import is_key_ref

T = TypeVar("T")


class ProviderReject(Exception):
    """Carries only a key provider code. Never leaves the package."""

    def __init__(self, code: KeyProviderErrorCode) -> None:
        super().__init__(code)
        self.code = code


def _is_wrapped_key(value: object) -> bool:
    return isinstance(value, bytes) and 1 <= len(value) <= _limits.WRAPPED_KEY_MAX_BYTES


def check_data_key(result: object) -> DataKey | None:
    if not isinstance(result, DataKey) or not is_key_ref(result.key_ref) or not _is_wrapped_key(result.wrapped_key):
        return None
    key = result.plaintext_key
    if type(key) is not bytearray or len(key) != _limits.DATA_KEY_BYTES:
        return None
    return result


def discard_data_key(result: object) -> None:
    key = getattr(result, "plaintext_key", None) if isinstance(result, DataKey) else None
    if isinstance(key, bytearray):
        _buffers.zero(key)


def check_plaintext_key(result: object) -> bytearray | None:
    if type(result) is bytearray and len(result) == _limits.DATA_KEY_BYTES:
        return result
    return None


def discard_plaintext_key(result: object) -> None:
    if isinstance(result, bytearray):
        _buffers.zero(result)


def check_stored_key(result: object) -> StoredKey | None:
    if isinstance(result, StoredKey) and is_key_ref(result.key_ref) and _is_wrapped_key(result.wrapped_key):
        return StoredKey(result.key_ref, bytes(result.wrapped_key))
    return None


def _discard_late(discard: Callable[[object], None]) -> Callable[[asyncio.Task[object]], None]:
    def callback(task: asyncio.Task[object]) -> None:
        if task.cancelled() or task.exception() is not None:  # exception() marks it retrieved
            return
        discard(task.result())

    return callback


async def call_provider(
    invoke: Callable[[], Awaitable[T]],
    check: Callable[[object], T | None],
    discard: Callable[[object], None],
    timeout_s: float,
) -> T:
    async def run() -> T:
        return await invoke()

    task: asyncio.Task[T] = asyncio.ensure_future(run())
    try:
        done, _ = await asyncio.wait({task}, timeout=timeout_s)
    except asyncio.CancelledError:
        # The caller was cancelled: give the call up, overwrite whatever it still returns, and propagate.
        task.cancel()
        task.add_done_callback(_discard_late(discard))
        raise

    code: KeyProviderErrorCode | None = None
    checked: T | None = None
    if task not in done:
        task.cancel()
        task.add_done_callback(_discard_late(discard))
        code = "KEY_TIMEOUT"
    elif task.cancelled():
        code = "KEY_UNAVAILABLE"
    else:
        failure = task.exception()
        if failure is not None:
            code = failure.code if isinstance(failure, KeyProviderError) and failure.code in KEY_MESSAGES else None
            code = code or "KEY_UNAVAILABLE"
            failure = None  # drop the provider's exception, its traceback, and its frames
        else:
            result = task.result()
            checked = check(result)
            if checked is None:
                discard(result)
                code = "KEY_UNAVAILABLE"
            result = None
    if code is not None:
        raise ProviderReject(code)
    return checked  # type: ignore[return-value]
