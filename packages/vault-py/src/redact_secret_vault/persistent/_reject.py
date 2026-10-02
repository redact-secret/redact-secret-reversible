"""Internal: how the canonical encoders fail without leaving a link behind.

Helpers deep in a call raise ``Reject`` (private to the package). A public entry
point is wrapped by ``sanitized``, which lets ``Reject`` end its ``except``
block and only then raises a new ``RecordCryptoError`` from the entry point's
own frame. The error handed to the caller therefore has ``__cause__`` and
``__context__`` both ``None``, and its traceback starts at the entry point
instead of at a helper whose locals hold keys or plaintext
(docs/plans/python-persistence-parity.md section 3.4).
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import NoReturn, ParamSpec, TypeVar

from .errors import RecordCryptoError, RecordCryptoErrorCode

P = ParamSpec("P")
R = TypeVar("R")


class Reject(Exception):
    """Carries only a code. Never leaves the package."""

    def __init__(self, code: RecordCryptoErrorCode) -> None:
        super().__init__(code)
        self.code = code


def reject(code: RecordCryptoErrorCode) -> NoReturn:
    raise Reject(code)


def sanitized(fn: Callable[P, R]) -> Callable[P, R]:
    """Turn ``Reject`` into a fresh ``RecordCryptoError`` raised outside any ``except`` block."""

    @functools.wraps(fn)
    def entry(*args: P.args, **kwargs: P.kwargs) -> R:
        code: RecordCryptoErrorCode | None = None
        result: R | None = None
        try:
            result = fn(*args, **kwargs)
        except Reject as rejected:
            code = rejected.code
        if code is not None:
            raise RecordCryptoError(code)
        return result  # type: ignore[return-value]

    return entry
