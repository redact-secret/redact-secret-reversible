"""Sanitized errors shared by stores, key providers, and crypto layers.

Mirrors ``packages/vault-contracts/src/errors.ts`` (docs/specs/persistent-vault.md
section 4.1). Every message is a fixed string chosen by ``code``. No error
carries a driver or SDK message, an input, a key, ciphertext, or a token.

The JavaScript rule is "``cause`` is never set". Python has two links, and
``raise X from None`` clears only one of them, so code in the persistent
modules raises these errors only after any ``except`` block has ended; see
docs/plans/python-persistence-parity.md section 3.4.
"""

from __future__ import annotations

from typing import Literal

StoreErrorCode = Literal[
    "STORE_UNAVAILABLE",
    "STORE_AMBIGUOUS",
    "STORE_INVALID_ARGUMENT",
    "STORE_CAPABILITY",
    "STORE_CLOSED",
]

KeyProviderErrorCode = Literal[
    "KEY_UNAVAILABLE",
    "KEY_INTEGRITY",
    "KEY_TIMEOUT",
    "KEY_THROTTLED",
    "KEY_ABORTED",
    "KEY_INVALID_ARGUMENT",
]

RecordCryptoErrorCode = Literal[
    "RECORD_MALFORMED",
    "RECORD_UNSUPPORTED",
    "RECORD_INTEGRITY",
    "RECORD_LIMIT",
    "RECORD_INVALID_ARGUMENT",
]

STORE_MESSAGES: dict[str, str] = {
    "STORE_UNAVAILABLE": "The store was unavailable; the operation had no effect.",
    "STORE_AMBIGUOUS": "The store could not confirm whether the operation took effect.",
    "STORE_INVALID_ARGUMENT": "The store operation received an input that violates the contract.",
    "STORE_CAPABILITY": "The store operation exceeds a declared store capability.",
    "STORE_CLOSED": "The store adapter has been closed.",
}

KEY_MESSAGES: dict[str, str] = {
    "KEY_UNAVAILABLE": "The key is unknown, disabled, retired, or outside the provider's scope.",
    "KEY_INTEGRITY": "The wrapped key did not authenticate for this context.",
    "KEY_TIMEOUT": "The key provider did not answer in time.",
    "KEY_THROTTLED": "The key provider refused the call for load.",
    "KEY_ABORTED": "The key provider call was cancelled.",
    "KEY_INVALID_ARGUMENT": "The key provider received an input that violates the contract.",
}

RECORD_MESSAGES: dict[str, str] = {
    "RECORD_MALFORMED": "The encrypted record is not well-formed.",
    "RECORD_UNSUPPORTED": "The encrypted record uses an unsupported version or algorithm.",
    "RECORD_INTEGRITY": "The encrypted record did not authenticate.",
    "RECORD_LIMIT": "The record exceeds a size limit.",
    "RECORD_INVALID_ARGUMENT": "The crypto operation received an input that violates the contract.",
}


class _SanitizedError(Exception):
    """Shared shape: a code, and the one fixed message that code selects."""

    _messages: dict[str, str]
    code: str

    def __init__(self, code: str) -> None:
        message = self._messages[code]  # KeyError for an unknown code
        super().__init__(message)
        self.code = code

    def __reduce__(self) -> tuple[type, tuple[str]]:
        return (type(self), (self.code,))


class StoreError(_SanitizedError):
    """A store failure. ``code`` selects a fixed message; nothing else is carried."""

    _messages = STORE_MESSAGES
    code: StoreErrorCode

    def __init__(self, code: StoreErrorCode) -> None:
        super().__init__(code)


class KeyProviderError(_SanitizedError):
    """A key provider failure. ``code`` selects a fixed message; nothing else is carried."""

    _messages = KEY_MESSAGES
    code: KeyProviderErrorCode

    def __init__(self, code: KeyProviderErrorCode) -> None:
        super().__init__(code)


class RecordCryptoError(_SanitizedError):
    """A record encoding or crypto failure. ``code`` selects a fixed message; nothing else is carried."""

    _messages = RECORD_MESSAGES
    code: RecordCryptoErrorCode

    def __init__(self, code: RecordCryptoErrorCode) -> None:
        super().__init__(code)
