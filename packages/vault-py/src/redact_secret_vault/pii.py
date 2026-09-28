"""PII retention and PII option validation helpers.

Python port of ``packages/vault/src/pii.ts``, implementing
docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md
§1 (retention allowlist) and the bridge-side shape checks from §3 "Python
bridge". Each helper is a pure function of its argument, raises only a
fixed, value-free ``VaultServerError``, and never copies or enumerates the
core's PII inventory. The only core knowledge is the public ``pii_``
finding-type prefix and the ``selectors=`` field of the core's own canonical
activation identity.
"""

from __future__ import annotations

import re
from typing import Any

from .errors import VaultServerError, VaultServerErrorCode
from .types import PiiRetention

#: A finding is a PII finding iff its public type starts with exactly this.
PII_TYPE_PREFIX = "pii_"
#: ``PiiRetention.retain``: 1 to this many entries.
MAX_PII_RETAIN_TYPES = 64
#: ``NodeCoreBridge(pii=...)``: 0 to this many selectors.
MAX_PII_SELECTORS = 64
#: Longest selector string ``NodeCoreBridge(pii=...)`` accepts (shape only).
MAX_PII_SELECTOR_LENGTH = 128
#: Longest activation identity accepted, expected or reported.
MAX_PII_ACTIVATION_LENGTH = 512

# An exact public PII type: the `pii_` prefix, then 1 to 124 characters from
# [a-z0-9_-], at most 128 ASCII characters in total. Matched with
# `fullmatch`, so a trailing newline cannot slip past `$`.
_PII_TYPE_PATTERN = re.compile(r"pii_[a-z0-9_-]{1,124}")


def is_pii_finding_type(finding_type: str) -> bool:
    """True iff ``finding_type`` is a PII finding type (prefix check only)."""

    return finding_type.startswith(PII_TYPE_PREFIX)


def resolve_pii_retention(pii: Any) -> frozenset[str] | None:
    """Validates ``CaptureOptions.pii`` (ADR §1). Returns ``None`` when
    absent, otherwise the de-duplicated set of exact PII types whose
    ``redact`` findings may be retained. Raises ``INVALID_ARGUMENT`` when
    ``pii`` is not exactly a ``PiiRetention``, when ``retain`` is not a tuple
    or list of 1 to 64 strings, or when an entry is not an exact public PII
    type. Unknown but well-formed types are accepted and simply never match.
    """

    if pii is None:
        return None
    if type(pii) is not PiiRetention:
        raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
    retain = pii.retain
    if not isinstance(retain, (tuple, list)):
        raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
    entries = tuple(retain)
    if not (1 <= len(entries) <= MAX_PII_RETAIN_TYPES):
        raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
    for entry in entries:
        if type(entry) is not str or _PII_TYPE_PATTERN.fullmatch(entry) is None:
            raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
    return frozenset(entries)


def resolve_pii_selection(pii: Any) -> tuple[str, ...]:
    """Shape check for ``NodeCoreBridge(pii=...)``: a tuple or list of 0 to 64
    strings of 1 to 128 characters. A bare ``str`` is rejected rather than
    iterated character by character. Returns an immutable copy. Selector
    grammar is the core's to judge (``PII_SELECTOR_*``), not this package's.
    """

    if not isinstance(pii, (tuple, list)):
        raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
    entries = tuple(pii)
    if len(entries) > MAX_PII_SELECTORS:
        raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
    for entry in entries:
        if type(entry) is not str or not (1 <= len(entry) <= MAX_PII_SELECTOR_LENGTH):
            raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
    return entries


def resolve_expected_pii_activation(value: Any) -> str | None:
    """Shape check for ``expected_pii_activation``: ``None``, or a 1 to 512
    character string."""

    if value is None:
        return None
    if type(value) is not str or not (1 <= len(value) <= MAX_PII_ACTIVATION_LENGTH):
        raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
    return value


def is_pii_active(activation: str | None) -> bool:
    """True iff an observed activation identity has PII detection active: it
    is not ``None`` (a core without a PII surface) and its ``selectors=``
    field is present and not ``off``. An identity without a readable
    ``selectors=`` field counts as inactive (fail closed)."""

    if activation is None:
        return False
    for part in activation.split(";"):
        if part.startswith("selectors="):
            selectors = part[len("selectors=") :]
            return len(selectors) > 0 and selectors != "off"
    return False
