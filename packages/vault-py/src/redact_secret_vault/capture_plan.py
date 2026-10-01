"""The capture plan: everything a capture decides before anything is retained.

One input goes in; out come the redacted text and, for each finding that may
be retained, the issued token, the finding type, and the finding's range in
that input. The plan returns no value: the caller slices the input it already
holds (``CapturePlan.value_of``). It reads no vault and keeps no mapping, so
``InMemoryVaultServer`` and the persistent server profile share one
implementation of capture eligibility: argument validation, the core scan, the
action gate, the PII allowlist, ``eligible``, limits, token issuance, and
formatting (docs/specs/persistent-vault.md section 8.1).

Python counterpart of ``@redact-secret/vault/internal/capture-plan``. Internal:
not exported from the package root, with no stability guarantee.

Behavior is the behavior ``InMemoryVaultServer._capture`` had before the
extraction, check for check and in the same order, so the in-memory corpus
results are unchanged.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .core_client import CoreClient, CoreFinding
from .errors import VaultServerError, VaultServerErrorCode
from .pii import is_pii_active, is_pii_finding_type, resolve_pii_retention
from .token import has_marker, new_token
from .utf16 import build_unit_offsets, char_index, utf16_slice

__all__ = [
    "CAPTURE_DEFAULT_LIMITS",
    "CAPTURE_LIMIT_CEILINGS",
    "CapturePlan",
    "PlannedEntry",
    "PlannedGrant",
    "plan_capture",
    "resolve_capture_limits",
]

CAPTURE_DEFAULT_LIMITS: Mapping[str, int] = {
    "max_entries": 256,
    "max_retained_bytes": 64 * 1024,
    "max_value_bytes": 8 * 1024,
    "entry_ttl_ms": 10 * 60 * 1000,
    "vault_ttl_ms": 60 * 60 * 1000,
    "max_input_bytes": 1024 * 1024,
    "max_findings": 1024,
    "max_restore_fields": 64,
    "max_restore_field_bytes": 1024 * 1024,
    "max_uses_per_entry": 16,
}

#: Hard ceilings: a configured limit above these is rejected, not clamped.
CAPTURE_LIMIT_CEILINGS: Mapping[str, int] = {
    "max_entries": 100_000,
    "max_retained_bytes": 64 * 1024 * 1024,
    "max_value_bytes": 1024 * 1024,
    "entry_ttl_ms": 24 * 60 * 60 * 1000,
    "vault_ttl_ms": 24 * 60 * 60 * 1000,
    "max_input_bytes": 64 * 1024 * 1024,
    "max_findings": 50_000,
    "max_restore_fields": 10_000,
    "max_restore_field_bytes": 64 * 1024 * 1024,
    "max_uses_per_entry": 1_000,
}

MAX_IDENTIFIER_LENGTH = 256
MAX_GRANTS = 64
MAX_PATHS_PER_GRANT = 256
#: Attempts at a fresh token before giving up.
TOKEN_ATTEMPTS = 4


def _invalid() -> VaultServerError:
    return VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)


def _is_identifier(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_IDENTIFIER_LENGTH


def _utf8_length(text: str) -> int:
    return len(text.encode("utf-8"))


def resolve_capture_limits(
    partial: Mapping[str, int] | None,
    *,
    defaults: Mapping[str, int] = CAPTURE_DEFAULT_LIMITS,
    ceilings: Mapping[str, int] = CAPTURE_LIMIT_CEILINGS,
) -> dict[str, int]:
    """``defaults`` with ``partial`` applied; an unknown key or a value above its ceiling is ``INVALID_ARGUMENT``."""

    resolved = dict(defaults)
    for key, value in (partial or {}).items():
        if key not in defaults:
            raise _invalid()
        if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= ceilings[key]):
            raise _invalid()
        resolved[key] = value
    return resolved


@dataclass(frozen=True, slots=True)
class PlannedEntry:
    """One retained finding: its issued token, type, and range in the input."""

    token: str
    #: UTF-16 offset into the planned input, inclusive.
    start: int
    #: UTF-16 offset into the planned input, exclusive.
    end: int
    type: str


@dataclass(frozen=True, slots=True)
class PlannedGrant:
    """One release grant, deduplicated: a sink and the paths allowed in it."""

    sink: str
    paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CapturePlan:
    #: The redacted text: each retained token exactly once, no other marker.
    text: str
    #: Retained findings, in input order. Holds ranges, never values.
    retained: tuple[PlannedEntry, ...]
    passed_through: int
    #: Sorted, deduplicated types of the ``warn`` and ``allow`` findings.
    passed_through_types: tuple[str, ...]
    unrestorable: int
    #: ``options.release``, validated: one item per sink, paths deduplicated.
    grants: tuple[PlannedGrant, ...]
    #: The effective ``options.max_uses``.
    max_uses: int
    #: The input's UTF-16 offsets, so ``value_of`` slices without recomputing them. Not part of the plan's identity.
    _offsets: Sequence[int] = field(default=(), repr=False, compare=False)

    def value_of(self, input_text: str, entry: PlannedEntry) -> str:
        """The retained value: the slice of the input the caller already holds."""

        return utf16_slice(input_text, entry.start, entry.end, self._offsets if self._offsets else None)  # type: ignore[arg-type]


def plan_capture(
    core: CoreClient,
    input_text: str,
    options: Any,
    limits: Mapping[str, int],
    *,
    budget: Callable[[], tuple[int, int]] | None = None,
    is_taken: Callable[[str], bool] | None = None,
    expected_pii_activation: str | None = None,
) -> CapturePlan:
    """Plans one capture.

    ``options`` carries ``release``, ``max_uses``, ``unredacted``, ``policy``, ``eligible``, and ``pii`` (the
    ``CaptureOptions`` fields). ``budget`` is read once, after the input checks and before the core scan, and returns
    ``(live entries, retained bytes)`` the holder already has; a holder that holds nothing in this address space (a
    persistent server) omits it. ``is_taken`` says whether the holder already has a live entry under a token.
    ``expected_pii_activation``, when given, is compared with the activation identity the scan reports, and a different
    one is ``PII_ACTIVATION_MISMATCH`` before anything is gated or staged.
    """

    if not isinstance(input_text, str):
        raise _invalid()
    release = options.release
    if not release or len(release) > MAX_GRANTS:
        raise _invalid()
    grants: dict[str, dict[str, None]] = {}
    for grant in release:
        if not _is_identifier(grant.sink) or not grant.paths or len(grant.paths) > MAX_PATHS_PER_GRANT:
            raise _invalid()
        bucket = grants.setdefault(grant.sink, {})
        for path in grant.paths:
            if not _is_identifier(path):
                raise _invalid()
            bucket[path] = None
    max_uses = options.max_uses
    if not isinstance(max_uses, int) or not (1 <= max_uses <= limits["max_uses_per_entry"]):
        raise _invalid()
    if options.unredacted not in ("reject", "pass-through"):
        raise _invalid()
    eligible = options.eligible
    if eligible is not None and not callable(eligible):
        raise _invalid()
    # PII retention allowlist (PII ADR section 1), validated before the core runs. Whether PII detection is active is
    # checked right after the scan, against the identity that scan's own core realm reported.
    pii_retain = resolve_pii_retention(options.pii)

    if _utf8_length(input_text) > limits["max_input_bytes"]:
        raise VaultServerError(VaultServerErrorCode.LIMIT_EXCEEDED)
    if has_marker(input_text):
        raise VaultServerError(VaultServerErrorCode.TOKEN_LITERAL_IN_INPUT)

    live_entries, retained_bytes = (0, 0) if budget is None else budget()

    outcome = core.scan(
        input_text,
        policy=options.policy,
        limits={"maxInputBytes": limits["max_input_bytes"], "maxFindings": limits["max_findings"]},
    )
    # A capture that configures PII retention on a core that cannot produce PII findings (no PII surface, or
    # ``selectors=off``) would let the application believe PII is handled while it passes through as undetected
    # plaintext (PII ADR section 1). Refused before any finding is gated or staged.
    if pii_retain is not None and not is_pii_active(outcome.pii_activation):
        raise VaultServerError(VaultServerErrorCode.PII_UNAVAILABLE)
    if expected_pii_activation is not None and outcome.pii_activation != expected_pii_activation:
        raise VaultServerError(VaultServerErrorCode.PII_ACTIVATION_MISMATCH)
    findings = outcome.findings

    offsets = build_unit_offsets(input_text)
    total_units = offsets[-1]

    passed_through = 0
    passed_types: set[str] = set()
    retain: list[CoreFinding] = []
    unrestorable = 0
    previous_end = 0
    for finding in findings:
        if finding.start < previous_end or finding.end <= finding.start or finding.end > total_units:
            raise VaultServerError(VaultServerErrorCode.INVARIANT_VIOLATION)
        previous_end = finding.end
        if finding.action == "block":
            raise VaultServerError(VaultServerErrorCode.BLOCKED_FINDING)
        if finding.action in ("warn", "allow"):
            passed_through += 1
            passed_types.add(finding.type)
        elif finding.action == "redact":
            keep = True
            if is_pii_finding_type(finding.type) and (pii_retain is None or finding.type not in pii_retain):
                # A PII finding outside the exact-type allowlist is never retained, and ``eligible`` is not consulted:
                # it may narrow the allowlist, never widen it.
                keep = False
            elif eligible is not None:
                try:
                    keep = (
                        eligible(
                            {
                                "id": finding.id,
                                "type": finding.type,
                                "detector": finding.detector,
                                "confidence": finding.confidence,
                                "obfuscation": finding.obfuscation,
                            }
                        )
                        is True
                    )
                except Exception as exc:
                    raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT) from exc
            if keep:
                retain.append(finding)
            else:
                unrestorable += 1
        else:
            raise VaultServerError(VaultServerErrorCode.INVARIANT_VIOLATION)

    if passed_through > 0 and options.unredacted == "reject":
        raise VaultServerError(VaultServerErrorCode.UNREDACTED_FINDINGS)
    if live_entries + len(retain) > limits["max_entries"]:
        raise VaultServerError(VaultServerErrorCode.LIMIT_EXCEEDED)

    staged: dict[str, tuple[str, int, int, str]] = {}
    staged_tokens: set[str] = set()
    staged_bytes = 0
    for finding in retain:
        value = utf16_slice(input_text, finding.start, finding.end, offsets)
        value_bytes = _utf8_length(value)
        staged_bytes += value_bytes
        if value_bytes > limits["max_value_bytes"] or retained_bytes + staged_bytes > limits["max_retained_bytes"]:
            raise VaultServerError(VaultServerErrorCode.LIMIT_EXCEEDED)
        token = _issue_token(staged_tokens, is_taken)
        staged_tokens.add(token)
        staged[finding.id] = (token, finding.start, finding.end, finding.type)

    # Assemble the redacted text: retained findings become issued tokens, ineligible ``redact`` findings become a
    # non-restorable display placeholder, ``warn``/``allow`` are left as plaintext. ``placeholder_index`` counts every
    # ``redact`` finding in order (both kinds), one-based, as the core's own ``PlaceholderContext.placeholderIndex``.
    pieces: list[str] = []
    cursor = 0
    placeholder_index = 0
    for finding in findings:
        start_index = char_index(offsets, finding.start)
        end_index = char_index(offsets, finding.end)
        pieces.append(input_text[cursor:start_index])
        if finding.action == "redact":
            placeholder_index += 1
            if finding.id in staged:
                pieces.append(staged[finding.id][0])
            else:
                pieces.append(f"<SECRET_{placeholder_index}>")
        else:
            pieces.append(input_text[start_index:end_index])
        cursor = end_index
    pieces.append(input_text[cursor:])

    return CapturePlan(
        text="".join(pieces),
        retained=tuple(
            PlannedEntry(token=token, start=start, end=end, type=kind) for token, start, end, kind in staged.values()
        ),
        passed_through=passed_through,
        passed_through_types=tuple(sorted(passed_types)),
        unrestorable=unrestorable,
        grants=tuple(PlannedGrant(sink=sink, paths=tuple(paths)) for sink, paths in grants.items()),
        max_uses=max_uses,
        _offsets=offsets,
    )


def _issue_token(staged: set[str], is_taken: Callable[[str], bool] | None) -> str:
    for _ in range(TOKEN_ATTEMPTS):
        token = new_token()
        if token not in staged and (is_taken is None or not is_taken(token)):
            return token
    raise VaultServerError(VaultServerErrorCode.TOKEN_GENERATION_FAILED)
