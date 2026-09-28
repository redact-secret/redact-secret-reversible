"""Client for the qualified service boundary to ``@redact-secret/core``.

See ``boundary/core_bridge.mjs`` and
docs/research/python-server-integration-2026-09-27.md for why this boundary
exists: no native Python distribution of the core is published (verified
against the ``redact-secret/redact-secret`` GitHub organization), so this
package must not reimplement detection (AGENTS.md, CONVENTIONS.md). Detection
happens entirely in the pinned ``@redact-secret/core`` JavaScript package,
invoked as a short-lived Node.js subprocess; this module only parses the safe
finding metadata (id/type/detector/confidence/obfuscation/start/end/action)
that the core's public ``scan`` API returns, never a matched value.

``CoreClient`` is a ``Protocol`` so a caller may substitute a fake in unit
tests (see ``tests/test_server_authority.py``) or, in the future, a
differently-qualified boundary (an HTTP microservice fronting the same core,
for example) without changing ``InMemoryVaultServer``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .errors import VaultServerError, VaultServerErrorCode
from .pii import MAX_PII_ACTIVATION_LENGTH, resolve_expected_pii_activation, resolve_pii_selection

DEFAULT_BRIDGE_SCRIPT = Path(__file__).parent / "boundary" / "core_bridge.mjs"

# The exact core release this boundary is qualified against, matching the
# pin in this repository's root package.json and
# docs/research/qualification-0.1.0-alpha.1.md. A response reporting a
# different version is treated as CORE_FAILURE rather than silently trusted.
PINNED_CORE_VERSION = "0.1.0-beta.10"


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
_SUCCESS_KEYS = frozenset(("findings", "coreVersion", "artifact", "piiActivation"))
_UNPINNED: Any = object()


def _bad_output() -> VaultServerError:
    return VaultServerError(VaultServerErrorCode.CORE_FAILURE, core_code="BRIDGE_BAD_OUTPUT")


def _parse_finding(raw: Any) -> CoreFinding:
    if type(raw) is not dict or raw.keys() != _FINDING_KEYS:
        raise _bad_output()
    if not all(type(raw[key]) is str for key in _FINDING_STR_FIELDS):
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


class NodeCoreBridge:
    """Calls the real ``@redact-secret/core`` over a Node.js subprocess.

    Threat boundary: this class trusts the local ``node`` executable and the
    npm-installed ``@redact-secret/core`` resolved from this repository's
    workspace (or a caller-supplied script/executable). It is a server-side,
    same-host integration only — not qualified for browser/Worker/CSP
    contexts, which remain V1-V4's scope. It never passes a fixture, secret,
    or matched value back to the caller; the core's ``scan`` API structurally
    cannot return one, and the bridge script projects each finding to its
    eight safe metadata fields.

    PII activation (docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md
    §3 "Python bridge"): every ``scan`` runs in a fresh Node.js process whose
    realm has no other initializer, so ``pii`` is the only selection and
    omission means PII off. ``pii`` is forwarded verbatim to the core's
    ``initialize({ pii })``; the core owns selector grammar and its
    ``PII_SELECTOR_*`` rejections surface as ``CORE_FAILURE`` with
    ``core_code``. A non-empty ``pii`` on a core without a PII surface
    (beta.9) raises ``PII_UNAVAILABLE``. Every response's ``piiActivation`` is
    compared with ``expected_pii_activation`` when that is set
    (``PII_UNAVAILABLE`` if the core reports none). Otherwise the identity
    from the first successful response is pinned and every later response
    must match. A difference raises ``PII_ACTIVATION_MISMATCH``, which
    catches a core swapped underneath a long-running server.

    Failure behavior: a malformed ``pii`` or ``expected_pii_activation``
    raises ``INVALID_ARGUMENT`` and a missing ``node`` executable raises
    ``UNSUPPORTED_RUNTIME``, both at construction. A subprocess timeout, a
    non-zero exit, malformed or unexpected stdout, or a core-version mismatch
    each raise ``VaultServerError(CORE_FAILURE)`` — fail-closed, never a
    partial or best-effort finding list.

    Residual risk: a compromised local ``node`` binary or a supply-chain
    compromise of the installed ``@redact-secret/core`` package would affect
    this boundary exactly as it would affect the JS vault; this class adds no
    new trust beyond what already exists for capture in this repository. See
    docs/research/python-server-integration-2026-09-27.md.
    """

    def __init__(
        self,
        *,
        node_executable: str | None = None,
        script: Path = DEFAULT_BRIDGE_SCRIPT,
        timeout_s: float = 10.0,
        expected_core_version: str | None = PINNED_CORE_VERSION,
        pii: Sequence[str] = (),
        expected_pii_activation: str | None = None,
    ) -> None:
        selection = resolve_pii_selection(pii)
        expected_activation = resolve_expected_pii_activation(expected_pii_activation)
        resolved_node = node_executable or shutil.which("node")
        if resolved_node is None:
            raise VaultServerError(VaultServerErrorCode.UNSUPPORTED_RUNTIME)
        self._node = resolved_node
        self._script = script
        self._timeout_s = timeout_s
        self._expected_version = expected_core_version
        self._pii = selection
        self._expected_pii_activation = expected_activation
        self._pinned_pii_activation: Any = _UNPINNED
        self._pin_lock = threading.Lock()

    def scan(
        self,
        text: str,
        *,
        policy: Mapping[str, str] | None = None,
        limits: Mapping[str, int] | None = None,
    ) -> CoreScanOutcome:
        if not isinstance(text, str):
            raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
        payload = json.dumps({"input": text, "pii": list(self._pii), "policy": policy, "limits": limits})
        try:
            proc = subprocess.run(
                [self._node, str(self._script)],
                input=payload,
                capture_output=True,
                text=True,
                timeout=self._timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise VaultServerError(
                VaultServerErrorCode.CORE_FAILURE, core_code="BRIDGE_TIMEOUT"
            ) from exc
        except OSError as exc:
            raise VaultServerError(
                VaultServerErrorCode.CORE_FAILURE, core_code="BRIDGE_SPAWN_FAILED"
            ) from exc

        if proc.returncode != 0 and not proc.stdout.strip():
            raise VaultServerError(
                VaultServerErrorCode.CORE_FAILURE, core_code="BRIDGE_PROCESS_FAILED"
            )
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise _bad_output() from exc
        if type(data) is not dict:
            raise _bad_output()

        if "error" in data:
            error = data["error"]
            if type(error) is not dict:
                raise _bad_output()
            code = error.get("code")
            if code is not None and type(code) is not str:
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
        if activation is not None and (
            type(activation) is not str or not (1 <= len(activation) <= MAX_PII_ACTIVATION_LENGTH)
        ):
            raise _bad_output()
        if self._expected_version is not None and core_version != self._expected_version:
            raise VaultServerError(
                VaultServerErrorCode.CORE_FAILURE, core_code="CORE_VERSION_MISMATCH"
            )

        findings = tuple(_parse_finding(raw) for raw in raw_findings)
        self._check_pii_activation(activation)
        return CoreScanOutcome(
            findings=findings,
            core_version=core_version,
            artifact=artifact,
            pii_activation=activation,
        )

    def _check_pii_activation(self, activation: str | None) -> None:
        if self._expected_pii_activation is not None:
            if activation is None:
                # An expected identity on a core with no PII surface, as
                # `createVault({ expectPiiActivation })` does on beta.9.
                raise VaultServerError(VaultServerErrorCode.PII_UNAVAILABLE)
            if activation != self._expected_pii_activation:
                raise VaultServerError(VaultServerErrorCode.PII_ACTIVATION_MISMATCH)
            return
        with self._pin_lock:
            if self._pinned_pii_activation is _UNPINNED:
                self._pinned_pii_activation = activation
            elif activation != self._pinned_pii_activation:
                raise VaultServerError(VaultServerErrorCode.PII_ACTIVATION_MISMATCH)
