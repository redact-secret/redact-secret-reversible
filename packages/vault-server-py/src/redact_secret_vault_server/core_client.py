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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .errors import VaultServerError, VaultServerErrorCode

DEFAULT_BRIDGE_SCRIPT = Path(__file__).parent / "boundary" / "core_bridge.mjs"

# The exact core release this boundary is qualified against, matching the
# pin in this repository's root package.json and
# docs/research/qualification-0.1.0-alpha.1.md. A response reporting a
# different version is treated as CORE_FAILURE rather than silently trusted.
PINNED_CORE_VERSION = "0.1.0-beta.9"


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


@runtime_checkable
class CoreClient(Protocol):
    def scan(
        self,
        text: str,
        *,
        policy: Mapping[str, str] | None = None,
        limits: Mapping[str, int] | None = None,
    ) -> CoreScanOutcome: ...


class NodeCoreBridge:
    """Calls the real ``@redact-secret/core`` over a Node.js subprocess.

    Threat boundary: this class trusts the local ``node`` executable and the
    npm-installed ``@redact-secret/core`` resolved from this repository's
    workspace (or a caller-supplied script/executable). It is a server-side,
    same-host integration only — not qualified for browser/Worker/CSP
    contexts, which remain V1-V4's scope. It never passes a fixture, secret,
    or matched value back to the caller; the core's ``scan`` API structurally
    cannot return one.

    Failure behavior: a missing ``node`` executable, a subprocess timeout, a
    non-zero exit, malformed stdout, or a core-version mismatch each raise
    ``VaultServerError(CORE_FAILURE)`` — fail-closed, never a partial or
    best-effort finding list.

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
    ) -> None:
        resolved_node = node_executable or shutil.which("node")
        if resolved_node is None:
            raise VaultServerError(VaultServerErrorCode.UNSUPPORTED_RUNTIME)
        self._node = resolved_node
        self._script = script
        self._timeout_s = timeout_s
        self._expected_version = expected_core_version

    def scan(
        self,
        text: str,
        *,
        policy: Mapping[str, str] | None = None,
        limits: Mapping[str, int] | None = None,
    ) -> CoreScanOutcome:
        if not isinstance(text, str):
            raise VaultServerError(VaultServerErrorCode.INVALID_ARGUMENT)
        payload = json.dumps({"input": text, "policy": policy, "limits": limits})
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
            raise VaultServerError(
                VaultServerErrorCode.CORE_FAILURE, core_code="BRIDGE_BAD_OUTPUT"
            ) from exc

        if "error" in data:
            raise VaultServerError(
                VaultServerErrorCode.CORE_FAILURE, core_code=data["error"].get("code")
            )
        if self._expected_version is not None and data.get("coreVersion") != self._expected_version:
            raise VaultServerError(
                VaultServerErrorCode.CORE_FAILURE, core_code="CORE_VERSION_MISMATCH"
            )

        findings = tuple(
            CoreFinding(
                id=f["id"],
                type=f["type"],
                detector=f["detector"],
                confidence=f["confidence"],
                obfuscation=f["obfuscation"],
                start=f["start"],
                end=f["end"],
                action=f["action"],
            )
            for f in data["findings"]
        )
        return CoreScanOutcome(
            findings=findings,
            core_version=data["coreVersion"],
            artifact=data.get("artifact", ""),
        )
