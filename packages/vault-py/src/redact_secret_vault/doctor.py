"""``python -m redact_secret_vault doctor``: check that this installation can
reach ``@redact-secret/core``.

The package needs a ``node`` executable and the core at exactly
``PINNED_CORE_VERSION`` in a ``node_modules`` directory the application owns.
When one of those is missing, the first capture fails with a fixed code and no
path. This command runs the same bridge once and says which part is wrong and
how to fix it.

It scans one fixed synthetic input and prints counts and versions only: never
a finding's value. It prints the ``node_modules`` path, which the operator
running the command supplied.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

from .core_client import DEFAULT_BRIDGE_SCRIPT, NODE_MODULES_ENV, PINNED_CORE_VERSION, NodeCoreBridge
from .errors import VaultServerError

#: Node.js major versions the bridge is tested on.
SUPPORTED_NODE_MAJORS = (20, 22, 24)

# Unmistakably synthetic; never a real credential.
_SYNTHETIC_INPUT = "doctor check ghp_SYNTHETICxREVOKEDxTESTx0000000000000"
_NODE_VERSION_TIMEOUT_S = 10.0

_INSTALL_FIX = (
    f"run `npm install @redact-secret/core@{PINNED_CORE_VERSION}` in a directory your application owns, "
    f"then pass --node-modules <that directory>/node_modules or set {NODE_MODULES_ENV}"
)
_CORE_FIXES = {
    "BRIDGE_CORE_NOT_FOUND": f"the core is not in that directory: {_INSTALL_FIX}",
    "BRIDGE_CORE_LOAD_FAILED": (
        "the core is there but did not load: reinstall it with "
        f"`npm install @redact-secret/core@{PINNED_CORE_VERSION}` using the same Node.js that is on PATH"
    ),
    "BRIDGE_SPAWN_FAILED": "the node executable could not be started: check that it is runnable",
    "BRIDGE_TIMEOUT": "the bridge did not answer in time: run the command again, and check the machine's load",
}


def _node_version(node: str) -> str | None:
    try:
        done = subprocess.run(
            [node, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=_NODE_VERSION_TIMEOUT_S,
            check=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    text = done.stdout.decode("ascii", "replace").strip()
    return text if done.returncode == 0 and text.startswith("v") and len(text) <= 32 else None


def _node_major(version: str) -> int | None:
    head = version[1:].split(".", 1)[0]
    return int(head) if head.isdigit() else None


def run_doctor(
    node_modules: str | os.PathLike[str] | None = None,
    *,
    node_executable: str | None = None,
    script: Path = DEFAULT_BRIDGE_SCRIPT,
    out: Callable[[str], None] = print,
) -> int:
    """Run every check and report each on one line. Returns 0 when all pass,
    1 otherwise. A check that cannot run because an earlier one failed is
    reported as skipped."""
    failed = False

    def ok(name: str, detail: str) -> None:
        out(f"ok    {name}: {detail}")

    def fail(name: str, detail: str, fix: str) -> None:
        nonlocal failed
        failed = True
        out(f"FAIL  {name}: {detail}")
        out(f"      fix: {fix}")

    # 1. node
    node = node_executable or shutil.which("node")
    version = _node_version(node) if node is not None else None
    if node is None or version is None:
        fail("node", "no working `node` executable on PATH", "install Node.js 20, 22, or 24 and put it on PATH")
        out("skip  core: needs node")
        return 1
    major = _node_major(version)
    if major in SUPPORTED_NODE_MAJORS:
        ok("node", version)
    else:
        fail("node", f"{version} is not a tested version", "use Node.js 20, 22, or 24")

    # 2. where the core is loaded from
    explicit = node_modules is not None
    try:
        bridge = NodeCoreBridge(
            node_executable=node,
            script=script,
            node_modules=node_modules,
            expected_core_version=None,
        )
    except VaultServerError:
        fail("core location", "the node_modules path is not usable", "pass an existing directory path")
        out("skip  core: needs a core location")
        return 1
    location = bridge._node_modules
    if location is not None:
        source = "--node-modules" if explicit else NODE_MODULES_ENV
        ok("core location", f"{location} (from {source})")
    else:
        ok("core location", "next to the installed package (no --node-modules and no " + NODE_MODULES_ENV + ")")

    # 3. the core loads, 4. at the pinned version
    try:
        with bridge:
            outcome = bridge.scan(_SYNTHETIC_INPUT)
    except VaultServerError as error:
        code = error.core_code or error.code.value
        fix = _CORE_FIXES.get(code, _INSTALL_FIX)
        if code == "BRIDGE_CORE_NOT_FOUND" and location is None:
            fix = _INSTALL_FIX
        fail("core", code, fix)
        return 1
    if outcome.core_version == PINNED_CORE_VERSION:
        ok("core", f"@redact-secret/core {outcome.core_version} loaded ({outcome.artifact})")
    else:
        fail(
            "core",
            f"found @redact-secret/core {outcome.core_version}, need exactly {PINNED_CORE_VERSION}",
            f"run `npm install @redact-secret/core@{PINNED_CORE_VERSION}` in that directory",
        )
    if len(outcome.findings) >= 1:
        ok("scan", f"{len(outcome.findings)} finding(s) in the synthetic input")
    else:
        fail("scan", "the core found nothing in the synthetic input", "reinstall the core; this build detects nothing")

    return 1 if failed else 0
