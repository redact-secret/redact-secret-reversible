#!/usr/bin/env python3
"""Smoke-test an installed redact-secret-vault wheel outside the repository.

Run with the Python of a virtualenv that has the built wheel installed and
lives outside this repository (release.yml's python-dist job does this), with
SMOKE_NODE_MODULES set to a node_modules directory holding
@redact-secret/core at PINNED_CORE_VERSION.

Checks, in order:
1. redact_secret_vault is imported from that virtualenv, not from a checkout.
2. Without node_modules= (and without REDACT_SECRET_VAULT_NODE_MODULES), the
   bundled bridge cannot find the core from site-packages and fails closed
   with CORE_FAILURE / BRIDGE_CORE_NOT_FOUND. This proves the next check is
   not passing by accident through script-relative resolution.
3. With node_modules=SMOKE_NODE_MODULES, a scan of a synthetic token returns
   exactly one github_token finding from the pinned core.
"""

import os
import sys
from pathlib import Path

import redact_secret_vault
from redact_secret_vault import NodeCoreBridge, VaultServerError, VaultServerErrorCode
from redact_secret_vault.core_client import NODE_MODULES_ENV, PINNED_CORE_VERSION

SYNTHETIC_TOKEN = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000"


def fail(message: str) -> None:
    sys.exit(f"smoke test failed: {message}")


def main() -> None:
    node_modules = os.environ.get("SMOKE_NODE_MODULES", "")
    if not node_modules:
        fail("SMOKE_NODE_MODULES is not set")
    os.environ.pop(NODE_MODULES_ENV, None)

    package_file = Path(redact_secret_vault.__file__).resolve()
    if not package_file.is_relative_to(Path(sys.prefix).resolve()):
        fail(f"redact_secret_vault was imported from {package_file}, not from the virtualenv at {sys.prefix}")
    print(f"redact_secret_vault {redact_secret_vault.__version__} from {package_file.parent}")

    try:
        NodeCoreBridge().scan("text-synthetic")
    except VaultServerError as error:
        if error.code != VaultServerErrorCode.CORE_FAILURE or error.core_code != "BRIDGE_CORE_NOT_FOUND":
            fail(f"without node_modules=, expected CORE_FAILURE/BRIDGE_CORE_NOT_FOUND, got {error}")
        print("without node_modules=: CORE_FAILURE/BRIDGE_CORE_NOT_FOUND, as expected")
    else:
        fail("without node_modules=, the bridge found a core; the location check proves nothing")

    outcome = NodeCoreBridge(node_modules=node_modules).scan(f"deploy with {SYNTHETIC_TOKEN} now")
    types = [finding.type for finding in outcome.findings]
    if outcome.core_version != PINNED_CORE_VERSION:
        fail(f"core version {outcome.core_version}, expected {PINNED_CORE_VERSION}")
    if types != ["github_token"]:
        fail(f"expected one github_token finding, got {types}")
    print(f"with node_modules=: core {outcome.core_version} ({outcome.artifact}), findings {types}")


if __name__ == "__main__":
    main()
