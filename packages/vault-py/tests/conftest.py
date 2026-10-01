from __future__ import annotations

import sys

import pytest

from redact_secret_vault.core_client import NODE_MODULES_ENV


@pytest.fixture(autouse=True)
def _no_ambient_core_location(monkeypatch):
    """Keep a developer's REDACT_SECRET_VAULT_NODE_MODULES out of every test;
    tests that exercise it set it themselves."""
    monkeypatch.delenv(NODE_MODULES_ENV, raising=False)


# The persistent modules need Python 3.11 or later (docs/decisions/python-persistence-api-and-packaging.md);
# the rest of the package keeps its own floor, so their tests are not collected on 3.10.
collect_ignore_glob = (
    ["test_persistent_*.py", "test_crypto_*.py", "test_import_isolation.py", "test_store_memory.py"]
    if sys.version_info < (3, 11)
    else []
)
