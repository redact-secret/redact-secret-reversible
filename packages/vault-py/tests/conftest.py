from __future__ import annotations

import pytest

from redact_secret_vault.core_client import NODE_MODULES_ENV


@pytest.fixture(autouse=True)
def _no_ambient_core_location(monkeypatch):
    """Keep a developer's REDACT_SECRET_VAULT_NODE_MODULES out of every test;
    tests that exercise it set it themselves."""
    monkeypatch.delenv(NODE_MODULES_ENV, raising=False)
