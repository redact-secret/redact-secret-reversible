"""Runs the shared language-neutral adversarial conformance corpus
(``conformance/v1/corpus.json``) against ``InMemoryVaultServer``, the same
corpus `@redact-secret/vault` (JS) qualifies against
(``packages/vault/test/suite.js``). See ``conformance_runtime.py`` for the
adapter and its one documented, ADR-mandated divergence.

Every case runs in two PII lanes (``conformance_runtime.PII_LANES``): the
bridge's core with PII off (selection ``()``) and with PII on (selection
``("pii",)``). Cases that name a ``piiActivation`` run only in their lane;
cases that need a realm-global shared activation are skipped with a reason.

Requires a ``node`` executable and ``@redact-secret/core`` installed at the
repository root (``npm ci`` there first) — this exercises the real qualified
service boundary, not a fake.
"""

from __future__ import annotations

import asyncio
import re
import shutil

import pytest
from conformance_runtime import (
    PII_LANES,
    CaseSkipped,
    ConformanceFailure,
    case_skip_reason,
    load_corpus,
    run_case,
)

TOKEN_LIKE_PATTERN = re.compile(r"rsv_[a-z2-7]{26}")

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="node is required for the @redact-secret/core service boundary",
)

_CORPUS = load_corpus()


@pytest.mark.parametrize("lane", list(PII_LANES))
@pytest.mark.parametrize("case", _CORPUS["cases"], ids=[c["id"] for c in _CORPUS["cases"]])
def test_conformance_case(case: dict, lane: str) -> None:
    try:
        asyncio.run(run_case(case, _CORPUS["fixtures"], lane=lane))
    except CaseSkipped as exc:
        pytest.skip(str(exc))
    except ConformanceFailure as exc:
        pytest.fail(str(exc))


def test_corpus_has_expected_case_count() -> None:
    # A sentinel so a corpus upgrade (or a broken load) is visible as a
    # test change, not a silent drop in coverage.
    assert len(_CORPUS["cases"]) >= 50
    pii_cases = [c for c in _CORPUS["cases"] if c["id"].startswith("pii.")]
    assert len(pii_cases) >= 11
    # Only the two shared-realm activation-conflict cases may be skipped in
    # every lane; every other PII case is replayed here.
    unrunnable = [c["id"] for c in pii_cases if all(case_skip_reason(c, lane) is not None for lane in PII_LANES)]
    assert unrunnable == ["pii.activation.conflict-when-off", "pii.activation.conflict-when-on"]


@pytest.mark.parametrize("lane", list(PII_LANES))
def test_leakage_across_corpus(lane: str) -> None:
    """Mirrors packages/vault/test/suite.js's leakage check: no fixture
    value or issued token appears in any error or audit event produced
    while replaying the whole corpus."""

    fixtures = _CORPUS["fixtures"]
    secrets = list(fixtures.values())
    token_like = TOKEN_LIKE_PATTERN
    error_count = 0
    audit_count = 0

    for case in _CORPUS["cases"]:
        observed: dict = {"errors": [], "audit": []}
        try:
            asyncio.run(run_case(case, fixtures, observed=observed, lane=lane))
        except (ConformanceFailure, CaseSkipped):
            pass  # Correctness is covered by test_conformance_case; here we only check leakage.
        error_count += len(observed["errors"])
        audit_count += len(observed["audit"])
        haystacks = [repr(e) + str(e) for e in observed["errors"]] + [repr(a) for a in observed["audit"]]
        for text in haystacks:
            for secret in secrets:
                assert secret not in text, f"{case['id']}: fixture value leaked into diagnostics"
            assert not token_like.search(text), f"{case['id']}: issued token leaked into diagnostics"

    assert error_count > 15, "too few errors observed for a meaningful leakage check"
    assert audit_count > 15, "too few audit events observed for a meaningful leakage check"
