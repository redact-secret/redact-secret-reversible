"""Capture parity between the persistent server profile and ``InMemoryVaultServer``
(docs/plans/python-persistence-parity.md section 6.2, gate G5 for the in-memory half).

Persistence must not change what is retained. Every capture step of the shared corpus
(``conformance/v1/corpus.json``) runs in a PII-off and a PII-on lane against both servers, each over its own
``NodeCoreBridge``. For every capture the two servers must agree on:

* the outcome: success, or the same error code (and core code);
* the number of tokens and their types, ``unrestorable`` and ``passed_through`` and its types;
* the redacted text, after replacing each token by its position;
* what was stored: the persistent server's record of each token, opened with the test key, holds the type and the
  value the in-memory server holds under the same position.

``block`` aborts with nothing stored and no fence; ``warn`` and ``allow`` under ``reject`` store nothing; a PII type
outside ``pii.retain`` is never in a payload; and ``eligible`` cannot add one.

Two differences are specified, not accidental, and each is asserted in ``DIFFERENCES``, never skipped. The persistent
server bounds one capture, not a process: ``max_entries`` and ``max_retained_bytes`` count what the in-memory server
already holds plus what one capture adds, and the persistent profile counts the capture alone. And the persistent
profile refuses a clock reading below zero (``INVALID_ARGUMENT``, section 3.8), which the in-memory server accepts.

Needs ``node`` and ``@redact-secret/core`` installed at the repository root, and the ``crypto`` extra.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import sys
from typing import Any

import pytest
from conformance_runtime import (
    PII_LANES,
    SYNTHETIC_TENANT,
    CaseSkipped,
    _expand,
    _make_release_policy,
    _translate_limits,
    case_skip_reason,
    load_corpus,
)
from schedule_store import ScheduleStore

from redact_secret_vault import (
    CaptureGrant,
    CaptureOptions,
    InMemoryVaultServer,
    NodeCoreBridge,
    PiiRetention,
    PolicyDecision,
    Principal,
    VaultServerError,
)

pytestmark = [
    pytest.mark.skipif(sys.version_info < (3, 11), reason="the persistent modules need Python 3.11"),
    pytest.mark.skipif(shutil.which("node") is None, reason="node is required for the @redact-secret/core boundary"),
]

if sys.version_info >= (3, 11):
    from redact_secret_vault.crypto import LocalKey, LocalKeyScope, create_local_key_provider, create_record_crypto
    from redact_secret_vault.persistent import (
        KeyContext,
        LifecycleDecision,
        PersistentCaptureOptions,
        RecordBinding,
        StoredKey,
        create_persistent_server_vault,
        derive_entry_id,
    )

NAMESPACE = "conf-parity-synthetic"
KEY_MATERIAL = bytes(0x80 + index for index in range(32))
DIGEST_KEY = bytes(0x40 + index for index in range(32))
TOKEN = re.compile(r"<rsv_[a-z2-7]{26}>")

_CORPUS = load_corpus()

#: (case id, step index) -> (in-memory outcome, persistent outcome), each an error code name or ``None`` for success.
DIFFERENCES: dict[tuple[str, int], tuple[str | None, str | None]] = {
    ("limits.entries", 2): ("LIMIT_EXCEEDED", None),
    ("limits.retained-and-value-bytes", 3): ("LIMIT_EXCEEDED", None),
    ("lifecycle.observed-time-never-decreases", 5): (None, "INVALID_ARGUMENT"),
}


def _positions(text: str) -> str:
    """The redacted text with each token replaced by its position, so token values do not matter."""

    count = 0

    def replace(_match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return f"<TOKEN {count}>"

    return TOKEN.sub(replace, text)


class _Clock:
    def __init__(self) -> None:
        self.value = 0

    def now(self) -> int:
        return self.value


async def _open_persistent(bridge: NodeCoreBridge, step: dict[str, Any], clock: _Clock) -> Any:
    store = ScheduleStore(now=clock.now)
    await store.initialize_namespace(NAMESPACE, 1)
    crypto = create_record_crypto(
        key_provider=create_local_key_provider(
            keys=(LocalKey(id="synthetic-2026-10", material=KEY_MATERIAL, state="active"),),
            scope=LocalKeyScope(namespaces=(NAMESPACE,)),
        )
    )
    activation = bridge.scan("", policy=None, limits={"maxInputBytes": 1 << 20, "maxFindings": 1024}).pii_activation
    limits = _translate_limits(step.get("limits")) or {}
    vault = await create_persistent_server_vault(
        namespace=NAMESPACE,
        recovery_epoch=1,
        store=store,  # type: ignore[arg-type]
        crypto=crypto,
        core_client=bridge,
        expected_pii_activation=activation or "",
        digest_key=DIGEST_KEY,
        resolve_principal=lambda _context: Principal(id="user-conformance-synthetic", tenant=SYNTHETIC_TENANT),
        policy=lambda _decision: PolicyDecision(allow=True),
        lifecycle_policy=lambda _input: LifecycleDecision(allow=True),
        limits=limits,
        now=clock.now,
        allow_non_durable_store=True,
    )
    return vault, store, crypto


async def _stored(store: ScheduleStore, crypto: Any, tokens: list[str]) -> list[tuple[str, str]]:
    """``(value, type)`` of each token's stored record, opened with the test key, in the order of ``tokens``."""

    found: list[tuple[str, str]] = []
    if not tokens:
        return found
    rows = store._namespaces[NAMESPACE].tenants[SYNTHETIC_TENANT]
    for token in tokens:
        entry = rows.entries[derive_entry_id(NAMESPACE, SYNTHETIC_TENANT, token)]
        capture = rows.captures[entry.capture_id]
        payloads = await crypto.open_capture(
            StoredKey(key_ref=capture.key_ref, wrapped_key=capture.wrapped_key),
            KeyContext(namespace=NAMESPACE, tenant=SYNTHETIC_TENANT, capture_id=capture.capture_id),
            (
                (
                    RecordBinding(
                        namespace=NAMESPACE,
                        tenant=SYNTHETIC_TENANT,
                        capture_id=capture.capture_id,
                        entry_id=entry.entry_id,
                        session_id=None,
                        created_at=capture.created_at,
                        expires_at=capture.expires_at,
                        max_uses=entry.max_uses,
                    ),
                    entry.envelope,
                ),
            ),
        )
        found.append((bytes(payloads[0].value).decode("utf-8"), payloads[0].type))
        payloads[0].value[:] = bytes(len(payloads[0].value))
    return found


async def _compare_case(case: dict[str, Any], lane: str) -> int:
    """Runs the capture steps of ``case`` on both servers and compares them. Returns the number of captures compared."""

    clock = _Clock()
    fixtures = _CORPUS["fixtures"]
    selection = PII_LANES[lane]
    in_memory: InMemoryVaultServer | None = None
    persistent: tuple[Any, ScheduleStore, Any] | None = None
    captures: dict[str, dict[str, Any]] = {}
    compared = 0

    for index, step in enumerate(case["steps"]):
        where = f"{case['id']} step {index}"
        op = step["op"]
        if op == "vault":
            if "error" in step.get("expect", {}):
                # Creation under an activation expectation the core does not meet: covered by the factory's own tests.
                return compared
            in_memory = InMemoryVaultServer(
                core_client=NodeCoreBridge(pii=tuple(step.get("pii", selection))),
                principal_resolver=lambda _c: Principal(id="user-conformance-synthetic", tenant=SYNTHETIC_TENANT),
                release_policy=_make_release_policy(step.get("releasePolicy")),
                limits=_translate_limits(step.get("limits")),
                now=lambda: clock.value,
            )
            persistent = await _open_persistent(NodeCoreBridge(pii=tuple(step.get("pii", selection))), step, clock)
            continue
        if op == "advance":
            clock.value += step["ms"]
            continue
        if op != "capture":
            continue
        assert in_memory is not None and persistent is not None, where
        vault, store, crypto = persistent
        options = step["options"]
        eligible_types = options.get("eligibleTypes")
        pii_option = options.get("pii")
        release = tuple(CaptureGrant(sink=g["sink"], paths=tuple(g["paths"])) for g in options.get("release", []))
        shared: dict[str, Any] = {
            "release": release,
            "max_uses": options.get("maxUses", 1),
            "unredacted": options.get("unredacted", "reject"),
            "policy": options.get("policy"),
            "eligible": (lambda f, _t=eligible_types: f["type"] in _t) if eligible_types else None,
            "pii": PiiRetention(retain=tuple(pii_option["retain"])) if pii_option is not None else None,
        }
        text = _expand(step["input"], fixtures, captures)

        memory_result: Any = None
        memory_error: VaultServerError | None = None
        try:
            memory_result = in_memory.capture(text, CaptureOptions(issued_tenant=SYNTHETIC_TENANT, **shared))
        except VaultServerError as caught:
            memory_error = caught
        persistent_result: Any = None
        persistent_error: VaultServerError | None = None
        try:
            persistent_result = await vault.capture(text, PersistentCaptureOptions(context={}, **shared))
        except VaultServerError as caught:
            persistent_error = caught

        known = DIFFERENCES.get((case["id"], index))
        if known is not None:
            memory_name = None if memory_error is None else memory_error.code.value
            persistent_name = None if persistent_error is None else persistent_error.code.value
            actual = (memory_name, persistent_name)
            assert actual == known, f"{where}: in-memory {memory_name}, persistent {persistent_name}"
            return compared
        if memory_error is not None or persistent_error is not None:
            memory_code = None if memory_error is None else (memory_error.code, memory_error.core_code)
            persistent_code = None if persistent_error is None else (persistent_error.code, persistent_error.core_code)
            assert persistent_code == memory_code, f"{where}: persistent {persistent_code}, in-memory {memory_code}"
            # A refused capture stores nothing and leaves no fence behind.
            rows = store._namespaces[NAMESPACE].tenants.get(SYNTHETIC_TENANT)
            assert rows is None or all(not row.keyless for row in rows.captures.values()), where
            continue

        assert [t.type for t in persistent_result.tokens] == [t.type for t in memory_result.tokens], where
        assert persistent_result.passed_through == memory_result.passed_through, where
        assert persistent_result.passed_through_types == memory_result.passed_through_types, where
        assert persistent_result.unrestorable == memory_result.unrestorable, where
        assert _positions(persistent_result.text) == _positions(memory_result.text), where
        assert len(set(t.token for t in persistent_result.tokens)) == len(persistent_result.tokens), where

        memory_stored = [
            (in_memory._entries[t.token].value, in_memory._entries[t.token].type) for t in memory_result.tokens
        ]
        persistent_stored = await _stored(store, crypto, [t.token for t in persistent_result.tokens])
        assert persistent_stored == memory_stored, f"{where}: stored records differ"
        # A PII type outside the allowlist is never in a payload, and ``eligible`` never adds one.
        allowed = set(pii_option["retain"]) if pii_option is not None else set()
        for _value, kind in persistent_stored:
            assert not kind.startswith("pii_") or kind in allowed, where
        if step.get("as"):
            captures[step["as"]] = {
                "capture_id": memory_result.capture_id,
                "text": memory_result.text,
                "tokens": [t.token for t in memory_result.tokens],
                "vault": "A",
            }
        compared += 1
    return compared


@pytest.mark.parametrize("lane", list(PII_LANES))
@pytest.mark.parametrize("case", _CORPUS["cases"], ids=[c["id"] for c in _CORPUS["cases"]])
def test_capture_parity_with_the_in_memory_server(case: dict[str, Any], lane: str) -> None:
    skip = case_skip_reason(case, lane)
    if skip is not None:
        pytest.skip(skip)
    try:
        asyncio.run(_compare_case(case, lane))
    except CaseSkipped as skipped:
        pytest.skip(str(skipped))


def test_the_parity_run_compares_every_retaining_capture() -> None:
    """A sentinel: the comparison is not vacuous. Many captures retain a value and are compared value for value."""

    async def count() -> tuple[int, int]:
        compared = retained = 0
        for case in _CORPUS["cases"]:
            if case_skip_reason(case, "on") is not None:
                continue
            compared += await _compare_case(case, "on")
            retained += 1
        return compared, retained

    compared, cases = asyncio.run(count())
    assert cases >= 40
    assert compared >= 40
