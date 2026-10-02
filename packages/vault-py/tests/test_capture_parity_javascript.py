"""Capture parity between the Python and the JavaScript persistent servers (docs/plans/python-persistence-parity.md
section 6.2, gate G5, second bullet).

Every capture step of the shared corpus (``conformance/v1/corpus.json``) runs in a PII-off and a PII-on lane against
both persistent servers, each over its own real ``@redact-secret/core`` (the Python one through ``NodeCoreBridge``, the
JavaScript one in its own process; a new process per case and lane, because the core's activation is realm-global).
Each server stores into its own ``store-memory`` and opens its own records with the run's public test key. For every
capture the two must agree on:

* the outcome: success, or the same error code and core code;
* the number of tokens and their types, ``unrestorable``, and ``passed_through`` and its types;
* the redacted text, after replacing each token by its position;
* what was stored: the record of each token, opened with the test key, holds the same type and the same value, in the
  same order.

This is the capture half of G5 against the JavaScript persistent profile. That each side can also open the other's
records is G2 (``test_interop_postgres.py``). Skipped, with the reason, when ``node`` or the JavaScript build is
missing.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest
from conformance_runtime import (
    PII_LANES,
    SYNTHETIC_TENANT,
    CaseSkipped,
    _expand,
    _translate_limits,
    case_skip_reason,
    load_corpus,
)
from test_persistent_server_parity import NAMESPACE, _Clock, _open_persistent, _positions, _stored

from redact_secret_vault import CaptureGrant, NodeCoreBridge, PiiRetention, VaultServerError
from redact_secret_vault.persistent import PersistentCaptureOptions

REPO = Path(__file__).resolve().parents[3]
WORKER = Path(__file__).resolve().parent / "interop_js_corpus_worker.mjs"
BUILT = (REPO / "packages" / "vault-server" / "dist" / "persistent" / "index.js").is_file()

pytestmark = [
    pytest.mark.skipif(sys.version_info < (3, 11), reason="the persistent modules need Python 3.11"),
    pytest.mark.skipif(shutil.which("node") is None, reason="node is required for the core and the JavaScript server"),
    pytest.mark.skipif(not BUILT, reason="the JavaScript workspace is not built (npm run build)"),
]

_CORPUS = load_corpus()

#: (case id, step index) -> (JavaScript outcome, Python outcome) where they are specified to differ. None today: an
#: entry here would be a difference to state, not to hide.
DIFFERENCES: dict[tuple[str, int], tuple[str | None, str | None]] = {}


class JsWorker:
    def __init__(self) -> None:
        self._process: asyncio.subprocess.Process | None = None
        self._next = 0

    async def start(self) -> JsWorker:
        self._process = await asyncio.create_subprocess_exec(
            shutil.which("node") or "node",
            str(WORKER),
            cwd=str(REPO),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=1 << 26,
        )
        assert self._process.stdout is not None
        ready = json.loads(await asyncio.wait_for(self._process.stdout.readline(), timeout=60))
        assert ready == {"event": "ready"}
        return self

    async def call(self, op: str, **args: Any) -> dict[str, Any]:
        assert self._process is not None and self._process.stdin is not None and self._process.stdout is not None
        self._next += 1
        self._process.stdin.write((json.dumps({"id": self._next, "op": op, "args": args}) + "\n").encode())
        reply = json.loads(await asyncio.wait_for(self._process.stdout.readline(), timeout=120))
        assert reply["id"] == self._next
        return reply["reply"]

    async def stop(self) -> None:
        process = self._process
        if process is None:
            return
        try:
            assert process.stdin is not None
            process.stdin.write(b'{"id":0,"op":"exit"}\n')
            await process.stdin.drain()
            # Close the pipe's transport: left open, it is garbage-collected later as an "unclosed transport"
            # ResourceWarning that a later test, which records every warning, then fails on (found on Linux, where
            # this ran before test_crypto_leaks.py; it fails the same way on main).
            process.stdin.close()
            await asyncio.wait_for(process.wait(), timeout=15)
        except (TimeoutError, ProcessLookupError, ConnectionResetError, BrokenPipeError):
            process.kill()
            await process.wait()
        finally:
            if process.stdin is not None:
                process.stdin.close()


def _js_options(options: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "release": options.get("release", []),
        "maxUses": options.get("maxUses", 1),
        "unredacted": options.get("unredacted", "reject"),
    }
    if options.get("policy") is not None:
        out["policy"] = options["policy"]
    if options.get("eligibleTypes"):
        out["eligibleTypes"] = options["eligibleTypes"]
    if options.get("pii") is not None:
        out["pii"] = {"retain": list(options["pii"]["retain"])}
    return out


async def _compare_case(case: dict[str, Any], lane: str) -> int:
    clock = _Clock()
    fixtures = _CORPUS["fixtures"]
    selection = PII_LANES[lane]
    js: JsWorker | None = None
    persistent: tuple[Any, Any, Any] | None = None
    captures: dict[str, dict[str, Any]] = {}
    compared = 0
    try:
        for index, step in enumerate(case["steps"]):
            where = f"{case['id']} step {index} ({lane})"
            op = step["op"]
            if op == "vault":
                if "error" in step.get("expect", {}):
                    return compared
                pii = list(step.get("pii", selection))
                if js is not None:
                    # A case with a second `vault` step: the first worker is done, and must not be left running.
                    await js.stop()
                js = await JsWorker().start()
                configured = await js.call("configure", pii=pii, limits=step.get("limits"), namespace=NAMESPACE)
                assert configured == {"ok": True}, f"{where}: {configured}"
                persistent = await _open_persistent(NodeCoreBridge(pii=tuple(pii)), step, clock)
                continue
            if op == "advance":
                clock.value += step["ms"]
                if js is not None:
                    await js.call("advance", ms=step["ms"])
                continue
            if op != "capture":
                continue
            assert js is not None and persistent is not None, where
            vault, store, crypto = persistent
            options = step["options"]
            eligible_types = options.get("eligibleTypes")
            pii_option = options.get("pii")
            text = _expand(step["input"], fixtures, captures)

            js_reply = await js.call("capture", text=text, options=_js_options(options))
            python_result: Any = None
            python_error: VaultServerError | None = None
            try:
                python_result = await vault.capture(
                    text,
                    PersistentCaptureOptions(
                        context={},
                        release=tuple(
                            CaptureGrant(sink=g["sink"], paths=tuple(g["paths"])) for g in options.get("release", [])
                        ),
                        max_uses=options.get("maxUses", 1),
                        unredacted=options.get("unredacted", "reject"),
                        policy=options.get("policy"),
                        eligible=(lambda f, _t=eligible_types: f["type"] in _t) if eligible_types else None,
                        pii=PiiRetention(retain=tuple(pii_option["retain"])) if pii_option is not None else None,
                    ),
                )
            except VaultServerError as caught:
                python_error = caught

            known = DIFFERENCES.get((case["id"], index))
            if known is not None:
                actual = (
                    None if js_reply["ok"] else js_reply["code"],
                    None if python_error is None else python_error.code.value,
                )
                assert actual == known, f"{where}: javascript {actual[0]}, python {actual[1]}"
                return compared
            if not js_reply["ok"] or python_error is not None:
                # The JavaScript persistent server wraps a vault failure in VAULT_FAILURE and carries the vault's own
                # code beside it (``vaultCode``); the Python profile keeps the vault's code (decision record, item 10).
                javascript = None
                if not js_reply["ok"]:
                    code = js_reply["vaultCode"] if js_reply["code"] == "VAULT_FAILURE" else js_reply["code"]
                    javascript = (code, js_reply.get("coreCode"))
                python = None if python_error is None else (python_error.code.value, python_error.core_code)
                assert python == javascript, f"{where}: python {python}, javascript {javascript}"
                continue

            value = js_reply["value"]
            assert [t.type for t in python_result.tokens] == [t["type"] for t in value["tokens"]], where
            assert python_result.passed_through == value["passedThrough"], where
            assert list(python_result.passed_through_types) == value["passedThroughTypes"], where
            assert python_result.unrestorable == value["unrestorable"], where
            assert _positions(python_result.text) == _positions(value["text"]), where
            assert len(set(t.token for t in python_result.tokens)) == len(python_result.tokens), where
            python_stored = await _stored(store, crypto, [t.token for t in python_result.tokens])
            javascript_stored = [(item[0], item[1]) for item in js_reply["stored"]]
            assert python_stored == javascript_stored, f"{where}: stored records differ"
            allowed = set(pii_option["retain"]) if pii_option is not None else set()
            for _value, kind in python_stored:
                assert not kind.startswith("pii_") or kind in allowed, where
            if step.get("as"):
                captures[step["as"]] = {
                    "capture_id": python_result.capture_id,
                    "text": python_result.text,
                    "tokens": [t.token for t in python_result.tokens],
                    "vault": "A",
                }
            compared += 1
    finally:
        if js is not None:
            await js.stop()
    return compared


@pytest.mark.parametrize("lane", list(PII_LANES))
@pytest.mark.parametrize("case", _CORPUS["cases"], ids=[c["id"] for c in _CORPUS["cases"]])
def test_capture_parity_with_the_javascript_persistent_server(case: dict[str, Any], lane: str) -> None:
    skip = case_skip_reason(case, lane)
    if skip is not None:
        pytest.skip(skip)
    try:
        asyncio.run(_compare_case(case, lane))
    except CaseSkipped as skipped:
        pytest.skip(str(skipped))


def test_the_parity_run_compares_many_retaining_captures_value_for_value() -> None:
    """A sentinel: the comparison is not vacuous."""

    async def count() -> tuple[int, int]:
        compared = cases = 0
        for case in _CORPUS["cases"]:
            if case_skip_reason(case, "on") is not None:
                continue
            compared += await _compare_case(case, "on")
            cases += 1
        return compared, cases

    compared, cases = asyncio.run(count())
    assert cases >= 40 and compared >= 40
    print(f"captures compared with the JavaScript persistent server (PII on): {compared} in {cases} cases")


def test_the_translation_of_limits_is_the_one_the_python_side_uses() -> None:
    assert _translate_limits({"maxEntries": 3}) == {"max_entries": 3}
    assert SYNTHETIC_TENANT == "tenant-conformance-synthetic"
