"""PII selection and activation identity through ``NodeCoreBridge`` (PII ADR §3).

docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md,
§3 "Python bridge". Four layers:

1. ``NodeCoreBridge`` against a faked subprocess: selector propagation,
   identity pinning, ``expected_pii_activation``, and strict response
   parsing. No Node.js needed.
2. The real ``core_bridge.mjs`` against a fake ``@redact-secret/core``
   module, with and without a ``piiActivation`` export: the bridge's own
   initialize/PII_UNAVAILABLE logic and finding projection.
3. The real bridge against the installed core when it has no PII surface
   (the pinned ``0.1.0-beta.9``): ``null`` identity and fail-closed options.
4. The real bridge against a PII-capable core (the ``0.1.0-beta.10``
   candidate). Skipped with a reason unless such a core is resolvable.

Data is synthetic: repository ``*-synthetic*`` literals, and for layer 4 the
widely published documentation-example IBAN, which the beta.10 candidate
detects as ``pii_global_iban`` (High, ``redact``).
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from redact_secret_vault_server import (
    CaptureGrant,
    CaptureOptions,
    InMemoryVaultServer,
    NodeCoreBridge,
    PiiRetention,
    PolicyDecision,
    Principal,
    RestoreRequest,
    VaultServerError,
    VaultServerErrorCode,
)
from redact_secret_vault_server import core_client as core_client_module
from redact_secret_vault_server.core_client import DEFAULT_BRIDGE_SCRIPT, PINNED_CORE_VERSION
from redact_secret_vault_server.pii import is_pii_active

ACTIVE = "credentials=full;selectors=pii:global;families=pii:global:iban;vocabulary=pii-context/v1"
OTHER = "credentials=full;selectors=pii:global;families=pii:global:email;vocabulary=pii-context/v1"
GOOD_FINDING = {
    "id": "finding-1",
    "type": "github_token",
    "detector": "github-token",
    "confidence": "high",
    "obfuscation": "none",
    "start": 0,
    "end": 4,
    "action": "redact",
}


def _ok(activation, findings=None, version=PINNED_CORE_VERSION) -> dict:
    return {
        "findings": [dict(GOOD_FINDING)] if findings is None else findings,
        "coreVersion": version,
        "artifact": "addon",
        "piiActivation": activation,
    }


class FakeRun:
    """Stands in for ``subprocess.run``: records each request payload and
    replies with the next queued stdout."""

    def __init__(self, *responses) -> None:
        self.responses = list(responses)
        self.requests: list[dict] = []

    def __call__(self, args, *, input, **_kwargs):
        self.requests.append(json.loads(input))
        reply = self.responses.pop(0)
        stdout = reply if isinstance(reply, str) else json.dumps(reply)
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")


@pytest.fixture
def fake_run(monkeypatch):
    def install(*responses) -> FakeRun:
        fake = FakeRun(*responses)
        monkeypatch.setattr(core_client_module.subprocess, "run", fake)
        return fake

    return install


def _bridge(**kwargs) -> NodeCoreBridge:
    return NodeCoreBridge(node_executable="node-fake-synthetic", **kwargs)


# -- 1. NodeCoreBridge against a faked subprocess ------------------------------


def test_selectors_are_forwarded_verbatim_and_default_to_empty(fake_run):
    fake = fake_run(_ok(None), _ok(ACTIVE))
    _bridge().scan("text-synthetic")
    _bridge(pii=["pii:global", "pii:jurisdiction:us"]).scan("text-synthetic")
    assert fake.requests[0]["pii"] == []
    assert fake.requests[1]["pii"] == ["pii:global", "pii:jurisdiction:us"]


def test_selection_is_copied_at_construction(fake_run):
    fake = fake_run(_ok(ACTIVE))
    selection = ["pii"]
    bridge = _bridge(pii=selection)
    selection.append("pii:late-synthetic")
    bridge.scan("text-synthetic")
    assert fake.requests[0]["pii"] == ["pii"]


def test_null_identity_is_reported_for_a_core_without_pii(fake_run):
    fake_run(_ok(None))
    assert _bridge().scan("text-synthetic").pii_activation is None


def test_first_identity_is_pinned_and_a_change_is_a_mismatch(fake_run):
    fake_run(_ok(ACTIVE), _ok(ACTIVE), _ok(OTHER))
    bridge = _bridge(pii=["pii"])
    assert bridge.scan("a").pii_activation == ACTIVE
    assert bridge.scan("b").pii_activation == ACTIVE
    with pytest.raises(VaultServerError) as excinfo:
        bridge.scan("c")
    assert excinfo.value.code == VaultServerErrorCode.PII_ACTIVATION_MISMATCH
    assert str(excinfo.value) == "PII_ACTIVATION_MISMATCH"


@pytest.mark.parametrize(("first", "second"), [(None, ACTIVE), (ACTIVE, None)])
def test_swapping_between_a_pii_core_and_a_non_pii_core_is_a_mismatch(fake_run, first, second):
    fake_run(_ok(first), _ok(second))
    bridge = _bridge()
    bridge.scan("a")
    with pytest.raises(VaultServerError) as excinfo:
        bridge.scan("b")
    assert excinfo.value.code == VaultServerErrorCode.PII_ACTIVATION_MISMATCH


def test_a_failed_first_response_does_not_pin(fake_run):
    fake_run(_ok(OTHER, version="0.0.0-other"), _ok(ACTIVE), _ok(ACTIVE))
    bridge = _bridge()
    with pytest.raises(VaultServerError) as excinfo:
        bridge.scan("a")
    assert excinfo.value.core_code == "CORE_VERSION_MISMATCH"
    assert bridge.scan("b").pii_activation == ACTIVE
    assert bridge.scan("c").pii_activation == ACTIVE


def test_expected_identity_is_compared_on_every_response(fake_run):
    fake_run(_ok(ACTIVE), _ok(OTHER))
    bridge = _bridge(pii=["pii"], expected_pii_activation=ACTIVE)
    assert bridge.scan("a").pii_activation == ACTIVE
    with pytest.raises(VaultServerError) as excinfo:
        bridge.scan("b")
    assert excinfo.value.code == VaultServerErrorCode.PII_ACTIVATION_MISMATCH


def test_expected_identity_differs_on_first_response(fake_run):
    fake_run(_ok(OTHER))
    with pytest.raises(VaultServerError) as excinfo:
        _bridge(expected_pii_activation=ACTIVE).scan("a")
    assert excinfo.value.code == VaultServerErrorCode.PII_ACTIVATION_MISMATCH


def test_expected_identity_on_a_core_without_pii_is_unavailable(fake_run):
    fake_run(_ok(None))
    with pytest.raises(VaultServerError) as excinfo:
        _bridge(expected_pii_activation=ACTIVE).scan("a")
    assert excinfo.value.code == VaultServerErrorCode.PII_UNAVAILABLE


def test_bridge_pii_unavailable_maps_to_the_fixed_code(fake_run):
    fake_run({"error": {"message": "core has no PII support", "code": "PII_UNAVAILABLE"}})
    with pytest.raises(VaultServerError) as excinfo:
        _bridge(pii=["pii"]).scan("a")
    assert excinfo.value.code == VaultServerErrorCode.PII_UNAVAILABLE
    assert excinfo.value.core_code is None


@pytest.mark.parametrize("core_code", ["PII_SELECTOR_INVALID", "PII_ACTIVATION_CONFLICT", "NOT_INITIALIZED"])
def test_core_pii_errors_surface_as_core_failure_with_core_code(fake_run, core_code):
    fake_run({"error": {"message": "core scan failed", "code": core_code}})
    with pytest.raises(VaultServerError) as excinfo:
        _bridge(pii=["pii"]).scan("a")
    assert excinfo.value.code == VaultServerErrorCode.CORE_FAILURE
    assert excinfo.value.core_code == core_code


@pytest.mark.parametrize(
    "pii",
    [
        "pii",  # a bare str would otherwise be iterated per character
        ["pii", ""],
        ["x" * 129],
        [1],
        ["pii"] * 65,
        None,
    ],
)
def test_malformed_selection_is_invalid_argument_at_construction(pii):
    with pytest.raises(VaultServerError) as excinfo:
        _bridge(pii=pii)
    assert excinfo.value.code == VaultServerErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize("expected", ["", "x" * 513, 7, b"credentials=full"])
def test_malformed_expected_identity_is_invalid_argument(expected):
    with pytest.raises(VaultServerError) as excinfo:
        _bridge(expected_pii_activation=expected)
    assert excinfo.value.code == VaultServerErrorCode.INVALID_ARGUMENT


def _without(key: str) -> dict:
    response = _ok(None)
    del response[key]
    return response


@pytest.mark.parametrize(
    "stdout",
    [
        "not json",
        "[]",
        "null",
        {"error": "PII_UNAVAILABLE"},
        {"error": {"code": 5}},
        _without("piiActivation"),  # an older bridge script
        _without("findings"),
        _without("artifact"),
        {**_ok(None), "extra": 1},
        _ok(5),
        _ok(""),
        _ok("x" * 513),
        {**_ok(None), "coreVersion": 9},
        {**_ok(None), "findings": {}},
        _ok(None, findings=["finding"]),
        _ok(None, findings=[{**GOOD_FINDING, "value": "leak-synthetic"}]),
        _ok(None, findings=[{k: v for k, v in GOOD_FINDING.items() if k != "action"}]),
        _ok(None, findings=[{**GOOD_FINDING, "start": True}]),
        _ok(None, findings=[{**GOOD_FINDING, "end": 4.0}]),
        _ok(None, findings=[{**GOOD_FINDING, "type": None}]),
    ],
)
def test_malformed_responses_fail_closed(fake_run, stdout):
    fake_run(stdout)
    with pytest.raises(VaultServerError) as excinfo:
        _bridge().scan("a")
    assert excinfo.value.code == VaultServerErrorCode.CORE_FAILURE
    assert excinfo.value.core_code == "BRIDGE_BAD_OUTPUT"


def test_a_malformed_response_does_not_pin(fake_run):
    fake_run(_ok(OTHER, findings=["bad"]), _ok(ACTIVE), _ok(ACTIVE))
    bridge = _bridge()
    with pytest.raises(VaultServerError):
        bridge.scan("a")
    assert bridge.scan("b").pii_activation == ACTIVE
    assert bridge.scan("c").pii_activation == ACTIVE


# -- 2. The real core_bridge.mjs against a fake core module ------------------------

needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node is required to run core_bridge.mjs")

_FAKE_CORE_WITH_PII = """
let selection;
export const VERSION = "0.1.0-beta.9";
export function artifact() { return { kind: "fake" }; }
export async function initialize(...args) {
  if (args.length !== 1 || !Array.isArray(args[0]?.pii)) throw Object.assign(new Error("x"), { code: "FAKE_BAD_INIT" });
  if (args[0].pii.includes("bad-synthetic")) throw Object.assign(new Error("x"), { code: "PII_SELECTOR_INVALID" });
  selection = args[0].pii;
}
export function piiActivation() {
  return "credentials=full;selectors=" + (selection.length ? selection.join("+") : "off") + ";fake=1";
}
export function scan(input) {
  return [{ id: "finding-1", type: "pii_global_iban", detector: "fake", confidence: "high", obfuscation: "none",
            start: 0, end: 4, action: "redact", matched: input }];
}
"""

_FAKE_CORE_WITHOUT_PII = """
export const VERSION = "0.1.0-beta.9";
export function artifact() { return { kind: "fake" }; }
export async function initialize(...args) {
  if (args.length !== 0) throw Object.assign(new Error("x"), { code: "FAKE_UNEXPECTED_ARGS" });
  globalThis.__initialized = true;
}
export function scan(input) {
  if (!globalThis.__initialized) throw Object.assign(new Error("x"), { code: "NOT_INITIALIZED" });
  return [];
}
"""


def _fake_core_bridge(tmp_path: Path, source: str, **kwargs) -> NodeCoreBridge:
    package = tmp_path / "node_modules" / "@redact-secret" / "core"
    package.mkdir(parents=True)
    (package / "package.json").write_text(
        json.dumps({"name": "@redact-secret/core", "type": "module", "exports": "./index.js"})
    )
    (package / "index.js").write_text(source)
    script = tmp_path / "core_bridge.mjs"
    shutil.copyfile(DEFAULT_BRIDGE_SCRIPT, script)
    return NodeCoreBridge(script=script, **kwargs)


def _raw_bridge(bridge: NodeCoreBridge, payload: str) -> dict:
    proc = subprocess.run(
        [bridge._node, str(bridge._script)], input=payload, capture_output=True, text=True, timeout=10, check=False
    )
    return json.loads(proc.stdout)


@needs_node
def test_bridge_calls_initialize_with_the_selection_when_core_has_pii(tmp_path):
    bridge = _fake_core_bridge(tmp_path, _FAKE_CORE_WITH_PII, pii=["pii", "pii:jurisdiction:us"])
    outcome = bridge.scan("text-synthetic")
    assert outcome.pii_activation == "credentials=full;selectors=pii+pii:jurisdiction:us;fake=1"
    # The bridge projects findings to the eight safe fields (`matched` dropped).
    assert [f.type for f in outcome.findings] == ["pii_global_iban"]


@needs_node
def test_bridge_forwards_an_empty_selection_when_core_has_pii(tmp_path):
    bridge = _fake_core_bridge(tmp_path, _FAKE_CORE_WITH_PII)
    assert bridge.scan("text-synthetic").pii_activation == "credentials=full;selectors=off;fake=1"


@needs_node
def test_bridge_reports_core_selector_errors(tmp_path):
    bridge = _fake_core_bridge(tmp_path, _FAKE_CORE_WITH_PII, pii=["bad-synthetic"])
    with pytest.raises(VaultServerError) as excinfo:
        bridge.scan("text-synthetic")
    assert excinfo.value.code == VaultServerErrorCode.CORE_FAILURE
    assert excinfo.value.core_code == "PII_SELECTOR_INVALID"


@needs_node
def test_bridge_calls_plain_initialize_without_pii_surface(tmp_path):
    bridge = _fake_core_bridge(tmp_path, _FAKE_CORE_WITHOUT_PII)
    outcome = bridge.scan("text-synthetic")
    assert outcome.pii_activation is None
    assert outcome.findings == ()


@needs_node
def test_bridge_refuses_a_selection_without_pii_surface_before_initializing(tmp_path):
    bridge = _fake_core_bridge(tmp_path, _FAKE_CORE_WITHOUT_PII, pii=["pii"])
    with pytest.raises(VaultServerError) as excinfo:
        bridge.scan("text-synthetic")
    assert excinfo.value.code == VaultServerErrorCode.PII_UNAVAILABLE


@needs_node
@pytest.mark.parametrize(
    "request_body",
    [
        {"input": "text-synthetic"},  # pii missing
        {"input": "text-synthetic", "pii": "pii"},
        {"input": "text-synthetic", "pii": [""]},
        {"input": "text-synthetic", "pii": [1]},
        {"input": "text-synthetic", "pii": ["x" * 129]},
        {"input": "text-synthetic", "pii": ["pii"] * 65},
    ],
)
def test_bridge_rejects_a_malformed_pii_request_without_echoing_it(tmp_path, request_body):
    bridge = _fake_core_bridge(tmp_path, _FAKE_CORE_WITH_PII)
    reply = _raw_bridge(bridge, json.dumps(request_body))
    assert set(reply) == {"error"}
    assert "code" not in reply["error"]
    assert "text-synthetic" not in json.dumps(reply)


# -- 3 and 4. The real bridge against the installed core ------------------------


def _core_has_pii_surface(node_modules_parent: Path) -> bool | None:
    if shutil.which("node") is None:
        return None
    probe = (
        'import("@redact-secret/core").then((c) => process.stdout.write(typeof c.piiActivation === "function" ? '
        '"yes" : "no"), () => process.stdout.write("missing"))'
    )
    # `--eval` resolves bare specifiers from the working directory, so this
    # sees exactly the core a bridge script in that directory would import.
    try:
        proc = subprocess.run(
            ["node", "--input-type=module", "--eval", probe],
            cwd=node_modules_parent,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except OSError:
        return None
    return {"yes": True, "no": False}.get(proc.stdout.strip())


_INSTALLED_HAS_PII = _core_has_pii_surface(DEFAULT_BRIDGE_SCRIPT.parent)

needs_beta9_core = pytest.mark.skipif(
    _INSTALLED_HAS_PII is not False,
    reason="needs node and an installed @redact-secret/core without piiActivation (the pinned 0.1.0-beta.9)",
)


@needs_beta9_core
def test_beta9_reports_null_identity_and_scans_unchanged():
    outcome = NodeCoreBridge().scan("deploy with ghp_SYNTHETICxREVOKEDxTESTx0000000000000 now")
    assert outcome.pii_activation is None
    assert [f.type for f in outcome.findings] == ["github_token"]
    outcome = NodeCoreBridge(pii=[]).scan("nothing-synthetic")
    assert outcome.pii_activation is None


@needs_beta9_core
def test_beta9_rejects_a_pii_selection():
    with pytest.raises(VaultServerError) as excinfo:
        NodeCoreBridge(pii=["pii"]).scan("text-synthetic")
    assert excinfo.value.code == VaultServerErrorCode.PII_UNAVAILABLE


@needs_beta9_core
def test_beta9_rejects_an_expected_identity():
    with pytest.raises(VaultServerError) as excinfo:
        NodeCoreBridge(expected_pii_activation=ACTIVE).scan("text-synthetic")
    assert excinfo.value.code == VaultServerErrorCode.PII_UNAVAILABLE


@needs_beta9_core
def test_beta9_rejects_capture_pii_retention():
    server = InMemoryVaultServer(core_client=NodeCoreBridge())
    with pytest.raises(VaultServerError) as excinfo:
        server.capture(
            "deploy with ghp_SYNTHETICxREVOKEDxTESTx0000000000000 now",
            CaptureOptions(
                issued_tenant="tenant-acme-synthetic",
                release=(CaptureGrant(sink="sink-synthetic", paths=("body",)),),
                pii=PiiRetention(retain=("pii_global_iban",)),
            ),
        )
    assert excinfo.value.code == VaultServerErrorCode.PII_UNAVAILABLE
    assert server.stats().entries == 0


# Layer 4: a PII-capable core. Point VAULT_SERVER_PY_PII_CORE_NODE_MODULES
# at a node_modules directory holding the beta.10 candidate to run these.
_PII_NODE_MODULES = os.environ.get("VAULT_SERVER_PY_PII_CORE_NODE_MODULES")


@pytest.fixture(scope="module")
def pii_core_script(tmp_path_factory) -> Path:
    base = tmp_path_factory.mktemp("pii-core")
    if _PII_NODE_MODULES:
        (base / "node_modules").symlink_to(Path(_PII_NODE_MODULES).resolve(), target_is_directory=True)
        script = base / "core_bridge.mjs"
        shutil.copyfile(DEFAULT_BRIDGE_SCRIPT, script)
        has_pii = _core_has_pii_surface(base)
    else:
        script = DEFAULT_BRIDGE_SCRIPT
        has_pii = _INSTALLED_HAS_PII
    if not has_pii:
        pytest.skip(
            "installed @redact-secret/core has no piiActivation (PII needs the 0.1.0-beta.10 candidate); "
            "set VAULT_SERVER_PY_PII_CORE_NODE_MODULES to a node_modules holding it"
        )
    return script


# The widely published documentation-example IBAN (synthetic).
DOC_IBAN = "DE89 3704 0044 0532 0130 00"
GH = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000"
TENANT = "tenant-acme-synthetic"
RELEASE = (CaptureGrant(sink="sink-synthetic", paths=("body",)),)


def _pii_bridge(script: Path, **kwargs) -> NodeCoreBridge:
    return NodeCoreBridge(script=script, expected_core_version=None, **kwargs)


def test_real_core_selection_propagates_and_is_pinned(pii_core_script):
    bridge = _pii_bridge(pii_core_script, pii=["pii"])
    first = bridge.scan(f"iban {DOC_IBAN} end")
    assert is_pii_active(first.pii_activation)
    assert "selectors=pii:global" in first.pii_activation
    assert [(f.type, f.action) for f in first.findings] == [("pii_global_iban", "redact")]
    assert bridge.scan("nothing-synthetic").pii_activation == first.pii_activation
    with pytest.raises(VaultServerError) as excinfo:
        _pii_bridge(pii_core_script, pii=["pii"], expected_pii_activation=first.pii_activation + ";x").scan("a")
    assert excinfo.value.code == VaultServerErrorCode.PII_ACTIVATION_MISMATCH
    matching = _pii_bridge(pii_core_script, pii=["pii"], expected_pii_activation=first.pii_activation)
    assert matching.scan("a").pii_activation == first.pii_activation


def test_real_core_empty_selection_is_off_and_detects_no_pii(pii_core_script):
    outcome = _pii_bridge(pii_core_script).scan(f"iban {DOC_IBAN} end")
    assert outcome.pii_activation is not None
    assert not is_pii_active(outcome.pii_activation)
    assert outcome.findings == ()
    server = InMemoryVaultServer(core_client=_pii_bridge(pii_core_script))
    with pytest.raises(VaultServerError) as excinfo:
        server.capture(
            f"iban {DOC_IBAN} end",
            CaptureOptions(issued_tenant=TENANT, release=RELEASE, pii=PiiRetention(retain=("pii_global_iban",))),
        )
    assert excinfo.value.code == VaultServerErrorCode.PII_UNAVAILABLE


def test_real_core_invalid_selector_is_core_failure(pii_core_script):
    with pytest.raises(VaultServerError) as excinfo:
        _pii_bridge(pii_core_script, pii=["pii:not-a-family-synthetic"]).scan("a")
    assert excinfo.value.code == VaultServerErrorCode.CORE_FAILURE
    assert excinfo.value.core_code == "PII_SELECTOR_INVALID"


def test_real_core_retention_default_and_allowlist(pii_core_script):
    async def run():
        server = InMemoryVaultServer(
            core_client=_pii_bridge(pii_core_script, pii=["pii"]),
            principal_resolver=lambda _ctx: Principal(id="user-synthetic-1", tenant=TENANT),
            release_policy=lambda _input: PolicyDecision(allow=True),
        )
        text = f"token {GH} iban {DOC_IBAN} end"
        plain = server.capture(text, CaptureOptions(issued_tenant=TENANT, release=RELEASE, eligible=lambda _f: True))
        assert [t.type for t in plain.tokens] == ["github_token"]
        assert plain.unrestorable == 1
        assert DOC_IBAN not in plain.text

        kept = server.capture(
            text,
            CaptureOptions(issued_tenant=TENANT, release=RELEASE, pii=PiiRetention(retain=("pii_global_iban",))),
        )
        assert sorted(t.type for t in kept.tokens) == ["github_token", "pii_global_iban"]
        assert DOC_IBAN not in kept.text
        restored = await server.restore(
            RestoreRequest(
                sink="sink-synthetic",
                captures=(kept.capture_id,),
                fields={"body": kept.text},
                purpose="purpose-synthetic",
                tenant=TENANT,
            )
        )
        assert restored.fields["body"] == text

    asyncio.run(run())
