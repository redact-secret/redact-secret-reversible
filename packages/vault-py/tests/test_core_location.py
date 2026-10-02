"""Where ``NodeCoreBridge`` loads ``@redact-secret/core`` from.

A ``pip``-installed package keeps ``boundary/core_bridge.mjs`` in
site-packages, where no ``node_modules`` holding the core is an ancestor, so
script-relative resolution cannot find it. These tests copy the real bridge
script into such an out-of-tree directory and check that:

- without ``node_modules=`` or ``REDACT_SECRET_VAULT_NODE_MODULES`` the core
  is not found (``BRIDGE_CORE_NOT_FOUND``), and the working directory is never
  consulted;
- an explicit ``node_modules=`` or the environment variable loads the core
  from exactly that directory;
- a directory that does not hold the core fails closed with a fixed code and
  no path in the error.

Fake cores are used for the rules; the last test uses the real pinned core
from this repository's ``npm ci`` when it is installed.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from redact_secret_vault import NodeCoreBridge as _NodeCoreBridge
from redact_secret_vault import VaultServerError, VaultServerErrorCode
from redact_secret_vault.core_client import DEFAULT_BRIDGE_SCRIPT, NODE_MODULES_ENV, PINNED_CORE_VERSION


def NodeCoreBridge(**kwargs) -> _NodeCoreBridge:  # noqa: N802 - stands in for the class
    """The fake cores of this file are not the pinned release's files, so they opt out of the integrity pin (their
    subject is where a core is loaded from); the pin has its own tests in test_core_integrity.py."""
    kwargs.setdefault("expected_core_integrity", None)
    return _NodeCoreBridge(**kwargs)


pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is required to run core_bridge.mjs")

REPO_NODE_MODULES = Path(__file__).resolve().parents[3] / "node_modules"
SYNTHETIC_TOKEN = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000"


def _fake_core_source(tag: str) -> str:
    return f"""
export const VERSION = "{PINNED_CORE_VERSION}";
export function artifact() {{ return {{ kind: "fake-{tag}" }}; }}
export async function initialize() {{}}
export function piiActivation() {{ return "credentials=full;selectors=off;fake=1"; }}
export function scan() {{ return []; }}
"""


def _install_fake_core(node_modules: Path, tag: str, *, exports=None, source: str | None = None) -> Path:
    package = node_modules / "@redact-secret" / "core"
    (package / "dist").mkdir(parents=True)
    if exports is None:
        # The real core's shape.
        exports = {".": {"types": "./dist/index.d.ts", "import": "./dist/index.js"}}
    manifest = {"name": "@redact-secret/core", "type": "module", "exports": exports}
    (package / "package.json").write_text(json.dumps(manifest))
    (package / "dist" / "index.js").write_text(source if source is not None else _fake_core_source(tag))
    return node_modules


@pytest.fixture
def out_of_tree_script(tmp_path) -> Path:
    """The real bridge script in a site-packages-like directory with no
    node_modules above it."""
    boundary = tmp_path / "site-packages" / "redact_secret_vault" / "boundary"
    boundary.mkdir(parents=True)
    script = boundary / "core_bridge.mjs"
    shutil.copyfile(DEFAULT_BRIDGE_SCRIPT, script)
    return script


def _core_code(bridge: NodeCoreBridge) -> str | None:
    with pytest.raises(VaultServerError) as excinfo:
        bridge.scan("text-synthetic")
    assert excinfo.value.code == VaultServerErrorCode.CORE_FAILURE
    return excinfo.value.core_code


def test_out_of_tree_script_without_a_location_does_not_find_the_core(out_of_tree_script):
    assert _core_code(NodeCoreBridge(script=out_of_tree_script)) == "BRIDGE_CORE_NOT_FOUND"


def test_the_working_directory_is_never_used(tmp_path, out_of_tree_script, monkeypatch):
    cwd = tmp_path / "attacker-cwd"
    _install_fake_core(cwd / "node_modules", "cwd")
    monkeypatch.chdir(cwd)
    assert _core_code(NodeCoreBridge(script=out_of_tree_script)) == "BRIDGE_CORE_NOT_FOUND"


def test_explicit_node_modules_loads_the_core_from_that_directory(tmp_path, out_of_tree_script):
    node_modules = _install_fake_core(tmp_path / "app" / "node_modules", "app")
    outcome = NodeCoreBridge(script=out_of_tree_script, node_modules=node_modules).scan("text-synthetic")
    assert outcome.artifact == "fake-app"
    assert outcome.core_version == PINNED_CORE_VERSION


def test_explicit_node_modules_accepts_a_str(tmp_path, out_of_tree_script):
    node_modules = _install_fake_core(tmp_path / "app" / "node_modules", "app")
    outcome = NodeCoreBridge(script=out_of_tree_script, node_modules=str(node_modules)).scan("text-synthetic")
    assert outcome.artifact == "fake-app"


def test_environment_variable_is_the_fallback(tmp_path, out_of_tree_script, monkeypatch):
    node_modules = _install_fake_core(tmp_path / "env" / "node_modules", "env")
    monkeypatch.setenv(NODE_MODULES_ENV, str(node_modules))
    assert NodeCoreBridge(script=out_of_tree_script).scan("text-synthetic").artifact == "fake-env"


def test_explicit_argument_wins_over_the_environment_variable(tmp_path, out_of_tree_script, monkeypatch):
    monkeypatch.setenv(NODE_MODULES_ENV, str(_install_fake_core(tmp_path / "env" / "node_modules", "env")))
    explicit = _install_fake_core(tmp_path / "app" / "node_modules", "app")
    bridge = NodeCoreBridge(script=out_of_tree_script, node_modules=explicit)
    assert bridge.scan("text-synthetic").artifact == "fake-app"


def test_empty_environment_variable_means_unset(out_of_tree_script, monkeypatch):
    monkeypatch.setenv(NODE_MODULES_ENV, "")
    assert _core_code(NodeCoreBridge(script=out_of_tree_script)) == "BRIDGE_CORE_NOT_FOUND"


def test_relative_path_is_fixed_at_construction(tmp_path, out_of_tree_script, monkeypatch):
    _install_fake_core(tmp_path / "app" / "node_modules", "app")
    monkeypatch.chdir(tmp_path / "app")
    bridge = NodeCoreBridge(script=out_of_tree_script, node_modules="node_modules")
    elsewhere = tmp_path / "elsewhere"
    _install_fake_core(elsewhere / "node_modules", "elsewhere")
    monkeypatch.chdir(elsewhere)
    assert bridge.scan("text-synthetic").artifact == "fake-app"


def test_nonexistent_directory_is_a_fixed_value_free_error(tmp_path, out_of_tree_script):
    missing = tmp_path / "missing-synthetic" / "node_modules"
    with pytest.raises(VaultServerError) as excinfo:
        NodeCoreBridge(script=out_of_tree_script, node_modules=missing).scan("text-synthetic")
    assert excinfo.value.code == VaultServerErrorCode.CORE_FAILURE
    assert excinfo.value.core_code == "BRIDGE_CORE_NOT_FOUND"
    assert "missing-synthetic" not in str(excinfo.value)


def test_nonexistent_directory_from_the_environment_variable(tmp_path, out_of_tree_script, monkeypatch):
    monkeypatch.setenv(NODE_MODULES_ENV, str(tmp_path / "missing-synthetic"))
    assert _core_code(NodeCoreBridge(script=out_of_tree_script)) == "BRIDGE_CORE_NOT_FOUND"


def test_directory_without_the_core_is_not_found(tmp_path, out_of_tree_script):
    empty = tmp_path / "empty" / "node_modules"
    empty.mkdir(parents=True)
    assert _core_code(NodeCoreBridge(script=out_of_tree_script, node_modules=empty)) == "BRIDGE_CORE_NOT_FOUND"


def test_core_is_not_looked_up_in_parent_directories(tmp_path, out_of_tree_script):
    # <tmp>/outer/node_modules holds a core; <tmp>/outer/inner/node_modules does not.
    _install_fake_core(tmp_path / "outer" / "node_modules", "outer")
    inner = tmp_path / "outer" / "inner" / "node_modules"
    inner.mkdir(parents=True)
    assert _core_code(NodeCoreBridge(script=out_of_tree_script, node_modules=inner)) == "BRIDGE_CORE_NOT_FOUND"


def test_package_with_another_name_is_not_found(tmp_path, out_of_tree_script):
    node_modules = _install_fake_core(tmp_path / "app" / "node_modules", "app")
    manifest = node_modules / "@redact-secret" / "core" / "package.json"
    manifest.write_text(json.dumps({"name": "not-the-core-synthetic", "type": "module", "exports": "./dist/index.js"}))
    assert _core_code(NodeCoreBridge(script=out_of_tree_script, node_modules=node_modules)) == "BRIDGE_CORE_NOT_FOUND"


@pytest.mark.parametrize(
    "exports",
    [
        "../../outside.js",
        {".": {"import": "../../outside.js"}},
        {".": {"require": "./dist/index.js"}},  # no ESM condition
        {"./other": "./dist/index.js"},  # no root entry
    ],
)
def test_unusable_exports_are_not_found(tmp_path, out_of_tree_script, exports):
    node_modules = _install_fake_core(tmp_path / "app" / "node_modules", "app", exports=exports)
    (node_modules / "outside.js").write_text(_fake_core_source("outside"))
    assert _core_code(NodeCoreBridge(script=out_of_tree_script, node_modules=node_modules)) == "BRIDGE_CORE_NOT_FOUND"


@pytest.mark.parametrize(
    "exports", ["./dist/index.js", {"import": "./dist/index.js"}, {".": {"node": "./dist/index.js"}}]
)
def test_supported_exports_shapes(tmp_path, out_of_tree_script, exports):
    node_modules = _install_fake_core(tmp_path / "app" / "node_modules", "app", exports=exports)
    assert NodeCoreBridge(script=out_of_tree_script, node_modules=node_modules).scan("x").artifact == "fake-app"


def test_core_that_fails_to_load_is_a_fixed_error(tmp_path, out_of_tree_script):
    node_modules = _install_fake_core(
        tmp_path / "app" / "node_modules", "app", source='throw new Error("boom-synthetic");\n'
    )
    with pytest.raises(VaultServerError) as excinfo:
        NodeCoreBridge(script=out_of_tree_script, node_modules=node_modules).scan("text-synthetic")
    assert excinfo.value.core_code == "BRIDGE_CORE_LOAD_FAILED"
    assert "boom-synthetic" not in str(excinfo.value)


def test_pinned_version_check_still_applies(tmp_path, out_of_tree_script):
    source = _fake_core_source("old").replace(PINNED_CORE_VERSION, "0.0.0-synthetic")
    node_modules = _install_fake_core(tmp_path / "app" / "node_modules", "app", source=source)
    assert _core_code(NodeCoreBridge(script=out_of_tree_script, node_modules=node_modules)) == "CORE_VERSION_MISMATCH"


@pytest.mark.parametrize("value", [b"/bytes-synthetic", 123, "", "a\x00b"])
def test_malformed_node_modules_is_invalid_argument(value):
    with pytest.raises(VaultServerError) as excinfo:
        NodeCoreBridge(node_modules=value)
    assert excinfo.value.code == VaultServerErrorCode.INVALID_ARGUMENT


@pytest.mark.skipif(
    not (REPO_NODE_MODULES / "@redact-secret" / "core" / "package.json").is_file(),
    reason="run `npm ci` at the repository root to install the pinned @redact-secret/core",
)
def test_real_core_from_an_out_of_tree_script(out_of_tree_script):
    assert _core_code(NodeCoreBridge(script=out_of_tree_script)) == "BRIDGE_CORE_NOT_FOUND"
    outcome = NodeCoreBridge(script=out_of_tree_script, node_modules=REPO_NODE_MODULES).scan(
        f"deploy with {SYNTHETIC_TOKEN} now"
    )
    assert outcome.core_version == PINNED_CORE_VERSION
    assert [f.type for f in outcome.findings] == ["github_token"]
