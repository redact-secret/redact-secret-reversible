"""``python -m redact_secret_vault doctor`` (#135): one passing run against
the pinned core, and one test per failure it has to explain."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from redact_secret_vault.core_client import (
    DEFAULT_BRIDGE_SCRIPT,
    NODE_MODULES_ENV,
    PINNED_CORE_INTEGRITY,
    PINNED_CORE_VERSION,
)
from redact_secret_vault.doctor import run_doctor

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is required to run core_bridge.mjs")

REPO_NODE_MODULES = Path(__file__).resolve().parents[3] / "node_modules"
HAS_REAL_CORE = (REPO_NODE_MODULES / "@redact-secret" / "core" / "package.json").is_file()
SYNTHETIC_TOKEN = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000"


def _fake_core(
    node_modules: Path, *, version: str = PINNED_CORE_VERSION, findings: str = "[]", source: str | None = None
) -> Path:
    package = node_modules / "@redact-secret" / "core"
    (package / "dist").mkdir(parents=True)
    manifest = {"name": "@redact-secret/core", "type": "module", "exports": {".": {"import": "./dist/index.js"}}}
    (package / "package.json").write_text(json.dumps(manifest))
    (package / "dist" / "index.js").write_text(
        source
        if source is not None
        else f"""
export const VERSION = "{version}";
export function artifact() {{ return {{ kind: "fake" }}; }}
export async function initialize() {{}}
export function piiActivation() {{ return "credentials=full;selectors=off;fake=1"; }}
export function scan() {{ return {findings}; }}
"""
    )
    return node_modules


@pytest.fixture
def out_of_tree_script(tmp_path) -> Path:
    """The bridge script where no ``node_modules`` is an ancestor, as after ``pip install``."""
    target = tmp_path / "site-packages" / "boundary"
    target.mkdir(parents=True)
    return Path(shutil.copy(DEFAULT_BRIDGE_SCRIPT, target / "core_bridge.mjs"))


def _run(**kwargs) -> tuple[int, list[str]]:
    lines: list[str] = []
    # The fake cores of this file are not the pinned release's files, so they opt out of the integrity pin; the
    # tests of it are in test_core_integrity.py.
    kwargs.setdefault("integrity", None)
    return run_doctor(out=lines.append, **kwargs), lines


@pytest.mark.skipif(not HAS_REAL_CORE, reason="needs `npm ci` at the repository root")
def test_passes_against_the_pinned_core_and_prints_no_value(out_of_tree_script):
    code, lines = _run(node_modules=REPO_NODE_MODULES, script=out_of_tree_script)
    assert code == 0, lines
    assert [line.split(":")[0] for line in lines] == ["ok    node", "ok    core location", "ok    core", "ok    scan"]
    assert PINNED_CORE_VERSION in lines[2]
    assert all(SYNTHETIC_TOKEN not in line for line in lines)


def test_reads_the_environment_variable(out_of_tree_script, tmp_path, monkeypatch):
    monkeypatch.setenv(NODE_MODULES_ENV, str(_fake_core(tmp_path / "nm", findings="[]")))
    code, lines = _run(script=out_of_tree_script)
    assert any(line.startswith("ok    core location") and NODE_MODULES_ENV in line for line in lines)
    assert code == 1  # the fake core finds nothing
    assert lines[-2].startswith("FAIL  scan")


def test_missing_node_is_reported_with_a_fix(out_of_tree_script, tmp_path):
    code, lines = _run(node_executable=str(tmp_path / "no-such-node"), script=out_of_tree_script)
    assert code == 1
    assert lines[0].startswith("FAIL  node")
    assert "fix: install Node.js" in lines[1]
    assert lines[2].startswith("skip  core")


def test_untested_node_version_fails(out_of_tree_script, tmp_path):
    fake_node = tmp_path / "node"
    fake_node.write_text("#!/bin/sh\necho v18.20.0\n")
    fake_node.chmod(0o755)
    code, lines = _run(node_executable=str(fake_node), script=out_of_tree_script, node_modules=tmp_path)
    assert code == 1
    assert lines[0] == "FAIL  node: v18.20.0 is not a tested version"


def test_core_not_found(out_of_tree_script, tmp_path):
    empty = tmp_path / "empty" / "node_modules"
    empty.mkdir(parents=True)
    code, lines = _run(node_modules=empty, script=out_of_tree_script)
    assert code == 1
    assert "FAIL  core: BRIDGE_CORE_NOT_FOUND" in lines
    assert f"npm install @redact-secret/core@{PINNED_CORE_VERSION}" in lines[-1]


def test_no_location_at_all(out_of_tree_script):
    code, lines = _run(script=out_of_tree_script)
    assert code == 1
    assert any(line.startswith("ok    core location: next to the installed package") for line in lines)
    assert "FAIL  core: BRIDGE_CORE_NOT_FOUND" in lines
    assert "--node-modules" in lines[-1]


def test_core_that_does_not_load(out_of_tree_script, tmp_path):
    node_modules = _fake_core(tmp_path / "nm", source="throw new Error('synthetic load failure');")
    code, lines = _run(node_modules=node_modules, script=out_of_tree_script)
    assert code == 1
    assert "FAIL  core: BRIDGE_CORE_LOAD_FAILED" in lines
    assert all("synthetic load failure" not in line for line in lines)


def test_wrong_core_version_names_both_versions(out_of_tree_script, tmp_path):
    node_modules = _fake_core(tmp_path / "nm", version="0.1.0-beta.9")
    code, lines = _run(node_modules=node_modules, script=out_of_tree_script)
    assert code == 1
    assert f"FAIL  core: found @redact-secret/core 0.1.0-beta.9, need exactly {PINNED_CORE_VERSION}" in lines


def test_a_core_that_is_not_the_pinned_release_fails_the_integrity_pin_and_says_what_it_found(
    out_of_tree_script, tmp_path
):
    node_modules = _fake_core(tmp_path / "nm", version=PINNED_CORE_VERSION)
    manifest = node_modules / "@redact-secret" / "core" / "package.json"
    manifest.write_text(json.dumps({**json.loads(manifest.read_text()), "version": "0.1.0-beta.9"}))
    code, lines = _run(node_modules=node_modules, script=out_of_tree_script, integrity=PINNED_CORE_INTEGRITY)
    assert code == 1
    assert any(
        line.startswith("FAIL  core: CORE_INTEGRITY_MISMATCH (the installed package.json says 0.1.0-beta.9")
        for line in lines
    ), lines
    assert f"npm install @redact-secret/core@{PINNED_CORE_VERSION}" in lines[-1]


def test_unusable_path_argument(out_of_tree_script):
    code, lines = _run(node_modules="bad\x00path", script=out_of_tree_script)
    assert code == 1
    assert lines[0].startswith("ok    node")
    assert lines[1].startswith("FAIL  core location")


def test_module_entry_point_exits_non_zero_on_failure(tmp_path):
    empty = tmp_path / "node_modules"
    empty.mkdir()
    done = subprocess.run(
        [sys.executable, "-m", "redact_secret_vault", "doctor", "--node-modules", str(empty)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 1
    assert "FAIL  core: BRIDGE_CORE_NOT_FOUND" in done.stdout


@pytest.mark.skipif(not HAS_REAL_CORE, reason="needs `npm ci` at the repository root")
def test_module_entry_point_exits_zero():
    done = subprocess.run(
        [sys.executable, "-m", "redact_secret_vault", "doctor", "--node-modules", str(REPO_NODE_MODULES)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stdout
    assert SYNTHETIC_TOKEN not in done.stdout
