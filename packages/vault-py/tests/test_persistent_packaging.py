"""The base distribution keeps no runtime dependency (docs/plans/python-persistence-parity.md section 4)."""

from __future__ import annotations

from pathlib import Path

import tomllib

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_the_base_install_has_no_runtime_dependency() -> None:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    assert "dependencies" not in project
    assert "dynamic" not in project or "dependencies" not in project["dynamic"]
