"""Test-only: run the language-neutral schedule corpus through a driver (plan section 6.3).

The orchestrator is Node.js (``conformance/persistent/v1/orchestrator.mjs``), written once for every
language. A test starts it with the Python driver as the command, and reads its JSON report. The corpus
and the orchestrator are found through ``RSV_SCHEDULES_DIR``, defaulting to the repository checkout, as
the wheel ships neither.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ENV = "RSV_SCHEDULES_DIR"
DEFAULT = Path(__file__).resolve().parents[3] / "conformance" / "persistent" / "v1"
DRIVER = Path(__file__).resolve().parent / "schedule_driver.py"


def schedules_dir() -> Path:
    override = os.environ.get(ENV)
    return Path(override) if override else DEFAULT


def have_orchestrator() -> bool:
    return shutil.which("node") is not None and (schedules_dir() / "orchestrator.mjs").is_file()


def load_corpus() -> dict[str, Any]:
    data = json.loads((schedules_dir() / "schedules.json").read_text(encoding="utf-8"))
    assert isinstance(data["version"], str) and data["version"].split(".")[0] == "1", "unknown schedules version"
    return data


def run_schedules(
    *,
    driver: Path = DRIVER,
    level: str | None = None,
    ids: tuple[str, ...] = (),
    store_options: dict[str, Any] | None = None,
    parallelism: int | None = None,
    timeout: float = 300,
) -> dict[str, Any]:
    """The orchestrator's report: ``{"counts": {...}, "results": [{id, group, status, detail?, native}]}``."""

    command = f'"{sys.executable}" "{driver}"'
    args = [shutil.which("node") or "node", str(schedules_dir() / "orchestrator.mjs"), "--driver", command, "--json"]
    if level is not None:
        args += ["--level", level]
    if ids:
        args += ["--ids", ",".join(ids)]
    if store_options is not None:
        args += ["--store-options", json.dumps(store_options)]
    if parallelism is not None:
        args += ["--parallelism", str(parallelism)]
    done = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603
    if done.returncode not in (0, 1):
        raise AssertionError(f"orchestrator exited {done.returncode}")
    return json.loads(done.stdout.strip().splitlines()[-1])
