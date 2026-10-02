#!/usr/bin/env python3
"""Run the Python test suite against a packed wheel, one clean virtualenv per extra combination (gate G8).

    python scripts/qualify-python-wheel.py packages/vault-py/dist/redact_secret_vault-*.whl [--python 3.12] [--cells base,crypto]

docs/plans/python-persistence-parity.md section 6.6: the gates run against the built wheel installed in a virtualenv
outside the repository, never against an editable install. For each cell this script

1. creates a virtualenv in a temporary directory outside the repository (``uv venv --python <version>``);
2. installs the wheel with the cell's extras, plus ``pytest`` and, for a database cell, ``psycopg[binary]`` and
   ``psycopg-pool`` (the ``postgres`` extra names plain ``psycopg``, which needs a system ``libpq``; the variant that was
   tested is printed);
3. checks that ``redact_secret_vault`` is imported from that virtualenv and not from a checkout, that ``pip check``
   passes, that the wheel's installed files hold no test driver, fixture, or hold or fault hook, and prints the versions of
   ``cryptography``, ``cffi``, ``psycopg``, ``boto3``, and ``botocore`` that were installed;
4. copies the package's ``tests`` to a mirror of the repository's layout in the temporary directory (everything else is a
   link to the checkout, so the vectors, the corpus, the schedule corpus and its orchestrator, and ``node_modules`` are
   found), and runs the tests the cell selects there, with the vectors path given by ``RSV_PERSISTENT_VECTORS``.

A cell that needs a database runs only with ``RSV_PG_APP_URL`` and ``RSV_PG_ADMIN_URL`` set, and is otherwise reported
``NOT RUN``. Needs ``uv``, network access to the package index, and Node.js for the cells that run the bridge or the
orchestrator. Exit status 0 only when every cell that ran passed.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "packages" / "vault-py"

BASE_TESTS = (
    "tests/test_persistent_contracts.py",
    "tests/test_persistent_validate.py",
    "tests/test_persistent_codec.py",
    "tests/test_store_memory.py",
    "tests/test_import_isolation.py",
)
FORBIDDEN_PARTS = ("tests/", "conftest", "vectors.json", "insecure", "schedule_", "pg_support", "kms_support")


@dataclass(frozen=True)
class Cell:
    name: str
    extras: str
    #: Extra requirements installed beside the wheel, and why.
    requirements: tuple[str, ...]
    tests: tuple[str, ...]
    needs_database: bool = False


CELLS = (
    Cell("base", "", (), BASE_TESTS),
    Cell(
        "crypto",
        "crypto",
        (),
        (
            *BASE_TESTS,
            "tests/test_persistent_vectors.py",
            "tests/test_crypto_vectors.py",
            "tests/test_crypto_record.py",
            "tests/test_crypto_local_provider.py",
            "tests/test_crypto_leaks.py",
            "tests/test_persistent_server.py",
            "tests/test_persistent_server_leaks.py",
        ),
    ),
    Cell(
        "crypto-postgres",
        "crypto,postgres",
        ("psycopg[binary]", "psycopg-pool"),
        (
            "tests/test_stores_postgres.py",
            "tests/test_stores_postgres_processes.py",
            "tests/test_interop_postgres.py",
        ),
        needs_database=True,
    ),
    Cell(
        "crypto-aws-kms",
        "crypto,aws-kms",
        (),
        ("tests/test_aws_kms_provider.py", "tests/test_crypto_vectors.py", "tests/test_persistent_vectors.py"),
    ),
    Cell(
        "all",
        "crypto,postgres,aws-kms",
        ("psycopg[binary]", "psycopg-pool"),
        (
            "tests/test_persistent_vectors.py",
            "tests/test_crypto_vectors.py",
            "tests/test_import_isolation.py",
            "tests/test_aws_kms_provider.py",
            "tests/test_stores_postgres_processes.py",
            "tests/test_interop_postgres.py",
        ),
        needs_database=True,
    ),
)


class Failure(Exception):
    pass


def run(
    args: list[str], *, cwd: Path, env: dict[str, str] | None = None, capture: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, env=env, capture_output=capture, text=True, check=False)  # noqa: S603


def mirror(tree: Path) -> Path:
    for entry in REPO.iterdir():
        if entry.name in (".git", "packages", ".venv"):
            continue
        os.symlink(entry, tree / entry.name)
    packages = tree / "packages"
    packages.mkdir()
    for entry in (REPO / "packages").iterdir():
        if entry.name != "vault-py":
            os.symlink(entry, packages / entry.name)
    package = packages / "vault-py"
    package.mkdir()
    shutil.copytree(PACKAGE / "tests", package / "tests", ignore=shutil.ignore_patterns("__pycache__"))
    return package


def check_cell(cell: Cell, wheel: Path, python_version: str, have_database: bool) -> tuple[str, str]:
    if cell.needs_database and not have_database:
        return "NOT RUN", "no database (RSV_PG_APP_URL, RSV_PG_ADMIN_URL)"
    with tempfile.TemporaryDirectory(prefix="rsv-wheel-") as raw:
        root = Path(raw).resolve()
        if root.is_relative_to(REPO):
            raise Failure("the temporary directory is inside the repository")
        env_dir = root / "venv"
        made = run(["uv", "venv", "--python", python_version, str(env_dir)], cwd=root)
        if made.returncode != 0:
            raise Failure("could not create the virtualenv: " + made.stderr.strip()[-300:])
        python = env_dir / "bin" / "python"
        spec = f"{wheel}[{cell.extras}]" if cell.extras else str(wheel)
        installed = run(
            ["uv", "pip", "install", "--python", str(python), spec, "pytest>=8,<9", *cell.requirements], cwd=root
        )
        if installed.returncode != 0:
            raise Failure("install failed: " + installed.stderr.strip()[-400:])
        checked = run(["uv", "pip", "check", "--python", str(python)], cwd=root)
        if checked.returncode != 0:
            raise Failure("pip check failed: " + (checked.stdout + checked.stderr).strip()[-300:])
        origin = run(
            [
                str(python),
                "-I",
                "-c",
                "import redact_secret_vault, sys; print(redact_secret_vault.__file__); print(sys.version.split()[0])",
            ],
            cwd=root,
        )
        location, interpreter = origin.stdout.split()
        if "site-packages" not in location or str(REPO) in location:
            raise Failure(f"redact_secret_vault is not imported from the virtualenv: {location}")
        with zipfile.ZipFile(wheel) as archive:
            leaked = [n for n in archive.namelist() if any(part in n for part in FORBIDDEN_PARTS)]
        if leaked:
            raise Failure(f"the wheel holds test tooling: {leaked[:3]}")
        versions = run(
            [
                str(python),
                "-I",
                "-c",
                "import importlib.metadata as m\n"
                "for name in ('cryptography','cffi','psycopg','psycopg-binary','psycopg-pool','boto3','botocore'):\n"
                "    try:\n        print(name, m.version(name))\n    except m.PackageNotFoundError:\n        pass\n",
            ],
            cwd=root,
        ).stdout.replace("\n", "; ")
        package = mirror(root)
        env = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "RSV_PERSISTENT_VECTORS": str(REPO / "conformance" / "persistent" / "v1" / "vectors.json"),
            "RSV_SCHEDULES_DIR": str(REPO / "conformance" / "persistent" / "v1"),
            "REDACT_SECRET_VAULT_NODE_MODULES": str(REPO / "node_modules"),
        }
        env.pop("PYTHONPATH", None)
        if cell.needs_database:
            env["RSV_REQUIRE_POSTGRES"] = "1"
        tests = run(
            [str(python), "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rs", *cell.tests],
            cwd=package,
            env=env,
        )
        tail = [line for line in tests.stdout.strip().splitlines() if line.strip()][-1] if tests.stdout.strip() else ""
        detail = f"python {interpreter}; {versions}; {tail}"
        if tests.returncode != 0:
            return "FAILED", detail + "\n" + tests.stdout[-1500:]
        return "passed", detail


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel")
    parser.add_argument("--python", default="3.12")
    parser.add_argument("--cells", default=",".join(cell.name for cell in CELLS))
    options = parser.parse_args(argv[1:])
    wheel = Path(options.wheel).resolve()
    if not wheel.is_file() or wheel.suffix != ".whl":
        print(f"not a wheel: {wheel}", file=sys.stderr)
        return 2
    if shutil.which("uv") is None:
        print("uv is needed to create the virtualenvs", file=sys.stderr)
        return 2
    have_database = bool(os.environ.get("RSV_PG_APP_URL")) and bool(os.environ.get("RSV_PG_ADMIN_URL"))
    wanted = set(options.cells.split(","))
    failed = False
    for cell in CELLS:
        if cell.name not in wanted:
            continue
        try:
            status, detail = check_cell(cell, wheel, options.python, have_database)
        except Failure as failure:
            status, detail = "FAILED", str(failure)
        print(f"{status:>8}  {cell.name:<16} {detail}", flush=True)
        failed = failed or status == "FAILED"
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
