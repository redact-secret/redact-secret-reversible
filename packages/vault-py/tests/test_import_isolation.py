"""Import isolation of the optional modules (docs/plans/python-persistence-parity.md section 4.2).

These run in the development environment, in subprocesses, because another test may
already have imported a dependency in this process. The packed-wheel versions, in clean
virtualenvs, are scripts/check-python-isolation.py and scripts/verify-python-dist.py, run by CI.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from email.parser import HeaderParser
from pathlib import Path
from typing import Any

import pytest

SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"

FAMILIES = {
    "crypto": {"cryptography", "cffi", "_cffi_backend"},
    "postgres": {"psycopg", "psycopg_pool", "psycopg_binary", "psycopg_c"},
    "aws-kms": {"boto3", "botocore", "s3transfer", "jmespath"},
}
MODULES = {
    "crypto": "redact_secret_vault.crypto",
    "postgres": "redact_secret_vault.stores.postgres",
    "aws-kms": "redact_secret_vault.keys.aws_kms",
}
DEPENDENCY = {"crypto": "cryptography", "postgres": "psycopg", "aws-kms": "boto3"}
BASE = "import redact_secret_vault, redact_secret_vault.persistent, redact_secret_vault.persistent.store_memory\n"


def probe(imports: str, banned: set[str]) -> str:
    return (
        "import sys\n"
        f"{imports}\n"
        f"banned = {sorted(banned)!r}\n"
        "hit = sorted(m for m in sys.modules if m.split('.')[0] in banned)\n"
        "assert not hit, hit\n"
    )


def run(code: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-I", "-c", code], cwd=cwd, capture_output=True, text=True, check=False)


def everything() -> set[str]:
    return set().union(*FAMILIES.values())


def test_base_imports_load_no_optional_dependency(tmp_path: Path) -> None:
    result = run(probe(BASE, everything()), tmp_path)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("extra", sorted(FAMILIES))
def test_a_blocked_dependency_makes_the_module_raise_import_error_naming_the_extra(tmp_path: Path, extra: str) -> None:
    dependency = DEPENDENCY[extra]
    code = (
        "import sys\n"
        f"sys.modules[{dependency!r}] = None\n"  # how an import is blocked: the dependency is absent
        "try:\n"
        f"    import {MODULES[extra]}\n"
        "except ImportError as error:\n"
        f"    assert 'redact-secret-vault[{extra}]' in str(error), str(error)\n"
        f"    assert {MODULES[extra]!r} not in sys.modules\n"
        "else:\n"
        "    raise SystemExit('imported without the extra')\n"
    )
    result = run(code, tmp_path)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("extra", sorted(FAMILIES))
def test_an_installed_extra_imports_and_loads_only_its_own_family(tmp_path: Path, extra: str) -> None:
    if importlib.util.find_spec(DEPENDENCY[extra]) is None:
        pytest.skip(f"the {extra} extra is not installed here; the packed-wheel job installs it")
    others = everything() - FAMILIES[extra]
    result = run(probe(f"{BASE}import {MODULES[extra]}", others), tmp_path)
    assert result.returncode == 0, result.stderr


def test_the_optional_modules_do_not_fall_back_to_anything(tmp_path: Path) -> None:
    # With every dependency blocked, each module still fails; none of them defines a substitute.
    blocked = "".join(f"sys.modules[{d!r}] = None\n" for d in DEPENDENCY.values())
    for extra, module in MODULES.items():
        code = f"import sys\n{blocked}import {module}\n"
        result = run(code, tmp_path)
        assert result.returncode != 0
        assert f"redact-secret-vault[{extra}]" in result.stderr


def test_require_python_raises_import_error_below_the_floor() -> None:
    from redact_secret_vault._extras import require_python

    with pytest.raises(ImportError, match="requires Python 99.0 or later"):
        require_python("redact_secret_vault.persistent", (99, 0))
    require_python("redact_secret_vault.persistent", (3, 11))


# --------------------------------------------------------------------------
# The scripts CI runs against the packed wheel
# --------------------------------------------------------------------------


def load_script(name: str) -> Any:
    path = SCRIPTS / name
    if not path.is_file():
        pytest.skip(f"{path} is not in this checkout")
    spec = importlib.util.spec_from_file_location(name.replace("-", "_").removesuffix(".py"), path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_isolation_script_names_the_same_families_and_modules() -> None:
    script = load_script("check-python-isolation.py")
    assert {k: set(v) for k, v in script.FAMILIES.items()} == FAMILIES
    assert script.MODULES == MODULES
    assert script.MARKERS == DEPENDENCY


def metadata(*requires: str, extras: tuple[str, ...] = ("crypto", "postgres", "aws-kms")) -> Any:
    lines = ["Name: redact-secret-vault", "Version: 0"]
    lines += [f"Provides-Extra: {e}" for e in extras]
    lines += [f"Requires-Dist: {r}" for r in requires]
    return HeaderParser().parsestr("\n".join(lines) + "\n")


GATED = (
    "cryptography>=47; extra == 'crypto'",
    "psycopg<4,>=3.2; extra == 'postgres'",
    "boto3>=1.43; extra == 'aws-kms'",
)


def test_verify_python_dist_accepts_gated_requirements_and_rejects_the_rest() -> None:
    script = load_script("verify-python-dist.py")
    script.check_requirements("w.whl", metadata(*GATED))
    with pytest.raises(SystemExit, match="without an `extra ==` marker"):
        script.check_requirements("w.whl", metadata(*GATED, "requests>=2"))
    with pytest.raises(SystemExit, match="does not provide the extras"):
        script.check_requirements("w.whl", metadata(*GATED[:2], extras=("crypto", "postgres")))
    with pytest.raises(SystemExit, match="requires nothing"):
        script.check_requirements("w.whl", metadata(*GATED[:2]))
