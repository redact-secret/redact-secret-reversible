#!/usr/bin/env python3
"""Import-isolation checks on a built redact-secret-vault wheel, in clean virtualenvs.

    python scripts/check-python-isolation.py packages/vault-py/dist/redact_secret_vault-*.whl

Implements items 2 to 5 of docs/plans/python-persistence-parity.md section 4.2
(item 1, the METADATA check, is in verify-python-dist.py). Needs Python 3.11 or
later and network access to the package index. For each case it creates a
virtualenv in a temporary directory outside the repository, installs the wheel,
and runs probes with `python -I` from that directory, never from the checkout:

* base:      the wheel alone. `redact_secret_vault`, `.persistent`, and
             `.persistent.store_memory` import; `pip list` shows nothing but pip
             (and setuptools before 3.12) besides the wheel; `pip check` passes;
             and each optional module raises ImportError naming its extra.
* all:       the wheel with [crypto,postgres,aws-kms]. The three dependency
             families are installed and importable, and the base imports load none
             of them. Importing one optional module loads only its own family.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

FAMILIES: dict[str, frozenset[str]] = {
    "crypto": frozenset({"cryptography", "cffi", "_cffi_backend"}),
    "postgres": frozenset({"psycopg", "psycopg_pool", "psycopg_binary", "psycopg_c"}),
    "aws-kms": frozenset({"boto3", "botocore", "s3transfer", "jmespath"}),
}
MODULES: dict[str, str] = {
    "crypto": "redact_secret_vault.crypto",
    "postgres": "redact_secret_vault.stores.postgres",
    "aws-kms": "redact_secret_vault.keys.aws_kms",
}
#: A top-level module whose presence proves the extra is installed.
MARKERS: dict[str, str] = {"crypto": "cryptography", "postgres": "psycopg", "aws-kms": "boto3"}
BASE_IMPORTS = "import redact_secret_vault, redact_secret_vault.persistent, redact_secret_vault.persistent.store_memory"


def probe(imports: str, banned: frozenset[str]) -> str:
    """Python source that imports, then fails if any banned top-level module is loaded."""

    return (
        "import sys\n"
        f"{imports}\n"
        f"banned = {sorted(banned)!r}\n"
        "hit = sorted(m for m in sys.modules if m.split('.')[0] in banned)\n"
        "assert not hit, hit\n"
    )


def families(*names: str) -> frozenset[str]:
    return frozenset().union(*(FAMILIES[n] for n in names)) if names else frozenset()


class Failure(Exception):
    pass


def run(python: Path, code: str, cwd: Path, what: str) -> str:
    result = subprocess.run([str(python), "-I", "-c", code], cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise Failure(f"{what} failed:\n{result.stdout}{result.stderr}")
    print(f"ok: {what}")
    return result.stdout


def make_venv(root: Path, name: str, wheel: Path, extras: str) -> Path:
    env = root / name
    subprocess.run([sys.executable, "-m", "venv", str(env)], check=True)
    python = env / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    spec = f"{wheel}[{extras}]" if extras else str(wheel)
    subprocess.run(
        [str(python), "-m", "pip", "install", "--disable-pip-version-check", "--no-cache-dir", "--quiet", spec],
        cwd=root,
        check=True,
    )
    return python


def installed(python: Path, cwd: Path) -> set[str]:
    out = subprocess.run(
        [str(python), "-m", "pip", "list", "--format=json", "--disable-pip-version-check"],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return {item["name"].lower().replace("_", "-") for item in json.loads(out)}


MISSING_EXTRA_PROBE = (
    "import importlib, sys\n"
    f"cases = {[(MODULES[e], e) for e in MODULES]!r}\n"
    "for module, extra in cases:\n"
    "    try:\n"
    "        importlib.import_module(module)\n"
    "    except ImportError as error:\n"
    '        assert f"redact-secret-vault[{extra}]" in str(error), str(error)\n'
    "        assert module not in sys.modules, module\n"
    "    else:\n"
    "        raise SystemExit(f'{module} imported without the {extra} extra')\n"
)


def check_base(root: Path, wheel: Path) -> None:
    python = make_venv(root, "base", wheel, "")
    cwd = root
    allowed = {"pip", "redact-secret-vault"} | ({"setuptools"} if sys.version_info < (3, 12) else set())
    extra = installed(python, cwd) - allowed
    if extra:
        raise Failure(f"base install brought in {sorted(extra)}")
    print("ok: base install lists no third-party distribution besides pip")
    subprocess.run([str(python), "-m", "pip", "check", "--disable-pip-version-check"], cwd=cwd, check=True)
    run(python, probe(BASE_IMPORTS, families(*FAMILIES)), cwd, "base imports load no optional dependency")
    run(python, MISSING_EXTRA_PROBE, cwd, "each optional module raises ImportError naming its extra")


def check_all(root: Path, wheel: Path) -> None:
    python = make_venv(root, "all", wheel, "crypto,postgres,aws-kms")
    cwd = root
    present = installed(python, cwd)
    for extra, marker in MARKERS.items():
        if marker not in present:
            raise Failure(f"the {extra} extra did not install {marker}")
    subprocess.run([str(python), "-m", "pip", "check", "--disable-pip-version-check"], cwd=cwd, check=True)
    for extra, marker in MARKERS.items():
        run(python, f"import importlib.util as u\nassert u.find_spec({marker!r})\n", cwd, f"{marker} is importable")
    run(
        python,
        probe(BASE_IMPORTS, families(*FAMILIES)),
        cwd,
        "base imports load no optional dependency (all extras installed)",
    )
    for extra, module in MODULES.items():
        others = tuple(n for n in FAMILIES if n != extra)
        run(
            python,
            probe(f"{BASE_IMPORTS}\nimport {module}", families(*others)),
            cwd,
            f"importing {module} loads only the {extra} family",
        )


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    wheel = Path(argv[1]).resolve()
    if not wheel.is_file() or wheel.suffix != ".whl":
        print(f"not a wheel: {wheel}", file=sys.stderr)
        return 2
    if sys.version_info < (3, 11):
        print(
            "Python 3.11 or later is required: the persistent modules do not import on older versions", file=sys.stderr
        )
        return 2
    try:
        with tempfile.TemporaryDirectory(prefix="vault-py-isolation-") as tmp:
            root = Path(tmp).resolve()
            if root.is_relative_to(Path(__file__).resolve().parents[1]):
                raise Failure("the temporary directory is inside the repository")
            check_base(root, wheel)
            check_all(root, wheel)
    except Failure as failure:
        print(failure, file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        print(f"command failed with status {error.returncode}: {error.cmd[:4]}", file=sys.stderr)
        return 1
    print("import isolation: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
