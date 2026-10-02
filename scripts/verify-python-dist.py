#!/usr/bin/env python3
"""Check a built redact-secret-vault sdist and wheel before they are published.

Run from packages/vault-py after `python -m build` (release.yml's python-dist
job does this). Fails unless dist/ holds exactly one wheel and one sdist, the
wheel carries the Node.js core bridge script, and both carry the version in
pyproject.toml. It also checks that the base install has no runtime dependency
(every Requires-Dist line carries an `extra ==` marker), that the three extras
of the persistent groundwork exist, and that the wheel holds none of the test
tree. Python 3.11+ (tomllib).
"""

import pathlib
import sys
import tarfile
import tomllib
import zipfile
from email.parser import HeaderParser

BRIDGE = "redact_secret_vault/boundary/core_bridge.mjs"
EXTRAS = {"crypto", "postgres", "aws-kms"}
#: The optional modules ship in the wheel and fail with ImportError until their extra is installed.
OPTIONAL_MODULES = (
    "redact_secret_vault/crypto/__init__.py",
    "redact_secret_vault/stores/postgres.py",
    "redact_secret_vault/keys/aws_kms.py",
)
#: Nothing from the test tree may be installed: no test driver, fixture, or deterministic key provider.
FORBIDDEN_PARTS = ("tests/", "conftest", "vectors.json", "insecure")


def check_requirements(wheel_name: str, metadata) -> None:
    """The base install is dependency-free: every Requires-Dist is gated by an extra."""

    ungated = [r for r in metadata.get_all("Requires-Dist", []) if "extra ==" not in r]
    if ungated:
        sys.exit(f"{wheel_name} has a Requires-Dist without an `extra ==` marker: {ungated}")
    provided = set(metadata.get_all("Provides-Extra", []))
    missing = EXTRAS - provided
    if missing:
        sys.exit(f"{wheel_name} does not provide the extras {sorted(missing)}")
    for extra in EXTRAS:
        if not any(f"extra == '{extra}'" in r or f'extra == "{extra}"' in r for r in metadata.get_all("Requires-Dist", [])):
            sys.exit(f"{wheel_name}: the {extra!r} extra requires nothing")


def main() -> None:
    expected = tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"]
    dist = pathlib.Path("dist")
    found = sorted(p.name for p in dist.iterdir())
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1 or len(found) != 2:
        sys.exit(f"expected exactly one wheel and one sdist in dist/, found {found}")
    wheel, sdist = wheels[0], sdists[0]

    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
        if BRIDGE not in names:
            sys.exit(f"{wheel.name} is missing {BRIDGE}")
        meta = next(n for n in names if n.endswith(".dist-info/METADATA"))
        wheel_metadata = HeaderParser().parsestr(zf.read(meta).decode())
        wheel_version = wheel_metadata["Version"]
        check_requirements(wheel.name, wheel_metadata)
        for module in OPTIONAL_MODULES:
            if module not in names:
                sys.exit(f"{wheel.name} is missing {module}")
        installed_test_files = [n for n in names if any(part in n for part in FORBIDDEN_PARTS)]
        if installed_test_files:
            sys.exit(f"{wheel.name} carries test files: {installed_test_files}")
    with tarfile.open(sdist) as tf:
        pkg_info = next(m for m in tf.getmembers() if m.name.count("/") == 1 and m.name.endswith("/PKG-INFO"))
        sdist_version = HeaderParser().parsestr(tf.extractfile(pkg_info).read().decode())["Version"]

    for name, version in ((wheel.name, wheel_version), (sdist.name, sdist_version)):
        if version != expected:
            sys.exit(f"{name} has version {version!r}; pyproject.toml says {expected!r}")
    print(
        f"{wheel.name} and {sdist.name}: version {expected}, wheel carries {BRIDGE}, "
        f"no Requires-Dist outside the extras {sorted(EXTRAS)}"
    )


if __name__ == "__main__":
    main()
