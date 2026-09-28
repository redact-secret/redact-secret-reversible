#!/usr/bin/env python3
"""Check a built redact-secret-vault sdist and wheel before they are published.

Run from packages/vault-py after `python -m build` (release.yml's python-dist
job does this). Fails unless dist/ holds exactly one wheel and one sdist, the
wheel carries the Node.js core bridge script, and both carry the version in
pyproject.toml. Python 3.11+ (tomllib).
"""

import pathlib
import sys
import tarfile
import tomllib
import zipfile
from email.parser import HeaderParser

BRIDGE = "redact_secret_vault/boundary/core_bridge.mjs"


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
        wheel_version = HeaderParser().parsestr(zf.read(meta).decode())["Version"]
    with tarfile.open(sdist) as tf:
        pkg_info = next(m for m in tf.getmembers() if m.name.count("/") == 1 and m.name.endswith("/PKG-INFO"))
        sdist_version = HeaderParser().parsestr(tf.extractfile(pkg_info).read().decode())["Version"]

    for name, version in ((wheel.name, wheel_version), (sdist.name, sdist_version)):
        if version != expected:
            sys.exit(f"{name} has version {version!r}; pyproject.toml says {expected!r}")
    print(f"{wheel.name} and {sdist.name}: version {expected}, wheel carries {BRIDGE}")


if __name__ == "__main__":
    main()
