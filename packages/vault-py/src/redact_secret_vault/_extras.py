"""Internal: how an optional module fails when its extra is not installed.

The base distribution has no runtime dependency. Modules that need one
(``crypto``, ``stores.postgres``, ``keys.aws_kms``) call ``require_extra`` first,
so a missing dependency is an ``ImportError`` that names the extra to install,
and nothing falls back to another implementation. Presence is tested with
``find_spec``, which does not execute the dependency, so merely importing a
module here never imports a driver or an SDK.
"""

from __future__ import annotations

import importlib.util
import sys


def require_python(module: str, minimum: tuple[int, int] = (3, 11)) -> None:
    """``ImportError`` unless the interpreter is at least ``minimum`` (the persistent modules need 3.11)."""

    if sys.version_info < minimum:
        raise ImportError(f"{module} requires Python {minimum[0]}.{minimum[1]} or later", name=module)


def require_extra(module: str, dependency: str, extra: str) -> None:
    """``ImportError`` naming ``redact-secret-vault[extra]`` when ``dependency`` is not importable."""

    require_python(module)
    if sys.modules.get(dependency) is not None:
        return
    # ``sys.modules[name] = None`` is how an import is blocked; it counts as absent.
    present = dependency not in sys.modules and importlib.util.find_spec(dependency) is not None
    if not present:
        raise ImportError(
            f"{module} needs the optional dependency {dependency!r}. "
            f"Install it with: pip install 'redact-secret-vault[{extra}]'",
            name=module,
        )
