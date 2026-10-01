"""Command line entry: ``python -m redact_secret_vault doctor``."""

from __future__ import annotations

import argparse
import sys

from .core_client import NODE_MODULES_ENV
from .doctor import run_doctor


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m redact_secret_vault")
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="check that node and @redact-secret/core can be reached")
    doctor.add_argument(
        "--node-modules",
        default=None,
        help=(
            "the node_modules directory that holds @redact-secret/core "
            f"(default: {NODE_MODULES_ENV}, then next to the package)"
        ),
    )
    args = parser.parse_args(argv)
    return run_doctor(args.node_modules)


if __name__ == "__main__":
    sys.exit(main())
