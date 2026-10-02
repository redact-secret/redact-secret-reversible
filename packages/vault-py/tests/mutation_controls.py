# ruff: noqa: E501
"""The named mutation controls of docs/plans/python-persistence-parity.md section 6.5 (gate G7), as an on-demand table.

Each control is a *mutant*: one exact textual change to one module of the Python package that breaks one fence of the
specification. The table applies a mutant to a throwaway copy of the package, runs the tests that are supposed to catch
it, and records the tests that failed. A mutant the suite does not catch is a finding, not a pass.

    python tests/mutation_controls.py --list
    python tests/mutation_controls.py                  # every mutant; the PostgreSQL ones need RSV_PG_APP_URL and RSV_PG_ADMIN_URL
    python tests/mutation_controls.py --only aad-omits-tenant --json out.json

The copy is a tree that mirrors the repository: the package's ``src`` and ``tests`` are real copies (so the mutant is what
runs, including inside the schedule driver, which puts its own ``src`` first on the path), and everything else is a symbolic
link to the checkout. Nothing in the checkout is changed. ``tests/test_mutation_controls.py`` checks, quickly and without a
database, that every mutant still applies exactly once.

A mutant that needs a database and has none is reported ``NOT RUN`` with that reason, never as caught.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
REPO = Path(__file__).resolve().parents[3]
PKG = "src/redact_secret_vault"

SCHEDULES_PROBE = (
    "import json, sys\n"
    "sys.path.insert(0, 'tests')\n"
    "from schedule_support import run_schedules\n"
    "ids = tuple(json.loads(sys.argv[1]))\n"
    "report = run_schedules(level='store', ids=ids, store_options={'backend': 'postgres'}, parallelism=16, timeout=600)\n"
    "bad = [row['id'] for row in report['results'] if row['status'] == 'failed']\n"
    "print(json.dumps({'failed': bad, 'ran': len(report['results'])}))\n"
    "sys.exit(1 if bad else 0)\n"
)


@dataclasses.dataclass(frozen=True)
class Mutant:
    id: str
    #: The row of the plan's section 6.5 table this control belongs to.
    row: str
    file: str
    old: str
    new: str
    #: Extra regular-expression guard that ``old`` must appear exactly once; ``old`` is also checked literally.
    pytest_args: tuple[str, ...] = ()
    #: Schedule-corpus case ids that must fail, run through the Python driver against PostgreSQL.
    schedules: tuple[str, ...] = ()
    needs_database: bool = False
    note: str = ""
    #: Further exact changes to the same file, each of which must also occur exactly once.
    also: tuple[tuple[str, str], ...] = ()


def _lines(*lines: str) -> str:
    return "\n".join(lines)


CODEC = f"{PKG}/persistent/codec.py"
DIGEST = f"{PKG}/persistent/digest.py"
VALIDATE = f"{PKG}/persistent/validate.py"
REJECT = f"{PKG}/persistent/_reject.py"
SERVER = f"{PKG}/persistent/server.py"
RECORD = f"{PKG}/crypto/record_crypto.py"
LOCAL = f"{PKG}/crypto/local_key_provider.py"
PG = f"{PKG}/stores/postgres.py"

VECTORS = ("tests/test_persistent_vectors.py", "tests/test_crypto_vectors.py")
UNITS = (*VECTORS, "tests/test_persistent_validate.py", "tests/test_persistent_codec.py", "tests/test_crypto_record.py")
PROCESSES = "tests/test_stores_postgres_processes.py"

MUTANTS: tuple[Mutant, ...] = (
    # --- store: transactions and fences, against PostgreSQL -----------------------------------------------------
    Mutant(
        "commit-reads-capture-without-lock",
        "Commit does not conflict with a concurrent revoke (reads the capture without lock or condition)",
        PG,
        _lines("                ns.epoch,", '                " FOR SHARE",'),
        _lines("                ns.epoch,", '                "",'),
        pytest_args=(PROCESSES, "-k", "held_open_across_a_commit or late_revoke"),
        schedules=(
            "interleave.a-revocation-committed-between-a-restore-s-read-and-its-commit-the-restore-does-not-commit",
        ),
        needs_database=True,
    ),
    Mutant(
        "create-ignores-recovery-lock",
        "Create does not conflict with quarantine",
        PG,
        _lines(
            "        async def body(cursor: Any, head: _Head) -> CreateCaptureResult:",
            '            ns = await self._namespace(cursor, head, scope.namespace, "share")',
        ),
        _lines(
            "        async def body(cursor: Any, head: _Head) -> CreateCaptureResult:",
            '            ns = await self._namespace(cursor, head, scope.namespace, "none")',
        ),
        pytest_args=(PROCESSES, "-k", "recovery_operation"),
        schedules=(
            "interleave.a-quarantine-committed-between-a-creation-s-check-and-its-commit-the-creation-does-not-succeed",
        ),
        needs_database=True,
    ),
    Mutant(
        "generation-not-compared-at-commit",
        "generation, lifecycle_revision, or ciphertext_revision not compared at commit (generation)",
        PG,
        "                if capture.generation != expected.generation:",
        "                if False:",
        schedules=("commit.rejects-stale-for-a-different-lifecyclerevision-ciphertextrevision-or-generation",),
        needs_database=True,
    ),
    Mutant(
        "lifecycle-revision-not-compared-at-commit",
        "generation, lifecycle_revision, or ciphertext_revision not compared at commit (lifecycle revision)",
        PG,
        "                if _int(row[4], low=1) != use.lifecycle_revision or _int(row[5], low=1) != use.ciphertext_revision:",
        "                if _int(row[5], low=1) != use.ciphertext_revision:",
        schedules=("commit.rejects-stale-for-a-different-lifecyclerevision-ciphertextrevision-or-generation",),
        needs_database=True,
    ),
    Mutant(
        "ciphertext-revision-not-compared-at-commit",
        "generation, lifecycle_revision, or ciphertext_revision not compared at commit (ciphertext revision)",
        PG,
        "                if _int(row[4], low=1) != use.lifecycle_revision or _int(row[5], low=1) != use.ciphertext_revision:",
        "                if _int(row[4], low=1) != use.lifecycle_revision:",
        schedules=("commit.rejects-stale-for-a-different-lifecyclerevision-ciphertextrevision-or-generation",),
        needs_database=True,
    ),
    Mutant(
        "budget-not-checked-at-commit",
        "Budget checked at preflight only",
        PG,
        "                if used + use.count > max_uses:",
        "                if False:",
        pytest_args=(PROCESSES, "-k", "hundred_concurrent"),
        schedules=("commit.accepts-a-budget-exactly-at-maxuses-and-rejects-one-over",),
        needs_database=True,
    ),
    Mutant(
        "receipt-digest-not-compared",
        "Receipt lookup skipped, or digest not compared (digest)",
        PG,
        "                same = stored == digest",
        "                same = True",
        pytest_args=(PROCESSES, "-k", "one_attempt_submitted"),
        needs_database=True,
    ),
    Mutant(
        "receipt-lookup-skipped",
        "Receipt lookup skipped, or digest not compared (lookup)",
        PG,
        _lines(
            "                (scope.namespace, scope.tenant, attempt.attempt_id, digest, head.now, input.receipt_expires_at),",
            "            )",
            "            if cursor.rowcount != 1:",
        ),
        _lines(
            "                (scope.namespace, scope.tenant, attempt.attempt_id, digest, head.now, input.receipt_expires_at),",
            "            )",
            "            if False:",
        ),
        pytest_args=(PROCESSES, "-k", "one_attempt_submitted or ambiguous_commit"),
        needs_database=True,
    ),
    Mutant(
        "epoch-not-compared-at-commit",
        "Epoch not compared, or lower-epoch capture not treated as revoked (commit)",
        PG,
        _lines(
            '            ns = await self._namespace(cursor, head, scope.namespace, "share")',
            '            if ns.state != "serving" or ns.epoch != input.epoch:',
            '                raise _Rollback(RestoreRejected(reason="quarantined"))',
        ),
        _lines(
            '            ns = await self._namespace(cursor, head, scope.namespace, "share")',
            '            if ns.state != "serving":',
            '                raise _Rollback(RestoreRejected(reason="quarantined"))',
        ),
        pytest_args=("tests/test_stores_postgres.py", "-k", "epoch_other_than"),
        schedules=("recovery.captures-under-the-new-epoch-work-and-the-old-epoch-no-longer-does",),
        needs_database=True,
    ),
    Mutant(
        "lower-epoch-capture-not-revoked",
        "Epoch not compared, or lower-epoch capture not treated as revoked (read)",
        PG,
        '                    state="live" if state == "live" and epoch_of == epoch else "revoked",',
        '                    state="live" if state == "live" else "revoked",',
        schedules=("recovery.every-capture-of-an-earlier-epoch-is-treated-as-revoked-by-every-operation",),
        needs_database=True,
    ),
    Mutant(
        "commit-expiry-on-caller-clock",
        "Store clock replaced by caller now at commit",
        PG,
        "                if head.now >= capture.expires_at:",
        "                if input.now >= capture.expires_at:",
        also=(("            locked_at = await self._clock(cursor)", "            locked_at = input.now"),),
        pytest_args=("tests/test_stores_postgres.py", "-k", "expiry_is_judged"),
        schedules=(
            "commit.judges-expiry-on-the-store-s-clock-live-one-millisecond-before-expiresat-expired-exactly-at-it",
        ),
        needs_database=True,
    ),
    Mutant(
        "store-error-raised-inside-except",
        "Sanitized error raised inside the except block (store)",
        PG,
        _lines(
            "        except StoreError as error:",
            "            code = error.code",
            "        del operation, arguments",
            "        raise StoreError(code)  # type: ignore[arg-type]",
        ),
        _lines(
            "        except StoreError as error:",
            "            raise StoreError(error.code)",
            "        del operation, arguments",
            "        raise StoreError(code)  # type: ignore[arg-type]",
        ),
        pytest_args=("tests/test_stores_postgres.py", "-k", "nothing_secret or malformed or unreachable or closed"),
        needs_database=True,
    ),
    # --- record format: AAD, identifiers, ordering, decoder -----------------------------------------------------
    *(
        Mutant(
            f"aad-omits-{name}",
            f"AAD omits one field ({name})",
            CODEC,
            old,
            new,
            pytest_args=VECTORS,
        )
        for name, old, new in (
            (
                "tenant",
                "            lp16(utf8(b.tenant)),\n            lp16(utf8(b.capture_id)),",
                "            lp16(utf8(b.capture_id)),",
            ),
            (
                "capture",
                "            lp16(utf8(b.capture_id)),\n            lp16(utf8(b.entry_id)),",
                "            lp16(utf8(b.entry_id)),",
            ),
            (
                "entry",
                "            lp16(utf8(b.entry_id)),\n            u8(0 if b.session_id is None else 1),",
                "            u8(0 if b.session_id is None else 1),",
            ),
            ("session", "            u8(0 if b.session_id is None else 1),\n            lp16(session),", ""),
            (
                "created-at",
                "            u64(b.created_at),\n            u64(b.expires_at),",
                "            u64(b.expires_at),",
            ),
            (
                "expires-at",
                "            u64(b.expires_at),\n            u32(b.max_uses),",
                "            u32(b.max_uses),",
            ),
            (
                "max-uses",
                "            u64(b.expires_at),\n            u32(b.max_uses),\n",
                "            u64(b.expires_at),\n",
            ),
        )
    ),
    Mutant(
        "lone-surrogate-test-removed-well-formed",
        "Lone-surrogate test removed (is_well_formed)",
        VALIDATE,
        "    return type(text) is str and _SURROGATE.search(text) is None",
        "    return type(text) is str",
        pytest_args=UNITS,
    ),
    Mutant(
        "lone-surrogate-test-removed-identifier",
        "Lone-surrogate test removed (is_identifier)",
        VALIDATE,
        "    return _SURROGATE.search(value) is None and utf16_length(value) <= _limits.IDENTIFIER_MAX_LENGTH",
        "    return utf16_length(value) <= _limits.IDENTIFIER_MAX_LENGTH",
        pytest_args=UNITS,
    ),
    Mutant(
        "utf16-length-replaced-by-len",
        "UTF-16 length replaced by len()",
        VALIDATE,
        "    return _SURROGATE.search(value) is None and utf16_length(value) <= _limits.IDENTIFIER_MAX_LENGTH",
        "    return _SURROGATE.search(value) is None and len(value) <= _limits.IDENTIFIER_MAX_LENGTH",
        pytest_args=UNITS,
    ),
    Mutant(
        "digest-sorts-by-utf16",
        "Sort by the order of a UTF-16 encoding instead of UTF-8 bytes (request digest)",
        DIGEST,
        "    items.sort(key=key)",
        '    items.sort(key=lambda item: key(item).decode("utf-8").encode("utf-16-be"))',
        pytest_args=VECTORS,
    ),
    Mutant(
        "payload-sorts-by-utf16",
        "Sort by the order of a UTF-16 encoding instead of UTF-8 bytes (payload sets)",
        CODEC,
        "    encoded.sort()",
        '    encoded.sort(key=lambda item: item.decode("utf-8").encode("utf-16-be"))',
        pytest_args=UNITS,
    ),
    Mutant(
        "decoder-accepts-trailing-bytes",
        "Decoder accepts trailing bytes",
        CODEC,
        "    reader.end()\n",
        "    pass\n",
        pytest_args=UNITS,
    ),
    Mutant(
        "decoder-accepts-unsorted-grants",
        "Decoder accepts unsorted grants",
        CODEC,
        "        sink_raw, sink_text = _read_identifier(reader, previous_sink)",
        "        sink_raw, sink_text = _read_identifier(reader, None)",
        pytest_args=UNITS,
    ),
    Mutant(
        "sanitized-error-raised-inside-except",
        "Sanitized error raised inside the except block (crypto and codec)",
        REJECT,
        _lines(
            "        except Reject as rejected:",
            "            code = rejected.code",
            "        if code is not None:",
            "            raise RecordCryptoError(code)",
        ),
        _lines(
            "        except Reject as rejected:",
            "            raise RecordCryptoError(rejected.code)",
            "        if code is not None:",
            "            raise RecordCryptoError(code)",
        ),
        pytest_args=UNITS,
    ),
    # --- keys and the public surface ----------------------------------------------------------------------------
    Mutant(
        "unknown-key-ref-falls-back-to-the-active-key",
        "Fallback to another key when keyRef is unknown",
        LOCAL,
        _lines(
            "        if stored.key_ref.startswith(_KEY_REF_PREFIX):",
            "            material = self._held.get(stored.key_ref[len(_KEY_REF_PREFIX) :])",
            "        if material is None:",
            '            _reject("KEY_UNAVAILABLE")',
        ),
        _lines(
            "        if stored.key_ref.startswith(_KEY_REF_PREFIX):",
            "            material = self._held.get(stored.key_ref[len(_KEY_REF_PREFIX) :])",
            "        if material is None:",
            "            material = self._held.get(self._active)",
            "        if material is None:",
            '            _reject("KEY_UNAVAILABLE")',
        ),
        pytest_args=(*VECTORS, "tests/test_crypto_local_provider.py"),
    ),
    Mutant(
        "a-nonce-is-reachable-from-the-public-api",
        "Fixed nonce reachable from the public API",
        RECORD,
        _lines(
            "    async def seal_capture(",
            "        self, context: KeyContext, records: tuple[tuple[RecordBinding, RecordPayload], ...]",
            "    ) -> SealedCapture:",
        ),
        _lines(
            "    async def seal_capture(",
            "        self, context: KeyContext, records: tuple[tuple[RecordBinding, RecordPayload], ...], nonce: bytes | None = None",
            "    ) -> SealedCapture:",
        ),
        pytest_args=("tests/test_crypto_record.py",),
    ),
    # --- server --------------------------------------------------------------------------------------------------
    Mutant(
        "session-tag-not-checked-before-unwrap",
        "Session tag not checked before unwrap",
        SERVER,
        "            if expected is None or not _equal_tags(expected, capture.session_tag):\n                raise deny(ServerDenialReason.SOURCE)\n        for capture in captures.values():\n            if now >= capture.expires_at:",
        "            if False:\n                raise deny(ServerDenialReason.SOURCE)\n        for capture in captures.values():\n            if now >= capture.expires_at:",
        pytest_args=("tests/test_persistent_server.py", "tests/test_persistent_server_leaks.py"),
    ),
    Mutant(
        "fields-returned-when-the-commit-result-is-unknown",
        "Fields returned before the commit result is known",
        SERVER,
        _lines(
            "                # Unknown outcome: release nothing, retry nothing (section 7.3).",
            "                raise fail(code.COMMIT_AMBIGUOUS)",
        ),
        _lines(
            "                # Unknown outcome: release nothing, retry nothing (section 7.3).",
            "                return PersistentRestoreResult(",
            "                    fields=MappingProxyType(staged),",
            "                    restored=restored,",
            "                    principal_id=resolved.principal.id,",
            "                    tenant=resolved.tenant,",
            "                    attempt_id=attempt_id,",
            "                )",
        ),
        pytest_args=("tests/test_persistent_server.py", "tests/test_persistent_server_leaks.py"),
    ),
)


def mirror(tree: Path) -> Path:
    """A tree shaped like the repository, with real copies of the package's ``src`` and ``tests``."""

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
    shutil.copytree(PACKAGE / "src", package / "src", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(PACKAGE / "tests", package / "tests", ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("pyproject.toml", "README.md"):
        shutil.copy(PACKAGE / name, package / name)
    return package


def apply(mutant: Mutant, package: Path) -> None:
    path = package / mutant.file
    text = path.read_text(encoding="utf-8")
    for old, new in ((mutant.old, mutant.new), *mutant.also):
        if text.count(old) != 1:
            raise RuntimeError(f"{mutant.id}: the text to change occurs {text.count(old)} times in {mutant.file}")
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")


def failing_tests(output: str) -> list[str]:
    return sorted(set(re.findall(r"^FAILED (\S+)", output, flags=re.MULTILINE)))


def run_one(mutant: Mutant, have_database: bool) -> dict[str, object]:
    if mutant.needs_database and not have_database:
        return {
            "id": mutant.id,
            "row": mutant.row,
            "status": "NOT RUN",
            "reason": "no database (RSV_PG_APP_URL, RSV_PG_ADMIN_URL)",
        }
    with tempfile.TemporaryDirectory(prefix="rsv-mutant-") as raw:
        tree = Path(raw)
        package = mirror(tree)
        apply(mutant, package)
        env = {
            **os.environ,
            "PYTHONPATH": str(package / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
            # The orchestrator must run from its real path (it starts itself only when it is the main module).
            "RSV_SCHEDULES_DIR": str(REPO / "conformance" / "persistent" / "v1"),
        }
        caught_by: list[str] = []
        results: list[str] = []
        if mutant.pytest_args:
            done = subprocess.run(  # noqa: S603
                [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "-rf", *mutant.pytest_args],
                cwd=package,
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=1800,
            )
            names = failing_tests(done.stdout)
            if done.returncode == 1 and names:
                caught_by.extend(names[:3])
                results.append("pytest")
            elif done.returncode not in (0, 1):
                return {
                    "id": mutant.id,
                    "row": mutant.row,
                    "status": "ERROR",
                    "reason": f"pytest exited {done.returncode}",
                }
        if mutant.schedules:
            done = subprocess.run(  # noqa: S603
                [sys.executable, "-c", SCHEDULES_PROBE, json.dumps(list(mutant.schedules))],
                cwd=package,
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=1800,
            )
            if done.returncode == 1 and done.stdout.strip():
                payload = json.loads(done.stdout.strip().splitlines()[-1])
                caught_by.extend(f"schedule:{case}" for case in payload["failed"])
                results.append("schedules")
            elif done.returncode != 0:
                return {
                    "id": mutant.id,
                    "row": mutant.row,
                    "status": "ERROR",
                    "reason": "the schedule probe failed to run",
                }
        return {
            "id": mutant.id,
            "row": mutant.row,
            "status": "caught" if caught_by else "NOT CAUGHT",
            "caught_by": caught_by,
            "ran": results,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--only", action="append", default=[])
    parser.add_argument("--json")
    options = parser.parse_args()
    if options.list:
        for mutant in MUTANTS:
            print(f"{mutant.id}: {mutant.row}")
        return 0
    have_database = bool(os.environ.get("RSV_PG_APP_URL")) and bool(os.environ.get("RSV_PG_ADMIN_URL"))
    chosen = [m for m in MUTANTS if not options.only or m.id in options.only]
    rows = []
    for mutant in chosen:
        row = run_one(mutant, have_database)
        rows.append(row)
        detail = (
            ", ".join(row.get("caught_by", [])[:2]) if isinstance(row.get("caught_by"), list) else row.get("reason", "")
        )
        print(f"{row['status']:>10}  {mutant.id}  {detail}", flush=True)
    if options.json:
        Path(options.json).write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    counts: dict[str, int] = {}
    for row in rows:
        counts[str(row["status"])] = counts.get(str(row["status"]), 0) + 1
    print(f"mutants: {counts}")
    return 0 if all(row["status"] == "caught" for row in rows if row["status"] != "NOT RUN") else 1


if __name__ == "__main__":
    sys.exit(main())
