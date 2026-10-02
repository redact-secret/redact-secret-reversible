"""Contracts, errors, and limits against their TypeScript sources.

``packages/vault-contracts/src`` is read as text and compared value by value, so a
change on either side fails here until the other follows.
"""

from __future__ import annotations

import ast
import dataclasses
import pickle
import re
from pathlib import Path

import pytest

from redact_secret_vault import persistent
from redact_secret_vault.persistent import contracts, errors, limits, validate

TS_SRC = Path(__file__).resolve().parents[3] / "packages" / "vault-contracts" / "src"


def _ts(name: str) -> str:
    path = TS_SRC / name
    if not path.is_file():
        pytest.skip(f"{path} is not in this checkout")
    return path.read_text(encoding="utf-8")


def _snake(camel: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", camel).upper()


def _evaluate(expression: str) -> int:
    """Integer arithmetic only: literals, + - * and parentheses."""

    expression = expression.replace("Number.MAX_SAFE_INTEGER", "(2 ** 53 - 1)")
    expression = re.sub(r"\s+as\s+const", "", expression)
    node = ast.parse(expression.strip(), mode="eval").body

    def walk(n: ast.AST) -> int:
        if isinstance(n, ast.Constant) and type(n.value) is int:
            return n.value
        if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Sub, ast.Mult, ast.Pow)):
            left, right = walk(n.left), walk(n.right)
            return {ast.Add: left + right, ast.Sub: left - right, ast.Mult: left * right, ast.Pow: left**right}[
                type(n.op)
            ]
        raise AssertionError(f"unexpected expression {ast.dump(n)}")

    return walk(node)


def test_limits_equal_the_typescript_limits() -> None:
    source = _ts("limits.ts")
    body = source[source.index("Object.freeze({") :]
    pairs = re.findall(r"^\s*(\w+):\s*(.+?),\s*$", body, re.M)
    assert len(pairs) == 24, "the TypeScript LIMITS object changed shape; update the port"
    expected = {_snake(name): _evaluate(value) for name, value in pairs}
    actual = {name: value for name, value in vars(limits).items() if name.isupper()}
    assert actual == expected


def test_error_messages_equal_the_typescript_messages() -> None:
    source = _ts("errors.ts")
    ts_messages = dict(re.findall(r'^\s*([A-Z_]+):\s*"((?:[^"\\]|\\.)*)",\s*$', source, re.M))
    py_messages = {**errors.STORE_MESSAGES, **errors.KEY_MESSAGES, **errors.RECORD_MESSAGES}
    assert len(ts_messages) == 16
    assert py_messages == ts_messages


def test_error_codes_equal_the_typescript_unions() -> None:
    source = _ts("errors.ts")
    for union, messages in (
        ("StoreErrorCode", errors.STORE_MESSAGES),
        ("KeyProviderErrorCode", errors.KEY_MESSAGES),
        ("RecordCryptoErrorCode", errors.RECORD_MESSAGES),
    ):
        block = source[source.index(f"export type {union}") :].split(";", 1)[0]
        assert set(re.findall(r'"([A-Z_]+)"', block)) == set(messages)


def test_patterns_equal_the_typescript_patterns() -> None:
    source = _ts("validate.ts")
    ts_patterns = {name: pattern for name, pattern in re.findall(r"^const ([A-Z_]+) = /\^(.+)\$/;$", source, re.M)}
    assert set(ts_patterns) == {"NAMESPACE", "ATTEMPT_ID", "CAPTURE_ID", "ENTRY_ID", "SESSION_TAG"}
    for name, pattern in ts_patterns.items():
        assert getattr(validate, f"_{name}").pattern == pattern


def test_ts_record_fields_exist_in_python_in_snake_case() -> None:
    source = _ts("types.ts")
    for interface, cls in (
        ("StoreScope", contracts.StoreScope),
        ("StoreCapabilities", contracts.StoreCapabilities),
        ("NewEntry", contracts.NewEntry),
        ("StoredEntry", contracts.StoredEntry),
        ("RecordBinding", contracts.RecordBinding),
        ("RecordPayload", contracts.RecordPayload),
        ("KeyContext", contracts.KeyContext),
        ("RecoveryState", contracts.RecoveryState),
    ):
        block = source[source.index(f"export interface {interface}") :].split("\n}", 1)[0]
        ts_fields = re.findall(r"^\s+readonly (\w+)\??:", block, re.M)
        assert ts_fields, interface
        py_fields = [f.name for f in dataclasses.fields(cls)]
        assert py_fields == [re.sub(r"(?<!^)(?=[A-Z])", "_", f).lower() for f in ts_fields], interface


def test_errors_carry_a_fixed_message_and_no_link() -> None:
    for error in (
        errors.StoreError("STORE_AMBIGUOUS"),
        errors.KeyProviderError("KEY_INTEGRITY"),
        errors.RecordCryptoError("RECORD_INTEGRITY"),
    ):
        assert error.__cause__ is None and error.__context__ is None
        assert not hasattr(error, "__notes__")
        assert vars(error) == {"code": error.code}
        assert re.fullmatch(r"[A-Za-z ;,.'-]+", str(error))
        assert error.args == (str(error),)
        copy = pickle.loads(pickle.dumps(error))
        assert (type(copy), copy.code) == (type(error), error.code)


def test_an_unknown_code_is_a_key_error() -> None:
    with pytest.raises(KeyError):
        errors.StoreError("STORE_NOPE")  # type: ignore[arg-type]


def test_contracts_are_frozen_and_slotted() -> None:
    scope = contracts.StoreScope("ns", "tenant")
    with pytest.raises(dataclasses.FrozenInstanceError):
        scope.tenant = "other"  # type: ignore[misc]
    assert not hasattr(scope, "__dict__")


def test_the_public_names_are_all_importable() -> None:
    for name in persistent.__all__:
        assert hasattr(persistent, name), name


def test_the_store_protocol_names_every_operation_of_the_specification() -> None:
    operations = {
        "capabilities",
        "create_capture",
        "read_entries",
        "read_captures",
        "commit_restore",
        "revoke_capture",
        "inspect_attempt",
        "replace_capture_key",
        "delete_ciphertext",
        "sweep_expired",
        "recovery_state",
        "initialize_namespace",
        "quarantine",
        "invalidate_recovered",
    }
    assert {n for n in vars(contracts.Store) if not n.startswith("_")} >= operations
    source = _ts("types.ts")
    block = source[source.index("export interface Store ") :].split("\n}", 1)[0]
    ts_names = {re.sub(r"(?<!^)(?=[A-Z])", "_", n).lower() for n in re.findall(r"^\s+(\w+)\(", block, re.M)}
    assert ts_names == operations


def test_secret_holders_print_lengths_and_refuse_pickling() -> None:
    secret = bytearray(b"SYNTHETIC-SENTINEL-KEY-0123456789")
    key = contracts.DataKey("local:k", b"SYNTHETIC-WRAPPED", secret)
    payload = contracts.RecordPayload(bytearray(b"SYNTHETIC-VALUE"), "synthetic", (), None)
    stored = contracts.StoredEntry("0" * 64, "cap_" + "a" * 26, 1, 0, 1, 1, b"SYNTHETIC-ENVELOPE")
    for obj in (key, payload, stored):
        text = repr(obj) + str(obj)
        assert "SYNTHETIC" not in text.replace("synthetic", "")
        assert "len=" in text
    for obj in (key, payload):
        with pytest.raises(TypeError):
            pickle.dumps(obj)
