"""The SDK-debug-logging guard of the AWS KMS provider, on the real ``boto3`` with a stubbed HTTP layer.

Issue #145: with ``botocore``'s loggers at ``DEBUG``, a real ``GenerateDataKey`` or ``Decrypt`` writes the plaintext
data key (``botocore.parsers``, the response body) and the key ARN and wrapped key (``botocore.endpoint``, request
parameters) to the application's logs. This file builds a real ``boto3`` KMS client whose request is answered by a
``before-send`` handler, so the real request builder, the real response parser, and the real SDK loggers run, and no
network and no AWS account is involved. Every key, blob, ARN, and credential is synthetic.

It proves (a) that without the guard the data key is in log records, and (b) that with the guard the call is refused
before any request is made and before any record is written, for each guarded logger, and that the opt-in restores the
SDK's behavior. The guard never changes a logger's level or a handler.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import sys
from collections.abc import Iterator
from typing import Any

import pytest

pytest.importorskip("boto3")

import boto3  # noqa: E402
from botocore.awsrequest import AWSResponse  # noqa: E402
from botocore.config import Config  # noqa: E402
from kms_support import ACCOUNT, REGION, arn_for  # noqa: E402

from redact_secret_vault.keys.aws_kms import (  # noqa: E402
    SDK_LOGGERS_THAT_CAN_CARRY_KEY_MATERIAL,
    AwsKmsExpected,
    AwsKmsKey,
    AwsKmsScope,
    DataKeyCacheOptions,
    create_aws_kms_key_provider,
)
from redact_secret_vault.persistent import KeyContext, KeyProviderError, StoredKey  # noqa: E402

pytestmark = pytest.mark.skipif(sys.version_info < (3, 11), reason="the persistent modules need Python 3.11")

NS = "ns-synthetic"
TENANT = "tenant-acme-synthetic"
CAPTURE = "cap_" + "a" * 26
SYNTHETIC_KEY = bytes(range(1, 33))
SYNTHETIC_BLOB = b"SYNTHETIC-WRAPPED-KEY-" + bytes(range(40, 80))
KEY_ARN = arn_for("00000000-0000-4000-8000-0000000000aa")
SDK_ROOT_NAMES = ("botocore", "boto3", "urllib3")


def _secrets() -> dict[str, str]:
    return {
        "data key (base64)": base64.b64encode(SYNTHETIC_KEY).decode(),
        "data key (hex)": SYNTHETIC_KEY.hex(),
        "wrapped key (base64)": base64.b64encode(SYNTHETIC_BLOB).decode(),
        "key ARN": KEY_ARN,
    }


class _Body:
    """Stands in for the ``urllib3`` response ``botocore`` reads the body from."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def stream(self, *args: Any, **kwargs: Any) -> Iterator[bytes]:
        yield self._data

    def read(self, *args: Any, **kwargs: Any) -> bytes:
        return self._data


class StubbedKms:
    """A real ``boto3`` KMS client with its HTTP send replaced. ``requests`` counts what reached the stub."""

    def __init__(self) -> None:
        self.requests: list[str] = []
        self.client = boto3.client(
            "kms",
            region_name=REGION,
            aws_access_key_id="AKIASYNTHETICSYNTHET",
            aws_secret_access_key="synthetic-secret-synthetic-secret-0000",
            config=Config(retries={"max_attempts": 1}),
        )
        self.client.meta.events.register("before-send.kms.*", self._send)

    def _send(self, request: Any, **_: Any) -> AWSResponse:
        target = request.headers.get("X-Amz-Target", b"")
        target = target.decode() if isinstance(target, bytes) else target
        operation = target.rsplit(".", 1)[-1]
        self.requests.append(operation)
        asked = json.loads(request.body)
        body: dict[str, str] = {
            "KeyId": asked.get("KeyId", KEY_ARN),
            "Plaintext": base64.b64encode(SYNTHETIC_KEY).decode(),
        }
        if operation == "GenerateDataKey":
            body["CiphertextBlob"] = base64.b64encode(SYNTHETIC_BLOB).decode()
        return AWSResponse(
            request.url,
            200,
            {"content-type": "application/x-amz-json-1.1"},
            _Body(json.dumps(body).encode()),
        )


class Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def text(self) -> str:
        return "\n".join(record.getMessage() for record in self.records)


@pytest.fixture
def logs() -> Iterator[Records]:
    """A handler on the root logger that keeps every record, with every guarded logger back at its inherited level.

    The root level is left at ``WARNING``, so nothing at ``DEBUG`` is created until a test raises one logger."""

    root = logging.getLogger()
    names = (*SDK_LOGGERS_THAT_CAN_CARRY_KEY_MATERIAL, *SDK_ROOT_NAMES, "urllib3.connectionpool")
    saved_root = root.level
    saved = {name: logging.getLogger(name).level for name in names}
    saved_disable = logging.root.manager.disable
    handler = Records()
    root.addHandler(handler)
    root.setLevel(logging.WARNING)
    for name in names:
        logging.getLogger(name).setLevel(logging.NOTSET)
    logging.disable(logging.NOTSET)
    try:
        yield handler
    finally:
        root.removeHandler(handler)
        root.setLevel(saved_root)
        for name, level in saved.items():
            logging.getLogger(name).setLevel(level)
        logging.disable(saved_disable)


def levels() -> dict[str, int]:
    names = (*SDK_LOGGERS_THAT_CAN_CARRY_KEY_MATERIAL, *SDK_ROOT_NAMES, "")
    return {name: logging.getLogger(name).level for name in names}


def build(stub: StubbedKms, **options: Any) -> Any:
    return create_aws_kms_key_provider(
        client=stub.client,
        keys=(AwsKmsKey(KEY_ARN, "active"),),
        expected=AwsKmsExpected(region=REGION, account_id=ACCOUNT),
        scope=AwsKmsScope(namespaces=(NS,), tenants=(TENANT,)),
        **options,
    )


def ctx() -> KeyContext:
    return KeyContext(NS, TENANT, CAPTURE)


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def refusal(coro: Any) -> str:
    try:
        run(coro)
    except KeyProviderError as error:
        assert error.__cause__ is None and error.__context__ is None
        for value in _secrets().values():
            assert value not in repr(error) + str(error)
        return error.code
    raise AssertionError("expected the guard to refuse")


async def round_trip(provider: Any) -> None:
    key = await provider.generate_data_key(ctx())
    await provider.unwrap_data_key(StoredKey(key.key_ref, key.wrapped_key), ctx())


def enable_debug_only(*names: str) -> None:
    for name in names:
        logging.getLogger(name).setLevel(logging.DEBUG)


# ------------------------------------------------------------------ (a) what the SDK writes without the guard


def test_without_the_guard_the_sdk_writes_the_data_key_and_the_arn_to_log_records(logs: Records) -> None:
    stub = StubbedKms()
    provider = build(stub, allow_sdk_debug_logging=True)
    enable_debug_only("botocore", "urllib3")
    run(round_trip(provider))

    assert stub.requests == ["GenerateDataKey", "Decrypt"]
    by_logger: dict[str, str] = {}
    for record in logs.records:
        by_logger[record.name] = by_logger.get(record.name, "") + record.getMessage() + "\n"
    secrets = _secrets()
    # botocore.parsers logs the response body of both calls: the plaintext data key and the key ARN.
    assert secrets["data key (base64)"] in by_logger["botocore.parsers"]
    assert secrets["key ARN"] in by_logger["botocore.parsers"]
    # botocore.endpoint logs the request parameters: the Decrypt request carries the wrapped key and the ARN.
    assert secrets["wrapped key (base64)"] in by_logger["botocore.endpoint"]
    assert secrets["key ARN"] in by_logger["botocore.endpoint"]
    # The two loggers that are guarded for what they can carry in other configurations wrote none of it here.
    for quiet in ("botocore.hooks", "urllib3.connectionpool"):
        assert not any(value in by_logger.get(quiet, "") for value in secrets.values())


def test_the_decrypt_response_alone_writes_the_data_key(logs: Records) -> None:
    stub = StubbedKms()
    provider = build(stub, allow_sdk_debug_logging=True)
    key = run(provider.generate_data_key(ctx()))
    enable_debug_only("botocore")
    logs.records.clear()
    run(provider.unwrap_data_key(StoredKey(key.key_ref, key.wrapped_key), ctx()))
    assert _secrets()["data key (base64)"] in logs.text()


# ------------------------------------------------------------------ (b) the guard refuses before any record


@pytest.mark.parametrize("name", SDK_LOGGERS_THAT_CAN_CARRY_KEY_MATERIAL)
def test_each_guarded_logger_at_debug_refuses_construction(name: str, logs: Records) -> None:
    stub = StubbedKms()
    enable_debug_only(name)
    with pytest.raises(KeyProviderError) as caught:
        build(stub)
    assert caught.value.code == "KEY_INVALID_ARGUMENT"
    assert stub.requests == [] and logs.records == []


@pytest.mark.parametrize("name", SDK_LOGGERS_THAT_CAN_CARRY_KEY_MATERIAL)
def test_each_guarded_logger_at_debug_refuses_every_call_before_the_request_and_before_any_record(
    name: str, logs: Records
) -> None:
    stub = StubbedKms()
    provider = build(stub)
    key = run(provider.generate_data_key(ctx()))
    stored = StoredKey(key.key_ref, key.wrapped_key)
    stub.requests.clear()
    logs.records.clear()

    enable_debug_only(name)
    before = levels()
    assert refusal(provider.generate_data_key(ctx())) == "KEY_UNAVAILABLE"
    assert refusal(provider.unwrap_data_key(stored, ctx())) == "KEY_UNAVAILABLE"
    assert refusal(provider.rewrap_data_key(stored, ctx())) == "KEY_UNAVAILABLE"

    assert stub.requests == [], "no request reached the SDK's HTTP layer"
    assert logs.records == [], "no record was written by the SDK or the provider"
    assert levels() == before, "the guard changes no logger level"


def test_turning_the_logger_back_off_makes_the_provider_usable_again(logs: Records) -> None:
    stub = StubbedKms()
    provider = build(stub)
    enable_debug_only("botocore.parsers")
    assert refusal(provider.generate_data_key(ctx())) == "KEY_UNAVAILABLE"
    logging.getLogger("botocore.parsers").setLevel(logging.NOTSET)
    run(round_trip(provider))
    assert logs.records == []


def test_the_root_logger_at_debug_is_caught_through_inheritance(logs: Records) -> None:
    stub = StubbedKms()
    logging.getLogger().setLevel(logging.DEBUG)
    with pytest.raises(KeyProviderError) as caught:
        build(stub)
    assert caught.value.code == "KEY_INVALID_ARGUMENT"
    logging.getLogger().setLevel(logging.WARNING)
    provider = build(stub)
    logging.getLogger().setLevel(logging.DEBUG)
    assert refusal(provider.generate_data_key(ctx())) == "KEY_UNAVAILABLE"
    # The root is at DEBUG here, so asyncio writes its own record; none comes from the SDK or the provider.
    assert stub.requests == []
    assert [r.name for r in logs.records if r.name.split(".")[0] != "asyncio"] == []


def test_info_level_and_logging_disable_do_not_refuse(logs: Records) -> None:
    stub = StubbedKms()
    for name in SDK_LOGGERS_THAT_CAN_CARRY_KEY_MATERIAL:
        logging.getLogger(name).setLevel(logging.INFO)
    run(round_trip(build(stub)))
    assert not any(value in logs.text() for value in _secrets().values())
    # logging.disable raises the floor for every logger: no DEBUG record can be created, so nothing is refused.
    for name in SDK_LOGGERS_THAT_CAN_CARRY_KEY_MATERIAL:
        logging.getLogger(name).setLevel(logging.DEBUG)
    logging.disable(logging.CRITICAL)
    logs.records.clear()
    run(round_trip(build(stub)))
    assert logs.records == []


# ------------------------------------------------------------------ the opt-in


def test_the_opt_in_lets_the_provider_work_with_debug_on_and_does_not_hide_the_exposure(logs: Records) -> None:
    stub = StubbedKms()
    enable_debug_only("botocore.parsers", "botocore.endpoint")
    provider = build(stub, allow_sdk_debug_logging=True)
    run(round_trip(provider))
    assert stub.requests == ["GenerateDataKey", "Decrypt"]
    assert _secrets()["data key (base64)"] in logs.text()


@pytest.mark.parametrize("value", [None, 0, 1, "yes", [], "False"])
def test_the_opt_in_must_be_a_real_bool(value: object, logs: Records) -> None:
    stub = StubbedKms()
    with pytest.raises(KeyProviderError) as caught:
        build(stub, allow_sdk_debug_logging=value)
    assert caught.value.code == "KEY_INVALID_ARGUMENT"
    assert stub.requests == []


def test_the_default_is_the_guard_and_it_is_not_keyword_positional() -> None:
    import inspect

    parameter = inspect.signature(create_aws_kms_key_provider).parameters["allow_sdk_debug_logging"]
    assert parameter.default is False and parameter.kind is inspect.Parameter.KEYWORD_ONLY


def test_the_guarded_loggers_include_those_that_carried_key_material_in_the_recorded_run() -> None:
    assert {"botocore", "botocore.parsers", "botocore.hooks", "botocore.endpoint", "boto3"} <= set(
        SDK_LOGGERS_THAT_CAN_CARRY_KEY_MATERIAL
    )
    assert "urllib3.connectionpool" in SDK_LOGGERS_THAT_CAN_CARRY_KEY_MATERIAL


# ------------------------------------------------------------------ the cache makes no SDK call


def test_a_cache_hit_makes_no_sdk_call_and_is_not_refused(logs: Records) -> None:
    stub = StubbedKms()
    provider = build(stub, cache=DataKeyCacheOptions(max_entries=4, max_age_ms=60_000, per_tenant_max_entries=4))
    key = run(provider.generate_data_key(ctx()))
    stored = StoredKey(key.key_ref, key.wrapped_key)
    run(provider.unwrap_data_key(stored, ctx()))  # a miss: one Decrypt, DEBUG off
    stub.requests.clear()
    enable_debug_only("botocore.parsers")
    unwrapped = run(provider.unwrap_data_key(stored, ctx()))
    assert bytes(unwrapped) == SYNTHETIC_KEY
    assert stub.requests == [] and logs.records == []
    # A call that would reach KMS is still refused.
    assert refusal(provider.generate_data_key(ctx())) == "KEY_UNAVAILABLE"
    provider.close()
