"""The AWS KMS key provider against a real KMS key, and against the JavaScript provider on the same keys.

Skipped, with the reason, unless both are set (as in ``packages/key-provider-aws-kms``):

    RSV_KMS_TEST_KEY_ARN      a symmetric encryption key the caller may use
    RSV_KMS_TEST_OLD_KEY_ARN  a second one, in the same account and region

and AWS credentials are resolvable by the default chain (``AWS_PROFILE`` or the environment). The principal needs
``kms:GenerateDataKey``, ``kms:Decrypt``, ``kms:ReEncryptFrom``, and ``kms:ReEncryptTo`` on both keys and, for the
disabled-key case only, ``kms:DisableKey`` and ``kms:EnableKey`` on the second key. Only synthetic identifiers are sent.
No ARN, account id, key, or credential is printed. The JavaScript side is ``aws_kms_js_peer.mjs`` (needs
``npm run build``): the data key never leaves it, only its SHA-256 does.

A run with ``RSV_REQUIRE_KMS=1`` fails instead of skipping.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import warnings
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("boto3")

from redact_secret_vault.keys.aws_kms import (  # noqa: E402
    AwsKmsExpected,
    AwsKmsKey,
    AwsKmsScope,
    create_aws_kms_key_provider,
)
from redact_secret_vault.persistent import KeyContext, KeyProviderError, StoredKey  # noqa: E402

pytestmark = pytest.mark.skipif(sys.version_info < (3, 11), reason="the persistent modules need Python 3.11")

KEY_A = os.environ.get("RSV_KMS_TEST_KEY_ARN", "")
KEY_B = os.environ.get("RSV_KMS_TEST_OLD_KEY_ARN", "")
REQUIRED = os.environ.get("RSV_REQUIRE_KMS") == "1"
ARN = re.compile(r"arn:(aws[a-z-]*):kms:([a-z0-9-]+):(\d{12}):key/[0-9a-f-]{36}")
parsed, parsed_b = ARN.fullmatch(KEY_A), ARN.fullmatch(KEY_B)

if (not KEY_A or not KEY_B) and REQUIRED:
    raise RuntimeError("RSV_REQUIRE_KMS=1 but RSV_KMS_TEST_KEY_ARN and RSV_KMS_TEST_OLD_KEY_ARN are not set")
if (
    KEY_A
    and KEY_B
    and (parsed is None or parsed_b is None or KEY_A == KEY_B or parsed.groups()[1:] != parsed_b.groups()[1:])
):
    raise RuntimeError("the two test keys must be different full key ARNs of one account and region")

NOT_CONFIGURED = "real AWS KMS is not configured: set RSV_KMS_TEST_KEY_ARN and RSV_KMS_TEST_OLD_KEY_ARN"
needs_kms = pytest.mark.skipif(not KEY_A or not KEY_B, reason=NOT_CONFIGURED)

NAMESPACE = "rsv-127-qualification-synthetic"
TENANT = "tenant-acme-synthetic"
OTHER_TENANT = "tenant-globex-synthetic"
ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
REPO = Path(__file__).resolve().parents[3]
PEER = Path(__file__).resolve().parent / "aws_kms_js_peer.mjs"


def capture_id() -> str:
    return "cap_" + "".join(secrets.choice(ALPHABET) for _ in range(26))


def context(tenant: str = TENANT, capture: str | None = None) -> KeyContext:
    return KeyContext(NAMESPACE, tenant, capture or capture_id())


class RecordingClient:
    """The application's client, with every request this provider sent recorded."""

    def __init__(self, client: Any) -> None:
        self._client = client
        self.sent: list[tuple[str, dict[str, Any]]] = []

    def _call(self, name: str, method: str, request: dict[str, Any]) -> Any:
        import copy

        self.sent.append((name, copy.deepcopy(request)))
        return getattr(self._client, method)(**request)

    def generate_data_key(self, **request: Any) -> Any:
        return self._call("GenerateDataKey", "generate_data_key", request)

    def decrypt(self, **request: Any) -> Any:
        return self._call("Decrypt", "decrypt", request)

    def re_encrypt(self, **request: Any) -> Any:
        return self._call("ReEncrypt", "re_encrypt", request)


def real_client() -> Any:
    import boto3
    from botocore.config import Config

    region = parsed.group(2) if parsed else "us-east-1"
    return boto3.client(
        "kms", region_name=region, config=Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 1})
    )


def provider_for(client: Any, keys: tuple[AwsKmsKey, ...], **options: Any) -> Any:
    assert parsed is not None
    return create_aws_kms_key_provider(
        client=client,
        keys=keys,
        expected=AwsKmsExpected(region=parsed.group(2), account_id=parsed.group(3), partition=parsed.group(1)),
        scope=AwsKmsScope(namespaces=(NAMESPACE,), tenants=(TENANT, OTHER_TENANT)),
        **options,
    )


def active_a(client: Any, **options: Any) -> Any:
    return provider_for(client, (AwsKmsKey(KEY_A, "active"), AwsKmsKey(KEY_B, "decrypt-only")), **options)


def active_b(client: Any, **options: Any) -> Any:
    return provider_for(client, (AwsKmsKey(KEY_B, "active"), AwsKmsKey(KEY_A, "decrypt-only")), **options)


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def code_of(coro: Any) -> str:
    try:
        run(coro)
    except KeyProviderError as thrown:
        assert thrown.__cause__ is None and thrown.__context__ is None
        return thrown.code
    raise AssertionError("expected an error")


def sha256(raw: bytes | bytearray) -> str:
    return hashlib.sha256(bytes(raw)).hexdigest()


def js_peer(request: dict[str, Any], *, active: str = KEY_A, other: str = KEY_B) -> dict[str, Any]:
    """The JavaScript provider, in a child process, on the same two keys."""

    node = shutil.which("node")
    if node is None or not (REPO / "packages" / "key-provider-aws-kms" / "dist" / "index.js").is_file():
        if REQUIRED:
            raise RuntimeError("node and a built packages/key-provider-aws-kms are needed")
        pytest.skip("node and a built packages/key-provider-aws-kms are needed for the JavaScript side")
    keys = [{"keyArn": active, "state": "active"}, {"keyArn": other, "state": "decrypt-only"}]
    done = subprocess.run(
        [node, str(PEER)],
        input=json.dumps({"keys": keys, **request}),
        capture_output=True,
        text=True,
        check=False,
        env=dict(os.environ),
        timeout=120,
    )
    assert done.returncode == 0, "the JavaScript peer failed"
    return json.loads(done.stdout.strip().splitlines()[-1])


def ctx_json(value: KeyContext) -> dict[str, str]:
    return {"namespace": value.namespace, "tenant": value.tenant, "captureId": value.capture_id}


# ---------------------------------------------------------------------------------- interoperation


@needs_kms
def test_a_data_key_wrapped_by_the_javascript_provider_is_unwrapped_by_python() -> None:
    value = context()
    made = js_peer({"op": "generate", "context": ctx_json(value)})
    assert made["keyRef"] == "aws-kms:" + KEY_A
    client = RecordingClient(real_client())
    dek = run(active_a(client).unwrap_data_key(StoredKey(made["keyRef"], base64.b64decode(made["wrapped"])), value))
    assert sha256(dek) == made["plaintextSha256"]
    assert [name for name, _ in client.sent] == ["Decrypt"]
    dek[:] = bytes(len(dek))


@needs_kms
def test_a_data_key_wrapped_by_python_is_unwrapped_by_the_javascript_provider() -> None:
    value = context(OTHER_TENANT)
    client = RecordingClient(real_client())
    key = run(active_a(client).generate_data_key(value))
    assert key.key_ref == "aws-kms:" + KEY_A
    answer = js_peer(
        {
            "op": "unwrap",
            "context": ctx_json(value),
            "keyRef": key.key_ref,
            "wrapped": base64.b64encode(key.wrapped_key).decode(),
        }
    )
    assert answer == {"plaintextSha256": sha256(key.plaintext_key)}
    key.plaintext_key[:] = bytes(len(key.plaintext_key))


@needs_kms
def test_a_different_context_fails_integrity_for_a_key_from_either_side() -> None:
    value = context()
    other = KeyContext(NAMESPACE, TENANT, capture_id())
    client = real_client()
    made = js_peer({"op": "generate", "context": ctx_json(value)})
    js_wrapped = StoredKey(made["keyRef"], base64.b64decode(made["wrapped"]))
    assert code_of(active_a(client).unwrap_data_key(js_wrapped, other)) == "KEY_INTEGRITY"
    assert (
        code_of(active_a(client).unwrap_data_key(js_wrapped, context(OTHER_TENANT, value.capture_id)))
        == "KEY_INTEGRITY"
    )
    key = run(active_a(client).generate_data_key(value))
    answer = js_peer(
        {
            "op": "unwrap",
            "context": ctx_json(other),
            "keyRef": key.key_ref,
            "wrapped": base64.b64encode(key.wrapped_key).decode(),
        }
    )
    assert answer == {"error": "KEY_INTEGRITY"}


@needs_kms
def test_a_key_rewrapped_from_the_old_key_by_python_unwraps_in_javascript_and_the_old_key_is_decrypt_only() -> None:
    value = context()
    client = real_client()
    old = run(active_b(client).generate_data_key(value))
    assert old.key_ref == "aws-kms:" + KEY_B
    moved = run(active_a(client).rewrap_data_key(StoredKey(old.key_ref, old.wrapped_key), value))
    assert moved.key_ref == "aws-kms:" + KEY_A
    answer = js_peer(
        {
            "op": "unwrap",
            "context": ctx_json(value),
            "keyRef": moved.key_ref,
            "wrapped": base64.b64encode(moved.wrapped_key).decode(),
        }
    )
    assert answer == {"plaintextSha256": sha256(old.plaintext_key)}
    # And the other way: JavaScript rewraps a Python-wrapped key, Python unwraps the result.
    again = js_peer(
        {
            "op": "rewrap",
            "context": ctx_json(value),
            "keyRef": old.key_ref,
            "wrapped": base64.b64encode(old.wrapped_key).decode(),
        }
    )
    unwrapped = run(
        active_a(client).unwrap_data_key(StoredKey(again["keyRef"], base64.b64decode(again["wrapped"])), value)
    )
    assert sha256(unwrapped) == sha256(old.plaintext_key)


# --------------------------------------------------------------------------------- real behavior


@needs_kms
def test_a_disabled_key_fails_unavailable_and_works_again_when_enabled() -> None:
    import boto3
    from botocore.exceptions import ClientError

    client = real_client()
    value = context()
    key = run(active_b(client).generate_data_key(value))
    admin = boto3.client("kms", region_name=parsed.group(2) if parsed else "us-east-1")
    try:
        admin.disable_key(KeyId=KEY_B)
    except ClientError:
        pytest.skip("the principal may not disable the second test key (kms:DisableKey)")
    try:
        # KMS is eventually consistent: poll until the change is visible, for at most five minutes.
        import time

        started = time.monotonic()
        deadline = started + 300
        code = ""
        while time.monotonic() < deadline:
            try:
                run(active_b(client).unwrap_data_key(StoredKey(key.key_ref, key.wrapped_key), value))
            except KeyProviderError as thrown:
                code = thrown.code
                break
            time.sleep(1)
        print(f"DisableKey was visible to Decrypt after {time.monotonic() - started:.0f} s")
        assert code == "KEY_UNAVAILABLE"
        assert code_of(active_b(client).generate_data_key(value)) == "KEY_UNAVAILABLE"
    finally:
        admin.enable_key(KeyId=KEY_B)
    deadline = time.monotonic() + 60
    while True:
        try:
            run(active_b(client).unwrap_data_key(StoredKey(key.key_ref, key.wrapped_key), value))
            break
        except KeyProviderError:
            assert time.monotonic() < deadline, "the key did not become usable again"
            time.sleep(1)


@needs_kms
def test_no_identifier_appears_in_clear_in_any_request_context_of_a_real_run() -> None:
    value = context(OTHER_TENANT)
    client = RecordingClient(real_client())
    provider = active_a(client)
    key = run(provider.generate_data_key(value))
    run(provider.unwrap_data_key(StoredKey(key.key_ref, key.wrapped_key), value))
    run(active_a(client).rewrap_data_key(StoredKey(key.key_ref, key.wrapped_key), value))
    assert [name for name, _ in client.sent] == ["GenerateDataKey", "Decrypt", "ReEncrypt"]
    for name, request in client.sent:
        contexts = [item for field, item in request.items() if field.endswith("EncryptionContext")]
        assert contexts and all(set(item) == {"rsv:ctx", "rsv:v"} for item in contexts), name
        text = json.dumps(request, default=lambda raw: base64.b64encode(raw).decode())
        for identifier in (NAMESPACE, OTHER_TENANT, value.capture_id):
            assert identifier not in text, f"{identifier} sent in clear to {name}"


@needs_kms
def test_a_call_that_cannot_finish_in_the_provider_timeout_is_a_timeout_and_the_provider_recovers() -> None:
    client = real_client()
    provider = active_a(client, call_timeout_ms=1)
    assert code_of(provider.generate_data_key(context())) == "KEY_TIMEOUT"
    assert len(run(active_a(client).generate_data_key(context())).plaintext_key) == 32


@needs_kms
def test_the_cache_serves_a_real_key_without_a_second_decrypt_and_close_overwrites_it() -> None:
    from redact_secret_vault.keys.aws_kms import DataKeyCacheOptions

    client = RecordingClient(real_client())
    provider = active_a(client, cache=DataKeyCacheOptions(max_entries=4, max_age_ms=60_000, per_tenant_max_entries=2))
    value = context()
    key = run(provider.generate_data_key(value))
    stored = StoredKey(key.key_ref, key.wrapped_key)
    first = run(provider.unwrap_data_key(stored, value))
    second = run(provider.unwrap_data_key(stored, value))
    assert bytes(first) == bytes(second) == bytes(key.plaintext_key)
    assert [name for name, _ in client.sent].count("Decrypt") == 1
    held = next(iter(provider._cache._entries.values())).key
    provider.close()
    assert not any(held)


# -------------------------------------------------------------------- the SDK's own logging


@needs_kms
def test_what_the_sdk_logs_at_debug_is_established_and_the_provider_leaks_nothing_of_its_own(
    capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """Runs real calls with ``logging`` at ``DEBUG`` for the SDK's loggers and looks for the data key in what they log.

    The outcome about the SDK is *recorded*, not hidden: ``botocore`` is the application's dependency and what it logs
    is what the application must not enable. What the provider owns is asserted: it writes no record of its own, and
    no error, traceback, stream, or warning of its own carries a key, a blob, an ARN, or an identifier.
    """

    client = real_client()
    sentinels: set[str] = set()
    errors: list[KeyProviderError] = []
    value = context()

    async def scenario() -> None:
        # The guard refuses while DEBUG is on; this run measures the SDK, so it opts in.
        provider = active_a(client, allow_sdk_debug_logging=True)
        key = await provider.generate_data_key(value)
        raw = bytes(key.plaintext_key)
        sentinels.update({raw.hex(), base64.b64encode(raw).decode()})
        stored = StoredKey(key.key_ref, key.wrapped_key)
        await provider.unwrap_data_key(stored, value)
        try:
            await provider.unwrap_data_key(stored, context())
        except KeyProviderError as error:
            errors.append(error)
        try:
            await provider.unwrap_data_key(StoredKey("aws-kms:" + KEY_A.replace("a", "b", 1), key.wrapped_key), value)
        except KeyProviderError as error:
            errors.append(error)

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        root = logging.getLogger()
        previous = root.level
        root.setLevel(logging.DEBUG)
        names = ("botocore", "boto3", "urllib3", "asyncio", "redact_secret_vault")
        saved = {name: logging.getLogger(name).level for name in names}
        for name in names:
            logging.getLogger(name).setLevel(logging.DEBUG)
        try:
            with caplog.at_level(logging.DEBUG):
                run(scenario())
        finally:
            root.setLevel(previous)
            for name, level in saved.items():
                logging.getLogger(name).setLevel(level)

    own = [record for record in caplog.records if record.name.split(".")[0] == "redact_secret_vault"]
    assert own == [], "the provider writes no log record"
    assert errors and all(error.__cause__ is None and error.__context__ is None for error in errors)
    private = {KEY_A, KEY_B, KEY_A.rsplit("/", 1)[1], value.capture_id, NAMESPACE, *sentinels}
    for error in errors:
        text = repr(error) + str(error)
        assert not any(item in text for item in private)
    streams = capsys.readouterr()
    assert not any(item in streams.out + streams.err for item in private)

    sdk = [record for record in caplog.records if record.name.split(".")[0] in ("botocore", "boto3", "urllib3")]
    sdk_text = "\n".join(record.getMessage() for record in sdk)
    found = {
        "data key (hex or base64) in an SDK log record": any(item in sdk_text for item in sentinels),
        "key ARN in an SDK log record": KEY_A in sdk_text,
        "identifier in an SDK log record": value.capture_id in sdk_text,
    }
    print(f"SDK log records at DEBUG: {len(sdk)} from {sorted({record.name for record in sdk})}")
    for what, seen in found.items():
        print(f"  {what}: {'YES' if seen else 'no'}")
