"""Test-only: a hand-written fake of the three AWS KMS operations the provider uses, shaped like a ``boto3`` client.

Every ARN, account id, and key here is synthetic. It is not a KMS emulator: it reproduces the semantics the provider
depends on (context binding, key selection by ``KeyId`` or by the blob, key states, the error names ``botocore``
raises). Nothing here is in the wheel.
"""

from __future__ import annotations

import secrets
import time
import uuid
from typing import Any

ACCOUNT = "111122223333"
REGION = "us-east-1"
#: Text a real SDK error could carry. None of it may reach a raised error, a log record, or a stream.
SDK_TEXT = "SYNTHETIC-SDK-ERROR-TEXT"
SDK_REQUEST_ID = "synthetic-request-id-0f1e2d3c"


def arn_for(key_id: str | None = None, *, region: str = REGION, account: str = ACCOUNT) -> str:
    return f"arn:aws:kms:{region}:{account}:key/{key_id or uuid.uuid4()}"


class FakeSdkError(Exception):
    """Shaped like ``botocore.exceptions.ClientError``: a ``response`` mapping, and a message that names the key."""

    def __init__(self, code: str, arn: str = "", *, status: int = 400) -> None:
        super().__init__(f"{SDK_TEXT}: An error occurred ({code}) when calling the operation for {arn}")
        self.response = {
            "Error": {"Code": code, "Message": f"{SDK_TEXT} message for {arn}"},
            "ResponseMetadata": {"RequestId": SDK_REQUEST_ID, "HTTPStatusCode": status},
        }
        self.detail = SDK_TEXT
        self.__cause__ = RuntimeError(f"{SDK_TEXT} inner cause")


def sdk_error(name: str, arn: str = "", *, status: int = 400) -> Exception:
    """An error whose class name is ``name``, as botocore's modeled exceptions are."""

    return type(name, (FakeSdkError,), {})(name, arn, status=status)


class FakeKms:
    """An in-memory KMS. ``calls`` records every request (deep copies), in order."""

    def __init__(self) -> None:
        #: arn -> {"state": ..., "tag": bytes}
        self.keys: dict[str, dict[str, Any]] = {}
        #: blob -> (key arn, canonical context, plaintext)
        self._blobs: dict[bytes, tuple[str, tuple[tuple[str, str], ...], bytes]] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.next_failure: Exception | None = None
        self.delay_s = 0.0
        self.mutate: Any = None
        self.plaintexts: list[bytes] = []

    def create_key(self) -> str:
        arn = arn_for()
        self.keys[arn] = {"state": "Enabled"}
        return arn

    def set_state(self, arn: str, state: str) -> None:
        self.keys[arn]["state"] = state

    @staticmethod
    def _canonical(context: dict[str, str] | None) -> tuple[tuple[str, str], ...]:
        return tuple(sorted((context or {}).items()))

    def _usable(self, arn: str) -> dict[str, Any]:
        key = self.keys.get(arn)
        if key is None:
            raise sdk_error("NotFoundException", arn)
        if key["state"] == "Disabled":
            raise sdk_error("DisabledException", arn)
        if key["state"] != "Enabled":
            raise sdk_error("KMSInvalidStateException", arn)
        return key

    def _record(self, name: str, request: dict[str, Any]) -> None:
        import copy

        self.calls.append((name, copy.deepcopy(request)))
        if self.delay_s:
            time.sleep(self.delay_s)
        if self.next_failure is not None:
            failure, self.next_failure = self.next_failure, None
            raise failure

    def _decrypt(self, blob: bytes, key_id: str | None, context: dict[str, str] | None) -> tuple[str, bytes]:
        found = self._blobs.get(bytes(blob))
        if found is None:
            raise sdk_error("InvalidCiphertextException", key_id or "")
        arn, bound, plaintext = found
        if key_id is not None:
            self._usable(key_id)
            if key_id != arn:
                raise sdk_error("IncorrectKeyException", key_id)
        self._usable(arn)
        if bound != self._canonical(context):
            raise sdk_error("InvalidCiphertextException", arn)
        return arn, plaintext

    # -- the three operations, with boto3's parameter and result names --------------------------------------------

    def generate_data_key(self, **request: Any) -> dict[str, Any]:
        self._record("GenerateDataKey", request)
        arn = request["KeyId"]
        self._usable(arn)
        assert request["KeySpec"] == "AES_256"
        plaintext = secrets.token_bytes(32)
        blob = secrets.token_bytes(48)
        self._blobs[blob] = (arn, self._canonical(request.get("EncryptionContext")), plaintext)
        self.plaintexts.append(plaintext)
        result = {"KeyId": arn, "Plaintext": plaintext, "CiphertextBlob": blob}
        return self.mutate("generate", result) if self.mutate else result

    def decrypt(self, **request: Any) -> dict[str, Any]:
        self._record("Decrypt", request)
        arn, plaintext = self._decrypt(
            request["CiphertextBlob"], request.get("KeyId"), request.get("EncryptionContext")
        )
        result = {"KeyId": arn, "Plaintext": plaintext}
        return self.mutate("decrypt", result) if self.mutate else result

    def re_encrypt(self, **request: Any) -> dict[str, Any]:
        self._record("ReEncrypt", request)
        source, plaintext = self._decrypt(
            request["CiphertextBlob"], request.get("SourceKeyId"), request.get("SourceEncryptionContext")
        )
        destination = request["DestinationKeyId"]
        self._usable(destination)
        blob = secrets.token_bytes(48)
        self._blobs[blob] = (destination, self._canonical(request.get("DestinationEncryptionContext")), plaintext)
        result = {"SourceKeyId": source, "KeyId": destination, "CiphertextBlob": blob}
        return self.mutate("re_encrypt", result) if self.mutate else result
