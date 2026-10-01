"""A ``KeyProvider`` over AWS KMS, with a ``boto3`` client the application injects.

The Python counterpart of ``packages/key-provider-aws-kms`` (docs/specs/persistent-vault.md section 6.1). It uses
the same key reference (``aws-kms:<key ARN>``), the same encryption context (the context digest, never an identifier)
and the same profile name (``aws-kms-envelope-v1``), so a data key wrapped by one provider is unwrapped by the other.

**Python persistence is not supported.** Interoperation with the JavaScript provider is stated only by the
qualification record ``docs/research/qualification-python-persistence-0.1.0b3.md``, for the cells it lists.

The application supplies a configured KMS client (``boto3.client("kms", config=...)``), the exact key ARNs the provider
may use, and its scope. This module constructs no client, reads no environment variable, resolves no region, loads no
credential, and imports no part of ``boto3``. It never falls back to another key or to a local key, logs nothing, and
never lets an SDK error, its message, its response metadata, or its traceback reach the caller.

What Python cannot do (plan section 3.6): ``boto3`` returns ``Plaintext`` as immutable ``bytes``, which cannot be
overwritten; the provider copies it into a ``bytearray`` the caller overwrites and drops its own reference. A response
that arrives after a call was given up is dropped, not overwritten.

Timeouts: ``boto3`` is synchronous, so each call runs in a worker thread, bounded by ``call_timeout_ms``. A thread
cannot be cancelled, so a call given up (timeout or task cancellation) is still running when the provider returns, and
its result is dropped. Set the client's own ``connect_timeout`` and ``read_timeout`` so the thread ends too. The
provider never retries; the retry mode of the client the application built decides that.

Logging: this module logs nothing. ``botocore`` does: with its loggers at ``DEBUG``, a real ``GenerateDataKey`` or
``Decrypt`` was observed (``botocore`` 1.43.107, record in
``docs/research/qualification-python-persistence-0.1.0b3.md``) to write the response body, which holds the
plaintext data key in base64, and the key ARN, from ``botocore.parsers``.
The encryption context carries no identifier, so no namespace, tenant, or capture identifier is in those records. An
application must not enable ``DEBUG`` for ``botocore``, ``boto3``, or ``urllib3`` (or the root logger) in a process that
uses this provider.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal

from .._extras import require_extra

require_extra("redact_secret_vault.keys.aws_kms", "boto3", "aws-kms")

from ..persistent import _buffers  # noqa: E402
from ..persistent import limits as _limits  # noqa: E402
from ..persistent.codec import label, lp16, utf8  # noqa: E402
from ..persistent.contracts import DataKey, KeyContext, StoredKey  # noqa: E402
from ..persistent.errors import KeyProviderError, KeyProviderErrorCode  # noqa: E402
from ..persistent.validate import is_capture_id, is_identifier, is_namespace  # noqa: E402

__all__ = [
    "AWS_KMS_KEY_PROVIDER_PROFILE",
    "CACHE_MAX_AGE_CEILING_MS",
    "CACHE_MAX_ENTRIES_CEILING",
    "CONTEXT_DIGEST_KEY",
    "CONTEXT_VERSION_KEY",
    "DEFAULT_CALL_TIMEOUT_MS",
    "KEY_REF_PREFIX",
    "AwsKmsExpected",
    "AwsKmsKey",
    "AwsKmsKeyProvider",
    "AwsKmsKeyProviderStats",
    "AwsKmsScope",
    "DataKeyCacheOptions",
    "context_digest",
    "create_aws_kms_key_provider",
]

AWS_KMS_KEY_PROVIDER_PROFILE: Final = "aws-kms-envelope-v1"
KEY_REF_PREFIX: Final = "aws-kms:"
DEFAULT_CALL_TIMEOUT_MS: Final = 5000
_MAX_CALL_TIMEOUT_MS: Final = 2_147_483_647

#: Encryption context key of the context digest, and of the constant binding version.
CONTEXT_DIGEST_KEY: Final = "rsv:ctx"
CONTEXT_VERSION_KEY: Final = "rsv:v"
_CONTEXT_VERSION: Final = "1"
_CONTEXT_LABEL: Final = "rsv-kms-context-v1"
_MAX_LABELS: Final = 8

#: A full key ARN. An alias, an alias ARN, and a bare key id are not accepted: an alias can be repointed.
_KEY_ARN: Final = re.compile(
    r"arn:(aws(?:-[a-z]+)*):kms:([a-z]{2}(?:-[a-z]+)+-[0-9]{1,2}):([0-9]{12}):key/"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})"
)
_REGION: Final = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]{1,2}")
_ACCOUNT: Final = re.compile(r"[0-9]{12}")
_PARTITION: Final = re.compile(r"aws(?:-[a-z]+)*")
_LABEL_KEY: Final = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,62}")
_LABEL_VALUE: Final = re.compile(r"[A-Za-z0-9_.-]{1,128}")

#: Hard ceilings of the opt-in cache (spec section 6.2): five minutes, ten thousand entries.
CACHE_MAX_AGE_CEILING_MS: Final = 5 * 60 * 1000
CACHE_MAX_ENTRIES_CEILING: Final = 10_000

AwsKmsKeyState = Literal["active", "decrypt-only", "retired"]

_THROTTLED: Final = frozenset(
    {
        "ThrottlingException",
        "LimitExceededException",
        "TooManyRequestsException",
        "RequestLimitExceeded",
        "Throttling",
        "ThrottledException",
        "RequestThrottledException",
        "RequestThrottled",
    }
)
_TIMED_OUT: Final = frozenset(
    {
        "TimeoutError",
        "RequestTimeout",
        "RequestTimeoutException",
        "ReadTimeoutError",
        "ConnectTimeoutError",
        "timeout",
    }
)


@dataclass(frozen=True, slots=True)
class AwsKmsKey:
    #: A full key ARN, ``arn:<partition>:kms:<region>:<account>:key/<key-id>``. The key reference is ``aws-kms:<arn>``.
    key_arn: str
    state: AwsKmsKeyState


@dataclass(frozen=True, slots=True)
class AwsKmsExpected:
    """The region and account every key ARN must be in, stated by the application. ``partition`` defaults to ``aws``."""

    region: str
    account_id: str
    partition: str = "aws"


@dataclass(frozen=True, slots=True)
class AwsKmsScope:
    """The namespaces, and optionally the tenants, this provider may serve. Required."""

    namespaces: tuple[str, ...]
    tenants: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class DataKeyCacheOptions:
    """Opt-in cache of unwrapped data keys, bounded by count, age, and tenant. Disabling a key in KMS does not reach
    an entry held here until it ages out: the revocation delay is ``max_age_ms``."""

    #: Entries held at once, 1 to 10000.
    max_entries: int
    #: Lifetime of an entry in milliseconds, 1 to 300000. This is the revocation delay.
    max_age_ms: int
    #: Entries held at once for one tenant, 1 to ``max_entries``.
    per_tenant_max_entries: int
    #: Clock in milliseconds, for tests. Default: the monotonic clock.
    now: Callable[[], int | float] | None = None


@dataclass(frozen=True, slots=True)
class AwsKmsKeyProviderStats:
    """Counts only. No key, identifier, or ARN."""

    closed: bool
    cache_enabled: bool
    cache_entries: int
    cache_tenants: int
    cache_hits: int
    cache_misses: int
    cache_evictions: int
    generate_data_key_calls: int
    decrypt_calls: int
    re_encrypt_calls: int


class _Reject(Exception):  # noqa: N818 - an internal signal that carries a code and nothing else
    """Carries only a key provider code. Never leaves this module."""

    def __init__(self, code: KeyProviderErrorCode) -> None:
        super().__init__(code)
        self.code = code


def _reject(code: KeyProviderErrorCode) -> Any:
    raise _Reject(code)


# --------------------------------------------------------------------------------------- the context


def _base64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def context_digest(context: KeyContext) -> str:
    """``base64url(SHA-256("rsv-kms-context-v1" 0x00 || lp16(namespace) || lp16(tenant) || lp16(captureId)))``.

    The encryption context is authenticated but not secret, and AWS records it in CloudTrail, so this digest is sent in
    place of the identifiers (spec sections 3.7 and 6.1). Equal to ``contextDigest`` of the JavaScript provider.
    """

    parts = (
        label(_CONTEXT_LABEL),
        lp16(utf8(context.namespace)),
        lp16(utf8(context.tenant)),
        lp16(utf8(context.capture_id)),
    )
    return _base64url(hashlib.sha256(b"".join(parts)).digest())


def _snapshot_labels(labels: object) -> tuple[tuple[str, str], ...]:
    if labels is None:
        return ()
    if not isinstance(labels, Mapping) or len(labels) > _MAX_LABELS:
        _reject("KEY_INVALID_ARGUMENT")
    out: list[tuple[str, str]] = []
    for key, value in labels.items():
        if (
            type(key) is not str
            or _LABEL_KEY.fullmatch(key) is None
            or type(value) is not str
            or _LABEL_VALUE.fullmatch(value) is None
        ):
            _reject("KEY_INVALID_ARGUMENT")
        out.append((key, value))
    return tuple(out)


def _encryption_context(digest: str, labels: tuple[tuple[str, str], ...]) -> dict[str, str]:
    """A fresh context: the digest, the version, and the labels. Nothing else."""

    out = {CONTEXT_DIGEST_KEY: digest, CONTEXT_VERSION_KEY: _CONTEXT_VERSION}
    for key, value in labels:
        out[key] = value
    return out


# --------------------------------------------------------------------------------------- the cache


class _Entry:
    __slots__ = ("key", "stored_at", "tenant")

    def __init__(self, tenant: str, key: bytearray, stored_at: float) -> None:
        self.tenant = tenant
        self.key = key
        self.stored_at = stored_at


class _DataKeyCache:
    """Bounded by entry count, by age, and per tenant; every entry is overwritten when it is evicted, when it ages out,
    and on ``clear``. Insertion order is age order: an entry is never refreshed by a read."""

    def __init__(self, options: DataKeyCacheOptions) -> None:
        if not isinstance(options, DataKeyCacheOptions):
            _reject("KEY_INVALID_ARGUMENT")
        entries, age, per_tenant = options.max_entries, options.max_age_ms, options.per_tenant_max_entries
        if (
            not _is_count(entries, CACHE_MAX_ENTRIES_CEILING)
            or not _is_count(age, CACHE_MAX_AGE_CEILING_MS)
            or not _is_count(per_tenant, entries)
            or (options.now is not None and not callable(options.now))
        ):
            _reject("KEY_INVALID_ARGUMENT")
        self._max_entries, self._max_age, self._per_tenant = entries, age, per_tenant
        self._clock: Callable[[], int | float] = options.now or (lambda: time.monotonic_ns() / 1_000_000)
        self._entries: dict[str, _Entry] = {}
        self._tenants: dict[str, int] = {}
        self.hits = self.misses = self.evictions = 0

    def _now(self) -> float | None:
        reading = self._clock()
        if type(reading) is bool or not isinstance(reading, (int, float)) or reading != reading:
            return None
        return float(reading)

    def _remove(self, identifier: str, entry: _Entry) -> None:
        _buffers.zero(entry.key)
        self._entries.pop(identifier, None)
        left = self._tenants.get(entry.tenant, 1) - 1
        if left <= 0:
            self._tenants.pop(entry.tenant, None)
        else:
            self._tenants[entry.tenant] = left
        self.evictions += 1

    def _expired(self, entry: _Entry, now: float | None) -> bool:
        # An unreadable clock, or one that went backwards, expires the entry.
        return now is None or now < entry.stored_at or now - entry.stored_at >= self._max_age

    def get(self, identifier: str) -> bytearray | None:
        entry = self._entries.get(identifier)
        if entry is None:
            self.misses += 1
            return None
        if self._expired(entry, self._now()):
            self._remove(identifier, entry)
            self.misses += 1
            return None
        self.hits += 1
        copy = _buffers.new_buffer(len(entry.key))
        copy[:] = entry.key
        return copy

    def put(self, identifier: str, tenant: str, key: bytearray) -> None:
        """The cache owns ``key`` from here on and overwrites it on eviction."""

        now = self._now()
        if now is None:
            _buffers.zero(key)
            return
        for old_id, old in tuple(self._entries.items()):
            if self._expired(old, now):
                self._remove(old_id, old)
        previous = self._entries.get(identifier)
        if previous is not None:
            self._remove(identifier, previous)
        if self._tenants.get(tenant, 0) >= self._per_tenant:
            for old_id, old in self._entries.items():
                if old.tenant == tenant:
                    self._remove(old_id, old)
                    break
        if len(self._entries) >= self._max_entries:
            oldest = next(iter(self._entries.items()), None)
            if oldest is not None:
                self._remove(oldest[0], oldest[1])
        self._entries[identifier] = _Entry(tenant, key, now)
        self._tenants[tenant] = self._tenants.get(tenant, 0) + 1

    def clear(self) -> None:
        for identifier, entry in tuple(self._entries.items()):
            self._remove(identifier, entry)

    def counts(self) -> tuple[int, int]:
        return len(self._entries), len(self._tenants)


def _is_count(value: object, ceiling: int) -> bool:
    return type(value) is int and 1 <= value <= ceiling


# ------------------------------------------------------------------------------ what a client threw


def _classify(error: BaseException) -> KeyProviderErrorCode:
    """Maps what a client raised to a code. Only the exception's class name, the error ``Code`` of its response, and a
    429 status are read; the message, the request identifier, and every other field are not. Every name not listed,
    including ``DisabledException``, ``KMSInvalidStateException``, ``NotFoundException``, ``AccessDeniedException``,
    ``KeyUnavailableException``, and ``IncorrectKeyException``, is ``KEY_UNAVAILABLE``."""

    names: list[str] = []
    status: object = None
    try:
        names.append(type(error).__name__)
        response = getattr(error, "response", None)
        if isinstance(response, dict):
            detail = response.get("Error")
            if isinstance(detail, dict) and isinstance(detail.get("Code"), str):
                names.append(detail["Code"])
            metadata = response.get("ResponseMetadata")
            if isinstance(metadata, dict):
                status = metadata.get("HTTPStatusCode")
        if isinstance(error, TimeoutError):
            names.append("TimeoutError")
    except Exception:  # noqa: BLE001
        return "KEY_UNAVAILABLE"
    if "InvalidCiphertextException" in names:
        return "KEY_INTEGRITY"
    if status == 429 or any(name in _THROTTLED for name in names):
        return "KEY_THROTTLED"
    if any(name in _TIMED_OUT for name in names):
        return "KEY_TIMEOUT"
    return "KEY_UNAVAILABLE"


def _is_bytes_like(value: object) -> bool:
    return isinstance(value, (bytes, bytearray))


def _discard_late(task: asyncio.Future[Any]) -> None:
    """A call that was given up still finishes in its thread; its result is dropped and its exception retrieved."""

    if task.cancelled():
        return
    task.exception()


# -------------------------------------------------------------------------------------- the provider


class AwsKmsKeyProvider:
    """Build it with :func:`create_aws_kms_key_provider`."""

    __slots__ = (
        "_active",
        "_cache",
        "_calls",
        "_client",
        "_closed",
        "_labels",
        "_namespaces",
        "_tenants",
        "_timeout_s",
        "_usable",
    )

    def __init__(
        self,
        client: Any,
        usable: dict[str, str],
        active: str,
        namespaces: frozenset[str],
        tenants: frozenset[str] | None,
        timeout_s: float,
        labels: tuple[tuple[str, str], ...],
        cache: _DataKeyCache | None,
    ) -> None:
        self._client = client
        self._usable = usable
        self._active = active
        self._namespaces = namespaces
        self._tenants = tenants
        self._timeout_s = timeout_s
        self._labels = labels
        self._cache = cache
        self._closed = False
        self._calls = {"generate": 0, "decrypt": 0, "re_encrypt": 0}

    @property
    def profile(self) -> str:
        return AWS_KMS_KEY_PROVIDER_PROFILE

    def __repr__(self) -> str:
        return f"AwsKmsKeyProvider(profile={AWS_KMS_KEY_PROVIDER_PROFILE!r}, keys={len(self._usable)})"

    def __reduce__(self) -> tuple[object, ...]:
        raise TypeError("AwsKmsKeyProvider must not be pickled or copied")

    def close(self) -> None:
        """Overwrites and drops every cached data key. Every later call fails ``KEY_UNAVAILABLE``.

        It does not close the client: the application owns it."""

        self._closed = True
        if self._cache is not None:
            self._cache.clear()

    def stats(self) -> AwsKmsKeyProviderStats:
        entries, tenants = self._cache.counts() if self._cache is not None else (0, 0)
        cache = self._cache
        return AwsKmsKeyProviderStats(
            closed=self._closed,
            cache_enabled=cache is not None,
            cache_entries=entries,
            cache_tenants=tenants,
            cache_hits=cache.hits if cache is not None else 0,
            cache_misses=cache.misses if cache is not None else 0,
            cache_evictions=cache.evictions if cache is not None else 0,
            generate_data_key_calls=self._calls["generate"],
            decrypt_calls=self._calls["decrypt"],
            re_encrypt_calls=self._calls["re_encrypt"],
        )

    # -- internals: raise _Reject, never a foreign exception ---------------------------------------------------

    def _in_scope(self, context: KeyContext) -> bool:
        return context.namespace in self._namespaces and (self._tenants is None or context.tenant in self._tenants)

    def _arn_of(self, key_ref: str) -> str:
        """The ARN ``key_ref`` names, when it is a configured key that is not retired. Never another key."""

        if not key_ref.startswith(KEY_REF_PREFIX):
            _reject("KEY_UNAVAILABLE")
        arn = key_ref[len(KEY_REF_PREFIX) :]
        if arn not in self._usable:
            _reject("KEY_UNAVAILABLE")
        return arn

    def _enter(self) -> None:
        if self._closed:
            _reject("KEY_UNAVAILABLE")

    @staticmethod
    def _snapshot_context(context: object) -> KeyContext:
        if (
            not isinstance(context, KeyContext)
            or not is_namespace(context.namespace)
            or not is_identifier(context.tenant)
            or not is_capture_id(context.capture_id)
        ):
            _reject("KEY_INVALID_ARGUMENT")
        return KeyContext(context.namespace, context.tenant, context.capture_id)  # type: ignore[union-attr]

    @staticmethod
    def _snapshot_stored(stored: object) -> StoredKey:
        if (
            not isinstance(stored, StoredKey)
            or type(stored.key_ref) is not str
            or not isinstance(stored.wrapped_key, bytes)
        ):
            _reject("KEY_INVALID_ARGUMENT")
        if (
            len(stored.key_ref) == 0  # type: ignore[union-attr]
            or len(stored.wrapped_key) == 0  # type: ignore[union-attr]
            or len(stored.wrapped_key) > _limits.WRAPPED_KEY_MAX_BYTES  # type: ignore[union-attr]
        ):
            _reject("KEY_INVALID_ARGUMENT")
        return StoredKey(stored.key_ref, bytes(stored.wrapped_key))  # type: ignore[union-attr]

    async def _send(self, method: str, request: dict[str, Any]) -> dict[str, Any]:
        """One KMS call in a worker thread, bounded by the timeout. It ends in the response mapping or ``_Reject``.

        Nothing the client raised is rethrown or attached. A call given up (timeout, or the caller's cancellation,
        which propagates) is still running in its thread; its outcome is dropped."""

        call = getattr(self._client, method)
        task: asyncio.Future[Any] = asyncio.ensure_future(asyncio.to_thread(call, **request))
        try:
            done, _ = await asyncio.wait({task}, timeout=self._timeout_s)
        except asyncio.CancelledError:
            task.add_done_callback(_discard_late)
            raise
        code: KeyProviderErrorCode | None = None
        output: object = None
        if task not in done:
            task.add_done_callback(_discard_late)
            code = "KEY_TIMEOUT"
        elif task.cancelled():
            code = "KEY_UNAVAILABLE"
        else:
            failure = task.exception()
            if failure is not None:
                code = _classify(failure)
                failure = None  # drop the SDK's exception, its traceback, and its frames
            else:
                output = task.result()
        if code is not None:
            raise _Reject(code)
        if not isinstance(output, dict):
            output = None
            _reject("KEY_UNAVAILABLE")
        return output  # type: ignore[return-value]

    @staticmethod
    def _take_plaintext(output: dict[str, Any]) -> bytearray | None:
        """The data key of a response, in a buffer the caller overwrites. ``None`` unless it is exactly 32 bytes.

        The SDK's own ``bytes`` object cannot be overwritten: it is dropped from the mapping and not referenced."""

        plaintext = output.pop("Plaintext", None)
        try:
            if not _is_bytes_like(plaintext) or len(plaintext) != _limits.DATA_KEY_BYTES:  # type: ignore[arg-type]
                return None
            key = _buffers.new_buffer(_limits.DATA_KEY_BYTES)
            key[:] = plaintext  # type: ignore[assignment]
            return key
        finally:
            if isinstance(plaintext, bytearray):
                _buffers.zero(plaintext)

    @staticmethod
    def _wrapped_from(output: dict[str, Any]) -> bytes | None:
        blob = output.get("CiphertextBlob")
        if not _is_bytes_like(blob) or not 1 <= len(blob) <= _limits.WRAPPED_KEY_MAX_BYTES:  # type: ignore[arg-type]
            return None
        return bytes(blob)  # type: ignore[arg-type]

    async def _generate(self, context: object) -> DataKey:
        self._enter()
        snapshot = self._snapshot_context(context)
        if not self._in_scope(snapshot):
            _reject("KEY_UNAVAILABLE")
        digest = context_digest(snapshot)
        self._calls["generate"] += 1
        output = await self._send(
            "generate_data_key",
            {
                "KeyId": self._active,
                "KeySpec": "AES_256",
                "EncryptionContext": _encryption_context(digest, self._labels),
            },
        )
        key = self._take_plaintext(output)
        wrapped = self._wrapped_from(output)
        if self._closed or output.get("KeyId") != self._active or key is None or wrapped is None:
            _buffers.zero(key)
            _reject("KEY_INTEGRITY" if not self._closed else "KEY_UNAVAILABLE")
        assert key is not None and wrapped is not None
        return DataKey(KEY_REF_PREFIX + self._active, wrapped, key)

    async def _unwrap(self, stored: object, context: object) -> bytearray:
        self._enter()
        snapshot = self._snapshot_stored(stored)
        ctx = self._snapshot_context(context)
        if not self._in_scope(ctx):
            _reject("KEY_UNAVAILABLE")
        arn = self._arn_of(snapshot.key_ref)
        digest = context_digest(ctx)

        cache_id: str | None = None
        if self._cache is not None:
            cache_id = f"{arn}\n{_base64url(hashlib.sha256(snapshot.wrapped_key).digest())}\n{digest}"
            self._enter()
            cached = self._cache.get(cache_id)
            if cached is not None:
                return cached

        self._calls["decrypt"] += 1
        # KeyId is always sent: KMS must use the key the reference names, not the one the blob names.
        output = await self._send(
            "decrypt",
            {
                "KeyId": arn,
                "CiphertextBlob": snapshot.wrapped_key,
                "EncryptionContext": _encryption_context(digest, self._labels),
            },
        )
        key = self._take_plaintext(output)
        if self._closed or output.get("KeyId") != arn or key is None:
            _buffers.zero(key)
            _reject("KEY_INTEGRITY" if not self._closed else "KEY_UNAVAILABLE")
        assert key is not None
        if self._cache is not None and cache_id is not None:
            held = _buffers.new_buffer(len(key))
            held[:] = key
            self._cache.put(cache_id, ctx.tenant, held)
        return key

    async def _rewrap(self, stored: object, context: object) -> StoredKey:
        self._enter()
        snapshot = self._snapshot_stored(stored)
        ctx = self._snapshot_context(context)
        if not self._in_scope(ctx):
            _reject("KEY_UNAVAILABLE")
        arn = self._arn_of(snapshot.key_ref)
        digest = context_digest(ctx)
        self._calls["re_encrypt"] += 1
        # ReEncrypt decrypts and encrypts inside KMS: the data key does not reach this process.
        output = await self._send(
            "re_encrypt",
            {
                "CiphertextBlob": snapshot.wrapped_key,
                "SourceKeyId": arn,
                "SourceEncryptionContext": _encryption_context(digest, self._labels),
                "DestinationKeyId": self._active,
                "DestinationEncryptionContext": _encryption_context(digest, self._labels),
            },
        )
        wrapped = self._wrapped_from(output)
        if self._closed:
            _reject("KEY_UNAVAILABLE")
        if output.get("SourceKeyId") != arn or output.get("KeyId") != self._active or wrapped is None:
            _reject("KEY_INTEGRITY")
        assert wrapped is not None
        return StoredKey(KEY_REF_PREFIX + self._active, wrapped)

    # -- KeyProvider -------------------------------------------------------------------------------------------

    async def generate_data_key(self, context: KeyContext) -> DataKey:
        """A fresh 256-bit data key from KMS under the active key, bound to ``context``."""

        code: KeyProviderErrorCode | None = None
        result: DataKey | None = None
        try:
            result = await self._generate(context)
        except _Reject as rejected:
            code = rejected.code
        except Exception:
            code = "KEY_UNAVAILABLE"
        finally:
            del context
        if code is not None:
            raise KeyProviderError(code)
        assert result is not None
        return result

    async def unwrap_data_key(self, stored: StoredKey, context: KeyContext) -> bytearray:
        """Unwrap with exactly the key ``stored.key_ref`` names; never another key."""

        code: KeyProviderErrorCode | None = None
        result: bytearray | None = None
        try:
            result = await self._unwrap(stored, context)
        except _Reject as rejected:
            code = rejected.code
        except Exception:
            code = "KEY_UNAVAILABLE"
        finally:
            del stored, context
        if code is not None:
            raise KeyProviderError(code)
        assert result is not None
        return result

    async def rewrap_data_key(self, stored: StoredKey, context: KeyContext) -> StoredKey:
        """The same data key under the active key, for the same context, without it reaching this process."""

        code: KeyProviderErrorCode | None = None
        result: StoredKey | None = None
        try:
            result = await self._rewrap(stored, context)
        except _Reject as rejected:
            code = rejected.code
        except Exception:
            code = "KEY_UNAVAILABLE"
        finally:
            del stored, context
        if code is not None:
            raise KeyProviderError(code)
        assert result is not None
        return result


def _build(
    client: object,
    keys: object,
    expected: object,
    scope: object,
    cache: object,
    call_timeout_ms: object,
    context_labels: object,
) -> AwsKmsKeyProvider:
    if client is None or not all(
        callable(getattr(client, name, None)) for name in ("generate_data_key", "decrypt", "re_encrypt")
    ):
        _reject("KEY_INVALID_ARGUMENT")
    if not isinstance(scope, AwsKmsScope):
        _reject("KEY_INVALID_ARGUMENT")
    namespaces, tenants = scope.namespaces, scope.tenants  # type: ignore[union-attr]
    if type(namespaces) is not tuple or len(namespaces) == 0 or not all(is_namespace(n) for n in namespaces):
        _reject("KEY_INVALID_ARGUMENT")
    if tenants is not None and (
        type(tenants) is not tuple or len(tenants) == 0 or not all(is_identifier(t) for t in tenants)
    ):
        _reject("KEY_INVALID_ARGUMENT")
    if not isinstance(expected, AwsKmsExpected):
        _reject("KEY_INVALID_ARGUMENT")
    region, account, partition = expected.region, expected.account_id, expected.partition  # type: ignore[union-attr]
    if (
        type(region) is not str
        or _REGION.fullmatch(region) is None
        or type(account) is not str
        or _ACCOUNT.fullmatch(account) is None
        or type(partition) is not str
        or _PARTITION.fullmatch(partition) is None
    ):
        _reject("KEY_INVALID_ARGUMENT")
    if type(keys) is not tuple or len(keys) == 0:
        _reject("KEY_INVALID_ARGUMENT")

    usable: dict[str, str] = {}
    seen: set[str] = set()
    active: str | None = None
    for key in keys:
        if not isinstance(key, AwsKmsKey) or type(key.key_arn) is not str or key.key_arn in seen:
            _reject("KEY_INVALID_ARGUMENT")
        match = _KEY_ARN.fullmatch(key.key_arn)
        if match is None or match.group(1) != partition or match.group(2) != region or match.group(3) != account:
            _reject("KEY_INVALID_ARGUMENT")
        if key.state not in ("active", "decrypt-only", "retired"):
            _reject("KEY_INVALID_ARGUMENT")
        if key.state == "active":
            if active is not None:
                _reject("KEY_INVALID_ARGUMENT")
            active = key.key_arn
        seen.add(key.key_arn)
        if key.state != "retired":
            usable[key.key_arn] = key.state
    if active is None:
        _reject("KEY_INVALID_ARGUMENT")

    timeout_ms = DEFAULT_CALL_TIMEOUT_MS if call_timeout_ms is None else call_timeout_ms
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= _MAX_CALL_TIMEOUT_MS:
        _reject("KEY_INVALID_ARGUMENT")
    labels = _snapshot_labels(context_labels)
    held = None if cache is None else _DataKeyCache(cache)  # type: ignore[arg-type]
    return AwsKmsKeyProvider(
        client,
        usable,
        active,  # type: ignore[arg-type]
        frozenset(namespaces),
        None if tenants is None else frozenset(tenants),
        timeout_ms / 1000,  # type: ignore[operator]
        labels,
        held,
    )


def create_aws_kms_key_provider(
    *,
    client: Any,
    keys: tuple[AwsKmsKey, ...],
    expected: AwsKmsExpected,
    scope: AwsKmsScope,
    cache: DataKeyCacheOptions | None = None,
    call_timeout_ms: int | None = None,
    context_labels: Mapping[str, str] | None = None,
) -> AwsKmsKeyProvider:
    """Builds the provider. Makes no KMS call.

    ``KeyProviderError("KEY_INVALID_ARGUMENT")`` unless ``client`` has ``generate_data_key``, ``decrypt``, and
    ``re_encrypt``, the keys are full ARNs that all lie in the expected partition, region, and account, exactly one is
    ``active``, and the scope is explicit. ``context_labels`` are opt-in static, non-sensitive pairs added to the
    encryption context, for IAM conditions: they appear in CloudTrail and become part of the binding, so a key wrapped
    with one set does not unwrap with another.
    """

    code: KeyProviderErrorCode | None = None
    provider: AwsKmsKeyProvider | None = None
    try:
        provider = _build(client, keys, expected, scope, cache, call_timeout_ms, context_labels)
    except _Reject as rejected:
        code = rejected.code
    except Exception:
        code = "KEY_INVALID_ARGUMENT"
    if code is not None:
        raise KeyProviderError(code)
    assert provider is not None
    return provider
