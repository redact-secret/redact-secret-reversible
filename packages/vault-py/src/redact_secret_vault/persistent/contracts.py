"""Data types and protocols of the persistent vault contract.

Transcribed from ``packages/vault-contracts/src/types.ts`` and
docs/specs/persistent-vault.md sections 4 and 5, under the mapping of
docs/plans/python-persistence-parity.md section 3.1:

* data ``interface`` -> frozen, slotted dataclass; field names in ``snake_case``;
* behavior ``interface`` -> ``typing.Protocol`` with ``async def`` methods;
* discriminated union -> one dataclass per variant with a ``Literal`` field;
* ``Uint8Array`` -> ``bytes`` for stored or sent data, ``bytearray`` for secrets;
* ``readonly T[]`` -> ``tuple``; ``number`` -> ``int`` (never ``bool`` or ``float``).

Frozen dataclasses do not validate. The functions in ``validate`` do, and every
store calls them before any write. ``runtime_checkable`` verifies that methods
exist, nothing more: an injected implementation runs in the trusted process
and a ``Protocol`` does not contain it (spec section 2).

Classes that hold bytes print lengths, not content, in ``repr``.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Literal, Protocol, runtime_checkable

__all__ = [
    "Attempt",
    "AttemptAbsent",
    "AttemptCommitted",
    "CaptureCreated",
    "CaptureFenced",
    "CaptureGeneration",
    "CaptureKeyRejected",
    "CaptureKeyReplaced",
    "CaptureNotFound",
    "CaptureRejected",
    "CaptureRevoked",
    "CiphertextDeleted",
    "CiphertextRejected",
    "CommitRejection",
    "CommitRestoreInput",
    "CommitRestoreResult",
    "CreateCaptureInput",
    "CreateCaptureResult",
    "DataKey",
    "DeleteCiphertextInput",
    "DeleteCiphertextResult",
    "EntryUse",
    "Grant",
    "InitializeNamespaceResult",
    "InspectAttemptInput",
    "InspectAttemptResult",
    "InvalidateRecoveredInput",
    "InvalidateRecoveredResult",
    "InvalidateRejected",
    "KeyContext",
    "KeyProvider",
    "NamespaceInitialized",
    "NamespaceRejected",
    "NewCapture",
    "NewEntry",
    "ReadCapturesInput",
    "ReadEntriesInput",
    "ReadEntriesResult",
    "RecordBinding",
    "RecordCrypto",
    "RecordPayload",
    "RecoveredInvalidated",
    "RecoveryState",
    "ReplaceCaptureKeyInput",
    "ReplaceCaptureKeyResult",
    "RestoreAlreadyCommitted",
    "RestoreAttemptMismatch",
    "RestoreCommitted",
    "RestoreRejected",
    "RevokeCaptureInput",
    "RevokeCaptureResult",
    "SealedCapture",
    "Store",
    "StoreCapabilities",
    "StoreScope",
    "StoredCapture",
    "StoredEntry",
    "StoredKey",
    "SweepInput",
    "SweepRejected",
    "SweepResult",
    "Swept",
]


# --------------------------------------------------------------------------
# Printing: a dataclass's default repr would print every byte of a key.
# --------------------------------------------------------------------------


def _describe(value: object) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<{type(value).__name__} len={len(value)}>"
    if isinstance(value, tuple):
        return "(" + ", ".join(_describe(item) for item in value) + ("," if len(value) == 1 else "") + ")"
    return repr(value)


class _LengthRepr:
    """Mixin: ``repr`` shows byte-like fields as their length."""

    __slots__ = ()

    def __repr__(self) -> str:
        body = ", ".join(f"{f.name}={_describe(getattr(self, f.name))}" for f in fields(self))  # type: ignore[arg-type]
        return f"{type(self).__name__}({body})"


class _NoPickle(_LengthRepr):
    """Mixin for secret holders: never serialized, never copied by value."""

    __slots__ = ()

    def __reduce__(self) -> tuple[object, ...]:
        raise TypeError(f"{type(self).__name__} must not be pickled or copied")


# --------------------------------------------------------------------------
# Store
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StoreScope:
    namespace: str
    tenant: str


@dataclass(frozen=True, slots=True)
class StoreCapabilities:
    contract_version: Literal[1]
    adapter: str
    profile: str
    atomic_create: bool
    max_create_entries: int
    max_create_bytes: int
    atomic_restore: bool
    max_restore_entries: int
    max_restore_captures: int
    authoritative_commit: bool
    revocation_fences: bool
    attempt_receipts: bool
    store_clock: bool
    max_clock_skew_ms: int
    durability: Literal["volatile", "durable"]
    cross_process: bool
    restore_detection: str
    max_envelope_bytes: int


@dataclass(frozen=True, slots=True, repr=False)
class StoredKey(_LengthRepr):
    key_ref: str
    wrapped_key: bytes


@dataclass(frozen=True, slots=True, repr=False)
class NewEntry(_LengthRepr):
    entry_id: str
    max_uses: int
    envelope: bytes


@dataclass(frozen=True, slots=True, repr=False)
class NewCapture(_LengthRepr):
    """TypeScript: ``StoredKey & { captureId, sessionTag, ... }``."""

    capture_id: str
    key_ref: str
    wrapped_key: bytes
    session_tag: str | None
    created_at: int
    expires_at: int
    lookup_version: Literal[1] = 1


@dataclass(frozen=True, slots=True)
class CreateCaptureInput:
    scope: StoreScope
    epoch: int
    now: int
    capture: NewCapture
    entries: tuple[NewEntry, ...]


@dataclass(frozen=True, slots=True)
class CaptureCreated:
    outcome: Literal["created"] = "created"


@dataclass(frozen=True, slots=True)
class CaptureRejected:
    reason: Literal["exists", "fenced", "clock-skew", "quarantined", "stale"]
    outcome: Literal["rejected"] = "rejected"


CreateCaptureResult = CaptureCreated | CaptureRejected


@dataclass(frozen=True, slots=True, repr=False)
class StoredEntry(_LengthRepr):
    entry_id: str
    capture_id: str
    max_uses: int
    used: int
    lifecycle_revision: int
    ciphertext_revision: int
    envelope: bytes


@dataclass(frozen=True, slots=True, repr=False)
class StoredCapture(_LengthRepr):
    """TypeScript: ``StoredKey & { captureId, state, ... }``."""

    capture_id: str
    key_ref: str
    wrapped_key: bytes
    state: Literal["live", "revoked"]
    generation: int
    key_revision: int
    epoch: int
    session_tag: str | None
    created_at: int
    expires_at: int


@dataclass(frozen=True, slots=True)
class RecoveryState:
    #: 0 when the namespace has no recovery record.
    epoch: int
    state: Literal["uninitialized", "serving", "quarantined"]


@dataclass(frozen=True, slots=True)
class ReadEntriesInput:
    scope: StoreScope
    entry_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReadCapturesInput:
    scope: StoreScope
    capture_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReadEntriesResult:
    recovery: RecoveryState
    #: Entries found, in no particular order. A missing identifier is simply absent.
    entries: tuple[StoredEntry, ...]
    #: The capture of every returned entry.
    captures: tuple[StoredCapture, ...]


@dataclass(frozen=True, slots=True, repr=False)
class Attempt(_LengthRepr):
    attempt_id: str
    #: Exactly 32 bytes.
    request_digest: bytes


@dataclass(frozen=True, slots=True)
class CaptureGeneration:
    capture_id: str
    generation: int


@dataclass(frozen=True, slots=True)
class EntryUse:
    entry_id: str
    capture_id: str
    #: The entry's total occurrence count across the request.
    count: int
    lifecycle_revision: int
    ciphertext_revision: int


@dataclass(frozen=True, slots=True)
class CommitRestoreInput:
    scope: StoreScope
    epoch: int
    now: int
    attempt: Attempt
    receipt_expires_at: int
    #: Exactly the captures of the entries in ``uses``, each once.
    captures: tuple[CaptureGeneration, ...]
    #: Each entry once.
    uses: tuple[EntryUse, ...]


CommitRejection = Literal["revoked", "expired", "budget", "stale", "unknown", "clock-skew", "quarantined"]


@dataclass(frozen=True, slots=True)
class RestoreCommitted:
    outcome: Literal["committed"] = "committed"


@dataclass(frozen=True, slots=True)
class RestoreAlreadyCommitted:
    outcome: Literal["already-committed"] = "already-committed"


@dataclass(frozen=True, slots=True)
class RestoreAttemptMismatch:
    outcome: Literal["attempt-mismatch"] = "attempt-mismatch"


@dataclass(frozen=True, slots=True)
class RestoreRejected:
    reason: CommitRejection
    outcome: Literal["rejected"] = "rejected"


CommitRestoreResult = RestoreCommitted | RestoreAlreadyCommitted | RestoreAttemptMismatch | RestoreRejected


@dataclass(frozen=True, slots=True)
class RevokeCaptureInput:
    scope: StoreScope
    capture_id: str
    now: int
    #: How long past the capture's expiry (or past ``now``, if later) the tombstone is kept.
    retention_ms: int
    #: Write a fence when the capture does not exist. Only for an identifier the server itself issued.
    fence_absent: bool


@dataclass(frozen=True, slots=True)
class CaptureRevoked:
    entries: int
    outcome: Literal["revoked", "already-revoked"] = "revoked"


@dataclass(frozen=True, slots=True)
class CaptureNotFound:
    outcome: Literal["not-found"] = "not-found"


@dataclass(frozen=True, slots=True)
class CaptureFenced:
    outcome: Literal["fenced"] = "fenced"


RevokeCaptureResult = CaptureRevoked | CaptureNotFound | CaptureFenced


@dataclass(frozen=True, slots=True)
class InspectAttemptInput:
    scope: StoreScope
    attempt_id: str


@dataclass(frozen=True, slots=True, repr=False)
class AttemptCommitted(_LengthRepr):
    request_digest: bytes
    committed_at: int
    state: Literal["committed"] = "committed"


@dataclass(frozen=True, slots=True)
class AttemptAbsent:
    state: Literal["absent"] = "absent"


InspectAttemptResult = AttemptCommitted | AttemptAbsent


@dataclass(frozen=True, slots=True, repr=False)
class ReplaceCaptureKeyInput(_LengthRepr):
    scope: StoreScope
    capture_id: str
    key_revision: int
    key_ref: str
    wrapped_key: bytes


@dataclass(frozen=True, slots=True)
class CaptureKeyReplaced:
    key_revision: int
    outcome: Literal["replaced"] = "replaced"


@dataclass(frozen=True, slots=True)
class CaptureKeyRejected:
    reason: Literal["stale", "unknown", "revoked", "expired"]
    outcome: Literal["rejected"] = "rejected"


ReplaceCaptureKeyResult = CaptureKeyReplaced | CaptureKeyRejected


@dataclass(frozen=True, slots=True)
class DeleteCiphertextInput:
    scope: StoreScope
    capture_id: str
    now: int


@dataclass(frozen=True, slots=True)
class CiphertextDeleted:
    entries: int
    outcome: Literal["deleted"] = "deleted"


@dataclass(frozen=True, slots=True)
class CiphertextRejected:
    reason: Literal["live", "not-found", "clock-skew"]
    outcome: Literal["rejected"] = "rejected"


DeleteCiphertextResult = CiphertextDeleted | CiphertextRejected


@dataclass(frozen=True, slots=True)
class SweepInput:
    namespace: str
    now: int
    limit: int


@dataclass(frozen=True, slots=True)
class Swept:
    entries: int
    captures: int
    receipts: int
    more: bool
    outcome: Literal["swept"] = "swept"


@dataclass(frozen=True, slots=True)
class SweepRejected:
    reason: Literal["clock-skew"] = "clock-skew"
    outcome: Literal["rejected"] = "rejected"


SweepResult = Swept | SweepRejected


@dataclass(frozen=True, slots=True)
class NamespaceInitialized:
    outcome: Literal["initialized"] = "initialized"


@dataclass(frozen=True, slots=True)
class NamespaceRejected:
    reason: Literal["exists", "not-empty"]
    outcome: Literal["rejected"] = "rejected"


InitializeNamespaceResult = NamespaceInitialized | NamespaceRejected


@dataclass(frozen=True, slots=True)
class InvalidateRecoveredInput:
    namespace: str
    new_epoch: int


@dataclass(frozen=True, slots=True)
class RecoveredInvalidated:
    recovery: RecoveryState
    outcome: Literal["invalidated"] = "invalidated"


@dataclass(frozen=True, slots=True)
class InvalidateRejected:
    reason: Literal["epoch-not-greater", "uninitialized"]
    outcome: Literal["rejected"] = "rejected"


InvalidateRecoveredResult = RecoveredInvalidated | InvalidateRejected


@runtime_checkable
class Store(Protocol):
    """Ciphertext-only storage with atomic lifecycle operations (spec section 5).

    Cancellation is task cancellation; deadlines belong to the caller.
    """

    def capabilities(self) -> StoreCapabilities: ...

    async def create_capture(self, input: CreateCaptureInput) -> CreateCaptureResult: ...

    async def read_entries(self, input: ReadEntriesInput) -> ReadEntriesResult: ...

    async def read_captures(self, input: ReadCapturesInput) -> tuple[StoredCapture, ...]: ...

    async def commit_restore(self, input: CommitRestoreInput) -> CommitRestoreResult: ...

    async def revoke_capture(self, input: RevokeCaptureInput) -> RevokeCaptureResult: ...

    async def inspect_attempt(self, input: InspectAttemptInput) -> InspectAttemptResult: ...

    async def replace_capture_key(self, input: ReplaceCaptureKeyInput) -> ReplaceCaptureKeyResult: ...

    async def delete_ciphertext(self, input: DeleteCiphertextInput) -> DeleteCiphertextResult: ...

    async def sweep_expired(self, input: SweepInput) -> SweepResult: ...

    async def recovery_state(self, namespace: str) -> RecoveryState: ...

    async def initialize_namespace(self, namespace: str, epoch: int) -> InitializeNamespaceResult: ...

    async def quarantine(self, namespace: str) -> RecoveryState: ...

    async def invalidate_recovered(self, input: InvalidateRecoveredInput) -> InvalidateRecoveredResult: ...


# --------------------------------------------------------------------------
# Keys and records
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KeyContext:
    namespace: str
    tenant: str
    capture_id: str


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class DataKey(_NoPickle):
    key_ref: str
    wrapped_key: bytes
    #: 32 bytes. The caller overwrites it after use.
    plaintext_key: bytearray


@runtime_checkable
class KeyProvider(Protocol):
    """Wraps and unwraps capture data keys; never sees a payload (spec section 6.1)."""

    @property
    def profile(self) -> str: ...

    async def generate_data_key(self, context: KeyContext) -> DataKey: ...

    async def unwrap_data_key(self, stored: StoredKey, context: KeyContext) -> bytearray: ...

    async def rewrap_data_key(self, stored: StoredKey, context: KeyContext) -> StoredKey: ...


@dataclass(frozen=True, slots=True)
class RecordBinding:
    """Everything authenticated but not encrypted for one entry (spec section 3.4)."""

    namespace: str
    tenant: str
    capture_id: str
    entry_id: str
    session_id: str | None
    created_at: int
    expires_at: int
    max_uses: int


@dataclass(frozen=True, slots=True)
class Grant:
    sink: str
    paths: tuple[str, ...]


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class RecordPayload(_NoPickle):
    """Everything encrypted for one entry (spec section 3.5)."""

    #: UTF-8 bytes. Decode only when about to be returned; overwrite otherwise.
    value: bytearray
    type: str
    grants: tuple[Grant, ...]
    policy_revision: str | None


@dataclass(frozen=True, slots=True, repr=False)
class SealedCapture(_LengthRepr):
    key_ref: str
    wrapped_key: bytes
    #: In the order of the records.
    envelopes: tuple[bytes, ...]


@runtime_checkable
class RecordCrypto(Protocol):
    @property
    def profile(self) -> str: ...

    async def seal_capture(
        self, context: KeyContext, records: tuple[tuple[RecordBinding, RecordPayload], ...]
    ) -> SealedCapture: ...

    async def open_capture(
        self,
        stored: StoredKey,
        context: KeyContext,
        records: tuple[tuple[RecordBinding, bytes], ...],
    ) -> tuple[RecordPayload, ...]:
        """Payloads in the order of ``records``: all of them, or an error, never a partial result."""
        ...

    async def rewrap_capture_key(self, stored: StoredKey, context: KeyContext) -> StoredKey: ...
