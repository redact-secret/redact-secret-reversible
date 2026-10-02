# Python persistence parity and crypto interoperability plan

**Status:** plan only, for [#115](https://github.com/redact-secret/redact-secret-vault/issues/115) under epic [#4](https://github.com/redact-secret/redact-secret-vault/issues/4). Python persistence is **not implemented and not supported**. Nothing in `packages/vault-py` stores, encrypts, or shares a retained value between processes. The contracts in §3 and the layout in §4 are **proposed**; no item here is **planned** until the issues in §8 are filed. A qualification of the JavaScript packages does not transfer to Python: every gate in §6 is run against the Python artifacts, and a Python persistence claim rests only on those runs.

The design being mirrored is the [persistent vault specification](../specs/persistent-vault.md) (itself **proposed**), frozen by the [superseding decision](../decisions/supersede-persistent-store-contract.md) after the [design review](../research/persistent-vault-design-review.md). Section numbers written as "spec §n" refer to that specification. Third-party documentation was fetched on 2026-10-01; each claim about a library carries its URL.

## 1. Scope

In scope: how the specification's bytes, contracts, store semantics, key rules, and restore order map to Python; which dependencies are acceptable and how they are isolated; what evidence Python must produce; and the implementation issues to file.

Out of scope: writing any of that code; a Python detector (capture keeps using the Node.js bridge); a Python browser or Worker profile; Rust and Go (§7).

## 2. Current state of the Python package

All statements below were read from the tree on 2026-10-01.

### 2.1 What exists

| Item | Fact | Source |
| --- | --- | --- |
| Distribution | `redact-secret-vault` `0.1.0b3`, import package `redact_secret_vault`, `requires-python = ">=3.10"`, classifier "Development Status :: 3 - Alpha" | [pyproject.toml](../../packages/vault-py/pyproject.toml) |
| Runtime dependencies | None. `[project]` has no `dependencies` key; the only extras are `test` (pytest) and `lint` (ruff). Verified: the source imports only the standard library | [pyproject.toml](../../packages/vault-py/pyproject.toml) |
| Build | hatchling; the wheel carries `boundary/*.mjs` as an artifact | [pyproject.toml](../../packages/vault-py/pyproject.toml) |
| Server | `InMemoryVaultServer`: process-local dictionaries of entries, captures, and tombstones; values are held as `str` | [server.py](../../packages/vault-py/src/redact_secret_vault/server.py) lines 100 to 163 |
| Concurrency model | One operation at a time per instance. A `_busy` flag makes a second call fail `BUSY`; there is no lock, no queue, and no thread safety claim | [server.py](../../packages/vault-py/src/redact_secret_vault/server.py) lines 213 to 254 |
| Sync and async | `capture`, `revoke`, `dispose`, and `stats` are synchronous. `restore` is `async` because the principal resolver and the release policy may return awaitables; the policy is bounded by `asyncio.wait_for` | [server.py](../../packages/vault-py/src/redact_secret_vault/server.py) lines 323, 512, 668, 724 |
| Clock | Injected `now`, or a default that anchors `time.time()` once and then advances with `time.monotonic()`. Every reading is made non-decreasing and truncated to an integer | [server.py](../../packages/vault-py/src/redact_secret_vault/server.py) lines 178 to 199 and 779 to 787 |
| Identifier check | `_is_identifier` accepts a `str` of 1 to 256 **code points** and does not reject lone surrogates | [server.py](../../packages/vault-py/src/redact_secret_vault/server.py) lines 86 to 93 |
| Tenant and session | The tenant of a capture is `CaptureOptions.issued_tenant`, supplied by the caller. No principal is resolved at capture. `RestoreRequest.tenant` may override the principal's tenant. `session_id` is passed to the policy and not enforced. There is no session resolver | [types.py](../../packages/vault-py/src/redact_secret_vault/types.py), [server.py](../../packages/vault-py/src/redact_secret_vault/server.py) lines 583 to 615 |
| Errors | One class, `VaultServerError(code, core_code=, reason=)`, message built from the code, the reason, and the bridge's `core_code` string | [errors.py](../../packages/vault-py/src/redact_secret_vault/errors.py) |
| Exception chaining | Four sites raise `from exc` and therefore set `__cause__`: the clock callback, the `eligible` callback, a failed bridge spawn, and a bridge response that is not JSON | [server.py](../../packages/vault-py/src/redact_secret_vault/server.py) lines 182 and 423; [core_client.py](../../packages/vault-py/src/redact_secret_vault/core_client.py) lines 544 and 575 |
| Audit | `ServerAuditEvent` with four operations (`resolve-principal`, `restore`, `revoke`, `policy-error`). Capture emits no audit event. Hook exceptions are swallowed | [types.py](../../packages/vault-py/src/redact_secret_vault/types.py), [server.py](../../packages/vault-py/src/redact_secret_vault/server.py) lines 203 to 209 |
| Tokens | Same grammar as JavaScript; generated with `secrets.choice` | [token.py](../../packages/vault-py/src/redact_secret_vault/token.py) |
| UTF-16 handling | Helpers that convert the core's UTF-16 code-unit ranges to Python indices, and `utf16_length` | [utf16.py](../../packages/vault-py/src/redact_secret_vault/utf16.py) |
| Capture logic | Scan, action gate, PII allowlist, eligibility, staging, token issue, and output assembly are one method that also writes the dictionaries. There is no separate capture plan. Non-retained `redact` findings become `<SECRET_n>`; there is no `displayFormatter` | [server.py](../../packages/vault-py/src/redact_secret_vault/server.py) lines 333 to 508 |
| Shared corpus | `tests/conformance_runtime.py` loads `conformance/v1/corpus.json` by a path relative to the repository checkout and replays every case in a PII-off and a PII-on lane, under one fixed principal, tenant, and purpose | [conformance_runtime.py](../../packages/vault-py/tests/conformance_runtime.py), [test_conformance.py](../../packages/vault-py/tests/test_conformance.py), [conformance README](../../conformance/README.md) |
| Leak test | Over the corpus replay, asserts no fixture value or token in `repr` and `str` of each error and `repr` of each audit event. It does not inspect `__cause__`, `__context__`, tracebacks, logging, or warnings. One bridge test inspects `__cause__` | [test_conformance.py](../../packages/vault-py/tests/test_conformance.py) lines 66 to 93; [test_bridge_process.py](../../packages/vault-py/tests/test_bridge_process.py) line 176 |
| CI matrix | Python 3.10, 3.12, 3.13 on `ubuntu-latest`, Node.js 22. No macOS or Windows job for Python | [ci.yml](../../.github/workflows/ci.yml) lines 126 to 155 |
| Wheel evidence | The release workflow builds one sdist and one wheel, checks them, installs the wheel in a virtualenv outside the repository, and runs a one-scan smoke test against the pinned core | [release.yml](../../.github/workflows/release.yml) lines 249 to 311; [smoke-python-wheel.py](../../scripts/smoke-python-wheel.py); [verify-python-dist.py](../../scripts/verify-python-dist.py) |

### 2.2 The core bridge

Capture obtains findings from `@redact-secret/core` through `NodeCoreBridge`, which owns one Node.js child process running [core_bridge.mjs](../../packages/vault-py/src/redact_secret_vault/boundary/core_bridge.mjs).

- **What crosses to Node.** The entire capture input, as the `input` field of one newline-delimited ASCII JSON request, with the PII selectors, the policy map, the limits, and optionally the `node_modules` path ([core_client.py](../../packages/vault-py/src/redact_secret_vault/core_client.py) lines 474 to 494). That is every secret in the input, detected or not, not only the retained values.
- **What comes back.** Eight metadata fields per finding, the core version, the artifact kind, and the PII activation identity. No response field can carry a value; the parser rejects any other key ([core_client.py](../../packages/vault-py/src/redact_secret_vault/core_client.py) lines 146 to 177 and 571 to 615).
- **How long plaintext lives in Node.** Until the Node heap collects it or the process exits. One process serves up to `max_scans_per_process` scans (default 10,000), lives up to `max_process_age_s` (default 600 s), and exits after `idle_timeout_s` idle (default 60 s). `max_scans_per_process=1` gives one process per scan ([core_client.py](../../packages/vault-py/src/redact_secret_vault/core_client.py) lines 59 to 68 and 518 to 546).
- **Per process.** A bridge belongs to one Python process. After `os.fork()` the child abandons the inherited handle and starts its own Node process ([core_client.py](../../packages/vault-py/src/redact_secret_vault/core_client.py) lines 318 to 339). A pre-fork WSGI or ASGI server with N workers therefore runs N Node processes, each with its own core realm and its own PII activation, each pinned independently by the first scan in that worker.
- **Blocking and serialized.** `scan` is synchronous, holds a `threading.Lock` for the whole round trip, and waits up to `timeout_s` (default 10 s). Threads sharing a bridge queue behind each other; there is no lock timeout. Called from an event loop, it blocks the loop.
- **Recorded qualification gaps.** The [threat model](../specs/threat-model.md), section "Python core bridge", marks the bridge "research-grade, not qualified" and lists: plaintext lingering in the bridge heap up to the lifetime bounds; a compromised `node` binary or core package; a core replaced on disk being picked up at the next process start; unbounded queuing delay; discarded stderr; and "no dedicated adversarial qualification record, fuzzing, or Windows run".

### 2.3 What persistence leaves unchanged and what it makes worse

| Bridge or runtime property | Effect of persistence |
| --- | --- |
| Whole input crosses to Node and stays in its heap up to the lifetime bounds | **Unchanged.** Encryption at rest does not cover it. It must be stated beside any at-rest claim: a ciphertext-only store does not mean plaintext exists only as ciphertext on the host |
| Bridge returns no value | **Unchanged.** The Python process slices the input it already holds, which is the same rule as the JavaScript capture plan (spec §8.1) |
| Bridge is not qualified | **Unchanged, and now a blocker.** A persistence claim that includes capture inherits the bridge. Gate G5 (§6) is where the bridge is qualified or where the claim is limited to a consumer-supplied `CoreClient` |
| One bridge and one core realm per process | **Worse.** In-memory captures never leave their process, so workers with different PII activations cannot interact. With a shared store, a capture made by one worker is restored by another. The store carries the finding `type` inside the encrypted payload but not the activation identity. A deployment whose workers disagree on activation retains different sets for the same input. The persistent profile must require `expected_pii_activation` on the bridge (it is optional today) so every worker fails closed on a mismatch |
| `scan` blocks and is serialized by a lock | **Worse.** Capture now also performs a key-provider call and a store transaction. With an async server (§3.7) the scan must run in a worker thread, and one bridge is a per-process throughput ceiling for captures |
| Plaintext lifetime in the Python process | **Worse.** Today a retained value is one `str` in a dictionary. With persistence a capture additionally holds the UTF-8 encoding of each value and the encoded payload while it is sealed, and a restore holds the decrypted payload, the decoded grants, and the staged output, including for requests that are then denied (spec §7.2). Values that entered as `str` slices cannot be overwritten (§3.6) |
| Key material in the process | **New.** Wrapping material (local provider), data keys, and entry keys exist in Python memory; the limits on clearing them are in §3.6 |
| Single-operation `_busy` model | **Does not carry over.** The store is the authority across processes; an in-process flag orders nothing. See §3.7 |
| Default clock anchored once, then monotonic | **Worse.** A long-lived process drifts from wall time by whatever NTP corrected since start. With a store clock and a skew bound (spec §7.5) that drift becomes `clock-skew` rejections. The persistent profile needs a different default (§3.8) |
| Identifier limits in code points; lone surrogates accepted | **Incompatible** with the record format. See §3.5 |
| Caller-supplied `issued_tenant`; restore-side `tenant` override; advisory `session_id` | **Incompatible** with spec §8.2 and §8.3. The persistent profile takes tenant and session only from resolvers |
| `raise ... from exc` | **Incompatible** with spec §4.1 for the new error classes. See §3.4 |

## 3. Native Python contracts (proposed)

Module names are those of §4. Field names are the specification's names in `snake_case`; the mapping is mechanical and is itself tested (gate G3 serializes every result to the specification's JSON names).

### 3.1 General rules

| TypeScript | Python |
| --- | --- |
| `interface` of data | `@dataclass(frozen=True, slots=True)` |
| `interface` of behavior (`Store`, `KeyProvider`, `RecordCrypto`) | `typing.Protocol` with `async def` methods |
| Discriminated union | One frozen dataclass per variant, each with a `Literal` discriminator field (`outcome`, or `state` for `InspectAttemptResult`), and a `Union` alias. Callers branch on the field or with `match` |
| String-literal union | `typing.Literal[...]`, not `Enum`: the values are wire vocabulary shared with the schedule corpus |
| `Uint8Array` | `bytes` for anything stored or sent (envelopes, wrapped keys, digests); `bytearray` for anything secret (data keys, decrypted values). Never `str` |
| `string` | `str`, validated at the boundary (§3.5) |
| `number` | `int`. `bool` and `float` are rejected with `type(x) is int`, because `True == 1` and `1.0 == 1` in Python |
| `readonly T[]` | `tuple[T, ...]` |
| `T \| null` | `T \| None` |
| `options?: { signal?: AbortSignal }` | Omitted. Cancellation is task cancellation; deadlines are the caller's (§3.7) |
| `Promise<T>` | Coroutine returning `T` |

### 3.2 Data types and `Store`

```python
# redact_secret_vault/persistent/contracts.py  (standard library only)
from __future__ import annotations
from dataclasses import dataclass
from typing import Literal, Protocol, Union, runtime_checkable

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

@dataclass(frozen=True, slots=True)
class NewEntry:
    entry_id: str
    max_uses: int
    envelope: bytes

@dataclass(frozen=True, slots=True)
class NewCapture:                      # TS: StoredKey & { captureId, sessionTag, ... }
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

CreateCaptureResult = Union[CaptureCreated, CaptureRejected]

@dataclass(frozen=True, slots=True)
class StoredEntry:
    entry_id: str
    capture_id: str
    max_uses: int
    used: int
    lifecycle_revision: int
    ciphertext_revision: int
    envelope: bytes

@dataclass(frozen=True, slots=True)
class StoredCapture:
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
    epoch: int
    state: Literal["uninitialized", "serving", "quarantined"]

@dataclass(frozen=True, slots=True)
class ReadEntriesInput:
    scope: StoreScope
    entry_ids: tuple[str, ...]

@dataclass(frozen=True, slots=True)
class ReadEntriesResult:
    recovery: RecoveryState
    entries: tuple[StoredEntry, ...]
    captures: tuple[StoredCapture, ...]

@dataclass(frozen=True, slots=True)
class Attempt:
    attempt_id: str
    request_digest: bytes              # exactly 32 bytes

@dataclass(frozen=True, slots=True)
class CaptureGeneration:
    capture_id: str
    generation: int

@dataclass(frozen=True, slots=True)
class EntryUse:
    entry_id: str
    capture_id: str
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
    captures: tuple[CaptureGeneration, ...]
    uses: tuple[EntryUse, ...]

CommitRejection = Literal[
    "revoked", "expired", "budget", "stale", "unknown", "clock-skew", "quarantined"
]

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

CommitRestoreResult = Union[
    RestoreCommitted, RestoreAlreadyCommitted, RestoreAttemptMismatch, RestoreRejected
]

# RevokeCaptureInput/Result, InspectAttemptInput/Result, ReplaceCaptureKeyInput/Result,
# DeleteCiphertextInput/Result, SweepInput/Result, InitializeNamespaceResult,
# InvalidateRecoveredInput/Result follow the same pattern, one class per variant,
# from spec §5.6 to §5.8. InspectAttemptResult discriminates on `state`.

@runtime_checkable
class Store(Protocol):
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
```

`runtime_checkable` verifies that the methods exist, nothing more. As in spec §2, an injected implementation runs in the trusted process and a `Protocol` does not contain it.

Frozen dataclasses do not validate. Validation is a set of functions mirroring [validate.ts](../../packages/vault-contracts/src/validate.ts) (`validate_create_capture`, `validate_commit_restore`, and so on, plus `missing_capabilities`), called by every store before any write and raising `StoreError("STORE_INVALID_ARGUMENT")`. Limits are a module of constants equal to [limits.ts](../../packages/vault-contracts/src/limits.ts); a test compares the two files value by value.

### 3.3 `KeyProvider` and `RecordCrypto`

```python
@dataclass(frozen=True, slots=True)
class KeyContext:
    namespace: str
    tenant: str
    capture_id: str

@dataclass(frozen=True, slots=True)
class StoredKey:
    key_ref: str
    wrapped_key: bytes

@dataclass(frozen=True, slots=True)
class DataKey:
    key_ref: str
    wrapped_key: bytes
    plaintext_key: bytearray           # 32 bytes; the caller overwrites it after use

@runtime_checkable
class KeyProvider(Protocol):
    @property
    def profile(self) -> str: ...
    async def generate_data_key(self, context: KeyContext) -> DataKey: ...
    async def unwrap_data_key(self, stored: StoredKey, context: KeyContext) -> bytearray: ...
    async def rewrap_data_key(self, stored: StoredKey, context: KeyContext) -> StoredKey: ...

@dataclass(frozen=True, slots=True)
class RecordBinding:
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

@dataclass(frozen=True, slots=True)
class RecordPayload:
    value: bytearray                   # UTF-8; decoded only when about to be returned
    type: str
    grants: tuple[Grant, ...]
    policy_revision: str | None

@dataclass(frozen=True, slots=True)
class SealedCapture:
    key_ref: str
    wrapped_key: bytes
    envelopes: tuple[bytes, ...]       # in the order of the records

@runtime_checkable
class RecordCrypto(Protocol):
    @property
    def profile(self) -> str: ...
    async def seal_capture(
        self, context: KeyContext, records: tuple[tuple[RecordBinding, RecordPayload], ...]
    ) -> SealedCapture: ...
    async def open_capture(
        self, stored: StoredKey, context: KeyContext,
        records: tuple[tuple[RecordBinding, bytes], ...],
    ) -> tuple[RecordPayload, ...]: ...           # all, or an error; never partial
    async def rewrap_capture_key(self, stored: StoredKey, context: KeyContext) -> StoredKey: ...
```

`StoredKey & { context }` becomes two parameters because Python has no intersection type; the information is the same.

### 3.4 Errors

```python
# redact_secret_vault/persistent/errors.py
StoreErrorCode = Literal[
    "STORE_UNAVAILABLE", "STORE_AMBIGUOUS", "STORE_INVALID_ARGUMENT",
    "STORE_CAPABILITY", "STORE_CLOSED",
]

class StoreError(Exception):
    __slots__ = ("code",)
    def __init__(self, code: StoreErrorCode) -> None:
        self.code = code
        super().__init__(_STORE_MESSAGES[code])    # KeyError for an unknown code

class KeyProviderError(Exception): ...             # KEY_UNAVAILABLE, KEY_INTEGRITY, KEY_TIMEOUT,
                                                   # KEY_THROTTLED, KEY_ABORTED, KEY_INVALID_ARGUMENT
class RecordCryptoError(Exception): ...            # RECORD_MALFORMED, RECORD_UNSUPPORTED,
                                                   # RECORD_INTEGRITY, RECORD_LIMIT, RECORD_INVALID_ARGUMENT
```

- **Messages** are the fixed strings of [errors.ts](../../packages/vault-contracts/src/errors.ts), one per code, copied verbatim. A test parses that file and compares.
- **No cause.** JavaScript's rule is "`cause` is never set". Python has two links, and `raise X from None` clears only one of them: it sets `__cause__` to `None` and `__suppress_context__` to `True`, but `__context__` still references the exception being handled. A driver exception, `cryptography.exceptions.InvalidTag`, or a `UnicodeEncodeError` (whose `object` attribute is the whole offending string) would stay reachable from the sanitized error. The rule for the new modules is therefore stricter than `from None`:

  ```python
  failed = False
  try:
      plaintext_len = aead.decrypt_into(nonce, ciphertext, aad, buffer)
  except Exception:
      failed = True                    # nothing is bound; the except block ends here
  if failed:
      raise RecordCryptoError("RECORD_INTEGRITY")   # __cause__ and __context__ are both None
  ```

  The sanitized error is raised after the `except` block has exited, so neither link is set. Gate G6 asserts `__cause__ is None and __context__ is None` on every error the persistent modules raise.
- **Tracebacks.** A Python traceback references frame objects, and a frame keeps its local variables. An error raised deep in the crypto layer would carry frames whose locals hold keys and plaintext, and error reporters commonly serialize frame locals. Each public entry point (`seal_capture`, `open_capture`, each store and provider method, each server method) therefore catches its own sanitized errors and re-raises a new instance from its own frame, after overwriting or deleting its secret locals. The traceback a caller receives then starts at the entry point. Gate G6 walks `__traceback__` and inspects every frame's locals.
- **Existing class.** `VaultServerError` keeps its shape. The persistent profile adds the codes of spec §8.3 to it (`UNSUPPORTED_STORE`, `STORE_UNAVAILABLE`, `STORE_QUARANTINED`, `COMMIT_AMBIGUOUS`, `RESTORE_CONFLICT`, `CLOCK_SKEW`, `LIFECYCLE_DENIED`, `CLOSED`) and the denial reasons (`integrity-failure`, `key-unavailable`, `attempt-mismatch`, `attempt-already-committed`). The four existing `from exc` sites are outside the persistent modules; whether they change is an open question (§9).
- **`BaseException`.** `asyncio.CancelledError`, `KeyboardInterrupt`, and `SystemExit` are not `Exception`. They are never converted to a sanitized error and never swallowed; §3.7 says what the server does about them around a commit.

### 3.5 Strings

Python `str` is a sequence of code points; the specification counts UTF-16 code units and forbids lone surrogates (spec §3.1, §3.2, §3.6).

| Rule in the specification | Python semantics | Neutralization |
| --- | --- | --- |
| Identifier of 1 to 256 UTF-16 code units | `len(s)` counts code points: a supplementary character is 1 in Python and 2 in JavaScript | Count with `sum(2 if ord(c) > 0xFFFF else 1 for c in s)`, which is the existing `utf16_length` in [utf16.py](../../packages/vault-py/src/redact_secret_vault/utf16.py). A 200-character identifier of supplementary characters is 400 units and must be rejected; the vectors need that case |
| Well-formed: no lone surrogate; never encode with U+FFFD substitution | A `str` can hold lone surrogates (for example from `json.loads('"\\ud83d"')`, which accepts them). `s.encode("utf-8")` in strict mode raises `UnicodeEncodeError` rather than substituting | Test first: `any(0xD800 <= ord(c) <= 0xDFFF for c in s)`. Then encode with `errors="strict"` only; `"replace"`, `"ignore"`, `"surrogatepass"`, and `"surrogateescape"` are banned in the persistent modules by a lint rule. The explicit test exists so the failure is a fixed error and not a `UnicodeEncodeError` carrying the string |
| No normalization; equality is byte equality | `str ==` compares code points; no implicit normalization | Never call `unicodedata.normalize` on an identifier. The vectors include an NFC and an NFD spelling of one tenant that must produce different `entryId`s |
| "Ascending byte order" of UTF-8 | For well-formed strings, code-point order and UTF-8 byte order are the same order, so plain `sorted()` happens to agree. JavaScript's default sort (UTF-16 code units) is the one that differs | Sort with `sorted(items, key=lambda s: s.encode("utf-8"))` anyway, so the code states the specification's rule and does not depend on the coincidence. The decoder checks strict ascending order on the encoded bytes and rejects equal neighbours |
| Byte limits (`type`, `policyRevision`, `purpose`, `keyRef`) | `len(s)` is not bytes | Measure `len(s.encode("utf-8"))` |
| `namespace`, `attemptId`, `captureId`, `entryId`, `sessionTag` patterns | `re` `$` matches before a trailing newline; `\d` and `[a-z]` with `re.IGNORECASE` or Unicode classes can match non-ASCII | `re.fullmatch` with explicit ASCII classes and no flags, for example `re.fullmatch(r"[0-9a-f]{64}", s)` |
| Hex output | `bytes.hex()` is lowercase | Use it; never `binascii.hexlify(...).upper()` |

### 3.6 Integers, bytes, and overwriting

- **Integers.** Python `int` is unbounded; JavaScript numbers are safe to `2^53 − 1`. Every timestamp, epoch, revision, count, and limit is checked `type(x) is int and 0 <= x <= 2**53 - 1` (lower bound 1 where the specification says positive) before use and before encoding with `int.to_bytes(8, "big")`. Values read back from a database are checked the same way: a `bigint` column can hold more than `2^53 − 1`, and a value JavaScript cannot represent is a `STORE_AMBIGUOUS`-class integrity problem, not something to pass on. `u16` and `u32` fields are range-checked before `to_bytes`, which would otherwise raise `OverflowError`.
- **Timestamps.** Integer milliseconds. `datetime` and `float` are not accepted at any contract boundary.
- **What "overwrite the buffer" can mean.** `bytes` and `str` are immutable; there is no supported way to clear them. The `cryptography` documentation says the same of itself: it "does not clear memory by default, as there is no way to clear immutable structures such as bytes" (<https://cryptography.io/en/latest/limitations/>). What Python can do:
  - Hold data keys, entry keys, and decrypted values in `bytearray` and overwrite them in a `finally` block (`buf[:] = bytes(len(buf))`).
  - Write primitives' output directly into such a buffer. `cryptography` 47.0.0 added `AESGCM.decrypt_into` and `encrypt_into` (<https://cryptography.io/en/latest/hazmat/primitives/aead/>) and `HKDF.derive_into` (<https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/>). With them the entry key and the decrypted payload never exist as immutable `bytes`. This is the reason for the version floor in §4.1.
  - Parse the decrypted payload through a `memoryview` of that `bytearray`, copy `value` into its own `bytearray`, and release the view before overwriting.
- **What it cannot mean.** `AESGCM(key)` copies the key into the backing library's own context, which Python cannot clear. The key provider's SDK may have held the key as `bytes` first (boto3 returns `Plaintext` as `bytes`). A value that is returned to the caller becomes a `str`, and the captured values began as `str` slices of the input. The garbage collector may have moved or copied nothing (CPython does not move objects), but freed memory is not zeroed. As in spec §6.2: stated, not solved. Gate G6 tests only what is claimed, namely that buffers this package owns are zero after each call, on success and on every failure path.
- **Decoding the value.** `bytes(value).decode("utf-8", "strict")` only in restore step 8 (spec §7.2). A stored value that is not valid UTF-8 is `RECORD_MALFORMED`.

### 3.7 Sync or async

**Proposal: the three protocols and the persistent server are `async` only.** `capture`, `restore`, `revoke`, `delete_capture_ciphertext`, `resolve_attempt`, and `close` are all coroutines.

Reasons:

1. `restore` is already a coroutine and already awaits application callbacks ([server.py](../../packages/vault-py/src/redact_secret_vault/server.py) line 512). The persistent restore adds a resolver, a lifecycle policy, a key provider, and a store, each with a deadline (spec §6.1, §7.2, §8.2). One model for all of them is less surface than a mix.
2. The specification gives every call a timeout and every operation a total deadline. With coroutines that is `asyncio.wait_for` (or `asyncio.timeout` on 3.11 and later). A synchronous call into a driver can be bounded only by the driver's own timeouts or by abandoning a thread that keeps running.
3. One surface is one qualification. A synchronous twin of each protocol would double the store conformance run, the two-process schedules, and the leak tests.

How the synchronous parts fit:

- `NodeCoreBridge.scan` stays synchronous. The persistent server calls it with `asyncio.to_thread`, so the event loop is not blocked. The bridge's own lock still serializes scans.
- AES-GCM and HKDF calls are synchronous CPU work and are called inline. A capture is bounded at `maxCreateBytes`; whether sealing a maximum-size capture needs a thread is a measurement for issue 4, not an assumption.
- boto3 is synchronous. The AWS KMS provider wraps each call in `asyncio.to_thread` with a client-level timeout.
- psycopg 3 has a native `AsyncConnection` (<https://www.psycopg.org/psycopg3/docs/advanced/async.html>).

What a synchronous API would cost instead: no cancellation at all (simpler ambiguity rules, since a call either returns or raises), natural use from WSGI, and no thread hop for the bridge or boto3; against that, one blocked thread per in-flight restore, timeouts that depend on each driver, and awaitable resolvers and policies would have to be dropped or run through a private event loop. A deployment on WSGI can call the async API through one long-lived event-loop thread per process; `asyncio.run` per request is not acceptable because a connection pool is bound to its loop. That cost falls on WSGI users and is the main argument against this proposal.

**Cancellation.** JavaScript passes an `AbortSignal`, which a callee observes cooperatively. Python cancels a task by raising `asyncio.CancelledError` at whatever `await` it is suspended in, including inside a driver in the middle of `COMMIT`. psycopg's documentation says "cancelling the Python Task does not guarantee that the operation will not complete" (<https://www.psycopg.org/psycopg3/docs/advanced/async.html>). Rules:

- The server runs `store.commit_restore` and `store.create_capture` in an inner task under `asyncio.shield`. If the caller's task is cancelled while that task runs, the server discards the staged output, overwrites its buffers, lets the inner task finish under its own timeout so the connection is returned in a known state, and re-raises `CancelledError`. No fields are returned. The attempt is resolved later with `resolve_attempt`, exactly as after `COMMIT_AMBIGUOUS` (spec §7.3).
- A timeout the server itself applies to a mutating store call is reported as `COMMIT_AMBIGUOUS` (restore) or as a failed capture followed by one `revoke_capture(fence_absent=True)` (spec §8.2), never as `STORE_UNAVAILABLE`.
- An adapter that sees `CancelledError` inside a mutating statement does not convert it; it must leave the connection unusable (closed or discarded), because its transaction state is unknown.
- `KEY_ABORTED` is raised by a provider only for a cancellation it initiated itself (its own timeout uses `KEY_TIMEOUT`). Task cancellation propagates as `CancelledError` and the server treats it as failure.

**"Atomic in-process section."** The JavaScript reference store can rely on run-to-completion between `await`s. In Python that holds only among tasks of one event loop. It does not hold across threads, across event loops in one process, or on a free-threaded build (the `cryptography` 50.0.2 release ships `cp314t` wheels, <https://pypi.org/project/cryptography/#files>, so such interpreters are in use). The Python reference store therefore holds a `threading.Lock` for the whole of each operation and performs no `await` while holding it. The lock is what the store relies on, not the GIL. It still declares `cross_process=False` and `durability="volatile"`; a lock in one process orders nothing between processes, and no test of it counts toward the two-process gate.

The persistent server keeps no in-process ordering of its own. The `_busy` flag of the in-memory server is not reused: concurrent restores on one instance are allowed and are ordered by the store.

### 3.8 Clocks

- **Record time** (`created_at`, `expires_at`, `now` sent to the store) is wall time: the application-supplied `now`, default `time.time_ns() // 1_000_000`, made non-decreasing within the process by keeping the maximum seen, as spec §7.5 requires. The in-memory server's default (wall time sampled once, then advanced by the monotonic clock) is not used here: it never follows a clock correction, so a long-lived process would drift toward `clock-skew`.
- **Deadlines** (provider timeout, policy timeout, total operation deadline, bridge watchdog) use `time.monotonic()`, which "cannot go backwards" and "is not affected by system clock updates", with an undefined reference point (<https://docs.python.org/3/library/time.html>). A monotonic reading is never written to a record or compared with a timestamp from another process.
- A `now` callback that returns a `float` is floored; `bool`, NaN, infinities, negatives, and values above `2^53 − 1` are `INVALID_ARGUMENT`.

### 3.9 Standard library and third-party primitives

| Need (spec section) | Standard library | Decision |
| --- | --- | --- |
| SHA-256 for `entryId` (§3.2) | `hashlib.sha256`, a guaranteed algorithm (<https://docs.python.org/3/library/hashlib.html>) | Standard library |
| HMAC-SHA-256 for the session tag and request digest (§3.2, §7.3) | `hmac.digest(key, msg, "sha256")`; `hmac.compare_digest` for comparison in constant time (<https://docs.python.org/3/library/hmac.html>) | Standard library |
| CSPRNG for nonces, tokens, capture identifiers (§3.3) | `secrets.token_bytes`, from "the most secure source of randomness that your operating system provides" (<https://docs.python.org/3/library/secrets.html>) | Standard library |
| HKDF-SHA-256 for entry keys and local wrapping keys (§3.3, §6.3) | Not provided. `hashlib` documents only `pbkdf2_hmac` and `scrypt` as key derivation; `hmac` does not mention HKDF | `cryptography`'s `HKDF` with explicit `salt=bytes(32)`. HKDF could be written over `hmac` in a few lines, but it is needed only where AES-GCM is, so nothing is gained by hand-writing it |
| AES-256-GCM (§3.3) | Not provided. The standard library's cryptographic services are `hashlib`, `hmac`, and `secrets` only (<https://docs.python.org/3/library/crypto.html>) | `cryptography`'s `AESGCM`: tag of 16 bytes appended to the ciphertext, `InvalidTag` on authentication failure (<https://cryptography.io/en/latest/hazmat/primitives/aead/>). That layout equals the specification's `ciphertext \|\| tag` |

Consequence: the contracts, the canonical encoders for `entryId`, the AAD, the payload, the envelope framing, the session tag, and the request digest, the reference store, and the persistent server need only the standard library. Only the module that seals and opens, and the local key provider, need `cryptography`. This matches the JavaScript split, where `vault-server` depends on the contracts and the crypto layer is injected (spec §2).

## 4. Dependency isolation (proposed)

### 4.1 Layout

**Recommendation: one distribution, `redact-secret-vault`, with extras.** The base install stays free of runtime dependencies.

| Import path | Contents | Imports beyond the standard library | Installed by |
| --- | --- | --- | --- |
| `redact_secret_vault` | Today's package, unchanged | None | base |
| `redact_secret_vault.persistent` | Contracts, errors, limits, validators, canonical encoding, digests, the persistent server profile | None | base |
| `redact_secret_vault.persistent.store_memory` | Volatile reference store | None | base |
| `redact_secret_vault.crypto` | `RecordCrypto` over a `KeyProvider`; local key provider | `cryptography` | `redact-secret-vault[crypto]` |
| `redact_secret_vault.stores.postgres` | PostgreSQL adapter | `psycopg` | `redact-secret-vault[postgres]` |
| `redact_secret_vault.keys.aws_kms` | AWS KMS key provider | `boto3` | `redact-secret-vault[aws-kms]` |

```toml
[project.optional-dependencies]
crypto   = ["cryptography>=47"]
postgres = ["psycopg>=3.2,<4"]
aws-kms  = ["boto3>=1.43"]
```

The bounds above are starting points; the qualification record pins the exact versions tested. Facts behind them, from PyPI on 2026-10-01:

- `cryptography` 50.0.2 (uploaded 2026-09-30), `requires_python` `>=3.9` excluding 3.9.0 and 3.9.1, with `abi3` wheels for CPython 3.9+ and 3.11+, free-threaded 3.14 wheels, and PyPy 3.11 wheels (<https://pypi.org/project/cryptography/>). Wheels are statically linked for macOS arm64, Windows x86-64, and manylinux and musllinux on x86-64, aarch64, armv7l, and ppc64le; building from source needs Rust 1.83.0 or later (<https://cryptography.io/en/latest/installation/>). The floor of 47 is for the `_into` APIs (§3.6). It depends on `cffi` (and `typing-extensions` below Python 3.11), so the `[crypto]` extra brings in more than one distribution.
- `psycopg` 3.3.6 (uploaded 2026-09-18), `requires_python >=3.10`; its documentation states support for Python 3.10 to 3.15 and PostgreSQL 10 to 18, and that the pure-Python install needs the system `libpq` (<https://www.psycopg.org/psycopg3/docs/basic/install.html>). The extra names plain `psycopg`; whether the consumer adds `psycopg[binary]` or `psycopg[c]` is the consumer's packaging decision, and the qualification record states which one was tested.
- `boto3` 1.43.106 (uploaded 2026-09-30), `requires_python >=3.10` (<https://pypi.org/project/boto3/>).

**Why psycopg 3.** It offers synchronous and asynchronous connections over `libpq`; it reports failures with SQLSTATE-specific exception classes, which the adapter needs to tell a serialization failure or deadlock (`stale`, spec §5.2) from a lost connection (`STORE_AMBIGUOUS`); and its documented Python range covers this package's. Its documentation also states the two properties the adapter must respect: connections are thread-safe but "not process-safe", and an `AsyncConnection` used by several tasks serializes them on one session (<https://www.psycopg.org/psycopg3/docs/advanced/async.html>). `asyncpg` was not chosen: it implements the protocol itself rather than through `libpq`, and has no synchronous mode should §3.7 be reversed. This is a design choice, not a measured comparison.

**Connection ownership.** The application creates and owns the pool or connection factory and passes it in, as with `pg` in JavaScript (issue #20). The adapter accepts an object with an async context manager that yields a `psycopg.AsyncConnection` (a `psycopg_pool.AsyncConnectionPool` satisfies this; `psycopg-pool` is not a dependency of the extra). The adapter never opens a connection from a URL or the environment, never closes the pool, sets its own transaction settings per transaction and restores nothing it did not set, and must be constructed after `fork`.

**AWS KMS.** The application passes a KMS client. boto3 documents that clients are thread-safe but "cannot be shared across processes", and that the default-session shortcut should not be invoked in a concurrent context (<https://docs.aws.amazon.com/boto3/latest/guide/clients.html>). The provider therefore never creates a client and never reads credentials or region itself, consistent with spec §6.1.

**Same distribution or separate distributions.**

| | One distribution with extras (recommended) | Separate distributions (`redact-secret-vault-postgres`, ...) |
| --- | --- | --- |
| Releases to qualify | One, through the existing PyPI job in [release.yml](../../.github/workflows/release.yml) | One per distribution, each needing its own trusted-publisher setup |
| Version skew between contracts and adapter | Impossible | Possible; needs a compatibility range and tests at both ends |
| Adapter code present without its dependency | Yes: the module is in the wheel and raises `ImportError` on import | No |
| Independent support status per adapter | By documentation only: one version number covers a qualified and an unqualified module | By version and classifier |
| Matches the JavaScript split | No | Yes |
| Consistent with the 2026-09-28 naming note ("Python has one distribution") in [the naming decision](../decisions/name-vault-packages-and-language-contract.md) | Yes | Needs a new naming decision |

The recommendation is one distribution because the contracts and adapters are developed and qualified together here, and version skew between them is a failure mode with no benefit at this stage. The cost is that support status must be stated per module, and a fix to one adapter releases everything. Split a module into its own distribution when it needs a different release cadence or when a second backend of the same kind exists.

Never in any module: detector rules, overlap logic, or policy tables. Capture goes through `CoreClient`, and the default `CoreClient` is the bridge.

### 4.2 Import-isolation evidence

The JavaScript rule is "checked on packed artifacts" (spec §2). The Python equivalent:

1. **Metadata.** Extend [verify-python-dist.py](../../scripts/verify-python-dist.py): the wheel's `METADATA` has no `Requires-Dist` line without an `extra ==` marker.
2. **Base install, no extras.** In a clean virtualenv with only the wheel: `import redact_secret_vault`, `import redact_secret_vault.persistent`, and `import redact_secret_vault.persistent.store_memory` succeed; `pip list` shows no third-party distribution other than `pip` itself.
3. **All extras installed.** In a clean virtualenv with `redact-secret-vault[crypto,postgres,aws-kms]`, so the modules are importable and their absence from `sys.modules` proves they were not imported:

   ```python
   import subprocess, sys
   PROBE = (
       "import sys, redact_secret_vault, redact_secret_vault.persistent, "
       "redact_secret_vault.persistent.store_memory\n"
       "banned = {'cryptography', 'cffi', '_cffi_backend', 'psycopg', 'psycopg_pool', "
       "'psycopg_binary', 'psycopg_c', 'boto3', 'botocore', 's3transfer', 'jmespath'}\n"
       "hit = sorted(m for m in sys.modules if m.split('.')[0] in banned)\n"
       "assert not hit, hit\n"
   )
   def test_base_imports_no_optional_dependency():
       subprocess.run([sys.executable, "-I", "-c", PROBE], check=True)
   ```

   A subprocess is required: in the test process, another test may already have imported the libraries.
4. **Per-extra isolation.** The same probe after `import redact_secret_vault.crypto` allows `cryptography` and `cffi` and still bans the psycopg and boto families; likewise for the other two modules.
5. **Missing extra.** Importing `redact_secret_vault.crypto` without `cryptography` installed raises `ImportError` naming the extra. Nothing falls back to another implementation.

## 5. Shared wire vectors

### 5.1 State at the time of writing

`conformance/persistent/v1/` does not exist in this tree (commit `f0a3636`). Neither `vectors.json` nor `verify_vectors.py` was present when this plan was written; the JavaScript crypto work (#106) produces the vectors. If a `verify_vectors.py` arrives with them, the first step of issue 2 below is to read what it checks and either adopt it as the standard-library half of the Python obligations or replace it; this plan makes no statement about its content.

Existing evidence relevant to vectors: none. The current Python tests cover the in-memory corpus only (§2.1).

### 5.2 How Python consumes the file

- The test reads the file from a path given by an environment variable (proposed `RSV_PERSISTENT_VECTORS`), defaulting to the repository location. The wheel does not ship the vectors, and the packed-wheel gate (G8) runs from a directory outside the checkout, so a path relative to the test file, as [conformance_runtime.py](../../packages/vault-py/tests/conformance_runtime.py) uses today, is not enough.
- The loader checks the file's `version` and fails on an unknown major version. It asserts a minimum case count per group, as [test_conformance.py](../../packages/vault-py/tests/test_conformance.py) does for the corpus, so a truncated file cannot pass.
- `json.loads` accepts lone surrogates and returns Python `int` for integers of any size and `float` for `1.0`. The loader therefore passes vector inputs through the same boundary validation as any other input; a negative vector with a lone surrogate must reach the implementation as one.
- Bytes are expected as lowercase hexadecimal strings. If the produced file uses another encoding, the loader follows the file.

### 5.3 Obligations by group

Groups are those of spec §3.8. "Reproduce" means byte-for-byte equality with the expected output in the file.

| Group | Python computes | Needs `cryptography` | Negative cases to reject, and the error |
| --- | --- | --- | --- |
| `entryId` (§3.2) | SHA-256 over the labelled, length-prefixed input; lowercase hex | No | Lone surrogate, over-length namespace or tenant (in UTF-16 units), malformed token: `RECORD_INVALID_ARGUMENT` or the store or server equivalent the file names |
| Entry-key HKDF (§3.3) | 32 bytes from DEK, zero salt, and `info` | Yes | Wrong DEK length; unknown algorithm byte: `RECORD_UNSUPPORTED` |
| AAD (§3.4) | The byte string, including `sessionBound` 0 with empty `sessionId`, and timestamps at `0` and `2^53 − 1` | No | Non-integer or out-of-range timestamp, `maxUses` out of range: `RECORD_INVALID_ARGUMENT` |
| Payload (§3.5) | Encode, and decode back to the same structure | No | Unsorted or duplicate sinks or paths, `grantCount` 0 or over 64, `pathCount` 0 or over 256, presence flag 0 with a non-empty field, trailing bytes, length past the end, unknown `payloadVersion`: `RECORD_MALFORMED`, `RECORD_UNSUPPORTED`, or `RECORD_LIMIT` as the file states |
| Envelope (§3.5) | With the file's fixed DEK and nonce, the exact envelope; and open the file's envelope to the file's payload | Yes | Wrong magic, unknown format version or algorithm, truncated nonce, flipped bit in ciphertext, tag, or any AAD field, envelope swapped between entries, captures, tenants, or sessions: `RECORD_MALFORMED`, `RECORD_UNSUPPORTED`, `RECORD_INTEGRITY` |
| Request digest (§7.3) | HMAC-SHA-256 and the unkeyed SHA-256 variant; captures, entries, and paths sorted by UTF-8 bytes, including the supplementary-character ordering case | No | Over-length purpose, more captures than the limit |
| Session tag (§3.2) | HMAC-SHA-256, lowercase hex | No | Lone surrogate in `sessionId` |
| Local provider wrapped key (§6.3) | With fixed material, context, DEK, and nonce: the wrapping key and `0x01 \|\| nonce \|\| ciphertext \|\| tag`; unwrap the file's wrapped key | Yes | Different context: `KEY_INTEGRITY`; unknown or retired `keyRef`, context out of scope: `KEY_UNAVAILABLE`; unknown wrap version byte, wrong length: `KEY_INTEGRITY` or `KEY_INVALID_ARGUMENT` as the file states |

A fixed nonce is used only by the vector tests. The production seal path takes no nonce parameter; the test reaches a private function, and a separate test asserts that the public API has no way to supply one. The deterministic provider used for vectors lives in the test tree, not in the installed package, and refuses to construct without the same acknowledgement string as the JavaScript one (spec §6.3).

Every negative case must fail with exactly the mapped error code, raise no other exception type, and leave `__cause__` and `__context__` unset.

### 5.4 Bidirectional interoperation

Vectors prove that two implementations agree on fixed inputs. They do not prove that a record one produced in normal operation is usable by the other. The interop test does, through a real shared store:

1. One PostgreSQL database, initialized once with the schema owned by the JavaScript adapter (#20). The Python adapter creates no table of its own.
2. Both sides are given the same local key material, digest key, namespace, and recovery epoch.
3. **JS seals, Python opens.** A JavaScript persistent server captures a synthetic input. A Python persistent server, in its own process, restores the returned tokens into a granted field, and the restored fields equal the original values.
4. **Python seals, JS opens.** The reverse.
5. **Lifecycle across languages.** A capture made by one is revoked by the other and then denied `revoked` by both; a restore committed by one is reported `attempt-already-committed` to the other for the same attempt and request, and `attempt-mismatch` for a changed request (which also proves the request digests agree outside the vectors); a session-bound capture made by one is denied `source` by the other under a different session and restored under the same one (session tags agree); an exhausted budget is `budget` for both.
6. **Negative.** With a different digest key on one side, the session-bound restore is denied `source`; with different key material, the restore is denied `key-unavailable` or `integrity-failure` and nothing is consumed.

This test lives with the driver protocol of §6.3, so the same schedules can assign any actor to either language.

Evidence that exists today for this: none. Evidence to produce: the vector run on each matrix cell (G1), and the interop run recorded with both sides' exact versions (G2).

## 6. Qualification gates

No Python persistence claim is made until every gate has a recorded pass against the packed wheel. Gates come from issue #115, issue #110, and the epic's completion gate. "Real backend" means a PostgreSQL server in a named deployment profile, not the in-process reference store.

| Gate | Requirement | Evidence exists today | Evidence to produce |
| --- | --- | --- | --- |
| G1 Vectors | §5.3 in full | None | Vector test output per matrix cell |
| G2 Interop | §5.4 | None | Run record naming JS and Python versions, driver, PostgreSQL version |
| G3 Store conformance | The language-neutral schedule corpus (§6.3) passes against the Python reference store and the Python PostgreSQL adapter | None | Per-adapter run; a declared capability for every case skipped |
| G4 Two-process | §6.1 | None | Run record with process identifiers and topology |
| G5 PII and capture parity | §6.2 | In-memory only: corpus replay in two PII lanes ([test_conformance.py](../../packages/vault-py/tests/test_conformance.py)) | Persistent-profile parity run; bridge qualification record |
| G6 Diagnostics | §6.4 | Partial: `repr` and `str` of errors and audit events over the in-memory corpus | Full leak run over the persistent paths |
| G7 Mutation controls | §6.5 | None | Table of mutants and the test that failed for each |
| G8 Packed wheel | §6.6 | Base wheel smoke test only ([smoke-python-wheel.py](../../scripts/smoke-python-wheel.py)) | Clean-virtualenv runs per extra |
| G9 Matrix | §6.7 | CI: Python 3.10, 3.12, 3.13 on Linux, in-memory only ([ci.yml](../../.github/workflows/ci.yml)) | One record listing every cell and its result |

### 6.1 Two-process transaction, revoke, and receipt cases

Each case uses at least two operating-system processes, each with its own interpreter, bridge, and connection pool, against one database. Threads or tasks in one process do not count.

- **Revoke against restore (spec §5.2 schedule 1).** Process A reads the entries. Process B commits `revoke_capture`. A calls `commit_restore` with the generation it read. A must not get `committed`. Run in both forms: B commits before A's commit starts; and B's transaction is held open on its connection across A's commit attempt, then committed.
- **Quarantine against create (spec §5.2 schedule 2).** A's `create_capture` has passed its recovery check; B commits `quarantine` (and, separately, `invalidate_recovered`); A must not get `created`.
- **Budget.** 100 concurrent restores of one entry with `max_uses = N` from two or more processes: exactly N occurrences commit; every other attempt is `budget` or `RESTORE_CONFLICT`; `used` equals N.
- **Whole-request atomicity.** A restore naming several entries where one fails at commit changes no `used` and writes no receipt.
- **Receipts.** The same attempt and request submitted by A and B concurrently: exactly one `committed`, the other `already-committed` with no fields. The same attempt with a different request: `attempt-mismatch`. After a simulated ambiguous commit (connection dropped after the server-side commit and before the acknowledgement), `resolve_attempt` from the other process returns `committed`, and a new attempt for a single-use entry is denied.
- **Create against fence.** A delayed `create_capture` arriving after `revoke_capture(fence_absent=True)` is `fenced`.
- **Restart.** A process captures and exits; a new process restores. Then the reverse order with a revoke in between.
- **Clock skew.** A process whose `now` is outside `max_clock_skew_ms` gets `clock-skew` on create and commit; a revoke from it still succeeds.
- **Fork.** A pool or adapter created before `os.fork()` is not used by the child: the adapter detects a changed process identifier and fails `STORE_CLOSED` rather than share a connection.

Mixed-language variants of the first three (A in Python, B in JavaScript, and the reverse) run under G2.

### 6.2 PII eligibility parity through the bridge

Persistence must not change what is retained.

- For every capture case of `conformance/v1/corpus.json`, in the PII-off and PII-on lanes, the Python persistent server retains exactly the findings the Python in-memory server retains: same count, same types, same `unrestorable` and `passed_through` numbers, same redacted text up to token values.
- For the same inputs, the Python and JavaScript persistent servers store payloads with equal `type` and equal `value` bytes, in the same order. This is checked by opening each side's records with the test key. Redacted text is compared after replacing tokens by position; non-retained `redact` findings are excluded from the text comparison because Python writes `<SECRET_n>` and JavaScript uses the core's formatter (§2.1).
- `block` aborts with nothing stored and no fence left behind; `warn` and `allow` under `reject` store nothing; a PII type outside `pii.retain` is never in a payload; an `eligible` callback cannot add one.
- Supplementary characters, combining marks, and right-to-left text adjacent to a finding: the stored value's bytes equal the UTF-8 of the JavaScript slice. This exercises the UTF-16 range conversion in [utf16.py](../../packages/vault-py/src/redact_secret_vault/utf16.py) against stored bytes rather than against in-memory strings.
- Two workers whose bridges report different activation identities: with `expected_pii_activation` set, the second worker fails `PII_ACTIVATION_MISMATCH` before storing anything.
- Bridge qualification. The gaps recorded in the threat model stay open until closed by their own record: an adversarial protocol run, fuzzing of the frame parser, and a statement of supported operating systems. If they are not closed, the Python persistence claim is worded as "with an application-supplied, separately qualified `CoreClient`" and the bridge remains research-grade.

### 6.3 Making the Store conformance oracle language-neutral

The JavaScript harness (#108) will be code. For Python to be judged by the same oracle, the cases must be data and the two languages must be drivable by one orchestrator. Proposed, as two artifacts under `conformance/persistent/v1/`, to be agreed with #108 and #110 before either side builds on it:

**`schedules.json`: the cases.**

```json
{
  "version": "1.0.0",
  "fixtures": { "NS": "conformance-ns", "TENANT_A": "tenant-a-synthetic", "DIGEST_KEY": "00…(32 bytes hex)" },
  "cases": [
    {
      "id": "conflict.revoke-between-read-and-commit",
      "level": "store",
      "requires": { "crossProcess": true },
      "actors": ["A", "B"],
      "steps": [
        { "actor": "A", "op": "initializeNamespace", "input": { "namespace": "{NS}", "epoch": 1 }, "expect": { "outcome": "initialized" } },
        { "actor": "A", "op": "createCapture", "input": { "$ref": "captures.one-entry" }, "expect": { "outcome": "created" } },
        { "actor": "A", "op": "readEntries", "input": { "scope": "{SCOPE_A}", "entryIds": ["{e1}"] }, "save": "r1" },
        { "actor": "B", "op": "revokeCapture", "input": { "$ref": "revokes.c1" }, "hold": "before-commit", "as": "h1" },
        { "actor": "A", "op": "commitRestore", "input": { "$ref": "commits.e1-from-r1" }, "async": "p1" },
        { "release": "h1", "expect": { "outcome": "revoked", "entries": 1 } },
        { "await": "p1", "expectOneOf": [ { "outcome": "rejected", "reason": "revoked" }, { "outcome": "rejected", "reason": "stale" } ] },
        { "actor": "A", "op": "readEntries", "input": { "scope": "{SCOPE_A}", "entryIds": ["{e1}"] }, "expect": { "entries[0].used": 0 } }
      ]
    }
  ]
}
```

- Inputs and results use the specification's TypeScript field names. Bytes are lowercase hex. Each language maps names to its own types; that mapping is the only per-language code.
- `expect` is an exact result, `expectOneOf` a set where the specification leaves the reason open (spec §5.5), and `expectError` an error code.
- `requires` names capabilities. A runner whose store does not declare them reports the case as skipped with that reason, never as passed.
- `level` is `store` (operations of spec §5 against a `Store`) or `server` (`capture`, `restore`, `revoke`, `deleteCaptureCiphertext`, `resolveAttempt` against a persistent server with fixed synthetic resolvers and policies named in the case).
- `advance` moves the injected caller clock. A store with its own clock exposes a test-only offset; a case that needs to move the store clock declares `requires: { "testClock": true }`.
- `hold`, `release`, `async`, and `await` express the two-connection schedules. `fault` injects a named failure.

**Hold and fault points.** A fixed vocabulary, implemented by each adapter's test build and absent from its production API: `before-commit`, `after-commit-before-ack` (the commit is durable, the caller sees a lost connection), `before-first-write`, `drop-connection`, `unavailable`. For PostgreSQL, `hold: before-commit` means the actor's transaction has executed its statements and waits before `COMMIT`. The schedule states the required outcome, not the mechanism (lock or serialization failure), so a locking and an optimistic adapter can both pass.

**Driver protocol: the actors.** Each language provides a small executable that reads one JSON request per line on standard input and writes one response per line:

```text
-> {"id":1,"op":"configure","store":"postgres","dsnEnv":"RSV_TEST_DSN","keyMaterial":"…hex…","digestKey":"…hex…"}
<- {"id":1,"ok":true,"capabilities":{…}}
-> {"id":2,"op":"commitRestore","input":{…},"hold":null}
<- {"id":2,"result":{"outcome":"rejected","reason":"stale"}}
<- {"id":3,"error":"STORE_AMBIGUOUS"}
```

An orchestrator, written once, starts one driver process per actor and executes the schedule. Because the orchestrator does not care which language a driver is in, the same file gives the JavaScript-only run, the Python-only run (G3, G4), and the mixed runs (G2) with no additional cases. The database connection string is passed by environment variable name, never in the schedule file. Drivers are test tools: they are not shipped in the wheel or the npm package, they accept only synthetic fixtures, and their responses carry result structures and error codes only.

**Oracle.** The expected results in the file are the oracle. A model-based generator (a reference state machine that produces schedules and expected results, issue #110) is a JavaScript-side tool that emits more cases in this format; Python needs only to run them.

### 6.4 Diagnostics leak tests

Sentinels: every fixture value, every issued token, the data key, entry keys, wrapping material, the digest key, wrapped keys, envelope bytes (hex and base64 forms), the database connection string, and a marker string planted in a fake driver error and a fake SDK error. None may appear in any of:

| Channel | How it is inspected |
| --- | --- |
| Exception message, `repr`, `args`, attributes | Walk `vars()` and `__slots__` of every raised error |
| `__cause__` and `__context__` | Must both be `None` on errors from the persistent modules (§3.4) |
| `__notes__` (Python 3.11+) | Must be absent |
| Traceback | `traceback.format_exception`, and every frame's `f_locals` reachable from `__traceback__` |
| `logging` | A handler on the root logger at `DEBUG`, including the `psycopg`, `boto3`, `botocore`, and `urllib3` loggers. The package itself must emit no record. Whether those libraries log request or response bodies at `DEBUG` is established by this test, and the adapter documentation then states what an application must not enable |
| `warnings` | Run with `-W error`; any warning raised with a sentinel fails; the package raises none of its own |
| `stdout`, `stderr` | Captured for each driver process |
| Audit events | `repr` and field walk |
| `repr` and `str` of contract objects | `DataKey`, `RecordPayload`, `StoredKey`, `StoredEntry`, and the inputs that hold bytes define `__repr__` to print lengths, not content. A dataclass's default `repr` prints every field, which JavaScript's default object printing does not do at an error boundary |
| pytest failure output | A deliberately failing assertion on an object holding a sentinel must not print it (follows from the `__repr__` rule) |
| Pickling | `pickle.dumps` of `DataKey` and `RecordPayload` raises; they must not be sent between processes |

Run over: every negative vector, every schedule case, key-provider outage, throttling, and timeout, a store that raises a foreign exception, a malicious store returning out-of-contract values (oversized envelope, wrong capture, negative `used`, a `float` revision), and cancellation at each `await` of capture and restore.

Buffer hygiene, limited to what §3.6 claims: after each call, on success and on each failure and cancellation path, every `bytearray` the package allocated for a key or a payload is all zero. Tested by injecting the allocator.

### 6.5 Mutation controls

Each control is a named mutant applied by a test-only switch or patch; the suite must fail with it applied. The list mirrors the fences of the specification and is shared with JavaScript where the check exists in both.

| Mutant | Must be caught by |
| --- | --- |
| Commit does not conflict with a concurrent revoke (reads the capture without lock or condition) | §6.1 revoke-against-restore, held form |
| Create does not conflict with quarantine | §6.1 quarantine-against-create |
| `generation`, `lifecycle_revision`, or `ciphertext_revision` not compared at commit | Schedule cases `stale.*` |
| Budget checked at preflight only | 100-restore case |
| Receipt lookup skipped, or digest not compared | Receipt cases |
| Epoch not compared, or lower-epoch capture not treated as revoked | Recovery cases |
| Store clock replaced by caller `now` at commit | Expiry and skew cases |
| AAD omits one field (each of tenant, capture, entry, session, `createdAt`, `expiresAt`, `maxUses`) | Envelope negative vectors |
| Session tag not checked before unwrap | Session cases; provider call counter |
| Lone-surrogate test removed; UTF-16 length replaced by `len()` | Identifier vectors |
| Sort by default order of a UTF-16 encoding instead of UTF-8 bytes | Supplementary-character digest vector |
| Decoder accepts trailing bytes, or unsorted grants | Payload negative vectors |
| Sanitized error raised inside the `except` block | G6 `__context__` check |
| Fields returned before the commit result is known | Ambiguous-commit and cancellation cases |
| Fallback to another key when `keyRef` is unknown | Provider negative vectors |
| Fixed nonce reachable from the public API | Public-surface test |

A general mutation-testing tool over the persistent modules is additional evidence, not a substitute for the named controls; the choice of tool is an open question.

### 6.6 Packed-wheel tests

All gates run against the built wheel installed in a virtualenv outside the repository, as the existing smoke test does, never against an editable install.

- One virtualenv per extra combination: base; `[crypto]`; `[crypto,postgres]`; `[crypto,aws-kms]`; all.
- The import-isolation tests of §4.2.
- The vector tests, with the vectors path supplied by environment variable.
- A wheel content check: no test driver, no fixture, no deterministic key provider, no hold or fault hook in the installed files.
- `pip check` passes; the installed versions of `cryptography`, `cffi`, `psycopg`, `boto3`, and `botocore` are written to the record.

### 6.7 Matrix

A claim names cells; a cell not run is not claimed. Proposed first cells:

| Axis | Values to qualify first | Notes |
| --- | --- | --- |
| Python | Each minor version the claim will name. The package floor is 3.10 today | 3.10 is at or past the end of its upstream support window in October 2026 (<https://devguide.python.org/versions/>). Whether the persistent profile supports it is an open question. Free-threaded builds are not in the first matrix |
| Implementation | CPython | PyPy has `cryptography` wheels but psycopg's C extras exclude it; not in the first matrix |
| Operating system and architecture | Linux x86-64 and aarch64 (glibc) | macOS and Windows have no Python CI job today; musl is separate |
| `cryptography` | One exact version, with its bundled OpenSSL version recorded | |
| psycopg | One exact version and its install variant (pure with system `libpq`, `binary`, or `c`), with the `libpq` version | |
| PostgreSQL | The same server versions and deployment profile that #20 qualifies | Durability and failover statements are per profile (spec §7.6) |
| Topology | Two or more server processes on one host; two hosts with separate clocks | Skew cases need the second |
| Node.js and core | The bridge's Node.js version and `PINNED_CORE_VERSION` | Capture parity depends on both |
| Counterpart for G2 | Exact versions of the JavaScript persistent packages | |
| AWS KMS | Region, key spec, and SDK version, if the provider is claimed | Depends on #113 |

## 7. Non-claims

- Python persistence is not supported. `redact-secret-vault` remains an in-memory, research-grade server authority until a qualification record says otherwise.
- Passing JavaScript tests proves nothing about Python. Passing the shared vectors proves byte agreement on the listed inputs and nothing about transactions, concurrency, or diagnostics.
- A Python implementation that passes every gate with the reference store has not qualified any durable backend.
- The bridge is not qualified by any of this unless its own record is produced (§6.2).
- Memory clearing is not claimed beyond the buffers this package owns (§3.6).
- No exactly-once delivery, no erasure, and no malicious-rollback detection, as in spec §7.3, §9, and §9.3.

JavaScript-only until the Python gates pass: the persistent server profile, the crypto layer, the local key provider, `store-memory`, `store-postgres`, and the AWS KMS provider. JavaScript-only with no Python plan: a non-extractable key handle for local key material (§9), browser and Worker modes.

**Rust and Go** are future, independent qualification targets. Each would implement the record format from spec §3 and consume the same `vectors.json` and `schedules.json` through its own driver (§6.3). Neither depends on the npm server runtime or on the Python package: the vectors and schedules are data, and the orchestrator talks to a driver over standard input and output. Each needs its own core integration decision, its own dependency review, and its own matrix. Nothing in this plan starts that work.

## 8. Implementation handoffs

Filed on 2026-10-01, after the contracts and vectors were merged, as issues [#119](https://github.com/redact-secret/redact-secret-vault/issues/119), [#120](https://github.com/redact-secret/redact-secret-vault/issues/120), [#121](https://github.com/redact-secret/redact-secret-vault/issues/121), [#122](https://github.com/redact-secret/redact-secret-vault/issues/122), [#123](https://github.com/redact-secret/redact-secret-vault/issues/123), [#124](https://github.com/redact-secret/redact-secret-vault/issues/124), [#125](https://github.com/redact-secret/redact-secret-vault/issues/125), [#126](https://github.com/redact-secret/redact-secret-vault/issues/126), [#127](https://github.com/redact-secret/redact-secret-vault/issues/127), [#128](https://github.com/redact-secret/redact-secret-vault/issues/128), [#129](https://github.com/redact-secret/redact-secret-vault/issues/129), in the order below. Each is independently reviewable. "JS" dependencies are issues of this repository.

1. **Python: persistent contracts, errors, limits, and validators (standard library only)**
   - Scope: `redact_secret_vault.persistent` with the dataclasses and protocols of §3.2 and §3.3, the error classes of §3.4, limits, string and integer rules of §3.5 and §3.6, and validators mirroring `packages/vault-contracts/src/validate.ts`. No I/O, no crypto, no server changes.
   - Acceptance: every validator case of `packages/vault-contracts/test/validate.test.mjs` ported and passing; limits and error messages compared against the TypeScript sources by test; UTF-16 length, lone-surrogate, `bool`-as-`int`, `float`, and `2^53` boundary tests; `__cause__` and `__context__` unset on every raised error; base wheel still has no `Requires-Dist`.
   - Depends on: #104 (merged contracts). Blocks 2 to 9.

2. **Python: canonical encoding and digests, verified against the shared vectors (standard library only)**
   - Scope: `entryId`, AAD, payload encode and decode, envelope framing and parsing (without AEAD), session tag, request digest. Vector loader per §5.2.
   - Acceptance: the `entryId`, AAD, payload, request digest, and session tag groups of `conformance/persistent/v1/vectors.json` reproduced byte for byte; every negative case of those groups rejected with the mapped code; if `verify_vectors.py` exists, a written note of what it covers and whether it is kept.
   - Depends on: 1; #106 (vectors file). Blocks 3, 4, 6.

3. **Python: packaging extras and import isolation**
   - Scope: `[crypto]`, `[postgres]`, `[aws-kms]` extras; module skeletons that raise `ImportError` naming the extra; the tests of §4.2; extension of `scripts/verify-python-dist.py`; a CI job that builds the wheel and runs the isolation probes in clean virtualenvs.
   - Acceptance: §4.2 items 1 to 5 pass in CI on the packed wheel; a decision note if separate distributions are chosen instead.
   - Depends on: 1. Blocks 4, 7, 8 (they add code behind the extras).

4. **Python: record crypto and local key provider over `cryptography`**
   - Scope: `redact_secret_vault.crypto`: `RecordCrypto` over a `KeyProvider` (HKDF entry keys, AES-256-GCM, duplicate-entry and mismatched-binding rejection), the local key provider of spec §6.3 with active, decrypt-only, and retired states and explicit scope, buffer handling of §3.6, traceback rule of §3.4. Test-tree-only deterministic provider.
   - Acceptance: entry-key, envelope, and local-provider vector groups reproduced; all their negative cases rejected with mapped codes; bit-flip and cross-record swap tests; buffers zero after every path; no nonce parameter on the public API; leak tests of §6.4 for this module; measured seal and open time for a maximum-size capture, with the decision on thread offloading recorded.
   - Depends on: 2, 3; #106, #107.

5. **Conformance: language-neutral schedule corpus and driver protocol**
   - Scope: agree and document `conformance/persistent/v1/schedules.json` and the driver protocol of §6.3 with the owners of #108 and #110; an orchestrator; a JavaScript driver; conversion of the JavaScript store harness cases to the file. No Python code.
   - Acceptance: the JavaScript reference store passes the file through its driver with results identical to its native harness; the format documented in `conformance/README.md`; the hold and fault vocabulary fixed.
   - Depends on: #108, #110. Blocks 6, 8, 10. This is the one item that changes JavaScript-side work and should be raised first.

6. **Python: reference `store_memory` and schedule runner**
   - Scope: `redact_secret_vault.persistent.store_memory` (volatile, `cross_process=False`, a lock per §3.7); the Python driver; test hooks for holds and faults kept out of the wheel.
   - Acceptance: every `store`-level schedule the store's capabilities allow passes; skipped cases listed with reasons; a restart test showing all state is lost; mutation controls of §6.5 that apply to a store are caught.
   - Depends on: 1, 2, 5.

7. **Python: persistent server profile**
   - Scope: an explicit factory in `redact_secret_vault.persistent` taking a `Store`, a `RecordCrypto`, a digest key, principal and session resolvers, restore and lifecycle policies; a capture plan extracted from `InMemoryVaultServer._capture` so both servers share one eligibility implementation; restore order of spec §7.2; attempts and `resolve_attempt`; cancellation rules of §3.7; clock of §3.8; required `expected_pii_activation`; audit vocabulary extended for capture, ciphertext deletion, and attempt resolution. `InMemoryVaultServer` behavior unchanged.
   - Acceptance: every `server`-level schedule passes with `store_memory` and the crypto layer; in-memory corpus results unchanged; capture parity of §6.2 against the in-memory server; differences table of spec §8.3 reproduced as tests; cancellation at every `await` returns no field; leak tests of §6.4.
   - Depends on: 4, 6; #109 (for the frozen server semantics and the JavaScript counterpart of the capture plan).

8. **Python: PostgreSQL store adapter (psycopg 3)**
   - Scope: `redact_secret_vault.stores.postgres` against the schema owned by #20; consumer-injected pool; lock order and conflict rule of spec §5.2; SQLSTATE mapping to `stale`, `STORE_UNAVAILABLE`, and `STORE_AMBIGUOUS`; fork detection; no migrations.
   - Acceptance: all `store`-level schedules including both two-connection schedules; the two-process cases of §6.1 with real processes; disconnect before and after commit; malicious-row handling (values outside `2^53 − 1`, wrong lengths); leak tests with driver logging at `DEBUG`; the tested install variant and versions recorded.
   - Depends on: 3, 5, 6; #20 (schema and deployment profile), #111 (recovery operations).

9. **Python: AWS KMS key provider (boto3)**
   - Scope: `redact_secret_vault.keys.aws_kms` with an injected client, the `keyRef` format and context-digest encoding fixed by #113, timeout, throttling, and unavailable-key mapping, opt-in bounded cache per spec §6.2.
   - Acceptance: a data key wrapped by the JavaScript provider is unwrapped by Python and the reverse, against a real test key; a different context fails `KEY_INTEGRITY`; disabled key fails `KEY_UNAVAILABLE`; no identifier appears in clear in the request context; leak tests with SDK logging at `DEBUG`.
   - Depends on: 3, 4; #113. Optional: not required for a first Python persistence claim with the local provider.

10. **Qualification: cross-language interoperation and two-process record**
    - Scope: the runs of §5.4 and §6.1 with mixed-language actors; the PII parity run of §6.2 against the JavaScript persistent server; the mutation-control table of §6.5; the packed-wheel runs of §6.6; the matrix record of §6.7. Also the bridge qualification record, or the decision to limit the claim to an application-supplied `CoreClient`.
    - Acceptance: one qualification document under `docs/research/` listing each gate G1 to G9, the cells run, versions, and results, with failures and skips stated.
    - Depends on: 7, 8; #109, #20, #110, #112.

11. **Documentation: Python support matrix and threat-model update**
    - Scope: `packages/vault-py/README.md` (extras, what each module's status is, WSGI note, bridge limits beside the at-rest statement), `docs/specs/threat-model.md` (Python persistent row; what §2.3 lists as worse), `README.md` and `ARCHITECTURE.md` status lines, `conformance/README.md`.
    - Acceptance: every status word follows `CONVENTIONS.md`; no sentence claims support for a cell absent from the record of issue 10; link check passes.
    - Depends on: 10. Until 10 passes, only the plan and the "not supported" wording may be merged.

Order: 1, then 2 and 3 in parallel, then 4; 5 can start as soon as #108's harness shape is known and gates 6; then 7 and 8; 9 at any point after 4; 10; 11.

## 9. Open questions

Questions 1, 2, 3, 6, 7, and 8 are answered for the groundwork issues 1 to 4 by [the decision record](../decisions/python-persistence-api-and-packaging.md). The others stay open.

1. **Sync API.** Is an async-only persistent API acceptable for the Python users this package targets, or is a synchronous facade required for WSGI? (§3.7)
2. **One distribution or several.** Is per-module support status inside one version number acceptable? (§4.1)
3. **Python floor.** Does the persistent profile support 3.10, given its upstream end of life this month, or start at 3.11, which also provides `asyncio.timeout` and exception notes?
4. **Schema ownership.** The plan assumes the PostgreSQL schema is a language-neutral artifact owned by #20 and consumed by both adapters. If #20 keeps its schema inside the npm package, interop needs another arrangement.
5. **Driver protocol ownership.** §6.3 asks #108 and #110 to express their harness as data plus a driver. If the JavaScript harness stays code-only, Python needs a hand-ported copy, and "one oracle" is lost.
6. **Local key material.** JavaScript accepts a non-extractable `CryptoKey`; Python has only bytes. Is a bytes-only local provider acceptable as the same profile, or is it a distinct, weaker profile name?
7. **Existing `from exc` sites and `_is_identifier`.** Should the in-memory server's four chained raises and its code-point identifier limit be changed for consistency, given that doing so alters published behavior?
8. **`KEY_ABORTED`.** With no abort signal in the Python signatures, is the code ever raised by a Python provider, or is it reserved?
9. **Bridge.** Is the bridge to be qualified as part of this work, or is the first claim limited to an application-supplied `CoreClient`?
10. **Mutation tooling.** Named controls only, or also a general mutation tool; and which.
11. **Vector byte encoding and negative-case error mapping.** This plan assumes hex and an explicit expected code per negative case; both are settled by the file #106 produces.
12. **Free-threaded CPython.** Out of the first matrix; when, if ever, it is added.
