"""Diagnostics leak tests and cancellation for the persistent server profile
(docs/plans/python-persistence-parity.md sections 3.7 and 6.4).

Sentinels: every captured value, every issued token, the data key, the wrapping material, the digest key, wrapped keys,
envelopes (raw, hexadecimal, and base64), a database connection string, and a marker planted in every foreign failure
the injected store, key provider, resolvers, and policies are made to raise. None may appear in an error's message,
``repr``, ``args``, or attributes; in ``__cause__`` or ``__context__`` (both must be ``None``); in ``__notes__``; in a
traceback's text or the locals of any frame of this package that it reaches; in ``logging``, ``warnings``, or the
standard streams; or in an audit event. Over: every negative path of the server, a store that raises foreign
exceptions, a store that returns out-of-contract values, key-provider outage, throttling, and timeout, and
cancellation at every ``await`` of capture and restore.

Cancellation: at every ``await`` the operation returns no field, every buffer the package allocated is zero, no task
logs an unretrieved exception, and the attempt resolves consistently with the store afterwards.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import gc
import logging
import pickle
import sys
import traceback
import warnings
from typing import Any

import pytest

pytest.importorskip("cryptography")

from crypto_support import all_zero, track_buffers  # noqa: E402
from server_support import (  # noqa: E402
    CTX_A,
    KEY_MATERIAL,
    SECRET_A,
    SECRET_B,
    SECRET_C,
    FakeCore,
    Rig,
    ctx,
    make_rig,
    resolve_principal,
)

from redact_secret_vault import PolicyDecision, VaultServerError  # noqa: E402
from redact_secret_vault.persistent import (  # noqa: E402
    KeyProviderError,
    LifecycleDecision,
    LifecycleRequest,
    PersistentCaptureOptions,
    RecoveryState,
    StoreError,
    create_persistent_server_vault,
)

pytestmark = pytest.mark.skipif(sys.version_info < (3, 11), reason="the persistent modules need Python 3.11")

from server_support import RELEASE as RELEASE_GRANTS  # noqa: E402

MARKER = "SENTINEL-DRIVER-MARKER-c0ffee"
CONNECTION = "postgresql://synthetic-user:SENTINEL-DB-PASSWORD-0000@db.invalid:5432/vault"
FOREIGN_TEXT = f"synthetic driver failure at {CONNECTION} marker={MARKER}"


class ForeignError(Exception):
    """A driver or SDK failure: carries the marker in its message, an attribute, and its own cause."""

    def __init__(self) -> None:
        super().__init__(FOREIGN_TEXT)
        self.detail = MARKER
        self.__cause__ = RuntimeError(MARKER)


def _transient(buffers: list[bytearray]) -> list[bytearray]:
    """The buffers of one call: not the local provider's wrapping material, which lives as long as the provider."""

    return [buffer for buffer in buffers if bytes(buffer) != KEY_MATERIAL]


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def forms(raw: bytes) -> set[str]:
    out = {raw.hex(), base64.b64encode(raw).decode(), repr(raw), repr(bytearray(raw))}
    try:
        out.add(raw.decode("utf-8"))
    except UnicodeDecodeError:
        pass
    return {item for item in out if len(item) >= 8}


class Sentinels:
    def __init__(self) -> None:
        self.found: set[str] = {MARKER, CONNECTION, "SENTINEL-DB-PASSWORD-0000", SECRET_A, SECRET_B, SECRET_C}
        for raw in (KEY_MATERIAL, bytes(0x40 + index for index in range(32))):
            self.found |= forms(raw)

    def note_token(self, token: str) -> None:
        self.found.add(token)
        self.found.add(token.strip("<>"))

    def note_rig(self, rig: Rig) -> None:
        rows = rig.rows()
        if rows is not None:
            for capture in rows.captures.values():
                self.found |= forms(bytes(capture.wrapped_key))
            for entry in rows.entries.values():
                self.found |= forms(bytes(entry.envelope))

    def leak(self, text: str) -> str | None:
        for item in self.found:
            if item in text:
                return item[:6] + "..."
        return None


def frame_texts(error: BaseException) -> list[str]:
    """repr of every local of every frame below the caller that belongs to this package."""

    texts: list[str] = []
    tb = error.__traceback__
    first = True
    while tb is not None:
        frame = tb.tb_frame
        if not first and "redact_secret_vault" in frame.f_code.co_filename:
            for name, value in frame.f_locals.items():
                texts.append(f"{name}={_deep(value)}")
        first = False
        tb = tb.tb_next
    return texts


def _deep(value: Any, depth: int = 0) -> str:
    if depth > 4:
        return ""
    if isinstance(value, (str, bytes, bytearray)):
        return value.decode("latin-1") if isinstance(value, (bytes, bytearray)) else value
    if isinstance(value, dict):
        return " ".join(_deep(k, depth + 1) + _deep(v, depth + 1) for k, v in value.items())
    if isinstance(value, (list, tuple, set, frozenset)):
        return " ".join(_deep(item, depth + 1) for item in value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return " ".join(_deep(getattr(value, f.name), depth + 1) for f in dataclasses.fields(value))
    return repr(value)


def assert_error_clean(error: BaseException, sentinels: Sentinels) -> None:
    assert error.__cause__ is None, "an error must not carry a cause"
    assert error.__context__ is None, "an error must not carry a context"
    assert not hasattr(error, "__notes__"), "an error must not carry notes"
    surfaces = {
        "str": str(error),
        "repr": repr(error),
        "args": repr(error.args),
        "attrs": repr(sorted(vars(error).items())),
        "traceback": "".join(traceback.format_exception(error)),
        "frames": "\n".join(frame_texts(error)),
    }
    for where, text in surfaces.items():
        leaked = sentinels.leak(text)
        assert leaked is None, f"{type(error).__name__} leaks {leaked} through {where}"


class Harness:
    """Runs scenarios, recording every error and audit event for one scan at the end."""

    def __init__(self) -> None:
        self.sentinels = Sentinels()
        self.errors: list[VaultServerError] = []
        self.audits: list[Any] = []
        self.rigs: list[Rig] = []

    async def rig(self, **options: Any) -> Rig:
        rig = await make_rig(**options)
        self.rigs.append(rig)
        return rig

    async def capture(self, rig: Rig, text: str | None = None, **options: Any) -> Any:
        captured = await rig.capture(text, **options)
        for issued in captured.tokens:
            self.sentinels.note_token(issued.token)
        return captured

    async def fails(self, awaitable: Any) -> VaultServerError:
        try:
            await awaitable
        except VaultServerError as error:
            self.errors.append(error)
            return error
        raise AssertionError("the call was expected to fail")

    def finish(self) -> None:
        for rig in self.rigs:
            self.sentinels.note_rig(rig)
            self.audits.extend(rig.audits)
        assert self.errors, "no error was recorded"
        for error in self.errors:
            assert_error_clean(error, self.sentinels)
        for event in self.audits:
            for name, value in dataclasses.asdict(event).items():
                leaked = self.sentinels.leak(f"{name}={value!r}")
                assert leaked is None, f"an audit event leaks {leaked} through {name}"
            assert isinstance(event.at, int)
            # Only opaque identifiers, counts, and fixed vocabulary: no free-text field exists.
            for name in ("principal_id", "tenant", "sink", "path", "purpose", "request_id", "capture_id", "attempt_id"):
                value = getattr(event, name)
                assert value is None or isinstance(value, str)


async def every_negative_path(h: Harness) -> None:
    """Every way the server can refuse or fail, each with a foreign failure carrying the marker where one can occur."""

    foreign = ForeignError

    def throwing(*_args: Any) -> Any:
        raise foreign()

    # --- restore denials
    rig = await h.rig()
    captured = await h.capture(rig, f"{SECRET_A} and {SECRET_B}", max_uses=1)
    token_a, token_b = (t.token for t in captured.tokens)
    await h.fails(rig.restore(captured, fields={"body": "<rsv_ broken " + token_a}))
    await h.fails(rig.restore(captured, fields={"body": f"{token_a} <rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>"}))
    await h.fails(rig.restore(captured, sink="sink-not-granted"))
    await h.fails(rig.restore(captured, context={"principal": "principal-unknown"}))
    await h.fails(rig.restore(captured, purpose=""))
    await h.fails(rig.restore(captured, fields={"body": 7}))
    await rig.restore(captured, fields={"body": token_a})
    await h.fails(rig.restore(captured, fields={"body": token_a}, attempt_id="attempt-synthetic-1"))
    other = await h.capture(rig, f"{SECRET_C}")
    await h.fails(rig.restore(other, context=ctx("principal-synthetic-0002")))
    await rig.revoke(other)
    await h.fails(rig.restore(other))
    bound = await h.capture(rig, f"{SECRET_A}", context=ctx(session="session-synthetic-one"))
    await h.fails(rig.restore(bound, context=ctx(session="session-synthetic-two")))
    rig.clock.advance(11 * 60 * 1000)
    await h.fails(rig.restore(bound, context=ctx(session="session-synthetic-one")))

    # --- foreign failures from every injected collaborator
    good = await h.rig()
    base = await h.capture(good, max_uses=5)
    for override in ("resolve_principal", "resolve_session", "policy_revision", "now"):
        vault = await create_persistent_server_vault(**{**good.options, override: throwing})
        for call in (
            lambda v=vault: v.restore(good.restore_request(base)),
            lambda v=vault: v.capture(
                SECRET_A, PersistentCaptureOptions(context=CTX_A, release=base.tokens and RELEASE_GRANTS)
            ),
            lambda v=vault: v.revoke(LifecycleRequest(context=CTX_A, capture_id=base.capture_id)),
        ):
            try:
                await call()
            except VaultServerError as error:
                h.errors.append(error)
    for attribute in ("policy", "lifecycle"):
        original = getattr(good, attribute)
        setattr(good, attribute, throwing)
        for call in (
            lambda: good.restore(base),
            lambda: good.capture(),
            lambda: good.revoke(base),
            lambda: good.vault.resolve_attempt(good.restore_request(base, attempt_id="attempt-synthetic-7")),
        ):
            try:
                await call()
            except VaultServerError as error:
                h.errors.append(error)
        setattr(good, attribute, original)

    # --- the store raises foreign exceptions, from every operation, before and after the call
    for operation in (
        "create_capture",
        "read_entries",
        "read_captures",
        "commit_restore",
        "revoke_capture",
        "inspect_attempt",
        "delete_ciphertext",
        "recovery_state",
    ):
        scenario = await h.rig()
        base = await h.capture(scenario)
        for factory in (
            ForeignError,
            lambda: StoreError("STORE_AMBIGUOUS"),
            lambda: StoreError("STORE_UNAVAILABLE"),
            lambda: StoreError("STORE_INVALID_ARGUMENT"),
        ):
            scenario.store.fail[operation] = factory
            for call in (
                scenario.capture(f"{SECRET_B}"),
                scenario.restore(base, attempt_id="attempt-synthetic-9"),
                scenario.revoke(base),
                scenario.vault.delete_capture_ciphertext(LifecycleRequest(context=CTX_A, capture_id=base.capture_id)),
                scenario.vault.resolve_attempt(scenario.restore_request(base, attempt_id="attempt-synthetic-9")),
            ):
                try:
                    await call
                except VaultServerError as error:
                    h.errors.append(error)
            del scenario.store.fail[operation]

    # --- a store that returns out-of-contract values
    scenario = await h.rig()
    base = await h.capture(scenario)
    for operation, lie in (
        ("read_entries", lambda _r, _i: None),
        ("read_entries", lambda r, _i: dataclasses.replace(r, entries=(dataclasses.replace(r.entries[0], used=-1.5),))),
        (
            "read_entries",
            lambda r, _i: dataclasses.replace(
                r, entries=(dataclasses.replace(r.entries[0], envelope=b"x" * (3 << 20)),)
            ),
        ),
        ("read_entries", lambda r, _i: dataclasses.replace(r, recovery=RecoveryState(epoch=1, state="quarantined"))),
        ("read_captures", lambda _r, _i: (None, None)),
        ("commit_restore", lambda _r, _i: "gibberish"),
        ("create_capture", lambda _r, _i: object()),
        ("revoke_capture", lambda _r, _i: object()),
        ("inspect_attempt", lambda _r, _i: object()),
        ("delete_ciphertext", lambda _r, _i: object()),
    ):
        scenario.store.tamper[operation] = lie
        for call in (
            scenario.restore(base, attempt_id="attempt-synthetic-8"),
            scenario.capture(),
            scenario.revoke(base),
            scenario.vault.delete_capture_ciphertext(LifecycleRequest(context=CTX_A, capture_id=base.capture_id)),
            scenario.vault.resolve_attempt(scenario.restore_request(base, attempt_id="attempt-synthetic-8")),
        ):
            try:
                await call
            except VaultServerError as error:
                h.errors.append(error)
        del scenario.store.tamper[operation]

    # --- key provider outage, throttling, timeout, and a foreign SDK failure
    scenario = await h.rig(crypto_timeout_s=0.05)
    base = await h.capture(scenario)
    for failure in (
        lambda: KeyProviderError("KEY_UNAVAILABLE"),
        lambda: KeyProviderError("KEY_THROTTLED"),
        lambda: KeyProviderError("KEY_TIMEOUT"),
        lambda: KeyProviderError("KEY_INTEGRITY"),
        ForeignError,
    ):
        for method in ("generate", "unwrap"):
            scenario.provider.fail[method] = failure
            call = scenario.capture() if method == "generate" else scenario.restore(base)
            try:
                await call
            except VaultServerError as error:
                h.errors.append(error)
            del scenario.provider.fail[method]
    scenario.provider.delay["unwrap"] = 1
    try:
        await scenario.restore(base)
    except VaultServerError as error:
        h.errors.append(error)

    # --- capture refusals
    scenario = await h.rig(limits={"max_entries": 1})
    for options in (
        {"policy": {"github_token": "block"}},
        {"policy": {"github_token": "warn"}},
        {"max_uses": 0},
        {"release": ()},
    ):
        try:
            await scenario.capture(f"{SECRET_A} {SECRET_B}", **options)
        except VaultServerError as error:
            h.errors.append(error)
    await h.fails(scenario.capture(f"{SECRET_A} {SECRET_B}"))
    await h.fails(scenario.capture(f"{SECRET_A} <rsv_aaaaaaaaaaaaaaaaaaaaaaaaaaa>"))
    scenario.lifecycle = lambda _i: LifecycleDecision(allow=False)
    await h.fails(scenario.capture())
    await h.fails(scenario.revoke(base))

    # --- a closed server and a quarantined namespace
    scenario = await h.rig()
    base = await h.capture(scenario)
    await scenario.memory.quarantine("support-synthetic")
    await h.fails(scenario.restore(base))
    await h.fails(scenario.capture())
    await scenario.vault.close()
    await h.fails(scenario.capture())


def test_no_error_or_audit_event_of_any_negative_path_leaks() -> None:
    async def scenario() -> Harness:
        h = Harness()
        await every_negative_path(h)
        return h

    h = run(scenario())
    assert len(h.errors) >= 40
    h.finish()


def test_no_logging_warning_or_output_carries_a_sentinel_or_comes_from_the_package(
    capsys: pytest.CaptureFixture[str],
) -> None:
    records: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    root = logging.getLogger()
    handler = Capture(level=logging.DEBUG)
    previous = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    for name in ("asyncio", "psycopg", "boto3", "botocore", "urllib3", "redact_secret_vault"):
        logging.getLogger(name).setLevel(logging.DEBUG)
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")

            async def scenario() -> Harness:
                loop = asyncio.get_running_loop()
                loop.set_debug(True)
                h = Harness()
                await every_negative_path(h)
                gc.collect()
                return h

            h = asyncio.run(scenario())
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)
    out, err = capsys.readouterr()
    h.finish()
    for text in (out, err, *(record.getMessage() for record in records), *(str(w.message) for w in caught)):
        assert h.sentinels.leak(text) is None
    assert not [r for r in records if r.name.startswith("redact_secret_vault")], "the package must emit no log record"
    assert not [w for w in caught if "redact_secret_vault" in str(w.filename)], "the package must raise no warning"
    assert out == "" and err == ""


def test_the_server_object_prints_no_state_and_cannot_be_pickled() -> None:
    async def scenario() -> None:
        rig = await make_rig()
        text = repr(rig.vault) + str(rig.vault)
        assert "SENTINEL" not in text and "ghp_" not in text
        with pytest.raises(TypeError):
            pickle.dumps(rig.vault)

    run(scenario())


def test_buffers_the_package_allocated_are_zero_after_every_outcome(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        created = track_buffers(monkeypatch)
        # The server allocates through ``_buffers``; so do the record crypto and the local provider.
        h = Harness()
        await every_negative_path(h)
        rig = await h.rig()
        captured = await h.capture(rig, f"{SECRET_A} {SECRET_B}", max_uses=2)
        await rig.restore(captured, fields={"body": " ".join(t.token for t in captured.tokens)})
        assert created, "no buffer was tracked: the injection point is not used"
        assert all_zero(_transient(created))

    run(scenario())


# ------------------------------------------------------------------------ cancellation


class Canceller:
    """Counts the ``await`` points of the injected collaborators and cancels the operation at the Nth."""

    def __init__(self) -> None:
        self.count = 0
        self.at: int | None = None
        self.task: asyncio.Task[Any] | None = None

    async def tick(self) -> None:
        self.count += 1
        if self.at is not None and self.count == self.at and self.task is not None:
            self.task.cancel()
        await asyncio.sleep(0)


async def instrumented(canceller: Canceller) -> Rig:
    async def resolver(context: Any) -> Any:
        await canceller.tick()
        return resolve_principal(context)

    async def session(context: Any) -> Any:
        await canceller.tick()
        return context.get("session")

    rig = await make_rig(resolve_principal=resolver, resolve_session=session)

    async def policy(_decision: Any) -> PolicyDecision:
        await canceller.tick()
        return PolicyDecision(allow=True)

    async def lifecycle(_decision: Any) -> LifecycleDecision:
        await canceller.tick()
        return LifecycleDecision(allow=True)

    rig.policy = policy
    rig.lifecycle = lifecycle
    for operation in rig.store.OPERATIONS:

        async def before(_input: Any) -> None:
            await canceller.tick()

        rig.store.before[operation] = before

    original_generate, original_unwrap = rig.provider.generate_data_key, rig.provider.unwrap_data_key

    async def generate(context: Any) -> Any:
        await canceller.tick()
        return await original_generate(context)

    async def unwrap(stored: Any, context: Any) -> Any:
        await canceller.tick()
        return await original_unwrap(stored, context)

    rig.provider.generate_data_key = generate  # type: ignore[method-assign]
    rig.provider.unwrap_data_key = unwrap  # type: ignore[method-assign]
    return rig


def _unretrieved(loop: asyncio.AbstractEventLoop, sink: list[dict[str, Any]]) -> None:
    loop.set_exception_handler(lambda _loop, context: sink.append(context))


@pytest.mark.parametrize("operation", ["capture", "restore"])
def test_cancellation_at_every_await_returns_no_field_and_leaves_no_buffer_or_task_behind(
    operation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    created = track_buffers(monkeypatch)

    async def attempt(point: int | None) -> tuple[int, Any, Rig, list[dict[str, Any]], str, Any]:
        loop = asyncio.get_running_loop()
        problems: list[dict[str, Any]] = []
        _unretrieved(loop, problems)
        canceller = Canceller()
        rig = await instrumented(canceller)
        prior = None
        if operation == "restore":
            prior = await rig.capture(f"x {SECRET_A} y", context=ctx(session="session-synthetic-one"))
            canceller.count = 0
        canceller.at = point
        sentinel = "attempt-synthetic-cancel"

        async def body() -> Any:
            if operation == "capture":
                return await rig.capture(f"{SECRET_A} {SECRET_B}", context=ctx(session="session-synthetic-one"))
            return await rig.restore(prior, context=ctx(session="session-synthetic-one"), attempt_id=sentinel)

        task = asyncio.ensure_future(body())
        canceller.task = task
        await asyncio.wait({task})
        # Let a shielded store call finish under its own deadline, and any fence it scheduled.
        for _ in range(20):
            await asyncio.sleep(0.005)
        gc.collect()
        return canceller.count, task, rig, problems, sentinel, prior

    async def scenario() -> int:
        total, done, _rig, _problems, _s, _prior = await attempt(None)
        assert not done.cancelled() and done.exception() is None
        result = done.result()
        if operation == "restore":
            assert result.restored == 1
        for point in range(1, total + 1):
            created.clear()
            _count, task, rig, problems, sentinel, prior = await attempt(point)
            assert task.cancelled(), f"cancel at await {point} of {total}: the operation was not cancelled"
            assert not problems, f"cancel at await {point}: an unretrieved task exception"
            assert all_zero(_transient(created)), f"cancel at await {point}: a buffer still holds a value"
            rows = rig.rows()
            if operation == "restore":
                entry = next(e for e in rows.entries.values())
                request = rig.restore_request(prior, context=ctx(session="session-synthetic-one"), attempt_id=sentinel)
                state = (await rig.vault.resolve_attempt(request)).state
                # The commit either happened (receipt, use spent) or did not (no receipt, no use): never in between.
                assert (state == "committed") == (entry.used == 1), (
                    f"cancel at await {point}: {state} with used={entry.used}"
                )
            elif rows is not None:
                # A capture the cancelled call may have created was never returned, so no token left; it is fenced.
                assert all(row.state == "revoked" for row in rows.captures.values()), f"cancel at await {point}"
        return total

    total = run(scenario())
    assert total >= (5 if operation == "capture" else 6), "the instrumentation saw too few await points"


def test_cancellation_while_the_core_scans_stores_nothing_and_returns_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The scan runs in a worker thread, an ``await`` the collaborators' instrumentation cannot see."""

    import time

    created = track_buffers(monkeypatch)

    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        holder: dict[str, asyncio.Task[Any]] = {}

        class CancellingCore(FakeCore):
            def scan(self, text: str, *, policy: Any = None, limits: Any = None) -> Any:
                if text and "task" in holder:
                    loop.call_soon_threadsafe(holder["task"].cancel)
                    time.sleep(0.05)
                return super().scan(text, policy=policy, limits=limits)

        rig = await make_rig(core=CancellingCore())
        task = asyncio.ensure_future(rig.capture(f"{SECRET_A} {SECRET_B}"))
        holder["task"] = task
        await asyncio.wait({task})
        assert task.cancelled()
        await asyncio.sleep(0.1)
        assert rig.store.mutations() == 0 and rig.provider.calls["generate"] == 0
        assert all_zero(_transient(created))

    run(scenario())
