"""Diagnostics leak tests for the crypto module (docs/plans/python-persistence-parity.md section 6.4).

Sentinels: the plaintext value, the data key, the entry key, the wrapping material, the wrapped key,
the envelope (raw, hexadecimal, and base64), and a marker planted in a fake provider failure. None may
appear in an error's message, ``repr``, ``args``, or attributes; in its traceback text or the locals
of any frame of this package that the traceback reaches; in ``logging``, ``warnings``, or the standard
streams; in the ``repr`` of a contract object; or in pytest's failure output. ``__cause__`` and
``__context__`` are ``None`` and ``__notes__`` is absent on every error.
"""

from __future__ import annotations

import asyncio
import base64
import gc
import logging
import traceback
import warnings
from typing import Any

import pytest
from crypto_support import (
    CAPTURE_2,
    DEK,
    MATERIAL,
    NS,
    InsecureTestKeyProvider,
    ScriptedProvider,
    binding,
    context,
    payload,
)
from persistent_vectors import binding_from, load_vectors

pytest.importorskip("cryptography")

from redact_secret_vault.crypto import (  # noqa: E402
    LocalKey,
    LocalKeyScope,
    create_local_key_provider,
    create_record_crypto,
)
from redact_secret_vault.crypto.record_crypto import derive_entry_key  # noqa: E402
from redact_secret_vault.persistent import (  # noqa: E402
    DataKey,
    KeyContext,
    KeyProviderError,
    RecordCryptoError,
    StoredKey,
)

SECRET_VALUE = b"SENTINEL-PLAINTEXT-VALUE-31337"
MARKER = "SENTINEL-DRIVER-MARKER-c0ffee"
V = load_vectors()


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def forms(raw: bytes) -> set[str]:
    """Every way a byte string could be printed."""

    out = {raw.hex(), base64.b64encode(raw).decode(), repr(raw), repr(bytearray(raw))}
    try:
        out.add(raw.decode("utf-8"))
    except UnicodeDecodeError:
        pass
    return {f for f in out if len(f) >= 8}


def sentinels(*extra: bytes) -> set[str]:
    entry_key = derive_entry_key(bytearray(DEK), binding("a").entry_id)
    found: set[str] = {MARKER}
    for raw in (SECRET_VALUE, DEK, MATERIAL, bytes(entry_key), *extra):
        found |= forms(raw)
    for vector in V["envelope"]:
        for field in ("dek", "nonce", "entryKey", "envelope", "plaintext"):
            found.add(vector[field])
    for vector in V["localWrap"]:
        for field in ("material", "wrappingKey", "wrappedKey", "dek"):
            found.add(vector[field])
    found.discard("")
    return found


def assert_clean(error: BaseException, secrets_: set[str]) -> None:
    assert error.__cause__ is None, "__cause__ is set"
    assert error.__context__ is None, "__context__ is set"
    assert not hasattr(error, "__notes__"), "__notes__ is set"
    surfaces = [str(error), repr(error), repr(error.args)]
    surfaces += [repr(value) for value in vars(error).values()]
    surfaces += list(traceback.format_exception(error))
    tb = error.__traceback__
    while tb is not None:
        frame = tb.tb_frame
        if "redact_secret_vault" in frame.f_code.co_filename:
            for value in frame.f_locals.values():
                surfaces.append(repr(value))
        tb = tb.tb_next
    blob = "\n".join(surfaces)
    leaked = [s for s in secrets_ if s in blob]
    assert not leaked, f"{len(leaked)} sentinel(s) reachable from the error"


def collect(fn: Any) -> BaseException:
    captured: BaseException | None = None
    try:
        fn()
    except BaseException as thrown:
        captured = thrown
    assert captured is not None
    return captured


def local() -> Any:
    return create_local_key_provider(keys=(LocalKey("2026-10", MATERIAL, "active"),), scope=LocalKeyScope((NS,)))


def scenarios() -> list[tuple[str, Any]]:
    """Operations that must fail, each as a zero-argument function."""

    rc = create_record_crypto(key_provider=local())
    records = ((binding("a", session_id="session-synthetic"), payload(SECRET_VALUE)),)
    sealed = run(rc.seal_capture(context(), records))
    pairs = ((records[0][0], sealed.envelopes[0]),)
    stored = StoredKey(sealed.key_ref, sealed.wrapped_key)
    flipped = bytearray(sealed.envelopes[0])
    flipped[-1] ^= 1

    def with_provider(provider: Any, fn: Any) -> Any:
        return lambda: fn(create_record_crypto(key_provider=provider, key_timeout_s=0.05))

    async def outage(*_: Any) -> Any:
        raise KeyProviderError("KEY_UNAVAILABLE")

    async def throttled(*_: Any) -> Any:
        raise KeyProviderError("KEY_THROTTLED")

    async def explode(*_: Any) -> Any:
        raise RuntimeError(f"{MARKER} {SECRET_VALUE.decode()} {DEK.hex()}")

    async def stall(*_: Any) -> Any:
        await asyncio.sleep(5)

    async def malicious(*_: Any) -> Any:
        return DataKey("test:k", b"w", bytearray(16))

    async def wrong_type(*_: Any) -> Any:
        return bytes(DEK)

    scripted = ScriptedProvider(outage, outage, outage)
    cases: list[tuple[str, Any]] = [
        ("tampered envelope", lambda: run(rc.open_capture(stored, context(), ((records[0][0], bytes(flipped)),)))),
        ("changed binding", lambda: run(rc.open_capture(stored, context(), ((binding("a"), sealed.envelopes[0]),)))),
        ("malformed envelope", lambda: run(rc.open_capture(stored, context(), ((records[0][0], b"RSVE-junk"),)))),
        (
            "another capture's key",
            lambda: run(
                rc.open_capture(stored, context(CAPTURE_2), ((binding("a", capture=CAPTURE_2), sealed.envelopes[0]),))
            ),
        ),
        (
            "unknown key reference",
            lambda: run(rc.open_capture(StoredKey("local:nope", sealed.wrapped_key), context(), pairs)),
        ),
        (
            "invalid payload",
            lambda: run(
                rc.seal_capture(context(), ((binding("a"), payload(SECRET_VALUE, type="lone-" + chr(0xD800))),))
            ),
        ),
        ("duplicate entry", lambda: run(rc.seal_capture(context(), (records[0], records[0])))),
        ("provider outage", with_provider(scripted, lambda c: run(c.seal_capture(context(), records)))),
        (
            "provider throttled",
            with_provider(
                ScriptedProvider(throttled, throttled, throttled),
                lambda c: run(c.open_capture(stored, context(), pairs)),
            ),
        ),
        (
            "provider foreign exception",
            with_provider(
                ScriptedProvider(explode, explode, explode), lambda c: run(c.seal_capture(context(), records))
            ),
        ),
        (
            "provider foreign exception on open",
            with_provider(
                ScriptedProvider(explode, explode, explode), lambda c: run(c.open_capture(stored, context(), pairs))
            ),
        ),
        (
            "provider timeout",
            with_provider(ScriptedProvider(stall, stall, stall), lambda c: run(c.seal_capture(context(), records))),
        ),
        (
            "provider returns a short key",
            with_provider(
                ScriptedProvider(malicious, wrong_type, wrong_type), lambda c: run(c.seal_capture(context(), records))
            ),
        ),
        (
            "provider returns bytes",
            with_provider(
                ScriptedProvider(malicious, wrong_type, wrong_type),
                lambda c: run(c.open_capture(stored, context(), pairs)),
            ),
        ),
    ]
    for case in V["negative"]["open"]:
        provider = InsecureTestKeyProvider(acknowledge_insecure="test-only", dek=bytes.fromhex(case["dek"]))
        b = binding_from(case["binding"])
        c = KeyContext(b.namespace, b.tenant, b.capture_id)
        cases.append(
            (
                f"vector open: {case['name']}",
                lambda provider=provider, b=b, c=c, case=case: run(
                    create_record_crypto(key_provider=provider).open_capture(
                        StoredKey("test:fixed", b"w"), c, ((b, bytes.fromhex(case["envelope"])),)
                    )
                ),
            )
        )
    for case in V["negative"]["localUnwrap"]:
        provider = create_local_key_provider(
            keys=(LocalKey(case["keyId"], bytes.fromhex(case["material"]), "active"),),
            scope=LocalKeyScope((case["context"]["namespace"],)),
        )
        c = KeyContext(case["context"]["namespace"], case["context"]["tenant"], case["context"]["captureId"])
        cases.append(
            (
                f"vector unwrap: {case['name']}",
                lambda provider=provider, c=c, case=case: run(
                    provider.unwrap_data_key(StoredKey(case["keyRef"], bytes.fromhex(case["wrappedKey"])), c)
                ),
            )
        )
    return cases


def test_no_error_exposes_a_secret_or_links_to_another_exception() -> None:
    cases = scenarios()
    assert len(cases) > 40
    secrets_ = sentinels()
    for case in V["negative"]["open"]:
        secrets_ |= forms(bytes.fromhex(case["envelope"])) | forms(bytes.fromhex(case["dek"]))
    for case in V["negative"]["localUnwrap"]:
        secrets_ |= forms(bytes.fromhex(case["wrappedKey"])) | forms(bytes.fromhex(case["material"]))
    for name, fn in cases:
        error = collect(fn)
        assert isinstance(error, (RecordCryptoError, KeyProviderError)), (name, type(error))
        assert_clean(error, secrets_)


def test_the_package_emits_no_log_record_warning_or_output(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets_ = sentinels()
    caplog.set_level(logging.DEBUG)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        for _, fn in scenarios():
            collect(fn)
        # A provider that fails inside a task must not leave an unretrieved exception to be logged by asyncio.
        gc.collect()
    assert not [w for w in caught], [str(w.message) for w in caught]
    package_records = [r for r in caplog.records if r.name.startswith("redact_secret_vault")]
    assert package_records == []
    text = "\n".join(r.getMessage() + (r.exc_text or "") for r in caplog.records)
    assert not [s for s in secrets_ if s in text]
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""


def test_contract_objects_print_lengths_and_refuse_pickling() -> None:
    import pickle

    secret = SECRET_VALUE.decode()
    key = DataKey("local:k", b"SENTINEL-WRAPPED", bytearray(DEK))
    stored = StoredKey("local:k", SECRET_VALUE)
    rc = create_record_crypto(key_provider=local())
    provider = local()
    sealed = run(rc.seal_capture(context(), ((binding("a"), payload(SECRET_VALUE)),)))
    opened = run(
        rc.open_capture(
            StoredKey(sealed.key_ref, sealed.wrapped_key), context(), ((binding("a"), sealed.envelopes[0]),)
        )
    )
    for obj in (key, stored, sealed, opened[0], opened, rc, provider, LocalKey("k", MATERIAL, "active")):
        text = repr(obj) + str(obj)
        assert secret not in text and SECRET_VALUE.hex() not in text and "SENTINEL-WRAPPED" not in text
        assert not [s for s in sentinels() if s in text]
    for obj in (key, opened[0], rc, provider):
        with pytest.raises(TypeError):
            pickle.dumps(obj)


def test_a_failing_assertion_does_not_print_a_secret() -> None:
    one = payload(SECRET_VALUE)
    two = payload(SECRET_VALUE)
    with pytest.raises(AssertionError) as info:
        assert one == two
    message = str(info.value)
    assert "SENTINEL" not in message and SECRET_VALUE.hex() not in message
    key = DataKey("local:k", b"w", bytearray(DEK))
    with pytest.raises(AssertionError) as info:
        assert key == DataKey("local:k", b"w", bytearray(DEK))
    assert DEK.hex() not in str(info.value) and str(bytes(DEK)) not in str(info.value)


def test_cancelling_at_the_provider_call_leaks_nothing_and_is_not_converted() -> None:
    marker_seen: list[str] = []

    async def slow(*_: Any) -> Any:
        try:
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            marker_seen.append(MARKER)
            raise

    rc = create_record_crypto(key_provider=ScriptedProvider(slow, slow, slow), key_timeout_s=30)
    secrets_ = sentinels()

    async def scenario() -> BaseException:
        task = asyncio.ensure_future(rc.seal_capture(context(), ((binding("a"), payload(SECRET_VALUE)),)))
        await asyncio.sleep(0.02)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError as cancelled:
            return cancelled
        raise AssertionError("not cancelled")

    cancelled = run(scenario())
    assert isinstance(cancelled, asyncio.CancelledError)
    blob = "\n".join(traceback.format_exception(cancelled))
    assert not [s for s in secrets_ if s in blob]
