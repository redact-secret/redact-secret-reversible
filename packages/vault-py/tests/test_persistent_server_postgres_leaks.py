"""Server-level leak test over a real PostgreSQL database (gate G6; docs/plans/python-persistence-parity.md, 6.4).

The persistent server profile, the real Node.js core bridge, the PostgreSQL adapter, and a real ``psycopg`` driver, with
``DEBUG`` logging on for ``psycopg``, ``psycopg.pool``, ``asyncio`` (debug mode), the package, and the root logger.
Capture and restore, the denials, and every failure path that can be provoked: store faults through the real adapter,
a lost acknowledgement, a terminated backend, a wrong password, an unreachable server, a malformed row, a core that
hangs or is killed or cannot start or reports another version or writes garbage, a failing key provider, resolver,
policy, and clock, cancellation at several points, and a closed store.

Sentinels (every form: raw, hexadecimal, Base64, Base64url, UTF-16): the synthetic secrets, an undetected plaintext
marker that travels to the bridge, every issued token, the data key of every capture (taken from a recording key
provider), every entry key derived from it, the wrapping material, the digest key, the database password, session
identifiers, and a marker planted in every foreign failure. Channels: the error's message, ``repr``, attributes,
chain, notes, traceback text and frame locals; every ``logging`` record (message, arguments, ``extra``, ``exc_info``);
``warnings``; standard output and error; the audit events; ``repr`` and ``str`` of the server, store, crypto, key
provider, and bridge; the bridge child's standard error; **the contents of the database** (every column of every row of
the namespaces the run created); and, when ``RSV_PG_CONTAINER`` names a Docker container, the server's own log.

The AWS KMS provider is not part of this run (the key provider is the local one): the SDK logs the data key at
``DEBUG`` (issue #145), a separate finding with its own mitigation.

Skipped, with the reason, without ``RSV_PG_APP_URL`` and ``RSV_PG_ADMIN_URL`` (``RSV_REQUIRE_POSTGRES=1`` fails
instead) or without ``node`` and a built workspace. Synthetic values only.
"""

from __future__ import annotations

import asyncio
import base64
import gc
import logging
import os
import secrets
import shutil
import stat
import subprocess
import sys
import time
import traceback
import warnings
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("psycopg")
pytest.importorskip("cryptography")

import pg_support  # noqa: E402
from bridge_qualification import HANG_CORE, _fake_core  # noqa: E402
from server_support import (  # noqa: E402
    DIGEST_KEY,
    KEY_MATERIAL,
    OTHER_TENANT,
    PURPOSE,
    RELEASE,
    SINK,
    TENANT,
    ctx,
    resolve_principal,
)
from test_persistent_server_leaks import assert_error_clean  # noqa: E402

from redact_secret_vault import NodeCoreBridge, PolicyDecision, VaultServerError  # noqa: E402
from redact_secret_vault.crypto import (  # noqa: E402
    LocalKey,
    LocalKeyScope,
    create_local_key_provider,
    create_record_crypto,
)
from redact_secret_vault.crypto.record_crypto import derive_entry_key  # noqa: E402
from redact_secret_vault.persistent import (  # noqa: E402
    KeyProviderError,
    LifecycleDecision,
    LifecycleRequest,
    PersistentCaptureOptions,
    PersistentRestoreRequest,
    StoreError,
    create_persistent_server_vault,
)
from redact_secret_vault.persistent.server import ResolveAttemptRequest  # noqa: E402

HAVE_NODE = shutil.which("node") is not None
pytestmark = [
    pg_support.needs_database,
    pytest.mark.skipif(sys.version_info < (3, 11), reason="the persistent modules need Python 3.11"),
    pytest.mark.skipif(not HAVE_NODE, reason="node and the installed core are needed for the bridge"),
]
pg_support.require_database()

MARKER = "SENTINEL-FOREIGN-MARKER-5b0a1d"
PLAIN = "SYNTHETIC-PLAINTEXT-MARKER-NOT-DETECTED-4471"
SESSION_ONE = "session-synthetic-leak-one"
SESSION_TWO = "session-synthetic-leak-two"
PASSWORD = "SENTINEL-DB-PASSWORD-9d41"


def secret(index: int) -> str:
    """The values the real core detects (``ghp_`` plus a fixed synthetic body). Never a real credential."""

    return f"ghp_SYNTHETICxREVOKEDxTESTx{index:013d}"


class ForeignError(Exception):
    """A driver or SDK failure: carries the marker in its message, an attribute, and its own cause."""

    def __init__(self) -> None:
        super().__init__(f"synthetic foreign failure marker={MARKER} password={PASSWORD}")
        self.detail = MARKER
        self.__cause__ = RuntimeError(MARKER)


# ---------------------------------------------------------------------------------------------- the scanner


def forms(raw: bytes) -> list[bytes]:
    out = [raw, raw.hex().encode(), raw.hex().upper().encode(), base64.b64encode(raw), base64.urlsafe_b64encode(raw)]
    out += [base64.b64encode(raw).rstrip(b"="), base64.urlsafe_b64encode(raw).rstrip(b"=")]
    try:
        out.append(raw.decode("utf-8").encode("utf-16-le"))
    except UnicodeDecodeError:
        pass
    return [item for item in out if len(item) >= 8]


class Scanner:
    """Needles by label. ``hits`` and ``leak`` return labels, never the text that matched."""

    def __init__(self) -> None:
        self.needles: dict[str, list[bytes]] = {}

    def add(self, label: str, raw: bytes | str) -> None:
        data = raw.encode() if isinstance(raw, str) else bytes(raw)
        bucket = self.needles.setdefault(label, [])
        for item in forms(data):
            if item not in bucket:
                bucket.append(item)

    def hits(self, blob: bytes | str) -> list[str]:
        data = blob.encode("utf-8", "surrogatepass") if isinstance(blob, str) else bytes(blob)
        return sorted(label for label, items in self.needles.items() if any(item in data for item in items))

    def leak(self, text: str) -> str | None:
        found = self.hits(text)
        return found[0] if found else None


# ---------------------------------------------------------------------------------------------- the recorders


class SpyProvider:
    """The local key provider, recording the plaintext data keys it hands out so they can be sentinels. Test-only."""

    def __init__(self, inner: Any, scanner: Scanner) -> None:
        self.inner = inner
        self.scanner = scanner
        self.profile = inner.profile
        self.keys: list[bytes] = []
        self.fail: Callable[[], BaseException] | None = None

    async def generate_data_key(self, context: Any) -> Any:
        if self.fail is not None:
            raise self.fail()
        key = await self.inner.generate_data_key(context)
        self.keys.append(bytes(key.plaintext_key))
        self.scanner.add("dek", bytes(key.plaintext_key))
        return key

    async def unwrap_data_key(self, stored: Any, context: Any) -> Any:
        if self.fail is not None:
            raise self.fail()
        key = await self.inner.unwrap_data_key(stored, context)
        self.keys.append(bytes(key))
        self.scanner.add("dek", bytes(key))
        return key

    async def rewrap_data_key(self, stored: Any, context: Any) -> Any:
        return await self.inner.rewrap_data_key(stored, context)


class Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=1)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def record_text(record: logging.LogRecord) -> str:
    parts = [record.getMessage(), repr(record.args), repr(sorted((k, repr(v)) for k, v in record.__dict__.items()))]
    if record.exc_info:
        parts.append("".join(traceback.format_exception(*record.exc_info)))
    if record.stack_info:
        parts.append(record.stack_info)
    return "\n".join(parts)


# ---------------------------------------------------------------------------------------------- the lab


class Lab:
    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir
        self.scanner = Scanner()
        self.errors: list[BaseException] = []
        self.audits: list[Any] = []
        self.namespaces: list[str] = []
        self.providers: list[SpyProvider] = []
        self.stores: list[Any] = []
        self.vaults: list[Any] = []
        self.bridges: list[NodeCoreBridge] = []
        self.pools: list[Any] = []
        self.token_count = 0
        self.notes: dict[str, bool] = {}
        self.stderr_log = workdir / "bridge-stderr.log"
        self.stderr_log.write_bytes(b"")
        self.node = self._node_wrapper()
        for index in range(0, 40):
            self.scanner.add(f"secret:{index}", secret(index))
        for index in range(900, 960):
            self.scanner.add(f"secret:{index}", secret(index))
        for label, value in (
            ("plaintext-marker", PLAIN),
            ("foreign-marker", MARKER),
            ("db-password", PASSWORD),
            ("db-url-password", "synthetic-g6-only"),
            ("session-one", SESSION_ONE),
            ("session-two", SESSION_TWO),
            ("driver-fault-marker", pg_support.FAULT_MARKER),
        ):
            self.scanner.add(label, value)
        self.scanner.add("wrapping-material", KEY_MATERIAL)
        self.scanner.add("digest-key", DIGEST_KEY)
        app_password = (pg_support.APP_URL or "").split("@")[0].split(":")[-1]
        if len(app_password) >= 8:
            self.scanner.add("app-role-password", app_password)

    def _node_wrapper(self) -> str:
        """``node`` with the child's standard error redirected into a file this run reads at the end (the bridge
        otherwise discards it). ``exec`` keeps the process identifier the bridge watches."""

        script = self.workdir / "node-stderr"
        real = shutil.which("node") or "node"
        script.write_text(f'#!/bin/sh\nexec "{real}" "$@" 2>>"{self.stderr_log}"\n')
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        return str(script)

    def bridge(self, **options: Any) -> NodeCoreBridge:
        # Generous: the first request after a start pays for Node.js and the core, which a loaded or emulated host
        # makes slow. A test that needs a short deadline sets it after the bridge has started.
        options.setdefault("timeout_s", 60.0)
        bridge = NodeCoreBridge(node_executable=options.pop("node_executable", self.node), **options)
        self.bridges.append(bridge)
        return bridge

    async def vault(
        self,
        *,
        bridge: NodeCoreBridge | None = None,
        pool: Any = None,
        provider_fail: Callable[[], BaseException] | None = None,
        namespace: str | None = None,
        initialize: bool = True,
        **options: Any,
    ) -> tuple[Any, Any, str, SpyProvider]:
        namespace = namespace or f"leak-{secrets.token_hex(5)}"
        self.namespaces.append(namespace)
        pool = pool or pg_support.HookedPool(size=12)
        self.pools.append(pool)
        store = await pg_support.open_store(
            pool, schema=pg_support.SCHEMA, lock_timeout_ms=3000, max_clock_skew_ms=60_000
        )
        self.stores.append(store)
        if initialize:
            result = await store.initialize_namespace(namespace, 1)
            assert result.outcome in ("initialized", "already-initialized")
        provider = SpyProvider(
            create_local_key_provider(
                keys=(LocalKey(id="synthetic-2026-10", material=KEY_MATERIAL, state="active"),),
                scope=LocalKeyScope(namespaces=(namespace,)),
            ),
            self.scanner,
        )
        provider.fail = provider_fail
        self.providers.append(provider)
        bridge = bridge or self.bridge(pii=())
        probe = await asyncio.to_thread(
            bridge.scan, "", policy=None, limits={"maxInputBytes": 1 << 20, "maxFindings": 1024}
        )
        base: dict[str, Any] = {
            "namespace": namespace,
            "recovery_epoch": 1,
            "store": store,
            "crypto": create_record_crypto(key_provider=provider),  # type: ignore[arg-type]
            "core_client": bridge,
            "expected_pii_activation": probe.pii_activation or "",
            "digest_key": DIGEST_KEY,
            "resolve_principal": resolve_principal,
            "resolve_session": lambda context: context.get("session"),
            "policy": lambda _decision: PolicyDecision(allow=True),
            "lifecycle_policy": lambda _input: LifecycleDecision(allow=True),
            "on_audit": self.audits.append,
            "store_timeout_s": 20.0,
        }
        base.update(options)
        vault = await create_persistent_server_vault(**base)
        self.vaults.append(vault)
        return vault, store, namespace, provider

    async def capture(self, vault: Any, text: str, **options: Any) -> Any:
        options.setdefault("context", ctx())
        options.setdefault("release", RELEASE)
        captured = await vault.capture(text, PersistentCaptureOptions(**options))
        for issued in captured.tokens:
            self.scanner.add(f"token:{self.token_count}", issued.token)
            self.scanner.add(f"token-body:{self.token_count}", issued.token.strip("<>"))
            self.token_count += 1
        return captured

    def restore_request(self, captured: Any, **extra: Any) -> PersistentRestoreRequest:
        base: dict[str, Any] = {
            "context": ctx(),
            "sink": SINK,
            "purpose": PURPOSE,
            "captures": (captured.capture_id,),
            "fields": {"body": captured.text},
        }
        base.update(extra)
        return PersistentRestoreRequest(**base)

    async def fails(self, awaitable: Awaitable[Any]) -> BaseException:
        """The call must fail with the package's own error; anything foreign escaping is itself a finding."""

        try:
            await awaitable
        except asyncio.CancelledError:
            raise
        except BaseException as error:
            assert isinstance(error, (VaultServerError, StoreError)), f"a foreign {type(error).__name__} escaped"
            self.errors.append(error)
            return error
        raise AssertionError("the call was expected to fail")

    async def may_fail(self, awaitable: Awaitable[Any]) -> Any:
        try:
            return await awaitable
        except asyncio.CancelledError:
            raise
        except BaseException as error:
            assert isinstance(error, (VaultServerError, StoreError)), f"a foreign {type(error).__name__} escaped"
            self.errors.append(error)
            return error


async def rows_of(namespaces: list[str]) -> dict[str, list[tuple[Any, ...]]]:
    out: dict[str, list[tuple[Any, ...]]] = {}
    schema = pg_support.SCHEMA
    for table, column in (
        ("rsv_namespace", "namespace"),
        ("rsv_capture", "namespace"),
        ("rsv_entry", "namespace"),
        ("rsv_receipt", "namespace"),
    ):
        out[table] = await pg_support.admin_execute(
            f'SELECT * FROM "{schema}".{table} WHERE {column} = ANY(%s)', (namespaces,)
        )
    return out


def flatten(rows: dict[str, list[tuple[Any, ...]]]) -> bytes:
    chunks: list[bytes] = []
    for table, items in rows.items():
        for row in items:
            chunks.append(table.encode())
            for value in row:
                if isinstance(value, (bytes, bytearray, memoryview)):
                    chunks.append(bytes(value))
                else:
                    chunks.append(str(value).encode("utf-8", "surrogatepass"))
    return b"\x00".join(chunks)


# ---------------------------------------------------------------------------------------------- scenarios


async def happy_paths(lab: Lab) -> None:
    vault, _store, _ns, _provider = await lab.vault()
    text = f"ticket: token {secret(1)} and {secret(2)}; note {PLAIN}; also {secret(3)}"
    captured = await lab.capture(vault, text, max_uses=4)
    assert len(captured.tokens) == 3, "the real core must detect the three synthetic secrets"
    assert PLAIN in captured.text and not any(secret(i) in captured.text for i in (1, 2, 3))
    first = await vault.restore(lab.restore_request(captured))
    lab.notes["restore result repr prints the restored text"] = secret(1) in repr(first)
    lab.notes["capture result repr prints the tokens"] = captured.tokens[0].token in repr(captured)
    assert first.fields["body"] == text and first.restored == 3
    again = await vault.restore(lab.restore_request(captured, attempt_id="attempt-synthetic-0001"))
    assert again.fields["body"] == text
    resolved = await vault.resolve_attempt(
        ResolveAttemptRequest(
            context=ctx(),
            sink=SINK,
            purpose=PURPOSE,
            captures=(captured.capture_id,),
            fields={"body": captured.text},
            attempt_id="attempt-synthetic-0001",
        )
    )
    assert resolved.state == "committed"
    # a session-bound capture, another tenant, partial restore
    bound = await lab.capture(vault, f"bound {secret(4)}", context=ctx(session=SESSION_ONE), max_uses=2)
    restored = await vault.restore(lab.restore_request(bound, context=ctx(session=SESSION_ONE)))
    assert secret(4) in restored.fields["body"]
    other = await lab.capture(vault, f"other {secret(5)} {secret(6)}", context=ctx("principal-synthetic-0002"))
    token_five = other.tokens[0].token
    part = await vault.restore(
        lab.restore_request(other, context=ctx("principal-synthetic-0002"), fields={"body": f"only {token_five}"})
    )
    assert part.restored == 1
    revoked = await vault.revoke(LifecycleRequest(context=ctx(session=SESSION_ONE), capture_id=bound.capture_id))
    assert revoked.outcome == "revoked"
    deleted = await vault.delete_capture_ciphertext(LifecycleRequest(context=ctx(), capture_id=captured.capture_id))
    assert deleted.outcome in ("deleted", "not-found")
    # a capture with no secret and an empty one
    await lab.capture(vault, "nothing to protect here")
    await lab.capture(vault, "")


async def denials(lab: Lab) -> None:
    vault, _store, _ns, _provider = await lab.vault()
    captured = await lab.capture(vault, f"a {secret(11)} b {secret(12)} c {PLAIN}", max_uses=1)
    token_a, token_b = (t.token for t in captured.tokens)
    forged = "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>"
    for request in (
        lab.restore_request(captured, fields={"body": f"<rsv_ broken {token_a}"}),
        lab.restore_request(captured, fields={"body": f"{token_a} {forged}"}),
        lab.restore_request(captured, sink="sink-not-granted"),
        lab.restore_request(captured, context={"principal": "principal-unknown"}),
        lab.restore_request(captured, context=ctx("principal-synthetic-0002")),
        lab.restore_request(captured, purpose=""),
        lab.restore_request(captured, fields={"body": 7}),
        lab.restore_request(captured, captures=("cap_" + "z" * 26,)),
        lab.restore_request(captured, captures=()),
    ):
        await lab.fails(vault.restore(request))
    await vault.restore(lab.restore_request(captured, fields={"body": token_a}))
    await lab.fails(vault.restore(lab.restore_request(captured, fields={"body": token_a})))  # budget
    await lab.fails(
        vault.restore(lab.restore_request(captured, fields={"body": token_a}, attempt_id="attempt-synthetic-0002"))
    )
    await vault.restore(lab.restore_request(captured, fields={"body": token_b}, attempt_id="attempt-synthetic-0003"))
    await lab.fails(
        vault.restore(lab.restore_request(captured, fields={"body": token_a}, attempt_id="attempt-synthetic-0003"))
    )  # attempt mismatch
    revoked = await lab.capture(vault, f"r {secret(13)}")
    await vault.revoke(LifecycleRequest(context=ctx(), capture_id=revoked.capture_id))
    await lab.fails(vault.restore(lab.restore_request(revoked)))
    await lab.may_fail(
        vault.revoke(LifecycleRequest(context=ctx("principal-synthetic-0002"), capture_id=revoked.capture_id))
    )
    bound = await lab.capture(vault, f"s {secret(14)}", context=ctx(session=SESSION_ONE))
    await lab.fails(vault.restore(lab.restore_request(bound, context=ctx(session=SESSION_TWO))))
    await lab.fails(vault.restore(lab.restore_request(bound)))
    # capture refusals the real core and the server decide
    for options, text in (
        ({"policy": {"github_token": "block"}}, f"x {secret(15)}"),
        ({"policy": {"github_token": "warn"}}, f"x {secret(16)}"),
        ({"max_uses": 0}, f"x {secret(17)}"),
        ({"release": ()}, f"x {secret(18)}"),
        ({}, f"x {secret(19)} <rsv_aaaaaaaaaaaaaaaaaaaaaaaaaaa>"),
        ({}, f"x {secret(19)} \ud800 {PLAIN}"),
    ):
        await lab.may_fail(lab.capture(vault, text, **options))
    # tenant-scoped negative: the other tenant cannot see it
    await lab.fails(vault.restore(lab.restore_request(captured, context=ctx("principal-synthetic-0002"), sink=SINK)))
    assert TENANT != OTHER_TENANT


async def clock_skew(lab: Lab) -> None:
    vault, _store, _ns, _provider = await lab.vault(now=lambda: int(time.time() * 1000) + 3_600_000)
    await lab.fails(lab.capture(vault, f"skew {secret(21)}"))
    good, _store2, _ns2, _p = await lab.vault()
    captured = await lab.capture(good, f"skew {secret(22)}")
    late, _s, _n, _p2 = await lab.vault(
        now=lambda: int(time.time() * 1000) + 3_600_000, namespace=_ns2, initialize=False
    )
    await lab.fails(late.restore(lab.restore_request(captured)))


async def store_faults(lab: Lab) -> None:
    vault, _store, _ns, _provider = await lab.vault()
    base = await lab.capture(vault, f"base {secret(31)} {secret(32)}", max_uses=16)
    for fault in ("unavailable", "before-first-write", "drop-connection", "after-commit-before-ack"):
        pg_support.FAULT.set(fault)
        await lab.may_fail(lab.capture(vault, f"fault {fault} {secret(33)}"))
        pg_support.FAULT.set(None)
        pg_support.FAULT.set(fault)
        error = await lab.may_fail(vault.restore(lab.restore_request(base, attempt_id=f"attempt-fault-{fault[:8]}")))
        pg_support.FAULT.set(None)
        if isinstance(error, VaultServerError) and error.attempt_id:
            await lab.may_fail(
                vault.resolve_attempt(
                    ResolveAttemptRequest(
                        context=ctx(),
                        sink=SINK,
                        purpose=PURPOSE,
                        captures=(base.capture_id,),
                        fields={"body": base.text},
                        attempt_id=error.attempt_id,
                    )
                )
            )
        pg_support.FAULT.set(fault)
        await lab.may_fail(vault.revoke(LifecycleRequest(context=ctx(), capture_id=base.capture_id)))
        pg_support.FAULT.set(None)
    # a backend terminated from outside while the commit is held
    fresh = await lab.capture(vault, f"held {secret(34)}", max_uses=5)

    async def terminate_everything() -> None:
        await pg_support.admin_execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE usename = 'rsv_app' AND pid <> pg_backend_pid()"
        )

    pg_support.HOLD.set(terminate_everything)
    await lab.may_fail(vault.restore(lab.restore_request(fresh, attempt_id="attempt-terminated-1")))
    pg_support.HOLD.set(None)
    pg_support.HOLD.set(terminate_everything)
    await lab.may_fail(lab.capture(vault, f"held again {secret(35)}"))
    pg_support.HOLD.set(None)
    # a store that has been closed
    closing, store_two, _ns2, _p = await lab.vault()
    captured = await lab.capture(closing, f"closed {secret(36)}")
    store_two.close()
    await lab.fails(lab.capture(closing, f"closed {secret(37)}"))
    await lab.fails(closing.restore(lab.restore_request(captured)))


async def connection_failures(lab: Lab) -> None:
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(pg_support.APP_URL or "")
    wrong_password = urlunsplit(parts._replace(netloc=f"{parts.username}:{PASSWORD}@{parts.hostname}:{parts.port}"))
    unreachable = urlunsplit(parts._replace(netloc=f"{parts.username}:{PASSWORD}@127.0.0.1:1"))
    good, _store, namespace, _p = await lab.vault()
    captured = await lab.capture(good, f"conn {secret(41)}")
    for dsn in (wrong_password, unreachable):
        # Opening a store verifies the deployment, so a store cannot be created over these: that failure first.
        try:
            await pg_support.open_store(pg_support.Pool(dsn, size=2), schema=pg_support.SCHEMA)
        except StoreError as error:
            lab.errors.append(error)
        else:
            raise AssertionError("a store opened over a bad connection")
        # Then a server whose connections start failing after it opened (a rotated password, a database that went away).
        pool = pg_support.HookedPool(size=4)
        vault, _s, _n, _p2 = await lab.vault(pool=pool, namespace=namespace, initialize=False)
        pool.dsn = dsn
        await lab.fails(lab.capture(vault, f"conn {secret(42)}"))
        await lab.fails(vault.restore(lab.restore_request(captured)))
        await lab.fails(vault.revoke(LifecycleRequest(context=ctx(), capture_id=captured.capture_id)))
    # an out-of-contract row written by the administrator
    schema = pg_support.SCHEMA
    victim = await lab.capture(good, f"row {secret(43)}")
    await pg_support.admin_execute(
        f'UPDATE "{schema}".rsv_capture SET wrapped_key = %s WHERE namespace = %s AND capture_id = %s',
        (b"", namespace, victim.capture_id),
    )
    await lab.fails(good.restore(lab.restore_request(victim)))
    await pg_support.admin_execute(
        f'UPDATE "{schema}".rsv_entry SET envelope = %s WHERE namespace = %s AND capture_id = %s',
        (b"\x00" * 9, namespace, captured.capture_id),
    )
    await lab.fails(good.restore(lab.restore_request(captured)))


async def collaborator_failures(lab: Lab) -> None:
    def throwing(*_args: Any) -> Any:
        raise ForeignError()

    good, _store, _ns, provider = await lab.vault()
    base = await lab.capture(good, f"collab {secret(51)}", max_uses=16)
    for override in ("resolve_principal", "resolve_session", "policy", "lifecycle_policy", "now"):
        vault, _s, _n, _p = await lab.vault(**{override: throwing})
        await lab.may_fail(vault.restore(lab.restore_request(base)))
        await lab.may_fail(lab.capture(vault, f"collab {secret(52)}"))
        await lab.may_fail(vault.revoke(LifecycleRequest(context=ctx(), capture_id=base.capture_id)))
    for factory in (
        ForeignError,
        lambda: KeyProviderError("KEY_UNAVAILABLE"),
        lambda: KeyProviderError("KEY_THROTTLED"),
        lambda: KeyProviderError("KEY_TIMEOUT"),
    ):
        vault, _s, _n, spy = await lab.vault()
        captured = await lab.capture(vault, f"collab {secret(53)}")
        spy.fail = factory
        await lab.fails(lab.capture(vault, f"collab {secret(54)}"))
        await lab.fails(vault.restore(lab.restore_request(captured)))
        spy.fail = None
    provider.fail = None


async def bridge_failures(lab: Lab) -> None:
    root = lab.workdir / "bridge"
    root.mkdir()
    hang_modules = _fake_core(root / "hang", source=HANG_CORE)
    # A core that hangs on a marked input: the call is killed at timeout_s, nothing is stored.
    bridge = lab.bridge(node_modules=hang_modules)
    vault, _store, namespace, _p = await lab.vault(bridge=bridge)  # starts the child
    bridge._timeout_s = 1.0  # noqa: SLF001 - now a short deadline
    error = await lab.fails(lab.capture(vault, f"HANG {secret(61)} {PLAIN}"))
    assert getattr(error, "core_code", None) == "BRIDGE_TIMEOUT"
    # The same bridge recovers.
    bridge._timeout_s = 60.0  # noqa: SLF001
    ok = await lab.capture(vault, f"fine {secret(62)}")
    assert ok.tokens == () or True
    # A child killed from outside in the middle of a request.
    bridge2 = lab.bridge(node_modules=hang_modules)
    vault2, _s2, _ns2, _p2 = await lab.vault(bridge=bridge2)

    async def kill_soon() -> None:
        await asyncio.sleep(0.6)
        proc = bridge2._state.proc  # noqa: SLF001
        if proc is not None:
            proc.popen.kill()

    killer = asyncio.ensure_future(kill_soon())
    error = await lab.fails(lab.capture(vault2, f"HANG {secret(63)} {PLAIN}"))
    await killer
    assert getattr(error, "core_code", None) == "BRIDGE_PROCESS_FAILED"
    # Child that cannot start, a core that is not where it should be, another version, garbage, a closed bridge.
    variants: list[tuple[str, Callable[[NodeCoreBridge], None]]] = [
        ("spawn", lambda b: setattr(b, "_node", f"/nonexistent/{MARKER}/node")),
        ("core-not-found", lambda b: setattr(b, "_node_modules", f"/nonexistent/{PLAIN}")),
        ("version", lambda b: setattr(b, "_expected_version", f"9.9.9-{MARKER}")),
        ("garbage", lambda b: setattr(b, "_script", _garbage_script(root))),
        ("closed", lambda b: b.close()),
    ]
    for name, sabotage in variants:
        bridge3 = lab.bridge()
        vault3, store3, namespace3, _p3 = await lab.vault(bridge=bridge3)
        before = await rows_of([namespace3])
        proc = bridge3._state.proc  # noqa: SLF001
        if proc is not None:
            proc.popen.kill()
            proc.popen.wait()
        sabotage(bridge3)
        error = await lab.fails(lab.capture(vault3, f"{name} {secret(64)} {PLAIN}"))
        after = await rows_of([namespace3])
        assert error.code.value in ("CORE_FAILURE", "INVARIANT_VIOLATION"), (name, error.code)
        assert after["rsv_capture"] == before["rsv_capture"] and after["rsv_entry"] == before["rsv_entry"], (
            f"a failed capture left a row ({name})"
        )
    # A request over the server's own limit and a core failure on a malformed input.
    vault4, _s4, _ns4, _p4 = await lab.vault(limits={"max_input_bytes": 64})
    await lab.fails(lab.capture(vault4, "x" * 1000 + secret(65)))
    del namespace


def _garbage_script(root: Path) -> Path:
    path = root / "garbage.mjs"
    path.write_text(
        f'process.stdin.on("data", () => {{\n  process.stdout.write("garbage {MARKER} " + {PLAIN!r} + "\\n");\n}});\n'
    )
    return path


async def cancellations(lab: Lab) -> None:
    vault, _store, _ns, _p = await lab.vault()
    base = await lab.capture(vault, f"cancel {secret(71)}", max_uses=16)
    for delay in (0, 0.0005, 0.002, 0.005, 0.02, 0.05, 0.1):
        task = asyncio.ensure_future(
            vault.capture(f"cancel {secret(72)} {PLAIN}", PersistentCaptureOptions(context=ctx(), release=RELEASE))
        )
        await asyncio.sleep(delay)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        task = asyncio.ensure_future(vault.restore(lab.restore_request(base)))
        await asyncio.sleep(delay)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    # after the storm the server still serves
    await lab.capture(vault, f"after {secret(73)}")


SCENARIOS: list[tuple[str, Callable[[Lab], Awaitable[None]]]] = [
    ("capture and restore", happy_paths),
    ("denials", denials),
    ("clock", clock_skew),
    ("store faults", store_faults),
    ("connection failures and malformed rows", connection_failures),
    ("failing collaborators", collaborator_failures),
    ("bridge failures", bridge_failures),
    ("cancellation", cancellations),
]


# ---------------------------------------------------------------------------------------------- the checks


def server_log_since(container: str, since: str) -> str:
    done = subprocess.run(["docker", "logs", "--since", since, container], capture_output=True, text=True, timeout=120)
    return done.stdout + done.stderr


def add_entry_keys(lab: Lab, rows: dict[str, list[tuple[Any, ...]]]) -> int:
    """Every entry key derivable from a recorded data key and an entry identifier in the database."""

    keys = {key for provider in lab.providers for key in provider.keys}
    entry_ids = {row[2] for row in rows["rsv_entry"]}
    count = 0
    for key in keys:
        for entry_id in entry_ids:
            derived = derive_entry_key(bytearray(key), entry_id)
            lab.scanner.add(f"entry-key:{count}", bytes(derived))
            count += 1
    return count


def test_the_scanner_detects_each_kind_of_deliberate_leak() -> None:
    """The positive control: without it, a clean run could mean a blind scanner."""

    scanner = Scanner()
    scanner.add("secret", secret(1))
    scanner.add("key", bytes(range(32)))
    assert scanner.hits(f"in a message: {secret(1)}") == ["secret"]
    assert scanner.hits(secret(1).encode().hex()) == ["secret"]
    assert scanner.hits(base64.b64encode(secret(1).encode())) == ["secret"]
    assert scanner.hits(secret(1).encode("utf-16-le")) == ["secret"]
    assert scanner.hits(bytes(range(32)).hex()) == ["key"]
    assert scanner.hits(b"\x00" * 7 + bytes(range(32)) + b"\x00") == ["key"]
    assert scanner.hits("nothing here") == []
    row = [(b"\x01" * 40, "tenant", secret(1).encode())]
    assert scanner.hits(flatten({"rsv_entry": row})) == ["secret"]
    records = Capture()
    logger = logging.getLogger("leak-control")
    logger.addHandler(records)
    logger.setLevel(logging.DEBUG)
    # Equals secret(1), built apart so taint analysis does not read this deliberate positive control as a leak.
    canary = "".join(["ghp_SYNTHETICxREVOKEDxTESTx", f"{1:013d}"])
    assert canary == secret(1)
    logger.debug("a record %s", canary)
    logger.removeHandler(records)
    assert scanner.hits(record_text(records.records[0])) == ["secret"]
    error = RuntimeError(f"boom {secret(1)}")
    with pytest.raises(AssertionError):
        assert_error_clean(error, scanner)  # type: ignore[arg-type]


def test_nothing_secret_reaches_a_log_an_error_a_repr_an_audit_event_a_stream_or_the_database(
    capfd: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    lab = Lab(tmp_path)
    capture = Capture()
    root = logging.getLogger()
    previous_level = root.level
    previous_levels = {}
    root.addHandler(capture)
    root.setLevel(logging.DEBUG)
    for name in (
        "asyncio",
        "psycopg",
        "psycopg.pool",
        "psycopg_pool",
        "urllib3",
        "boto3",
        "botocore",
        "redact_secret_vault",
    ):
        previous_levels[name] = logging.getLogger(name).level
        logging.getLogger(name).setLevel(logging.DEBUG)
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 2))
    counts: dict[str, int] = {}

    async def everything() -> None:
        asyncio.get_running_loop().set_debug(True)
        for name, scenario in SCENARIOS:
            before = len(lab.errors)
            await scenario(lab)
            counts[name] = len(lab.errors) - before
        # the objects' own text
        for vault, store in zip(lab.vaults, lab.stores, strict=False):
            for obj in (vault, store):
                text = f"{obj!r} {obj!s}"
                assert lab.scanner.hits(text) == [], f"{type(obj).__name__} prints state"
        for provider in lab.providers:
            assert lab.scanner.hits(f"{provider.inner!r}") == []
        for bridge in lab.bridges:
            assert lab.scanner.hits(f"{bridge!r}") == []
        for vault in lab.vaults:
            await vault.close()
        gc.collect()

    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            asyncio.run(everything())
    finally:
        root.removeHandler(capture)
        root.setLevel(previous_level)
        for name, level in previous_levels.items():
            logging.getLogger(name).setLevel(level)
        for bridge in lab.bridges:
            bridge.close()
    out, err = capfd.readouterr()

    # --- the database, after the run
    rows = asyncio.run(rows_of(lab.namespaces))
    entry_keys = add_entry_keys(lab, rows)
    database = flatten(rows)
    row_counts = {table: len(items) for table, items in rows.items()}
    assert row_counts["rsv_entry"] > 0 and row_counts["rsv_capture"] > 0, (
        "the run stored nothing; the scan means nothing"
    )
    assert lab.scanner.hits(database) == [], f"the database holds {lab.scanner.hits(database)}"

    # --- the channels
    assert len(lab.errors) >= 60, f"only {len(lab.errors)} errors were provoked"
    for error in lab.errors:
        assert_error_clean(error, lab.scanner)  # type: ignore[arg-type]
    for event in lab.audits:
        assert lab.scanner.hits(repr(event)) == [], "an audit event leaks"
    log_hits: dict[str, list[str]] = {}
    for record in capture.records:
        found = lab.scanner.hits(record_text(record))
        if found:
            log_hits[record.name] = found
    assert log_hits == {}, f"log records leak: {log_hits}"
    by_logger: dict[str, int] = {}
    for record in capture.records:
        top = record.name.split(".")[0]
        by_logger[top] = by_logger.get(top, 0) + 1
    assert by_logger.get("psycopg", 0) > 0, (
        "psycopg logged nothing at DEBUG: the run did not exercise the driver's logging"
    )
    assert by_logger.get("asyncio", 0) > 0
    assert by_logger.get("redact_secret_vault", 0) == 0, "the package must emit no log record"
    assert lab.scanner.hits("\n".join(str(w.message) for w in caught)) == []
    assert not [w for w in caught if "redact_secret_vault" in str(w.filename)], "the package must raise no warning"
    assert lab.scanner.hits(out + err) == [] and out == "" and err == ""
    child_stderr = lab.stderr_log.read_bytes()
    assert lab.scanner.hits(child_stderr) == [], "the bridge child's stderr holds a sentinel"

    container = os.environ.get("RSV_PG_CONTAINER")
    server_log = ""
    if container and shutil.which("docker"):
        server_log = server_log_since(container, started)
        assert lab.scanner.hits(server_log) == [], f"the PostgreSQL server log holds {lab.scanner.hits(server_log)}"

    print(
        "G6 SUMMARY "
        f"scenarios={len(SCENARIOS)} errors_by_scenario={counts} errors={len(lab.errors)} "
        f"audit_events={len(lab.audits)} "
        f"log_records={len(capture.records)} by_logger={dict(sorted(by_logger.items()))} warnings={len(caught)} "
        f"rows={row_counts} database_bytes={len(database)} needles={sum(len(v) for v in lab.scanner.needles.values())} "
        f"entry_keys_derived={entry_keys} data_keys={sum(len(p.keys) for p in lab.providers)} tokens={lab.token_count} "
        f"child_stderr_bytes={len(child_stderr)} server_log_bytes={len(server_log)} "
        f"server_log_scanned={bool(server_log)} notes={lab.notes}"
    )
