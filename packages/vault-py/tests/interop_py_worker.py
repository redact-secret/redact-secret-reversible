"""Test tooling for the cross-language runs (docs/plans/python-persistence-parity.md sections 5.4 and 6.1): one Python
persistent server process over PostgreSQL, speaking the same line protocol as ``interop_js_worker.mjs``.

It builds what an application process would build for itself: its own pool, the PostgreSQL adapter, the local key
provider, record crypto, the Node.js core bridge, and a persistent server. It shares nothing with the JavaScript process
except the database and the key material, which the test generates per run and passes as hex.

Configuration: ``RSV_INTEROP_CONFIG`` = ``{url, schema, namespace, epoch, keyHex, digestHex, poolMax}``. Requests are
``{id, op, args}``; answers ``{id, reply}``; events ``{event: "ready" | "held", ...}``. The hold point and the answers
mirror the JavaScript worker's. Synthetic values only; no restored value is logged.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
for _path in (_HERE, _HERE.parent / "src"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import pg_support  # noqa: E402
import schedule_driver  # noqa: E402

from redact_secret_vault import CaptureGrant, NodeCoreBridge, PolicyDecision, Principal, VaultServerError  # noqa: E402
from redact_secret_vault.crypto import (  # noqa: E402
    LocalKey,
    LocalKeyScope,
    create_local_key_provider,
    create_record_crypto,
)
from redact_secret_vault.persistent import (  # noqa: E402
    LifecycleDecision,
    LifecycleRequest,
    PersistentCaptureOptions,
    PersistentRestoreRequest,
    StoreError,
    create_persistent_server_vault,
)


def write(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def settle_failure(error: VaultServerError) -> dict[str, Any]:
    return {
        "ok": False,
        "name": "VaultServerError",
        "code": error.code.value,
        "reason": None if error.reason is None else error.reason.value,
        "attemptId": error.attempt_id,
        "hasFields": False,
    }


def restore_request(data: dict[str, Any]) -> PersistentRestoreRequest:
    return PersistentRestoreRequest(
        context=data["context"],
        sink=data["sink"],
        purpose=data["purpose"],
        captures=tuple(data["captures"]),
        fields=data["fields"],
        attempt_id=data.get("attemptId"),
    )


async def main() -> None:
    config = json.loads(os.environ["RSV_INTEROP_CONFIG"])
    namespace = config["namespace"]
    pool = pg_support.HookedPool(config["url"], size=config.get("poolMax", 20))
    store_options = {"lock_timeout_ms": 2000, "max_clock_skew_ms": 2000}
    for name, option in (
        ("lockTimeoutMs", "lock_timeout_ms"),
        ("statementTimeoutMs", "statement_timeout_ms"),
        ("maxClockSkewMs", "max_clock_skew_ms"),
    ):
        if name in (config.get("storeOptions") or {}):
            store_options[option] = config["storeOptions"][name]
    store = await pg_support.open_store(pool, schema=config.get("schema"), **store_options)
    crypto = create_record_crypto(
        key_provider=create_local_key_provider(
            # The same key identifier as the JavaScript worker, so the key reference is the same string.
            keys=(LocalKey(id="synthetic-1", material=bytes.fromhex(config["keyHex"]), state="active"),),
            scope=LocalKeyScope(namespaces=(namespace,)),
        )
    )
    bridge = NodeCoreBridge(pii=())
    activation = (
        await asyncio.to_thread(bridge.scan, "", policy=None, limits={"maxInputBytes": 1 << 20, "maxFindings": 1024})
    ).pii_activation
    vault = await create_persistent_server_vault(
        namespace=namespace,
        recovery_epoch=config.get("epoch", 1),
        store=store,
        crypto=crypto,
        core_client=bridge,
        expected_pii_activation=activation or "",
        digest_key=bytes.fromhex(config["digestHex"]),
        # The trusted context of these runs, as in the JavaScript worker: the transport has authenticated it.
        resolve_principal=lambda context: Principal(
            id=context.get("principal", "user-synthetic-1"), tenant=context["tenant"]
        ),
        resolve_session=lambda context: context.get("session"),
        policy=lambda _decision: PolicyDecision(allow=True),
        lifecycle_policy=lambda _input: LifecycleDecision(allow=True),
        **(
            {"store_timeout_s": config["vaultOptions"]["storeTimeoutMs"] / 1000}
            if "storeTimeoutMs" in (config.get("vaultOptions") or {})
            else {}
        ),
    )
    releases: dict[str, asyncio.Event] = {}

    async def settle(work: Any) -> dict[str, Any]:
        try:
            return {"ok": True, "value": await work}
        except VaultServerError as error:
            return settle_failure(error)
        except StoreError as error:
            return {"ok": False, "name": "StoreError", "code": error.code, "reason": None, "attemptId": None}
        except Exception:  # noqa: BLE001 - a foreign failure is reported by shape only
            schedule_driver._debug()
            return {"ok": False, "name": "Error", "code": "INTERNAL", "reason": None, "attemptId": None}

    def plain_capture(result: Any) -> dict[str, Any]:
        return {
            "captureId": result.capture_id,
            "text": result.text,
            "tokens": [{"token": item.token, "type": item.type} for item in result.tokens],
        }

    def plain_restore(result: Any) -> dict[str, Any]:
        return {"fields": dict(result.fields), "restored": result.restored, "attemptId": result.attempt_id}

    async def capture(args: dict[str, Any]) -> dict[str, Any]:
        options = PersistentCaptureOptions(
            context=args["context"],
            release=tuple(CaptureGrant(sink=g["sink"], paths=tuple(g["paths"])) for g in args["release"]),
            **({"max_uses": args["maxUses"]} if args.get("maxUses") is not None else {}),
        )

        async def go() -> Any:
            return plain_capture(await vault.capture(args["text"], options))

        return await settle(go())

    async def restore(args: dict[str, Any]) -> dict[str, Any]:
        async def go() -> Any:
            return plain_restore(await vault.restore(restore_request(args["request"])))

        return await settle(go())

    async def burst(args: dict[str, Any]) -> list[dict[str, Any]]:
        return list(await asyncio.gather(*(restore({"request": request}) for request in args["requests"])))

    async def revoke(args: dict[str, Any]) -> dict[str, Any]:
        async def go() -> Any:
            result = await vault.revoke(LifecycleRequest(context=args["context"], capture_id=args["captureId"]))
            return {"outcome": result.outcome, "entries": result.entries}

        return await settle(go())

    async def resolve_attempt(args: dict[str, Any]) -> dict[str, Any]:
        async def go() -> Any:
            result = await vault.resolve_attempt(restore_request(args["request"]))
            return {"state": result.state, "committedAt": result.committed_at}

        return await settle(go())

    async def store_op(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await schedule_driver._call(store, args["method"], args.get("input") or {})
            return {"result": schedule_driver.encode(result)}
        except StoreError as error:
            return {"error": error.code}

    async def handle(message: dict[str, Any]) -> None:
        op, args = message["op"], message.get("args") or {}
        if op == "capture":
            reply: Any = await capture(args)
        elif op == "restore":
            reply = await restore(args)
        elif op == "burst":
            reply = await burst(args)
        elif op == "revoke":
            reply = await revoke(args)
        elif op == "resolveAttempt":
            reply = await resolve_attempt(args)
        elif op == "store":
            reply = await store_op(args)
        elif op == "arm-hold":
            hold_id = args["holdId"]
            released = releases[hold_id] = asyncio.Event()

            async def pause() -> None:
                write({"event": "held", "holdId": hold_id})
                await released.wait()

            # The next write transaction of this process pauses before COMMIT. The hook is armed per task in the
            # test driver; here one process-wide slot serves the next call that reaches a COMMIT.
            pg_support.HOLD_NEXT.append(pause)
            reply = {"ok": True}
        elif op == "release":
            event = releases.pop(args["holdId"], None)
            if event is not None:
                event.set()
            reply = {"ok": True}
        else:
            reply = {"ok": False, "code": "UNKNOWN_OPERATION"}
        write({"id": message["id"], "reply": reply})

    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=1 << 26)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    write({"event": "ready"})
    pending: set[asyncio.Task[None]] = set()
    while True:
        line = await reader.readline()
        if not line:
            break
        if not line.strip():
            continue
        message = json.loads(line)
        if message["op"] == "exit":
            await vault.close()
            break
        task = asyncio.ensure_future(handle(message))
        pending.add(task)
        task.add_done_callback(pending.discard)
    if pending:
        await asyncio.gather(*pending)


if __name__ == "__main__":
    asyncio.run(main())
