"""Python side of the B5 (#79) Python-vs-JS mode boundary metric.

Run by ``bench/metrics/mode-python.mjs`` with ``PYTHONPATH`` pointing at the
workspace ``packages/vault-py/src`` (never an installed copy). Reads one JSON
request from stdin and writes one JSON object of timing samples (milliseconds)
to stdout. It never writes an input, a token, or a restored value: stdout
carries numbers and fixed error codes only.

Request: {"node": str, "nodeModules": str, "iterations": int, "warmup": int,
          "input": str, "expectedFindings": int, "limits": {"maxInputBytes", "maxFindings"},
          "restore": {"fields": [{"path", "slot", "before", "after"}], "usesPerToken": int}}

Per iteration, in a rotating order so no step always runs first:
  node_spawn        subprocess.run([node, "-e", ""]): bare Node.js process start and exit
  bridge_start      a new NodeCoreBridge's first scan(""): spawn + bridge script + core load and
                    initialize, paid once per bridge process (#89); closing it is not timed
  bridge_scan_empty NodeCoreBridge.scan("") on the long-lived bridge: one request round trip, no scan work
  bridge_scan       NodeCoreBridge.scan(input) on the long-lived bridge
  capture           InMemoryVaultServer.capture(input): one bridge scan plus Python staging
The long-lived bridge serves every step but bridge_start; it is started once, untimed, before warmup.
Then, untimed, a capture for restore, and timed:
  restore           InMemoryVaultServer.restore of every restore field (pure Python, no subprocess)
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time


def _ms(start: int) -> float:
    return (time.perf_counter_ns() - start) / 1_000_000


def _fail(code: str) -> None:
    sys.stdout.write(json.dumps({"error": code}))
    sys.exit(0)


def main() -> None:
    # Read the whole request first, so an early exit never breaks the writer's pipe.
    req = json.loads(sys.stdin.read())
    if sys.version_info < (3, 10):
        _fail("PYTHON_TOO_OLD")
    try:
        from redact_secret_vault import (
            CaptureGrant,
            CaptureOptions,
            InMemoryVaultServer,
            NodeCoreBridge,
            PolicyDecision,
            Principal,
            RestoreRequest,
        )
    except ImportError:
        _fail("PACKAGE_NOT_IMPORTABLE")

    node = req["node"]
    text = req["input"]
    expected = req["expectedFindings"]
    templates = req["restore"]["fields"]
    uses = req["restore"]["usesPerToken"]
    sink, purpose, tenant = "bench-sink", "bench-purpose", "bench-tenant"

    bridge = NodeCoreBridge(node_executable=node, node_modules=req["nodeModules"])
    server = InMemoryVaultServer(
        core_client=bridge,
        principal_resolver=lambda context: Principal(id="bench-principal", tenant=context["tenant"]),
        release_policy=lambda _decision: PolicyDecision(allow=True),
    )
    limits = req["limits"]
    capture_options = CaptureOptions(issued_tenant=tenant, release=(CaptureGrant(sink=sink, paths=("body",)),))
    restore_options = CaptureOptions(
        issued_tenant=tenant,
        release=(CaptureGrant(sink=sink, paths=tuple(f["path"] for f in templates)),),
        max_uses=uses,
    )

    def node_spawn() -> None:
        proc = subprocess.run([node, "-e", ""], capture_output=True, check=False)
        if proc.returncode != 0:
            _fail("NODE_SPAWN_FAILED")

    def bridge_start() -> None:
        # Timed up to the first response; the loop closes the bridge after
        # the timer stops.
        fresh = NodeCoreBridge(node_executable=node, node_modules=req["nodeModules"])
        _close_later.append(fresh)
        if len(fresh.scan("", limits=limits).findings) != 0:
            _fail("UNEXPECTED_FINDINGS")

    def scan_empty() -> None:
        if len(bridge.scan("", limits=limits).findings) != 0:
            _fail("UNEXPECTED_FINDINGS")

    def scan_input() -> None:
        if len(bridge.scan(text, limits=limits).findings) != expected:
            _fail("UNEXPECTED_FINDINGS")

    def capture() -> None:
        result = server.capture(text, capture_options)
        if len(result.tokens) + result.unrestorable != expected:
            _fail("UNEXPECTED_FINDINGS")
        server.revoke(result.capture_id)

    _close_later: list = []
    steps = [
        ("node_spawn", node_spawn),
        ("bridge_start", bridge_start),
        ("bridge_scan_empty", scan_empty),
        ("bridge_scan", scan_input),
        ("capture", capture),
    ]
    samples: dict[str, list[float]] = {name: [] for name, _ in steps}
    samples["restore"] = []

    async def restore_once(record: bool) -> None:
        captured = server.capture(text, restore_options)
        fields = {f["path"]: f["before"] + captured.tokens[f["slot"]].token + f["after"] for f in templates}
        request = RestoreRequest(
            sink=sink,
            captures=(captured.capture_id,),
            fields=fields,
            purpose=purpose,
            tenant=tenant,
            context={"tenant": tenant},
        )
        start = time.perf_counter_ns()
        result = await server.restore(request)
        elapsed = _ms(start)
        if result.restored != len(templates):
            _fail("UNEXPECTED_RESTORE_COUNT")
        server.revoke(captured.capture_id)
        if record:
            samples["restore"].append(elapsed)

    async def loop() -> None:
        total = req["warmup"] + req["iterations"]
        for i in range(total):
            record = i >= req["warmup"]
            k = i % len(steps)
            for name, fn in steps[k:] + steps[:k]:
                start = time.perf_counter_ns()
                fn()
                elapsed = _ms(start)
                if record:
                    samples[name].append(elapsed)
                while _close_later:
                    _close_later.pop().close()
            await restore_once(record)

    try:
        bridge.scan("", limits=limits)  # start the long-lived bridge process, untimed
        asyncio.run(loop())
    except Exception as exc:  # report only a fixed code, never a message
        code = getattr(exc, "code", None)
        _fail(f"{type(exc).__name__}:{getattr(code, 'value', code)}"[:80])
    finally:
        server.dispose()
        bridge.close()

    sys.stdout.write(
        json.dumps(
            {
                "python": ".".join(str(p) for p in sys.version_info[:3]),
                "samples": samples,
            }
        )
    )


if __name__ == "__main__":
    main()
