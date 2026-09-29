// B5 (#79), mode pair 2: Python ÷ JS on the same workload. The Python
// package (`packages/vault-py`, `redact-secret-vault`) implements the server
// authority contract natively but detects through `NodeCoreBridge`, which
// spawns one Node.js process per scan (core_client.py, `subprocess.run`), so
// its JS counterpart is `@redact-secret/vault-server` in-process.
//
// The Python side runs in one `python` process per run() call
// (bench/python/mode_python_driver.py, with PYTHONPATH at the workspace
// `packages/vault-py/src`, so no install is needed and an installed copy is
// never measured). It returns timing samples only. Per iteration it times,
// in rotating order, a bare `node -e ""` spawn, a bridge scan of an empty
// string, a bridge scan of the input, and a whole server capture; then one
// restore. From those, paired within each iteration:
//
//   python.bridge.startup_ms    scan("") − node_spawn: bridge script, core load and initialize
//   python.bridge.scan_work_ms  scan(input) − scan(""): the scan itself, seen from Python
//   python.capture.native_ms    capture − scan(input): Python's own capture work
//
// so process spawn is reported apart from scan time (#79's acceptance).
// The JS side times `vaultServer.capture`, `vaultServer.restore`, and
// `core.scan` on the same input in this process.
//
// Candidate-only: Python exists only for the workspace, so a published side
// skips (and so does the whole metric in `bench:compare`). It also skips when
// no Python >= 3.10 is found or the package does not import; the harness
// never fails for lack of Python. Interpreter: $BENCH_PYTHON, else
// `.venv/bin/python` at the repository root or in packages/vault-py, else
// `python3` on PATH. Python iterations are capped (subprocess per scan):
// quick 5 after 1, full 30 after 3, or fewer if --iterations/--warmup are
// lower. Nothing here gates: every measurement is `gating: false`.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const id = "mode-python";
export const issue = 79;
export const title = "Mode boundary cost: Python bridge vs JS";
export const piiModes = ["off"];

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const DRIVER = join(ROOT, "bench", "python", "mode_python_driver.py");
const PY_SRC = join(ROOT, "packages", "vault-py", "src");
const SKIP_CODES = new Set(["PYTHON_TOO_OLD", "PACKAGE_NOT_IMPORTABLE"]);

const SINK = "bench-sink";
const PURPOSE = "bench-purpose";
const TENANT = "bench-tenant";

function pythonCandidates() {
  const out = [];
  if (process.env.BENCH_PYTHON) out.push(process.env.BENCH_PYTHON);
  for (const dir of [ROOT, join(ROOT, "packages", "vault-py")]) {
    const venv = join(dir, ".venv", "bin", "python");
    if (existsSync(venv)) out.push(venv);
  }
  out.push("python3");
  return out;
}

function median(samples) {
  const sorted = [...samples].sort((x, y) => x - y);
  const mid = sorted.length >> 1;
  return sorted.length % 2 === 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

const round4 = (x) => Math.round(x * 10_000) / 10_000;
const diff = (b, a) => b.map((x, i) => x - a[i]);

function expectCount(actual, expected, what) {
  if (actual !== expected) throw new Error(`${what}: expected ${expected}, got ${actual}`);
}

/** Runs the driver; returns its samples, or calls ctx.skip when Python is unusable. */
function runPython(ctx, request) {
  const timeout = 30_000 + (request.warmup + request.iterations) * 5_000;
  const env = { ...process.env, PYTHONPATH: PY_SRC, PYTHONDONTWRITEBYTECODE: "1" };
  delete env.REDACT_SECRET_VAULT_NODE_MODULES;
  for (const python of pythonCandidates()) {
    const proc = spawnSync(python, [DRIVER], { input: JSON.stringify(request), env, encoding: "utf8", timeout });
    if (proc.error?.code === "ENOENT") continue;
    if (proc.error !== undefined) throw Object.assign(new Error("python driver failed"), { code: proc.error.code ?? "PYTHON_SPAWN_FAILED" });
    let data;
    try {
      data = JSON.parse(proc.stdout);
    } catch {
      throw Object.assign(new Error("python driver output"), { code: "PYTHON_BAD_OUTPUT" });
    }
    if (typeof data.error === "string") {
      if (SKIP_CODES.has(data.error)) ctx.skip(`python: ${data.error}`);
      const failure = new Error("python driver error");
      failure.code = data.error.slice(0, 80);
      throw failure;
    }
    return data;
  }
  return ctx.skip("no python interpreter found");
}

async function measureJs(ctx, server, iterations, warmup) {
  const item = ctx.corpus.items.capture1k;
  const expected = item.findings.piiOff;
  const { core } = ctx;
  const limits = { maxInputBytes: ctx.vault.DEFAULT_LIMITS.maxInputBytes, maxFindings: ctx.vault.DEFAULT_LIMITS.maxFindings };
  const release = [{ sink: SINK, paths: ["body"] }];

  const scan = await ctx.sample({
    iterations,
    warmup,
    setup: () => ({}),
    op: (state) => {
      state.n = core.scan(item.input, { limits }).length;
    },
    teardown: (state) => expectCount(state.n, expected, "core findings"),
  });
  const capture = await ctx.sample({
    iterations,
    warmup,
    setup: () => ({}),
    op: async (state) => {
      state.c = await server.capture(item.input, { release, issuedTenant: TENANT });
    },
    teardown: async (state) => {
      expectCount(state.c.tokens.length + state.c.unrestorable, expected, "server capture findings");
      await server.revoke(state.c.captureId);
    },
  });
  const { fields: templates, usesPerToken } = ctx.corpus.items.restore64;
  const restoreOptions = { release: [{ sink: SINK, paths: templates.map((f) => f.path) }], maxUses: usesPerToken, issuedTenant: TENANT };
  const restore = await ctx.sample({
    iterations,
    warmup,
    setup: async () => {
      const c = await server.capture(item.input, restoreOptions);
      const fields = {};
      for (const f of templates) fields[f.path] = f.before + c.tokens[f.slot].token + f.after;
      return { id: c.captureId, request: { context: { tenant: TENANT }, sink: SINK, purpose: PURPOSE, captures: [c.captureId], fields } };
    },
    op: async (state) => {
      state.n = (await server.restore(state.request)).restored;
    },
    teardown: async (state) => {
      expectCount(state.n, templates.length, "server restored occurrences");
      await server.revoke(state.id);
    },
  });
  return { scan, capture, restore, limits };
}

export async function run(ctx) {
  if (ctx.side.source !== "workspace") ctx.skip("python is measured for the workspace candidate only");
  if (ctx.vaultServer === null) ctx.skip("no @redact-secret/vault-server on this side");

  const pyIterations = Math.min(ctx.iterations, ctx.quick ? 5 : 30);
  const pyWarmup = Math.min(ctx.warmup, ctx.quick ? 1 : 3);
  const item = ctx.corpus.items.capture1k;
  const expected = item.findings.piiOff;
  const { fields: templates, usesPerToken } = ctx.corpus.items.restore64;

  const server = await ctx.vaultServer.createServerVault({
    resolvePrincipal: (context) => ({ id: "bench-principal", tenant: context.tenant }),
    policy: () => ({ allow: true }),
    // As in mode-server: forget revoked captures at once, so the JS figures
    // do not grow with the iteration count (see that file's header).
    revocationMemoryMs: 0,
  });
  let js;
  try {
    js = await measureJs(ctx, server, ctx.iterations, ctx.warmup);
  } finally {
    await server.dispose();
  }

  const py = runPython(ctx, {
    node: process.execPath,
    nodeModules: join(ROOT, "node_modules"),
    iterations: pyIterations,
    warmup: pyWarmup,
    input: item.input,
    expectedFindings: expected,
    limits: js.limits,
    restore: { fields: templates, usesPerToken },
  });
  const s = py.samples;
  for (const name of ["node_spawn", "bridge_scan_empty", "bridge_scan", "capture", "restore"]) {
    if (!(Array.isArray(s[name]) && s[name].length === pyIterations && s[name].every(Number.isFinite))) {
      throw Object.assign(new Error("python samples"), { code: "PYTHON_BAD_OUTPUT" });
    }
  }

  const pyParams = { python: String(py.python).slice(0, 16), item: "capture1k", inputBytes: item.bytes, findings: expected };
  const jsParams = { item: "capture1k", inputBytes: item.bytes, findings: expected };
  const restoreParams = { fields: templates.length, tokenOccurrences: templates.length };
  const lat = (name, samples, params) => ({ name, kind: "latency", unit: "ms", samples, params, gating: false });
  const ratio = (name, num, den, of, params) => ({
    name,
    kind: "deterministic",
    unit: "ratio",
    value: median(den) > 0 ? round4(median(num) / median(den)) : 0,
    params: { ...params, of },
    gating: false,
  });

  return [
    lat("python.node_spawn", s.node_spawn, pyParams),
    lat("python.bridge.scan_empty", s.bridge_scan_empty, pyParams),
    lat("python.bridge.scan", s.bridge_scan, pyParams),
    lat("python.bridge.startup_ms", diff(s.bridge_scan_empty, s.node_spawn), pyParams),
    lat("python.bridge.scan_work_ms", diff(s.bridge_scan, s.bridge_scan_empty), pyParams),
    lat("python.capture", s.capture, pyParams),
    lat("python.capture.native_ms", diff(s.capture, s.bridge_scan), pyParams),
    lat("python.restore", s.restore, { ...pyParams, ...restoreParams }),
    lat("js.core_scan", js.scan, jsParams),
    lat("js.server.capture", js.capture, jsParams),
    lat("js.server.restore", js.restore, restoreParams),
    ratio("capture.ratio", s.capture, js.capture, "p50 python capture / p50 js server capture", jsParams),
    ratio("scan.ratio", s.bridge_scan, js.scan, "p50 python bridge scan / p50 js core.scan", jsParams),
    ratio("restore.ratio", s.restore, js.restore, "p50 python restore / p50 js server restore", restoreParams),
    ratio("capture.spawn_share", s.bridge_scan_empty, s.capture, "p50 bridge scan('') / p50 python capture", pyParams),
  ];
}
