#!/usr/bin/env node
/**
 * Qualified service boundary between the Python server authority package
 * (`redact-secret-vault`, #17) and the JavaScript-only
 * `@redact-secret/core` detection engine.
 *
 * No Python core package exists (verified against the `redact-secret/redact-secret`
 * GitHub organization on 2026-09-27: only `packages/javascript` exists there;
 * see docs/research/python-server-integration-2026-09-27.md). Rather than
 * reimplementing detection in Python — forbidden by AGENTS.md and
 * CONVENTIONS.md — the Python package shells out to this script, which calls
 * only the core's documented public `initialize`/`scan`/`piiActivation` APIs
 * and returns its safe finding metadata
 * (id/type/detector/confidence/obfuscation/start/end/action) as JSON. It
 * never returns a matched value: `scan` never receives or reports one, and
 * each finding is projected to exactly those eight fields before it is
 * written.
 *
 * Protocol: one JSON object read from stdin —
 *   { "input": string, "pii": string[], "policy"?: {[type: string]: SecretAction, default?: SecretAction}, "limits"?: {maxInputBytes, maxFindings}, "nodeModules"?: string }
 * — one JSON object written to stdout —
 *   { "findings": SafeFinding[], "coreVersion": string, "artifact": string, "piiActivation": string | null }
 *   or { "error": { "message": string, "code"?: string } } on failure.
 *
 * PII activation (docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md
 * §3 "Python bridge"): this process is a fresh realm with no other
 * initializer, so the Python caller's `pii` list is the only selection.
 * - Core exports `piiActivation` (beta.10+): `initialize({ pii })` verbatim,
 *   then report `piiActivation()`.
 * - No PII surface (beta.9) and `pii` is empty: plain `initialize()`, and
 *   report `piiActivation: null`. No identity string is invented.
 * - No PII surface and `pii` is non-empty: `{"error":{"code":"PII_UNAVAILABLE"}}`
 *   before the core is initialized or the input is scanned.
 * Selector grammar is the core's to judge (`PII_SELECTOR_*`); this script
 * only checks the request shape.
 *
 * Core location: when the request carries `nodeModules` (an absolute path
 * the application chose, via `NodeCoreBridge(node_modules=...)` or
 * `REDACT_SECRET_VAULT_NODE_MODULES`), `@redact-secret/core` is loaded from
 * exactly `<nodeModules>/@redact-secret/core`: its package.json `exports`
 * entry is resolved here and imported by file URL. There is no fallback to
 * parent directories and none to the working directory, so whoever controls
 * the cwd cannot substitute the core. Without `nodeModules`, the core is
 * resolved as a bare specifier relative to this script (the repository and
 * in-project-venv layouts). Either way, a core that cannot be found or
 * resolved yields `{"error":{"code":"BRIDGE_CORE_NOT_FOUND"}}` and one that
 * fails to load yields `BRIDGE_CORE_LOAD_FAILED`; neither echoes the path.
 * The Python caller still checks the reported `coreVersion` against its pin.
 *
 * This process is short-lived (one request per invocation) and trusted only
 * to run the pinned `@redact-secret/core` version from the location above;
 * it is not a network service and accepts no untrusted transport input
 * beyond stdin from its own Python caller.
 */

import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const CORE_PACKAGE = "@redact-secret/core";
// The conditions Node.js itself applies when importing an ES module.
const ESM_CONDITIONS = new Set(["node", "import", "default"]);
const MAX_NODE_MODULES_LENGTH = 4096;

const MAX_PII_SELECTORS = 64;
const MAX_PII_SELECTOR_LENGTH = 128;

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
    });
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

function makePolicy(spec) {
  if (spec === undefined || spec === null) return undefined;
  return { evaluate: (finding) => spec[finding.type] ?? spec.default ?? "redact" };
}

function isSelectorList(value) {
  return (
    Array.isArray(value) &&
    value.length <= MAX_PII_SELECTORS &&
    value.every((s) => typeof s === "string" && s.length > 0 && s.length <= MAX_PII_SELECTOR_LENGTH)
  );
}

function safeFinding(f) {
  return {
    id: f.id,
    type: f.type,
    detector: f.detector,
    confidence: f.confidence,
    obfuscation: f.obfuscation,
    start: f.start,
    end: f.end,
    action: f.action,
  };
}

function writeError(message, code) {
  process.stdout.write(JSON.stringify({ error: code === undefined ? { message } : { message, code } }));
}

function coreError(code) {
  return Object.assign(new Error(code === "BRIDGE_CORE_NOT_FOUND" ? "core not found" : "core failed to load"), {
    code,
  });
}

// First target whose condition Node.js would match, walking the conditions
// object in key order (Node's own rule), or undefined.
function conditionalTarget(entry) {
  if (typeof entry === "string") return entry;
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return undefined;
  for (const [condition, value] of Object.entries(entry)) {
    if (!ESM_CONDITIONS.has(condition)) continue;
    const target = conditionalTarget(value);
    if (target !== undefined) return target;
  }
  return undefined;
}

// The package's root entry point, relative to its directory.
function rootEntry(manifest) {
  const { exports } = manifest;
  if (exports === undefined) return typeof manifest.main === "string" ? manifest.main : "./index.js";
  if (exports !== null && typeof exports === "object" && !Array.isArray(exports)) {
    const keys = Object.keys(exports);
    if (keys.length > 0 && keys.every((key) => key.startsWith("."))) return conditionalTarget(exports["."]);
  }
  return conditionalTarget(exports);
}

async function loadCoreFrom(nodeModules) {
  if (nodeModules.length === 0 || nodeModules.length > MAX_NODE_MODULES_LENGTH || !path.isAbsolute(nodeModules)) {
    throw coreError("BRIDGE_CORE_NOT_FOUND");
  }
  const packageDir = path.join(nodeModules, "@redact-secret", "core");
  let manifest;
  try {
    manifest = JSON.parse(await readFile(path.join(packageDir, "package.json"), "utf8"));
  } catch {
    throw coreError("BRIDGE_CORE_NOT_FOUND");
  }
  if (manifest === null || typeof manifest !== "object" || manifest.name !== CORE_PACKAGE) {
    throw coreError("BRIDGE_CORE_NOT_FOUND");
  }
  const entry = rootEntry(manifest);
  if (typeof entry !== "string") throw coreError("BRIDGE_CORE_NOT_FOUND");
  const file = path.resolve(packageDir, entry);
  // The entry must stay inside the package directory.
  if (!file.startsWith(packageDir + path.sep)) throw coreError("BRIDGE_CORE_NOT_FOUND");
  try {
    if (!(await stat(file)).isFile()) throw new Error("not a file");
  } catch {
    throw coreError("BRIDGE_CORE_NOT_FOUND");
  }
  try {
    return await import(pathToFileURL(file).href);
  } catch {
    throw coreError("BRIDGE_CORE_LOAD_FAILED");
  }
}

// Namespace import: a named import of `piiActivation` would fail to link on
// a core without it (beta.9). PII support is detected at runtime, never by
// version string (ADR §4).
async function loadCore(nodeModules) {
  if (nodeModules !== undefined) return loadCoreFrom(nodeModules);
  try {
    // A bare specifier in a dynamic import() resolves relative to this file.
    return await import(CORE_PACKAGE);
  } catch (error) {
    throw coreError(error?.code === "ERR_MODULE_NOT_FOUND" ? "BRIDGE_CORE_NOT_FOUND" : "BRIDGE_CORE_LOAD_FAILED");
  }
}

async function main() {
  const raw = await readStdin();
  let request;
  try {
    request = JSON.parse(raw);
  } catch (error) {
    writeError("invalid request JSON");
    return;
  }
  if (typeof request?.input !== "string") {
    writeError("request.input must be a string");
    return;
  }
  if (!isSelectorList(request.pii)) {
    writeError("request.pii must be an array of selector strings");
    return;
  }
  if (request.nodeModules !== undefined && typeof request.nodeModules !== "string") {
    writeError("request.nodeModules must be a string");
    return;
  }
  const pii = [...request.pii];
  let core;
  try {
    core = await loadCore(request.nodeModules);
  } catch (error) {
    writeError(error.message, error.code);
    return;
  }
  const hasPiiSurface = typeof core.piiActivation === "function";
  if (!hasPiiSurface && pii.length > 0) {
    writeError("core has no PII support", "PII_UNAVAILABLE");
    return;
  }

  try {
    let piiActivation = null;
    if (hasPiiSurface) {
      await core.initialize({ pii });
      piiActivation = core.piiActivation();
      if (typeof piiActivation !== "string") {
        writeError("core reported a malformed PII activation");
        return;
      }
    } else {
      await core.initialize();
    }
    const findings = core.scan(request.input, {
      ...(request.policy ? { policy: makePolicy(request.policy) } : {}),
      ...(request.limits ? { limits: request.limits } : {}),
    });
    const artifact = core.artifact();
    process.stdout.write(
      JSON.stringify({
        findings: findings.map(safeFinding),
        coreVersion: core.VERSION,
        artifact: artifact?.kind ?? String(artifact),
        piiActivation,
      }),
    );
  } catch (error) {
    // Never echo the request text or selectors back; only the core's own error code.
    writeError("core scan failed", typeof error?.code === "string" ? error.code : undefined);
  }
}

main().catch((error) => {
  writeError("bridge failure", typeof error?.code === "string" ? error.code : undefined);
  process.exitCode = 1;
});
