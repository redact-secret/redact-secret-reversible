#!/usr/bin/env node
/**
 * Qualified service boundary between the Python server authority package
 * (`redact-secret-vault`, #17) and the JavaScript-only
 * `@redact-secret/core` detection engine.
 *
 * No Python core package exists (verified against the `redact-secret/redact-secret`
 * GitHub organization on 2026-09-27: only `packages/javascript` exists there).
 * Rather than reimplementing detection in Python — forbidden by AGENTS.md and
 * CONVENTIONS.md — the Python package runs this script, which calls only the
 * core's documented public `initialize`/`scan`/`piiActivation` APIs and
 * returns its safe finding metadata
 * (id/type/detector/confidence/obfuscation/start/end/action) as JSON. It
 * never returns a matched value: `scan` never receives or reports one, and
 * each finding is projected to exactly those eight fields before it is
 * written.
 *
 * Lifetime (#89): one process serves a sequence of requests from the single
 * `NodeCoreBridge` that spawned it, one request at a time. The Python side
 * bounds its lifetime (request count, age, idle time) and replaces it after
 * any failure. This script also exits on its own:
 * - at end of stdin (the owner closed it or died), so it never outlives its owner;
 * - after writing any error response, so a process that failed once is never reused;
 * - after `--idle-exit-ms=<n>` milliseconds without a request.
 * It keeps no per-request state between requests: the request object, its
 * input, and the policy built from it go out of scope once the response is
 * written. The only state that outlives a request is the core's
 * realm-global, one-shot activation, fixed by the first request.
 *
 * Protocol: newline-delimited JSON on stdin/stdout. Neither side writes a
 * raw newline inside a frame (JSON escapes it). Each request is one line —
 *   { "id": integer, "input": string, "pii": string[], "policy"?: {[type: string]: SecretAction, default?: SecretAction}, "limits"?: {maxInputBytes, maxFindings}, "nodeModules"?: string, "integrity"?: {[package: string]: sha256 hex} }
 * — and gets exactly one response line carrying the same `id` —
 *   { "id", "findings": SafeFinding[], "coreVersion": string, "artifact": string, "piiActivation": string | null, "integrity": {[package: string]: sha256 hex} | null }
 *   or { "id", "error": { "message": string, "code"?: string } } on failure
 * (`"id": null` when the request had no usable id). Ids count up from 1 by
 * one; any other id is refused. A request line longer than
 * `MAX_REQUEST_CHARS` is refused with `BRIDGE_REQUEST_TOO_LARGE`. `pii` and
 * `nodeModules` configure the core on the first request; every later request
 * must repeat them unchanged, or it is refused. `integrity` (core integrity,
 * see "core integrity" below) is sent with the first request only; a later
 * request that carries it is refused as a changed configuration. The response
 * to the first request reports the digests that were verified; later ones
 * report null.
 *
 * PII activation (docs/decisions/decide-pii-retention-and-activation-ownership.md
 * §3 "Python bridge"): this process is its own realm with no other
 * initializer, so the Python caller's `pii` list is the only selection.
 * - Core exports `piiActivation` (beta.10+): `initialize({ pii })` verbatim,
 *   then report `piiActivation()`.
 * - No PII surface (beta.9) and `pii` is empty: plain `initialize()`, and
 *   report `piiActivation: null`. No identity string is invented.
 * - No PII surface and `pii` is non-empty: `{"error":{"code":"PII_UNAVAILABLE"}}`
 *   before the core is initialized or the input is scanned.
 * Selector grammar is the core's to judge (`PII_SELECTOR_*`); this script
 * only checks the request shape. `piiActivation()` is read again for every
 * response, and the Python caller checks it on every response of every
 * process.
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
 * This process is trusted only to run the pinned `@redact-secret/core`
 * version from the location above; it is not a network service and accepts
 * no input beyond stdin from its own Python owner. It writes nothing to
 * stderr itself, and its owner discards stderr.
 */

import { createHash } from "node:crypto";
import { readdir, readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const CORE_PACKAGE = "@redact-secret/core";
// The conditions Node.js itself applies when importing an ES module.
const ESM_CONDITIONS = new Set(["node", "import", "default"]);
const MAX_NODE_MODULES_LENGTH = 4096;

const MAX_PII_SELECTORS = 64;
const MAX_PII_SELECTOR_LENGTH = 128;

// Longest request line accepted, in UTF-16 code units, without its newline.
// Equals MAX_REQUEST_FRAME_BYTES in core_client.py (requests are ASCII) and
// stays below V8's maximum string length.
const MAX_REQUEST_CHARS = 448 * 1024 * 1024;
const MAX_IDLE_EXIT_MS = 24 * 60 * 60 * 1000;

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

// Where the core is, without importing it: `{ packageDir, file }`, the package directory and its entry file.
async function locateCoreFrom(nodeModules) {
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
  return { packageDir, file };
}

// Without `nodeModules`: the entry a bare specifier resolves to from this
// file, and the package directory above it.
async function locateCoreDefault() {
  let file;
  try {
    file = fileURLToPath(import.meta.resolve(CORE_PACKAGE));
  } catch {
    throw coreError("BRIDGE_CORE_NOT_FOUND");
  }
  let directory = path.dirname(file);
  for (let depth = 0; depth < 16; depth += 1) {
    try {
      const manifest = JSON.parse(await readFile(path.join(directory, "package.json"), "utf8"));
      if (manifest?.name === CORE_PACKAGE) return { packageDir: directory, file };
    } catch {
      // not a package directory; keep climbing
    }
    const parent = path.dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  throw coreError("BRIDGE_CORE_NOT_FOUND");
}

function locateCore(nodeModules) {
  return nodeModules !== undefined ? locateCoreFrom(nodeModules) : locateCoreDefault();
}

// Namespace import: a named import of `piiActivation` would fail to link on
// a core without it (beta.9). PII support is detected at runtime, never by
// version string (ADR §4). The file is the one that was located (and, when
// pins were sent, hashed), not a second resolution of the same name.
async function importCore(file) {
  try {
    return await import(pathToFileURL(file).href);
  } catch {
    throw coreError("BRIDGE_CORE_LOAD_FAILED");
  }
}

// ---- core integrity (docs/decisions/limit-python-persistence-claim-to-a-supplied-core-client.md) ----
//
// The Python caller sends, with the first request of a process, the digest it
// pins for each package of the core. Before the core's code is imported or
// sees any input, this process hashes the package directories it is about to
// load and refuses on any difference. The digest is "rsv-tree-v1", the same
// function as scripts/core-integrity.py: SHA-256 over one line per regular file,
// `<sha256 of the content> <size> <relative path>`, sorted by the UTF-8 bytes
// of the POSIX relative path; a symbolic link or any other kind of entry has no
// digest. It covers every file of the package directories it names (the core,
// its WebAssembly package, and the platform addon package that Node.js finds
// beside the core). It does not cover the node executable, the bridge script,
// other directories on Node.js's module path, or a change made between the
// hash and the import (a race by someone who can write those files).
const INTEGRITY_FAILED = "CORE_INTEGRITY_MISMATCH";
const WASM_PACKAGE = "@redact-secret/wasm";
const MAX_INTEGRITY_PACKAGES = 32;
const MAX_INTEGRITY_FILES = 4096;
const MAX_INTEGRITY_BYTES = 64 * 1024 * 1024;
const INTEGRITY_READ_BATCH = 16;
const PACKAGE_NAME_PATTERN = /^@redact-secret\/[a-z0-9][a-z0-9-]{0,63}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;

function isIntegrityPins(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const entries = Object.entries(value);
  return (
    entries.length > 0 &&
    entries.length <= MAX_INTEGRITY_PACKAGES &&
    entries.every(([name, digest]) => PACKAGE_NAME_PATTERN.test(name) && typeof digest === "string" && DIGEST_PATTERN.test(digest))
  );
}

function integrityError() {
  return Object.assign(new Error("core integrity check failed"), { code: INTEGRITY_FAILED });
}

async function treeDigest(directory) {
  const files = [];
  async function walk(current, prefix) {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const relative = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
      if (entry.isDirectory()) {
        await walk(path.join(current, entry.name), relative);
      } else if (entry.isFile()) {
        files.push(relative);
        if (files.length > MAX_INTEGRITY_FILES) throw integrityError();
      } else {
        throw integrityError(); // a symbolic link, a device, a socket
      }
    }
  }
  await walk(directory, "");
  files.sort((a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")));
  const outer = createHash("sha256");
  let total = 0;
  // Files are read a few at a time (the digest of each is independent); the lines are fed to the outer hash in order.
  for (let at = 0; at < files.length; at += INTEGRITY_READ_BATCH) {
    const lines = await Promise.all(
      files.slice(at, at + INTEGRITY_READ_BATCH).map(async (relative) => {
        const data = await readFile(path.join(directory, ...relative.split("/")));
        return { size: data.length, line: `${createHash("sha256").update(data).digest("hex")} ${data.length} ${relative}\n` };
      }),
    );
    for (const { size, line } of lines) {
      total += size;
      if (total > MAX_INTEGRITY_BYTES) throw integrityError();
      outer.update(line);
    }
  }
  return outer.digest("hex");
}

// The directory Node.js would resolve `name` to for a module inside the core's
// package: `node_modules` of the package, then of each ancestor that is not
// itself called node_modules. Undefined when it is not installed.
async function findDependency(packageDir, name) {
  const candidates = [path.join(packageDir, "node_modules", name)];
  for (let directory = path.dirname(packageDir); ; ) {
    if (path.basename(directory) !== "node_modules") candidates.push(path.join(directory, "node_modules", name));
    const parent = path.dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  for (const candidate of candidates) {
    try {
      const manifest = JSON.parse(await readFile(path.join(candidate, "package.json"), "utf8"));
      if (manifest?.name === name) return candidate;
    } catch {
      // not there
    }
  }
  return undefined;
}

// Returns `{ [name]: digest }` for every pinned package that is installed, or
// throws CORE_INTEGRITY_MISMATCH. The core and its WebAssembly package must be
// installed; an addon package need not be (the core then falls back to
// WebAssembly), but one that is installed must match.
async function verifyIntegrity(located, pins) {
  const base = await realpath(located.packageDir).catch(() => {
    throw integrityError();
  });
  const verified = {};
  for (const [name, expected] of Object.entries(pins)) {
    const directory = name === CORE_PACKAGE ? base : await findDependency(base, name);
    if (directory === undefined) continue;
    const actual = await treeDigest(directory).catch(() => {
      throw integrityError();
    });
    if (actual !== expected) throw integrityError();
    verified[name] = actual;
  }
  if (verified[CORE_PACKAGE] === undefined || verified[WASM_PACKAGE] === undefined) throw integrityError();
  return verified;
}

// After the core is initialized: the artifact it chose must be one that was
// verified. A native addon is verified only if its package was found beside the
// core; an addon that Node.js found elsewhere (NODE_PATH, a global folder) is not.
function checkArtifact(core, verified) {
  let kind;
  try {
    const artifact = core.artifact();
    kind = typeof artifact === "string" ? artifact : artifact?.kind;
  } catch {
    throw integrityError();
  }
  const addonVerified = Object.keys(verified).some((name) => name !== CORE_PACKAGE && name !== WASM_PACKAGE);
  if (kind === "addon" ? !addonVerified : kind !== "wasm") throw integrityError();
}

// `--idle-exit-ms=<n>` is the only accepted argument; undefined when absent,
// null when malformed.
function parseIdleExitMs(argv) {
  let idleExitMs;
  for (const arg of argv) {
    const match = /^--idle-exit-ms=([1-9][0-9]{0,8})$/.exec(arg);
    if (match === null || idleExitMs !== undefined) return null;
    idleExitMs = Number(match[1]);
  }
  if (idleExitMs !== undefined && idleExitMs > MAX_IDLE_EXIT_MS) return null;
  return idleExitMs;
}

function frame(id, body) {
  return `${JSON.stringify({ id, ...body })}\n`;
}

function errorFrame(id, message, code) {
  return frame(id, { error: code === undefined ? { message } : { message, code } });
}

function sameConfig(config, request) {
  return (
    config.nodeModules === request.nodeModules &&
    config.pii.length === request.pii.length &&
    config.pii.every((selector, i) => selector === request.pii[i])
  );
}

function errorCode(error) {
  return typeof error?.code === "string" ? error.code : undefined;
}

function main() {
  const idleExitMs = parseIdleExitMs(process.argv.slice(2));
  let stopped = false;
  let busy = false;
  let nextId = 1;
  // Fixed by the first request: { pii, nodeModules, core }.
  let config;
  let pending = [];
  let chunks = [];
  let partialLength = 0;
  let idleTimer;

  function stop(exitCode) {
    if (stopped) return;
    stopped = true;
    clearTimeout(idleTimer);
    pending = [];
    chunks = [];
    process.exitCode = exitCode;
    // Stop reading; the process exits once the last frame is flushed.
    process.stdin.removeAllListeners("data");
    process.stdin.destroy();
  }

  function armIdle() {
    if (idleExitMs === undefined || stopped) return;
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => stop(0), idleExitMs);
  }

  // Writes one frame. After an error the process stops: one that failed once
  // is never asked again.
  function respond(text, failed) {
    process.stdout.write(text);
    if (failed) stop(1);
  }

  async function configure(id, request) {
    const pii = [...request.pii];
    let core;
    let verified;
    try {
      const located = await locateCore(request.nodeModules);
      // Hashed before the core's code is imported, and before any input is scanned.
      if (request.integrity !== undefined) verified = await verifyIntegrity(located, request.integrity);
      core = await importCore(located.file);
    } catch (error) {
      respond(errorFrame(id, error.message, error.code), true);
      return false;
    }
    const hasPiiSurface = typeof core.piiActivation === "function";
    if (!hasPiiSurface && pii.length > 0) {
      respond(errorFrame(id, "core has no PII support", "PII_UNAVAILABLE"), true);
      return false;
    }
    try {
      if (hasPiiSurface) {
        await core.initialize({ pii });
      } else {
        await core.initialize();
      }
    } catch (error) {
      // Never echo the selectors back; only the core's own error code.
      respond(errorFrame(id, "core initialize failed", errorCode(error)), true);
      return false;
    }
    if (verified !== undefined) {
      try {
        checkArtifact(core, verified);
      } catch (error) {
        respond(errorFrame(id, error.message, error.code), true);
        return false;
      }
    }
    config = { pii, nodeModules: request.nodeModules, core, integrity: verified };
    return true;
  }

  async function handle(line) {
    let request;
    try {
      request = JSON.parse(line);
    } catch {
      respond(errorFrame(null, "invalid request JSON"), true);
      return;
    }
    if (request === null || typeof request !== "object" || Array.isArray(request)) {
      respond(errorFrame(null, "request must be an object"), true);
      return;
    }
    const { id } = request;
    if (id !== nextId) {
      respond(errorFrame(null, "request.id out of sequence"), true);
      return;
    }
    nextId += 1;
    if (typeof request.input !== "string") {
      respond(errorFrame(id, "request.input must be a string"), true);
      return;
    }
    if (!isSelectorList(request.pii)) {
      respond(errorFrame(id, "request.pii must be an array of selector strings"), true);
      return;
    }
    if (request.nodeModules !== undefined && typeof request.nodeModules !== "string") {
      respond(errorFrame(id, "request.nodeModules must be a string"), true);
      return;
    }
    if (request.integrity !== undefined && !isIntegrityPins(request.integrity)) {
      respond(errorFrame(id, "request.integrity must map package names to digests"), true);
      return;
    }
    // The digests this process verified, reported with the response to the
    // request that configured it and as null with every later one.
    let reportedIntegrity = null;
    if (config === undefined) {
      if (!(await configure(id, request))) return;
      reportedIntegrity = config.integrity ?? null;
    } else if (!sameConfig(config, request) || request.integrity !== undefined) {
      respond(errorFrame(id, "request configuration changed"), true);
      return;
    }

    const { core } = config;
    try {
      // Read for every response, so an activation that changed underneath
      // this process is reported rather than masked by a cached value.
      let piiActivation = null;
      if (typeof core.piiActivation === "function") {
        piiActivation = core.piiActivation();
        if (typeof piiActivation !== "string") {
          respond(errorFrame(id, "core reported a malformed PII activation"), true);
          return;
        }
      }
      const findings = core.scan(request.input, {
        ...(request.policy ? { policy: makePolicy(request.policy) } : {}),
        ...(request.limits ? { limits: request.limits } : {}),
      });
      const artifact = core.artifact();
      respond(
        frame(id, {
          findings: findings.map(safeFinding),
          coreVersion: core.VERSION,
          artifact: artifact?.kind ?? String(artifact),
          piiActivation,
          integrity: reportedIntegrity,
        }),
        false,
      );
    } catch (error) {
      // Never echo the request text or selectors back; only the core's own error code.
      respond(errorFrame(id, "core scan failed", errorCode(error)), true);
    }
  }

  // Requests are handled strictly one after another.
  async function pump() {
    if (busy) return;
    busy = true;
    clearTimeout(idleTimer);
    try {
      while (!stopped && pending.length > 0) {
        await handle(pending.shift());
      }
    } catch (error) {
      respond(errorFrame(null, "bridge failure", errorCode(error)), true);
    } finally {
      busy = false;
      armIdle();
    }
  }

  function tooLarge() {
    respond(errorFrame(null, "request too large", "BRIDGE_REQUEST_TOO_LARGE"), true);
  }

  if (idleExitMs === null) {
    respond(errorFrame(null, "invalid bridge arguments"), true);
    return;
  }

  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    if (stopped) return;
    let start = 0;
    let newline = chunk.indexOf("\n");
    while (newline !== -1) {
      if (partialLength + (newline - start) > MAX_REQUEST_CHARS) return tooLarge();
      chunks.push(chunk.slice(start, newline));
      pending.push(chunks.join(""));
      chunks = [];
      partialLength = 0;
      start = newline + 1;
      newline = chunk.indexOf("\n", start);
    }
    if (start < chunk.length) {
      partialLength += chunk.length - start;
      if (partialLength > MAX_REQUEST_CHARS) return tooLarge();
      chunks.push(chunk.slice(start));
    }
    void pump();
  });
  // End of stdin: the owner closed the pipe or exited. Never outlive it.
  process.stdin.on("end", () => stop(0));
  process.stdin.on("error", () => stop(1));
  armIdle();
}

main();
