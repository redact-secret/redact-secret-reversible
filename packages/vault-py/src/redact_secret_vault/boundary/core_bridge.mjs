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
 *   { "input": string, "pii": string[], "policy"?: {[type: string]: SecretAction, default?: SecretAction}, "limits"?: {maxInputBytes, maxFindings} }
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
 * This process is short-lived (one request per invocation) and trusted only
 * to run the pinned `@redact-secret/core` version resolved from this repo's
 * npm workspace; it is not a network service and accepts no untrusted
 * transport input beyond stdin from its own Python caller.
 */

// Namespace import: a named import of `piiActivation` would fail to link on
// a core without it (beta.9). PII support is detected at runtime, never by
// version string (ADR §4).
import * as core from "@redact-secret/core";

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
  const pii = [...request.pii];
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
