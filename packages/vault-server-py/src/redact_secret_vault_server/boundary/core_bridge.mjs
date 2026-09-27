#!/usr/bin/env node
/**
 * Qualified service boundary between the Python server authority package
 * (`redact-secret-vault-server`, #17) and the JavaScript-only
 * `@redact-secret/core` detection engine.
 *
 * No Python core package exists (verified against the `redact-secret/redact-secret`
 * GitHub organization on 2026-09-27: only `packages/javascript` exists there;
 * see docs/research/python-server-integration-2026-09-27.md). Rather than
 * reimplementing detection in Python — forbidden by AGENTS.md and
 * CONVENTIONS.md — the Python package shells out to this script, which calls
 * only the core's documented public `scan` API and returns its safe finding
 * metadata (id/type/detector/confidence/obfuscation/start/end/action) as
 * JSON. It never returns a matched value: `scan` never receives or reports
 * one. All redaction/substitution/token issuance happens in Python, exactly
 * as `@redact-secret/vault` performs substitution itself via a formatter
 * callback, not inside the core.
 *
 * Protocol: one JSON object read from stdin —
 *   { "input": string, "policy"?: {[type: string]: SecretAction, default?: SecretAction}, "limits"?: {maxInputBytes, maxFindings} }
 * — one JSON object written to stdout —
 *   { "findings": DetectedSecretFindingWithAction[], "coreVersion": string, "artifact": string }
 *   or { "error": { "message": string, "code"?: string } } on failure.
 *
 * This process is short-lived (one request per invocation) and trusted only
 * to run the pinned `@redact-secret/core` version resolved from this repo's
 * npm workspace; it is not a network service and accepts no untrusted
 * transport input beyond stdin from its own Python caller.
 */

import { initialize, scan, VERSION, artifact } from "@redact-secret/core";

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

async function main() {
  const raw = await readStdin();
  let request;
  try {
    request = JSON.parse(raw);
  } catch (error) {
    process.stdout.write(JSON.stringify({ error: { message: "invalid request JSON" } }));
    return;
  }
  if (typeof request?.input !== "string") {
    process.stdout.write(JSON.stringify({ error: { message: "request.input must be a string" } }));
    return;
  }

  try {
    await initialize();
    const findings = scan(request.input, {
      ...(request.policy ? { policy: makePolicy(request.policy) } : {}),
      ...(request.limits ? { limits: request.limits } : {}),
    });
    process.stdout.write(
      JSON.stringify({ findings, coreVersion: VERSION, artifact: artifact()?.kind ?? String(artifact()) }),
    );
  } catch (error) {
    // Never echo the request text back; only the core's own error code.
    process.stdout.write(JSON.stringify({ error: { message: "core scan failed", code: error?.code } }));
  }
}

main().catch((error) => {
  process.stdout.write(JSON.stringify({ error: { message: "bridge failure", code: error?.code } }));
  process.exitCode = 1;
});
