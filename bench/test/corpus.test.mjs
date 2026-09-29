import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";

import { CORPUS_SHA256, CORPUS_VERSION, corpusDigest, generateCorpus, loadCorpus, SENSITIVE_VALUES } from "../corpus/v1/index.mjs";
import { publicEntry, REPO_ROOT } from "../lib/sides.mjs";

const CORE_URL = pathToFileURL(publicEntry(join(REPO_ROOT, "node_modules", "@redact-secret", "core"))).href;

test("corpus-v1 is deterministic and pinned by its digest", () => {
  const corpus = loadCorpus();
  assert.equal(corpus.version, CORPUS_VERSION);
  assert.equal(corpus.sha256, CORPUS_SHA256);
  assert.equal(corpusDigest(generateCorpus()), CORPUS_SHA256);
  assert.ok(Object.isFrozen(corpus.items.capture1k));
});

test("inputs have the documented minimum sizes", () => {
  const { capture1k, capture1kPii, restore64 } = loadCorpus().items;
  assert.equal(capture1k.bytes, 1024);
  assert.equal(Buffer.byteLength(capture1k.input), 1024);
  assert.equal(capture1kPii.bytes, 1024);
  assert.equal(restore64.fields.length, 64);
  assert.equal(new Set(restore64.fields.map((f) => f.path)).size, 64);
  assert.equal(restore64.usesPerToken, 16);
  for (const f of restore64.fields) assert.ok(!/rsv_/i.test(f.before + f.after));
});

test("every sensitive value is visibly synthetic or a published example", () => {
  for (const value of SENSITIVE_VALUES) {
    assert.ok(/SYNTHETIC/.test(value) || ["GB82 WEST 1234 5698 7654 32", "DE89370400440532013000"].includes(value));
  }
});

// Detection is verified in fresh processes because core PII activation is
// one-shot per process.
function scanInChild(selectors) {
  const script = `
    const core = await import(${JSON.stringify(CORE_URL)});
    const { loadCorpus, SENSITIVE_VALUES } = await import(${JSON.stringify(pathToFileURL(join(REPO_ROOT, "bench/corpus/v1/index.mjs")).href)});
    await core.initialize({ pii: ${JSON.stringify(selectors)} });
    const out = {};
    for (const [name, item] of Object.entries(loadCorpus().items)) {
      if (typeof item.input !== "string") continue;
      const findings = core.scan(item.input);
      out[name] = {
        count: findings.length,
        allRedact: findings.every((f) => f.action === "redact"),
        allDeclared: findings.every((f) => SENSITIVE_VALUES.includes(item.input.slice(f.start, f.end))),
        types: findings.map((f) => f.type),
      };
    }
    process.stdout.write(JSON.stringify(out));
  `;
  return JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" }));
}

test("the pinned core detects exactly the declared values with PII off", () => {
  const { capture1k, capture1kPii } = loadCorpus().items;
  const got = scanInChild([]);
  assert.equal(got.capture1k.count, capture1k.findings.piiOff);
  assert.equal(got.capture1kPii.count, capture1kPii.findings.piiOff);
  for (const item of Object.values(got)) {
    assert.ok(item.allRedact && item.allDeclared);
    assert.ok(!item.types.some((t) => t.startsWith("pii_")));
  }
  assert.equal(new Set(got.capture1k.types).size, 4);
});

test("the pinned core detects exactly the declared values with PII on", () => {
  const { capture1k, capture1kPii } = loadCorpus().items;
  const got = scanInChild(["pii"]);
  assert.equal(got.capture1k.count, capture1k.findings.piiOn);
  assert.equal(got.capture1kPii.count, capture1kPii.findings.piiOn);
  assert.deepEqual(
    got.capture1kPii.types.filter((t) => t.startsWith("pii_")),
    ["pii_global_iban", "pii_global_iban"],
  );
  for (const item of Object.values(got)) assert.ok(item.allRedact && item.allDeclared);
});
