// corpus-v1: the fixed, versioned, synthetic-only benchmark inputs (#75).
//
// Every item is generated from a fixed seed, so the corpus is the same bytes
// on every machine. `CORPUS_SHA256` pins those bytes: any change to this file
// that alters the corpus fails loadCorpus() until the version is bumped
// (copy to corpus/v2/ and never mix its figures with v1's).
//
// Every sensitive value is unmistakably synthetic or a published documentation
// example. None is, or was ever, a live credential or a real person's data.

import { createHash } from "node:crypto";

import { mulberry32, randomInt } from "../../lib/rng.mjs";

export const CORPUS_VERSION = "corpus-v1";
export const CORPUS_SHA256 = "447f1e169df8e6beb70fd980c46591e224539b3240384156c1a1636ffbc6c37d";

/**
 * Credential-shaped values the pinned core (0.1.0-beta.11) detects with a
 * `redact` action and PII off. Four distinct types, so a capture exercises
 * four detectors and retains four entries.
 */
const SECRETS = Object.freeze([
  Object.freeze({ type: "github_token", before: "please rotate ", value: "ghp_SYNTHETICxREVOKEDxTESTx0000000000000", after: " before the release.\n" }),
  Object.freeze({ type: "aws_access_key_id", before: "the old key id ", value: "AKIASYNTHETIC0TEST00", after: " is retired.\n" }),
  Object.freeze({ type: "bearer_token", before: "Authorization: Bearer ", value: "SYNTHETICxREVOKEDxTESTx0000000000", after: "\n" }),
  Object.freeze({ type: "connection_string_password", before: "db url postgres://bench:", value: "SYNTHETICxREVOKED", after: "@db.example.invalid:5432/app\n" }),
]);

/**
 * PII-shaped values: the IBAN examples published in ISO 13616 / bank
 * documentation. Detected (`pii_global_iban`, `redact`) only with PII on.
 */
const PII = Object.freeze([
  Object.freeze({ type: "pii_global_iban", before: "refund to iban ", value: "GB82 WEST 1234 5698 7654 32", after: " please.\n" }),
  Object.freeze({ type: "pii_global_iban", before: "or IBAN ", value: "DE89370400440532013000", after: " instead.\n" }),
]);

// Plain filler vocabulary: no digits, no `=`/`:` assignments, no key-like
// words, so the only findings are the inserted values above.
const WORDS = Object.freeze(
  (
    "the a team review notes weekly meeting agenda draft summary release plan " +
    "schedule build pipeline backlog item update we will after before during " +
    "follow up with design check results for next sprint and then share doc " +
    "please confirm owner status blocked done open ticket queue triage batch " +
    "report later morning afternoon friday monday cleanup refactor rename move"
  ).split(" "),
);

/** Exactly `bytes` ASCII characters of seeded filler, ending in a newline. */
function filler(random, bytes) {
  if (bytes < 1) return "";
  let text = "";
  let sinceBreak = 0;
  while (text.length < bytes) {
    const word = WORDS[randomInt(random, WORDS.length)];
    sinceBreak += word.length + 1;
    if (sinceBreak > 64) {
      text += `${word}.\n`;
      sinceBreak = 0;
    } else {
      text += `${word} `;
    }
  }
  return `${text.slice(0, bytes - 1)}\n`;
}

/** One input of exactly `bytes` bytes with `values` spread evenly through filler. */
function composeInput(seed, bytes, values) {
  const random = mulberry32(seed);
  const fixed = values.reduce((sum, v) => sum + v.before.length + v.value.length + v.after.length, 0);
  const chunks = values.length + 1;
  const room = bytes - fixed;
  if (room < chunks) throw new RangeError("input too small for its values");
  const base = Math.floor(room / chunks);
  let text = "";
  for (let i = 0; i < chunks; i += 1) {
    const size = i === chunks - 1 ? room - base * (chunks - 1) : base;
    text += filler(random, size);
    if (i < values.length) text += values[i].before + values[i].value + values[i].after;
  }
  return text;
}

function buildRestoreFields(seed, fieldCount, slots) {
  const random = mulberry32(seed);
  const fields = [];
  for (let i = 0; i < fieldCount; i += 1) {
    fields.push({
      path: `field_${String(i).padStart(2, "0")}`,
      before: filler(random, 40).replaceAll("\n", " "),
      slot: i % slots,
      after: filler(random, 24).replaceAll("\n", ""),
    });
  }
  return fields;
}

/** The corpus as generated, without the digest check. Prefer loadCorpus(). */
export function generateCorpus() {
  const capture1k = composeInput(0x0c0de001, 1024, SECRETS);
  const capture1kPii = composeInput(0x0c0de002, 1024, [SECRETS[0], PII[0], SECRETS[1], SECRETS[2], PII[1], SECRETS[3]]);
  return {
    version: CORPUS_VERSION,
    items: {
      // Capture latency: 1 KiB, four credential findings (PII off and on).
      capture1k: {
        input: capture1k,
        bytes: Buffer.byteLength(capture1k, "utf8"),
        findings: { piiOff: SECRETS.length, piiOn: SECRETS.length },
      },
      // Capture with PII on: 1 KiB, four credentials plus two PII findings.
      // With PII off only the four credentials are found.
      capture1kPii: {
        input: capture1kPii,
        bytes: Buffer.byteLength(capture1kPii, "utf8"),
        findings: { piiOff: SECRETS.length, piiOn: SECRETS.length + PII.length },
        piiTypes: [...new Set(PII.map((p) => p.type))],
      },
      // Restore latency: 64 fields (the default maxRestoreFields), each
      // holding one token of a capture of `capture1k`. `slot` indexes that
      // capture's `tokens` array; with four tokens each is used 16 times, the
      // default maxUsesPerEntry.
      restore64: {
        source: "capture1k",
        fields: buildRestoreFields(0x0c0de003, 64, SECRETS.length),
        usesPerToken: 64 / SECRETS.length,
      },
    },
  };
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

/** SHA-256 of the canonical JSON of the generated corpus. */
export function corpusDigest(corpus) {
  return createHash("sha256").update(JSON.stringify(corpus)).digest("hex");
}

/**
 * Every sensitive string in the corpus. A benchmark result, log line, or
 * artifact must contain none of them (see lib/leak-guard.mjs).
 */
export const SENSITIVE_VALUES = Object.freeze([...SECRETS, ...PII].map((v) => v.value));

let cached;

/** The frozen corpus with its version and digest. Throws if the bytes drifted. */
export function loadCorpus() {
  if (cached !== undefined) return cached;
  const corpus = generateCorpus();
  const sha256 = corpusDigest(corpus);
  if (sha256 !== CORPUS_SHA256) {
    throw new Error(`${CORPUS_VERSION} bytes changed (sha256 ${sha256}); bump the corpus version instead of editing v1`);
  }
  cached = deepFreeze({ ...corpus, sha256 });
  return cached;
}
