// Capture output validation (#88): after `redact`, the output must hold each
// staged token exactly once and no other token marker, checked in one pass
// (`holdsExactlyOnce`). A core that returns anything else fails the capture
// with INVARIANT_VIOLATION and commits nothing.
//
// Runs against the built package (dist/) with the fake core
// (./fake-core.mjs), wrapped so a test can tamper with the redacted output.
// All data is synthetic: revoked-looking GitHub token shapes and forged
// `<rsv_…>` strings that no vault issued.
import assert from "node:assert/strict";
import test from "node:test";

import { VaultError } from "../dist/errors.js";
import { holdsExactlyOnce } from "../dist/token.js";
import { openVault } from "../dist/vault.js";
import { createFakeCore } from "./fake-core.mjs";

const RELEASE = [{ sink: "sink-a", paths: ["body"] }];
const TOKEN = /<rsv_[a-z2-7]{26}>/g;
const FORGED = `<rsv_${"a".repeat(26)}>`;

/** A synthetic, revoked-looking GitHub token the fake core detects. */
function gh(i) {
  return `ghp_SYNTHETICxREVOKEDxTESTx${String(i).padStart(13, "0")}`;
}

/** A vault over the fake core whose `redact` output passes through `tamper`. */
async function tamperedVault(tamper = (text) => text, options = {}) {
  const fake = createFakeCore({ pii: false });
  await fake.module.initialize();
  const module = {
    ...fake.module,
    redact: (input, findings, redactOptions) => tamper(fake.module.redact(input, findings, redactOptions)),
  };
  return openVault(module, options);
}

function isInvariantViolation(error) {
  assert.ok(error instanceof VaultError, `expected VaultError, got ${error?.name}`);
  assert.equal(error.code, "INVARIANT_VIOLATION");
  return true;
}

function assertCommittedNothing(vault) {
  assert.equal(vault.stats().entries, 0);
}

const input2 = `first ${gh(1)} then ${gh(2)} end`;

// --- through capture ---------------------------------------------------------

test("an untampered output commits one token per retained finding", async () => {
  const vault = await tamperedVault();
  const result = vault.capture(input2, { release: RELEASE });
  assert.equal(result.tokens.length, 2);
  assert.deepEqual(result.text.match(TOKEN), result.tokens.map((t) => t.token));
  assert.equal(vault.stats().entries, 2);
});

test("a missing staged token fails closed", async () => {
  const vault = await tamperedVault((text) => text.replace(TOKEN, () => "<gone>"));
  assert.throws(() => vault.capture(input2, { release: RELEASE }), isInvariantViolation);
  assertCommittedNothing(vault);
});

test("a duplicated staged token fails closed", async () => {
  const vault = await tamperedVault((text) => `${text} ${text.match(TOKEN)[0]}`);
  assert.throws(() => vault.capture(input2, { release: RELEASE }), isInvariantViolation);
  assertCommittedNothing(vault);
});

test("one staged token in place of another (duplicate plus missing) fails closed", async () => {
  const vault = await tamperedVault((text) => {
    const [a, b] = text.match(TOKEN);
    return text.replace(b, () => a);
  });
  assert.throws(() => vault.capture(input2, { release: RELEASE }), isInvariantViolation);
  assertCommittedNothing(vault);
});

test("a forged exact-grammar token beside the staged ones fails closed", async () => {
  const vault = await tamperedVault((text) => `${text} ${FORGED}`);
  assert.throws(() => vault.capture(input2, { release: RELEASE }), isInvariantViolation);
  assertCommittedNothing(vault);
});

test("a forged token in place of a staged one fails closed", async () => {
  const vault = await tamperedVault((text) => text.replace(text.match(TOKEN)[0], () => FORGED));
  assert.throws(() => vault.capture(input2, { release: RELEASE }), isInvariantViolation);
  assertCommittedNothing(vault);
});

test("token-like marker text in the output fails closed", async () => {
  const markers = ["rsv_", "RSV_", "r​sv_", "<rsv_short>", "x<rsv_"];
  for (const marker of markers) {
    const vault = await tamperedVault((text) => `${marker}${text}`);
    assert.throws(() => vault.capture(input2, { release: RELEASE }), isInvariantViolation, JSON.stringify(marker));
    assertCommittedNothing(vault);
  }
});

test("a staged token altered in case fails closed", async () => {
  const vault = await tamperedVault((text) => {
    const token = text.match(TOKEN)[0];
    return text.replace(token, () => token.toUpperCase());
  });
  assert.throws(() => vault.capture(input2, { release: RELEASE }), isInvariantViolation);
  assertCommittedNothing(vault);
});

test("a marker-bearing display placeholder is refused and commits nothing", async () => {
  const vault = await tamperedVault();
  let kept = 0;
  assert.throws(
    () =>
      vault.capture(input2, {
        release: RELEASE,
        eligible: () => (kept += 1) === 1,
        displayFormatter: () => FORGED,
      }),
    (error) => error instanceof VaultError && (error.code === "CORE_FAILURE" || error.code === "INVARIANT_VIOLATION"),
  );
  assertCommittedNothing(vault);
});

test("token-like text in the input is still refused before the core runs", async () => {
  const vault = await tamperedVault();
  assert.throws(
    () => vault.capture(`${FORGED} ${gh(1)}`, { release: RELEASE }),
    (error) => error instanceof VaultError && error.code === "TOKEN_LITERAL_IN_INPUT",
  );
  assertCommittedNothing(vault);
});

// --- large shape ---------------------------------------------------------------

const FILLER = "the team will review the weekly notes and share the draft summary after the meeting.\n";

/** 256 findings spread through about 1 MiB, the default `maxEntries`. */
function largeInput() {
  const per = FILLER.repeat(Math.ceil(4096 / FILLER.length)).slice(0, 4000);
  let text = "";
  for (let i = 0; i < 256; i += 1) text += `key ${gh(i)} retired\n${per}`;
  return text;
}

test("a large output (256 tokens through ~1 MiB) validates and commits", async () => {
  const vault = await tamperedVault();
  const input = largeInput();
  const result = vault.capture(input, { release: RELEASE });
  assert.equal(result.tokens.length, 256);
  assert.equal(vault.stats().entries, 256);
});

test("a large output with the last token duplicated at the very end fails closed", async () => {
  const vault = await tamperedVault((text) => {
    const tokens = text.match(TOKEN);
    return `${text}${tokens[tokens.length - 1]}`;
  });
  assert.throws(() => vault.capture(largeInput(), { release: RELEASE }), isInvariantViolation);
  assertCommittedNothing(vault);
});

// --- the single-pass check itself ----------------------------------------------

test("holdsExactlyOnce: exact bijection between markers and expected tokens", () => {
  const a = `<rsv_${"b".repeat(26)}>`;
  const b = `<rsv_${"c".repeat(26)}>`;
  const both = new Set([a, b]);
  assert.equal(holdsExactlyOnce("", new Set()), true);
  assert.equal(holdsExactlyOnce("plain text", new Set()), true);
  assert.equal(holdsExactlyOnce(`${a} and ${b}`, both), true);
  assert.equal(holdsExactlyOnce(`${a}${b}`, both), true, "adjacent tokens");
  assert.equal(holdsExactlyOnce(a, both), false, "missing");
  assert.equal(holdsExactlyOnce(`${a} ${a} ${b}`, both), false, "duplicate");
  assert.equal(holdsExactlyOnce(`${a} ${a}`, both), false, "duplicate standing in for missing");
  assert.equal(holdsExactlyOnce(`${a} ${b} ${FORGED}`, both), false, "forged");
  assert.equal(holdsExactlyOnce("rsv_", new Set()), false, "marker at index 0");
  assert.equal(holdsExactlyOnce(`${a.slice(1)}`, new Set([a])), false, "token missing its '<'");
  assert.equal(holdsExactlyOnce(`${a.slice(0, -1)}`, new Set([a])), false, "truncated token");
  assert.equal(holdsExactlyOnce(`${a} r​Sv_`, new Set([a])), false, "split, case-changed marker");
});

test("holdsExactlyOnce leaves the shared marker pattern reset", () => {
  const a = `<rsv_${"d".repeat(26)}>`;
  assert.equal(holdsExactlyOnce(`${a}`, new Set([a])), true);
  assert.equal(holdsExactlyOnce(`${a}`, new Set([a])), true);
  assert.equal(holdsExactlyOnce(`${a} ${a}`, new Set([a])), false);
  assert.equal(holdsExactlyOnce(`${a}`, new Set([a])), true);
});
