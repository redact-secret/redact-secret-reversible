// Guards against drift between this package's local, documented copy of the
// issued-token grammar (src/token-pattern.ts, duplicated because
// @redact-secret/vault does not export its own token.ts — see that file's
// header comment) and the real grammar @redact-secret/vault actually uses.
import assert from "node:assert/strict";
import test from "node:test";

import { createVault } from "@redact-secret/vault";

import { TOKEN_PATTERN, MARKER_PATTERN } from "../dist/token-pattern.js";
import { SECRET_A } from "./helpers.mjs";

test("a token issued by the real vault matches this package's local grammar exactly", async () => {
  const vault = await createVault({ pii: [] });
  try {
    const { text, tokens } = vault.capture(`value ${SECRET_A} end`, {
      release: [{ sink: "s", paths: ["p"] }],
    });
    assert.equal(tokens.length, 1);
    const issued = tokens[0].token;

    TOKEN_PATTERN.lastIndex = 0;
    const matches = text.match(TOKEN_PATTERN) ?? [];
    TOKEN_PATTERN.lastIndex = 0;
    assert.deepEqual(matches, [issued], "local TOKEN_PATTERN must find exactly the real issued token");

    MARKER_PATTERN.lastIndex = 0;
    assert.equal(MARKER_PATTERN.test(issued), true, "local MARKER_PATTERN must match inside a real token");
    MARKER_PATTERN.lastIndex = 0;
  } finally {
    vault.dispose();
  }
});

test("MARKER_PATTERN still matches a marker split by invisible format characters", () => {
  MARKER_PATTERN.lastIndex = 0;
  assert.equal(MARKER_PATTERN.test("r‍s‍v‍_"), true);
  MARKER_PATTERN.lastIndex = 0;
});
