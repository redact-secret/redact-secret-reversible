// A conversation: capture each new user turn once, keep the redacted history,
// and list every capture of the conversation when restoring.
// Run: node examples/02-multi-turn.mjs
import assert from "node:assert/strict";

import { createVault, VaultError } from "@redact-secret/vault";

const callModel = async (history) => `Summary of ${history.length} messages: ${history.join(" | ")}`;
const release = [{ sink: "chat-reply", paths: ["body"] }];

const vault = await createVault({ pii: [] });
try {
  const history = []; // redacted text only
  const captures = []; // every capture of this conversation

  for (const turn of [
    "My old token is ghp_SYNTHETICxREVOKEDxTESTx0000000000000",
    "The new one is ghp_SYNTHETICxREVOKEDxTESTx1111111111111",
  ]) {
    const captured = vault.capture(turn, { release }); // the new turn only
    history.push(captured.text);
    captures.push(captured.captureId);
  }

  // Do not capture the history again: it already contains tokens.
  assert.throws(
    () => vault.capture(history.join("\n"), { release }),
    (error) => error instanceof VaultError && error.code === "TOKEN_LITERAL_IN_INPUT",
  );

  const modelReply = await callModel(history);
  const { fields, restored } = vault.restore({ sink: "chat-reply", captures, fields: { body: modelReply } });
  console.log(fields.body);
  assert.equal(restored, 2);
  assert.ok(fields.body.includes("x0000000000000") && fields.body.includes("x1111111111111"));
} finally {
  vault.dispose();
}
