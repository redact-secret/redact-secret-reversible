// The whole flow in one file: capture, send, restore, dispose.
// Run: node examples/01-single-user.mjs
import assert from "node:assert/strict";

import { createVault } from "@redact-secret/vault";

// Stands in for your LLM call. It only ever sees tokens.
const callModel = async (text) => `Understood. I will handle this: ${text}`;

// Unmistakably synthetic; never a real credential.
const userText = "Please rotate ghp_SYNTHETICxREVOKEDxTESTx0000000000000 today";

const vault = await createVault({ pii: [] }); // pii: [] = PII detection off
try {
  const captured = vault.capture(userText, {
    release: [{ sink: "draft-reply", paths: ["body"] }], // where values may come back
  });
  console.log("to the model:  ", captured.text);
  assert.ok(!captured.text.includes("ghp_"), "the model must not see the secret");

  const modelReply = await callModel(captured.text);

  const { fields } = vault.restore({
    sink: "draft-reply",
    captures: [captured.captureId],
    fields: { body: modelReply },
  });
  console.log("to the user:   ", fields.body);
  assert.equal(fields.body, `Understood. I will handle this: ${userText}`);
} finally {
  vault.dispose();
}
