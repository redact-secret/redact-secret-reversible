// What a denied restore looks like, and what to do: keep the redacted text.
// Run: node examples/03-denied-restore.mjs
import assert from "node:assert/strict";

import { createVault, VaultError } from "@redact-secret/vault";

const vault = await createVault({ pii: [] });

/** Restore, or fall back to the redacted text. Returns [text, denial reason]. */
function restoreOrKeepRedacted(request) {
  try {
    return [vault.restore(request).fields.body, null];
  } catch (error) {
    if (!(error instanceof VaultError) || error.code !== "RESTORE_DENIED") throw error;
    // The reason is for your logs. Do not show it to the model or to end users.
    return [request.fields.body, error.reason];
  }
}

try {
  const captured = vault.capture("Use ghp_SYNTHETICxREVOKEDxTESTx0000000000000 here", {
    release: [{ sink: "draft-reply", paths: ["body"] }],
  });
  const reply = `Reply: ${captured.text}`;
  const request = { sink: "draft-reply", captures: [captured.captureId], fields: { body: reply } };

  // 1. A sink the capture did not grant.
  let [text, reason] = restoreOrKeepRedacted({ ...request, sink: "email" });
  console.log("other sink:        ", reason);
  assert.equal(reason, "sink-or-path");
  assert.equal(text, reply, "nothing was restored");

  // 2. A path the capture did not grant.
  [text, reason] = restoreOrKeepRedacted({ ...request, fields: { subject: reply } });
  console.log("other path:        ", reason);
  assert.equal(reason, "sink-or-path");

  // 3. A token the model altered.
  [text, reason] = restoreOrKeepRedacted({ ...request, fields: { body: reply.replace("<rsv_", "<rsv_x") } });
  console.log("altered token:     ", reason);
  assert.ok(reason === "malformed-token" || reason === "unknown-token");

  // A denial consumes nothing, so the granted restore still works...
  [text, reason] = restoreOrKeepRedacted(request);
  console.log("granted:           ", reason ?? "restored");
  assert.equal(reason, null);
  assert.ok(text.includes("ghp_SYNTHETIC"));

  // 4. ...once. Each token restores `maxUses` times (default 1).
  [text, reason] = restoreOrKeepRedacted(request);
  console.log("second time:       ", reason);
  assert.notEqual(reason, null);
  assert.equal(text, reply);
} finally {
  vault.dispose();
}
