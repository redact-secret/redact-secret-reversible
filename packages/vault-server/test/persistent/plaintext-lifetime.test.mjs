// How long plaintext bytes live inside one call
// (docs/specs/persistent-vault.md §7.2: "on a denial it overwrites them";
// §8.2: "Staged plaintext exists only inside one call").
//
// The crypto layer is wrapped so the test holds the very buffers the server
// handed to it (capture) or received from it (restore), and checks they were
// overwritten by the time the call settled.
import assert from "node:assert/strict";
import test from "node:test";

import {
  captureOne,
  createRig,
  CTX_A,
  denied,
  registerLeakHygiene,
  rejects,
  RELEASE,
  restoreRequest,
  SECRET_A,
  SECRET_B,
  sleep,
} from "./helpers.mjs";

const TWO = `first ${SECRET_A} second ${SECRET_B} end`;

function allZero(buffers) {
  return buffers.length > 0 && buffers.every((buffer) => buffer.byteLength > 0 && buffer.every((byte) => byte === 0));
}

/** A crypto layer that remembers the value buffers that crossed it, in both directions. */
function watch(rig, { openDelayMs = 0 } = {}) {
  const seen = { sealed: [], opened: [], pending: 0 };
  const crypto = {
    profile: rig.crypto.profile,
    rewrapCaptureKey: rig.crypto.rewrapCaptureKey,
    async sealCapture(input, options) {
      const buffers = input.records.map((record) => record.payload.value);
      // The server hands over real plaintext, not a zeroed buffer.
      assert.ok(buffers.every((buffer) => buffer.some((byte) => byte !== 0)));
      seen.sealed.push(...buffers);
      return rig.crypto.sealCapture(input, options);
    },
    async openCapture(input, options) {
      seen.pending += 1;
      try {
        // A delayed layer ignores cancellation, so that it does finish and does return plaintext late.
        const payloads = await rig.crypto.openCapture(input, openDelayMs > 0 ? undefined : options);
        assert.ok(payloads.every((payload) => payload.value.some((byte) => byte !== 0)));
        seen.opened.push(...payloads.map((payload) => payload.value));
        if (openDelayMs > 0) await sleep(openDelayMs);
        return payloads;
      } finally {
        seen.pending -= 1;
      }
    },
  };
  return { seen, crypto };
}

test("capture: the value bytes handed to the crypto layer are overwritten when the call settles, on success and on failure", async () => {
  const rig = await createRig();
  const { seen, crypto } = watch(rig);
  const vault = await rig.open({ crypto });

  await vault.capture(TWO, { context: CTX_A, release: RELEASE });
  assert.equal(seen.sealed.length, 2);
  assert.deepEqual(seen.sealed.map((buffer) => buffer.byteLength), [Buffer.byteLength(SECRET_A), Buffer.byteLength(SECRET_B)]);
  assert.ok(allZero(seen.sealed), "after a successful capture");

  for (const fault of [{ kind: "unavailable" }, { kind: "ambiguous", applied: true }, { kind: "malformed", shape: "null" }]) {
    seen.sealed.length = 0;
    rig.failNext("createCapture", fault);
    await rejects(vault.capture(TWO, { context: CTX_A, release: RELEASE }), fault.kind === "malformed" ? "INVARIANT_VIOLATION" : "STORE_UNAVAILABLE");
    assert.ok(allZero(seen.sealed), `after createCapture ${fault.kind}`);
  }

  seen.sealed.length = 0;
  rig.keys.fail.generate = () => {
    throw new Error("synthetic");
  };
  await rejects(vault.capture(TWO, { context: CTX_A, release: RELEASE }), "KEY_UNAVAILABLE");
  assert.ok(allZero(seen.sealed), "after a key provider failure");
});

test("restore: decrypted value bytes are overwritten on every denial after decryption, and after a success", async () => {
  const rig = await createRig();
  const { seen, crypto } = watch(rig);
  const vault = await rig.open({ crypto, policyRevision: () => revision });
  let revision = "policy-rev-synthetic-1";
  const captured = await captureOne(rig, { vault, text: TWO, maxUses: 8 });
  const request = restoreRequest(captured);
  const check = async (label, run) => {
    seen.opened.length = 0;
    await run();
    assert.equal(seen.opened.length, 2, `${label}: the values were decrypted`);
    assert.ok(allZero(seen.opened), `${label}: and overwritten`);
  };

  await check("sink-or-path", () => denied(vault.restore({ ...request, sink: "sink-not-granted" }), "sink-or-path"));
  rig.policy = () => ({ allow: false, reason: "policy" });
  await check("policy", () => denied(vault.restore(request), "policy"));
  rig.policy = () => {
    throw new Error("synthetic");
  };
  await check("policy-evaluation-error", () => denied(vault.restore(request), "policy-evaluation-error"));
  rig.policy = () => {
    revision = `${revision}+`;
    return { allow: true };
  };
  await check("stale-policy", () => denied(vault.restore(request), "stale-policy"));
  rig.policy = () => ({ allow: true });

  for (const [fault, code] of [
    [{ kind: "unavailable" }, "STORE_UNAVAILABLE"],
    [{ kind: "ambiguous", applied: false }, "COMMIT_AMBIGUOUS"],
    [{ kind: "malformed", shape: "null" }, "COMMIT_AMBIGUOUS"],
    [{ kind: "result", result: { outcome: "rejected", reason: "revoked" }, delegate: false }, "RESTORE_DENIED"],
  ]) {
    rig.failNext("commitRestore", fault);
    await check(`commit ${fault.kind}`, () => rejects(vault.restore(request), code));
  }

  await check("success", async () => {
    const restored = await vault.restore(request);
    assert.equal(restored.fields.body, TWO);
  });
});

test("restore: a crypto result that arrives after the deadline is overwritten, not left behind", async () => {
  const rig = await createRig();
  const { seen, crypto } = watch(rig, { openDelayMs: 120 });
  const vault = await rig.open({ crypto, cryptoTimeoutMs: 30 });
  const captured = await captureOne(rig, { text: TWO });
  await denied(vault.restore(restoreRequest(captured)), "key-unavailable");
  // Let the abandoned call finish and hand its result to a server that already answered.
  for (let waited = 0; (seen.pending > 0 || seen.opened.length < 2) && waited < 10_000; waited += 10) await sleep(10);
  assert.equal(seen.pending, 0, "the abandoned crypto call finished");
  assert.equal(seen.opened.length, 2, "and returned plaintext after the deadline");
  await sleep(10);
  assert.ok(allZero(seen.opened), "the late plaintext was overwritten");
  assert.deepEqual(await rig.used(captured.tokens.map(({ token }) => token)), [0, 0]);
  assert.equal(rig.spy.count("commitRestore"), 0);
});

registerLeakHygiene({ minErrors: 10 });
