// A key provider that throws, hangs, lies about its result, or is cancelled.
import assert from "node:assert/strict";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";

import { KeyProviderError } from "@redact-secret/vault-contracts";

import { createRecordCrypto, DEFAULT_KEY_TIMEOUT_MS } from "../dist/index.js";
import {
  assertClean,
  base64,
  binding,
  CONTEXT,
  entryId,
  fakeProvider,
  FIXED_DEK,
  hex,
  keyError,
  payload,
  recordError,
  utf8,
  VALUES,
} from "./helpers.mjs";

const FOREIGN_MESSAGE = "SYNTHETIC-PROVIDER-MESSAGE-0001 credential=SYNTHETIC-NOT-A-REAL-CREDENTIAL host=kms.synthetic.invalid";
const FORBIDDEN = [FOREIGN_MESSAGE, "SYNTHETIC-PROVIDER-MESSAGE", "SYNTHETIC-NOT-A-REAL-CREDENTIAL", "kms.synthetic.invalid", "SyntheticSdkError"];

class SyntheticSdkError extends Error {
  constructor() {
    super(FOREIGN_MESSAGE);
    this.name = "SyntheticSdkError";
    this.requestId = "SYNTHETIC-PROVIDER-MESSAGE-request";
    this.cause = new Error(FOREIGN_MESSAGE);
  }
}

const sealInput = () => ({ context: CONTEXT, records: [{ binding: binding(), payload: payload() }] });

/** A sealed capture from a working provider, to drive openCapture and rewrapCaptureKey against a broken one. */
async function sealedOnce() {
  const crypto = createRecordCrypto({ keyProvider: fakeProvider() });
  const input = sealInput();
  const sealed = await crypto.sealCapture(input);
  return {
    open: { context: CONTEXT, keyRef: sealed.keyRef, wrappedKey: sealed.wrappedKey, records: [{ binding: input.records[0].binding, envelope: sealed.envelopes[0] }] },
    rewrap: { context: CONTEXT, keyRef: sealed.keyRef, wrappedKey: sealed.wrappedKey },
  };
}

/** Runs seal, open, and rewrap against a provider whose three methods all behave as `behave`. */
async function eachOperation(behave, check, options = {}) {
  const stored = await sealedOnce();
  const provider = { profile: "broken-test-only", generateDataKey: behave, unwrapDataKey: behave, rewrapDataKey: behave };
  const crypto = createRecordCrypto({ keyProvider: provider, ...options });
  await check(() => crypto.sealCapture(sealInput()), "sealCapture");
  await check(() => crypto.openCapture(stored.open), "openCapture");
  await check(() => crypto.rewrapCaptureKey(stored.rewrap), "rewrapCaptureKey");
}

test("the default provider timeout is 5 seconds", () => {
  assert.equal(DEFAULT_KEY_TIMEOUT_MS, 5000);
});

test("a foreign error from the provider becomes KEY_UNAVAILABLE and none of it survives", async () => {
  const behaviours = [
    async () => {
      throw new SyntheticSdkError();
    },
    () => {
      throw new SyntheticSdkError(); // synchronous throw
    },
    async () => {
      throw FOREIGN_MESSAGE; // not an Error
    },
    async () => {
      throw { code: "KEY_INTEGRITY", message: FOREIGN_MESSAGE }; // looks like ours, is not
    },
    () => Promise.reject(undefined),
  ];
  for (const behave of behaviours) {
    await eachOperation(behave, async (run) => {
      const error = await keyError(run, "KEY_UNAVAILABLE", FORBIDDEN);
      assert.equal(error.message, new KeyProviderError("KEY_UNAVAILABLE").message);
      assert.ok(!(error instanceof SyntheticSdkError));
    });
  }
});

test("a KeyProviderError from the provider keeps its code and loses everything attached to it", async () => {
  for (const code of ["KEY_UNAVAILABLE", "KEY_INTEGRITY", "KEY_TIMEOUT", "KEY_THROTTLED", "KEY_ABORTED", "KEY_INVALID_ARGUMENT"]) {
    const thrown = new KeyProviderError(code);
    thrown.cause = new SyntheticSdkError();
    thrown.detail = FOREIGN_MESSAGE;
    thrown.message = FOREIGN_MESSAGE;
    await eachOperation(
      async () => {
        throw thrown;
      },
      async (run) => {
        const error = await keyError(run, code, FORBIDDEN);
        assert.notEqual(error, thrown, "the provider's own error object was rethrown");
      },
    );
  }
  const unknownCode = new KeyProviderError("KEY_INTEGRITY");
  Object.defineProperty(unknownCode, "code", { value: FOREIGN_MESSAGE });
  await eachOperation(
    async () => {
      throw unknownCode;
    },
    (run) => keyError(run, "KEY_UNAVAILABLE", FORBIDDEN),
  );
});

test("a provider that never answers is KEY_TIMEOUT after keyTimeoutMs, and its signal is aborted", async () => {
  const signals = [];
  const hang = (_input, options) => {
    signals.push(options.signal);
    return new Promise(() => {});
  };
  await eachOperation(
    hang,
    async (run, operation) => {
      const started = performance.now();
      await keyError(run, "KEY_TIMEOUT", FORBIDDEN);
      const elapsed = performance.now() - started;
      assert.ok(elapsed >= 55 && elapsed < 2000, `${operation} took ${elapsed} ms for a 60 ms timeout`);
    },
    { keyTimeoutMs: 60 },
  );
  assert.equal(signals.length, 3);
  for (const signal of signals) assert.equal(signal.aborted, true, "the provider was not told to stop");
});

test("a data key that arrives after the timeout is overwritten, not used", async () => {
  const late = FIXED_DEK.slice();
  const provider = {
    profile: "slow-test-only",
    async generateDataKey() {
      await delay(120);
      return { keyRef: "fake:1", wrappedKey: utf8("synthetic-wrapped-key"), plaintextKey: late };
    },
    async unwrapDataKey() {
      await delay(120);
      return late;
    },
    async rewrapDataKey() {
      await delay(120);
      return { keyRef: "fake:1", wrappedKey: utf8("synthetic-wrapped-key") };
    },
  };
  const crypto = createRecordCrypto({ keyProvider: provider, keyTimeoutMs: 30 });
  await keyError(() => crypto.sealCapture(sealInput()), "KEY_TIMEOUT");
  await delay(150);
  assert.ok(late.every((byte) => byte === 0), "a late data key was left in memory");
});

test("an already aborted signal is KEY_ABORTED and the provider is not called", async () => {
  const provider = fakeProvider();
  const crypto = createRecordCrypto({ keyProvider: provider });
  const stored = await sealedOnce();
  const signal = AbortSignal.abort();
  await keyError(() => crypto.sealCapture(sealInput(), { signal }), "KEY_ABORTED");
  await keyError(() => crypto.openCapture(stored.open, { signal }), "KEY_ABORTED");
  await keyError(() => crypto.rewrapCaptureKey(stored.rewrap, { signal }), "KEY_ABORTED");
  assert.deepEqual(provider.calls, { generate: 0, unwrap: 0, rewrap: 0 });
});

test("a signal aborted during the provider call is KEY_ABORTED, promptly, and reaches the provider", async () => {
  const controller = new AbortController();
  let providerSignal;
  const hang = (_input, options) => {
    providerSignal = options.signal;
    setTimeout(() => controller.abort(new Error(FOREIGN_MESSAGE)), 20);
    return new Promise(() => {});
  };
  const crypto = createRecordCrypto({ keyProvider: { profile: "p", generateDataKey: hang, unwrapDataKey: hang, rewrapDataKey: hang } });
  const started = performance.now();
  await keyError(() => crypto.sealCapture(sealInput(), { signal: controller.signal }), "KEY_ABORTED", FORBIDDEN);
  assert.ok(performance.now() - started < 2000);
  assert.equal(providerSignal.aborted, true);
  assert.notEqual(providerSignal, controller.signal, "the provider gets this layer's signal, which also carries the timeout");
});

test("a result of the wrong shape is rejected, and a key in it is overwritten", async () => {
  const stored = await sealedOnce();
  const wrapped = utf8("synthetic-wrapped-key");
  const badDataKeys = [
    { keyRef: "fake:1", wrappedKey: wrapped, plaintextKey: new Uint8Array(16).fill(5) },
    { keyRef: "fake:1", wrappedKey: wrapped, plaintextKey: new Uint8Array(31).fill(5) },
    { keyRef: "fake:1", wrappedKey: wrapped, plaintextKey: new Uint8Array(33).fill(5) },
    { keyRef: "fake:1", wrappedKey: wrapped, plaintextKey: new Uint8Array(0) },
    { keyRef: "fake:1", wrappedKey: wrapped, plaintextKey: Array.from({ length: 32 }, () => 5) },
    { keyRef: "fake:1", wrappedKey: wrapped, plaintextKey: "5".repeat(32) },
    { keyRef: "fake:1", wrappedKey: wrapped },
    { keyRef: "", wrappedKey: wrapped, plaintextKey: new Uint8Array(32).fill(5) },
    { keyRef: "k".repeat(513), wrappedKey: wrapped, plaintextKey: new Uint8Array(32).fill(5) },
    { keyRef: "bad-\ud800", wrappedKey: wrapped, plaintextKey: new Uint8Array(32).fill(5) },
    { keyRef: 7, wrappedKey: wrapped, plaintextKey: new Uint8Array(32).fill(5) },
    { keyRef: "fake:1", wrappedKey: new Uint8Array(0), plaintextKey: new Uint8Array(32).fill(5) },
    { keyRef: "fake:1", wrappedKey: new Uint8Array(4097), plaintextKey: new Uint8Array(32).fill(5) },
    { keyRef: "fake:1", wrappedKey: "wrapped", plaintextKey: new Uint8Array(32).fill(5) },
    null,
    undefined,
    "a string",
    new Uint8Array(32).fill(5),
  ];
  for (const result of badDataKeys) {
    const crypto = createRecordCrypto({ keyProvider: { ...fakeProvider(), generateDataKey: async () => result } });
    await keyError(() => crypto.sealCapture(sealInput()), "KEY_UNAVAILABLE");
    if (result?.plaintextKey instanceof Uint8Array) {
      assert.ok(result.plaintextKey.every((byte) => byte === 0), "a rejected data key was left in memory");
    }
  }
  // Exactly at the limits is accepted.
  const atLimit = createRecordCrypto({
    keyProvider: { ...fakeProvider(), generateDataKey: async () => ({ keyRef: "k".repeat(512), wrappedKey: new Uint8Array(4096), plaintextKey: FIXED_DEK.slice() }) },
  });
  assert.equal((await atLimit.sealCapture(sealInput())).wrappedKey.length, 4096);

  for (const result of [new Uint8Array(16).fill(5), new Uint8Array(33).fill(5), new Uint8Array(0), Array.from({ length: 32 }, () => 5), "5".repeat(32), null, undefined, { plaintextKey: FIXED_DEK.slice() }]) {
    const crypto = createRecordCrypto({ keyProvider: { ...fakeProvider(), unwrapDataKey: async () => result } });
    await keyError(() => crypto.openCapture(stored.open), "KEY_UNAVAILABLE");
    if (result instanceof Uint8Array) assert.ok(result.every((byte) => byte === 0));
  }

  for (const result of [null, undefined, {}, { keyRef: "fake:2" }, { keyRef: "", wrappedKey: wrapped }, { keyRef: "fake:2", wrappedKey: new Uint8Array(0) }, { keyRef: "fake:2", wrappedKey: new Uint8Array(4097) }, { keyRef: "k".repeat(513), wrappedKey: wrapped }]) {
    const crypto = createRecordCrypto({ keyProvider: { ...fakeProvider(), rewrapDataKey: async () => result } });
    await keyError(() => crypto.rewrapCaptureKey(stored.rewrap), "KEY_UNAVAILABLE");
  }
});

test("a rewrap result is returned as a copy, without extra properties", async () => {
  const stored = await sealedOnce();
  const wrappedKey = utf8("synthetic-rewrapped-key");
  const crypto = createRecordCrypto({
    keyProvider: { ...fakeProvider(), rewrapDataKey: async () => ({ keyRef: "fake:2", wrappedKey, plaintextKey: FIXED_DEK.slice(), extra: FOREIGN_MESSAGE }) },
  });
  const result = await crypto.rewrapCaptureKey(stored.rewrap);
  assert.deepEqual(Object.keys(result).sort(), ["keyRef", "wrappedKey"]);
  wrappedKey.fill(0);
  assert.deepEqual(result.wrappedKey, utf8("synthetic-rewrapped-key"));
});

test("invalid input is rejected before the provider is called", async () => {
  const provider = fakeProvider();
  const crypto = createRecordCrypto({ keyProvider: provider });
  const stored = await sealedOnce();
  const record = sealInput().records[0];
  const sealCases = [
    [null, "RECORD_INVALID_ARGUMENT"],
    [{ context: CONTEXT, records: [] }, "RECORD_INVALID_ARGUMENT"],
    [{ context: CONTEXT, records: "records" }, "RECORD_INVALID_ARGUMENT"],
    [{ context: CONTEXT, records: [null] }, "RECORD_INVALID_ARGUMENT"],
    [{ context: null, records: [record] }, "RECORD_INVALID_ARGUMENT"],
    [{ context: { ...CONTEXT, namespace: "bad namespace" }, records: [record] }, "RECORD_INVALID_ARGUMENT"],
    [{ context: { ...CONTEXT, captureId: "cap_x" }, records: [record] }, "RECORD_INVALID_ARGUMENT"],
    // A duplicate entry would derive one entry key for two messages.
    [{ context: CONTEXT, records: [record, { binding: binding(), payload: payload(VALUES[1]) }] }, "RECORD_INVALID_ARGUMENT"],
    [{ context: CONTEXT, records: [record, { binding: binding({ entryId: entryId(2), tenant: "tenant-northwind-synthetic" }), payload: payload() }] }, "RECORD_INVALID_ARGUMENT"],
    [{ context: CONTEXT, records: [{ binding: binding({ namespace: "support-synthetic-2" }), payload: payload() }] }, "RECORD_INVALID_ARGUMENT"],
    [{ context: CONTEXT, records: [{ binding: binding({ captureId: "cap_bbbbbbbbbbbbbbbbbbbbbbbbbb" }), payload: payload() }] }, "RECORD_INVALID_ARGUMENT"],
    [{ context: CONTEXT, records: [{ binding: binding({ maxUses: 0 }), payload: payload() }] }, "RECORD_INVALID_ARGUMENT"],
    [{ context: CONTEXT, records: [{ binding: binding(), payload: payload(VALUES[0], { grants: [] }) }] }, "RECORD_INVALID_ARGUMENT"],
    [{ context: CONTEXT, records: [{ binding: binding() }] }, "RECORD_INVALID_ARGUMENT"],
  ];
  for (const [input, code] of sealCases) await recordError(() => crypto.sealCapture(input), code);
  assert.equal(provider.calls.generate, 0, "the provider was called for an input that was then rejected");

  const openCases = [
    [{ ...stored.open, records: [stored.open.records[0], stored.open.records[0]] }, "RECORD_INVALID_ARGUMENT"],
    [{ ...stored.open, records: [] }, "RECORD_INVALID_ARGUMENT"],
    [{ ...stored.open, keyRef: "" }, "RECORD_INVALID_ARGUMENT"],
    [{ ...stored.open, keyRef: "k".repeat(513) }, "RECORD_INVALID_ARGUMENT"],
    [{ ...stored.open, wrappedKey: new Uint8Array(0) }, "RECORD_INVALID_ARGUMENT"],
    [{ ...stored.open, wrappedKey: new Uint8Array(4097) }, "RECORD_LIMIT"],
    [{ ...stored.open, wrappedKey: "wrapped" }, "RECORD_INVALID_ARGUMENT"],
    [{ ...stored.open, context: { ...CONTEXT, tenant: "tenant-northwind-synthetic" } }, "RECORD_INVALID_ARGUMENT"],
    [{ ...stored.open, records: Array.from({ length: 1025 }, (_unused, i) => ({ binding: binding({ entryId: entryId(i + 1) }), envelope: stored.open.records[0].envelope })) }, "RECORD_LIMIT"],
  ];
  for (const [input, code] of openCases) await recordError(() => crypto.openCapture(input), code);
  await recordError(() => crypto.rewrapCaptureKey({ ...stored.rewrap, wrappedKey: new Uint8Array(0) }), "RECORD_INVALID_ARGUMENT");
  await recordError(() => crypto.rewrapCaptureKey({ ...stored.rewrap, context: {} }), "RECORD_INVALID_ARGUMENT");
  assert.deepEqual(provider.calls, { generate: 0, unwrap: 0, rewrap: 0 });

  await keyError(() => crypto.sealCapture(sealInput(), "options"), "KEY_INVALID_ARGUMENT");
  await keyError(() => crypto.sealCapture(sealInput(), { signal: "signal" }), "KEY_INVALID_ARGUMENT");
});

test("createRecordCrypto validates its options", async () => {
  const provider = fakeProvider();
  for (const options of [undefined, null, {}, { keyProvider: null }, { keyProvider: { generateDataKey() {} } }, { keyProvider: provider, keyTimeoutMs: 0 }, { keyProvider: provider, keyTimeoutMs: -1 }, { keyProvider: provider, keyTimeoutMs: 1.5 }, { keyProvider: provider, keyTimeoutMs: Number.POSITIVE_INFINITY }, { keyProvider: provider, keyTimeoutMs: "5000" }, { keyProvider: provider, keyTimeoutMs: 2 ** 31 }]) {
    await recordError(() => createRecordCrypto(options), "RECORD_INVALID_ARGUMENT");
  }
});

test("no error of a failed open carries a value, a token, a data key, or ciphertext", async () => {
  const crypto = createRecordCrypto({ keyProvider: fakeProvider() });
  const input = sealInput();
  const sealed = await crypto.sealCapture(input);
  const envelope = sealed.envelopes[0];
  const forbidden = [hex(FIXED_DEK), base64(FIXED_DEK), hex(envelope), base64(envelope), hex(envelope.subarray(22)), base64(envelope.subarray(22)), hex(utf8(VALUES[0])), base64(utf8(VALUES[0]))];
  const errors = [];
  const attempt = async (run) => {
    try {
      await run();
      assert.fail("expected a failure");
    } catch (error) {
      if (error.code === "ERR_ASSERTION") throw error;
      errors.push(error);
    }
  };
  const tampered = envelope.slice();
  tampered[30] ^= 0xff;
  const open = (overrides, recordOverrides = {}) =>
    crypto.openCapture({ context: CONTEXT, keyRef: sealed.keyRef, wrappedKey: sealed.wrappedKey, records: [{ binding: input.records[0].binding, envelope, ...recordOverrides }], ...overrides });
  await attempt(() => open({}, { envelope: tampered }));
  await attempt(() => open({}, { envelope: envelope.slice(0, 40) }));
  await attempt(() => open({}, { binding: binding({ maxUses: 9 }) }));
  await attempt(() => open({}, { binding: binding({ sessionId: "session-synthetic-0002" }) }));
  await attempt(() => open({ keyRef: "" }));
  await attempt(() => crypto.sealCapture({ context: CONTEXT, records: [input.records[0], input.records[0]] }));
  const throwing = createRecordCrypto({
    keyProvider: {
      ...fakeProvider(),
      async unwrapDataKey(stored) {
        // A provider that puts what it was given, and a key, into its error.
        throw new Error(`${FOREIGN_MESSAGE} ${hex(stored.wrappedKey)} ${hex(FIXED_DEK)} ${VALUES[0]}`);
      },
    },
  });
  await attempt(() => throwing.openCapture({ context: CONTEXT, keyRef: sealed.keyRef, wrappedKey: sealed.wrappedKey, records: [{ binding: input.records[0].binding, envelope }] }));
  assert.equal(errors.length, 7);
  assert.deepEqual(
    errors.map((error) => error.code),
    ["RECORD_INTEGRITY", "RECORD_MALFORMED", "RECORD_INTEGRITY", "RECORD_INTEGRITY", "RECORD_INVALID_ARGUMENT", "RECORD_INVALID_ARGUMENT", "KEY_UNAVAILABLE"],
  );
  for (const error of errors) assertClean(error, [...forbidden, ...FORBIDDEN]);
});
