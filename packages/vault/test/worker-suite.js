/**
 * Portable Worker-mode qualification suite for @redact-secret/vault (#14).
 *
 * Runs in a real browser page against a real dedicated Worker. It receives
 * an already-connected `workerVault` (the async client from
 * `@redact-secret/vault/worker`), the raw `worker` object the host runner
 * created, and the shared conformance fixtures. It never prints a fixture
 * value: failures describe the mismatch by id and sanitized code only.
 *
 * Two kinds of case:
 * - Parity: Worker mode's capture/restore round trip behaves like the
 *   documented main-thread contract for the same input.
 * - Hostile main thread: this suite talks to `worker` directly with
 *   `postMessage`, bypassing the safe `createWorkerVault` wrapper entirely,
 *   to demonstrate what a compromised page can and cannot do. It can still
 *   reach the same validated protocol a legitimate caller uses (that is not
 *   a security boundary — see docs/specs/in-memory-security.md section 5);
 *   it cannot make the Worker execute an operation outside that protocol,
 *   and every malformed or adversarial message is rejected explicitly.
 */

export async function runWorkerSuite({ workerVault, worker, fixtures }) {
  const results = [];
  const record = async (id, body) => {
    try {
      await body();
      return { id, ok: true };
    } catch (error) {
      return { id, ok: false, message: error instanceof AssertionFailure ? error.message : safeDescribe(error) };
    }
  };

  const RELEASE = [{ sink: "draft-reply", paths: ["body"] }];

  results.push(
    await record("parity:capture-restore-round-trip", async () => {
      const input = `Please rotate ${fixtures.GH} today`;
      const captured = await workerVault.capture(input, { release: RELEASE });
      assert(captured.tokens.length === 1, "expected exactly one issued token");
      assert(!captured.text.includes(fixtures.GH), "fixture value leaked into redacted text");
      assert(/<rsv_[a-z2-7]{26}>/.test(captured.text), "redacted text does not contain an issued token");
      const { fields, restored } = await workerVault.restore({
        sink: "draft-reply",
        captures: [captured.captureId],
        fields: { body: captured.text },
      });
      assert(restored === 1, `expected 1 restored occurrence, got ${restored}`);
      assert(fields.body === input, "restored value does not match the original input");
    }),
  );

  results.push(
    await record("parity:restore-denied-for-unlisted-capture-source", async () => {
      const a = await workerVault.capture(fixtures.GH, { release: RELEASE });
      const b = await workerVault.capture(fixtures.GH2, { release: RELEASE });
      await expectWorkerError(
        () => workerVault.restore({ sink: "draft-reply", captures: [b.captureId], fields: { body: a.tokens[0].token } }),
        "RESTORE_DENIED",
      );
    }),
  );

  results.push(
    await record("parity:stats-reveal-counts-only", async () => {
      const stats = await workerVault.stats();
      assert(typeof stats.entries === "number", "stats().entries missing");
      assert(typeof stats.disposed === "boolean", "stats().disposed missing");
      assert(Object.keys(stats).every((k) => !JSON.stringify(stats[k]).includes(fixtures.GH)), "stats leaked a fixture value");
    }),
  );

  results.push(
    await record("protocol:non-cloneable-capture-option-rejected-before-send", async () => {
      let sawMessage = false;
      const onMessage = () => {
        sawMessage = true;
      };
      worker.addEventListener("message", onMessage);
      try {
        let code;
        try {
          // `eligible` is a function: not part of WorkerCaptureOptions, and not
          // structured-clonable. This must throw synchronously, before any
          // postMessage happens — never silently dropped, never sent raw.
          workerVault.capture("x", { release: RELEASE, eligible: () => true });
        } catch (error) {
          code = error && error.code;
        }
        assert(code === "INVALID_ARGUMENT", `expected synchronous INVALID_ARGUMENT, got ${code}`);
        await settle();
        assert(!sawMessage, "a message reached the worker despite the disallowed option");
      } finally {
        worker.removeEventListener("message", onMessage);
      }
    }),
  );

  results.push(
    await record("hostile:no-dump-or-export-operation-exists", async () => {
      for (const op of ["dump", "listSecrets", "export", "entries", "getMapping"]) {
        const reply = await rawRequest(worker, { kind: "vault-request", v: 1, id: `hostile-op-${op}`, op });
        assert(reply.ok === false, `${op} was not rejected`);
        assert(reply.error.code === "WORKER_PROTOCOL_VIOLATION", `${op} gave ${reply.error && reply.error.code}, not WORKER_PROTOCOL_VIOLATION`);
      }
    }),
  );

  results.push(
    await record("hostile:unrecognized-kind-rejected", async () => {
      const reply = await rawRequest(worker, { kind: "vault-dump-request", v: 1, id: "hostile-kind" });
      assert(reply.ok === false && reply.error.code === "WORKER_PROTOCOL_VIOLATION", "wrong kind was not rejected");
    }),
  );

  results.push(
    await record("hostile:extra-unexpected-key-rejected", async () => {
      const reply = await rawRequest(worker, { kind: "vault-request", v: 1, id: "hostile-extra", op: "stats", debug: true });
      assert(reply.ok === false && reply.error.code === "WORKER_PROTOCOL_VIOLATION", "an unexpected extra key was accepted");
    }),
  );

  results.push(
    await record("hostile:prototype-pollution-shaped-payload-rejected", async () => {
      const payload = JSON.parse(
        `{"kind":"vault-request","v":1,"id":"hostile-proto","op":"capture","input":"x","options":{"release":[],"__proto__":{"polluted":true}}}`,
      );
      const reply = await rawRequest(worker, payload);
      assert(reply.ok === false && reply.error.code === "WORKER_PROTOCOL_VIOLATION", "a __proto__-bearing payload was accepted");
      assert(({}).polluted === undefined, "Object.prototype was polluted by a hostile message");
    }),
  );

  results.push(
    await record("hostile:malformed-envelope-without-id-does-not-crash-the-worker", async () => {
      // No `id`: the host cannot correlate a reply, so it drops the message
      // silently rather than guess a recipient. The demonstration here is
      // that the worker keeps serving legitimate requests afterward.
      worker.postMessage({ op: "capture", input: fixtures.AWS });
      await settle();
      const stats = await workerVault.stats();
      assert(typeof stats.entries === "number", "the worker stopped responding after a malformed message");
    }),
  );

  results.push(
    await record("hostile:non-object-message-rejected-without-crash", async () => {
      for (const bad of ["a string", 42, null, ["array"], true]) {
        worker.postMessage(bad);
      }
      await settle();
      const stats = await workerVault.stats();
      assert(typeof stats.entries === "number", "the worker stopped responding after non-object messages");
    }),
  );

  results.push(
    await record("leakage:no-plaintext-in-hostile-protocol-error-replies", async () => {
      const reply = await rawRequest(worker, {
        kind: "vault-request",
        v: 1,
        id: "hostile-leak",
        op: "capture",
        input: fixtures.JWT,
        options: { release: RELEASE, policy: "not-a-function-and-not-allowed" },
      });
      const haystack = JSON.stringify(reply);
      assert(!haystack.includes(fixtures.JWT), "a fixture value leaked into a protocol-violation reply");
      assert(reply.ok === false, "a malformed capture options object was accepted");
    }),
  );

  return {
    passed: results.filter((r) => r.ok).length,
    failed: results.filter((r) => !r.ok).length,
    results,
  };
}

class AssertionFailure extends Error {}

function assert(condition, message) {
  if (!condition) throw new AssertionFailure(message);
}

function safeDescribe(error) {
  if (error && typeof error === "object" && "code" in error) return `${error.name ?? "Error"}(${error.code})`;
  return String(error && error.message ? error.message : error);
}

async function expectWorkerError(fn, code) {
  try {
    await fn();
  } catch (error) {
    assert(error && error.code === code, `expected ${code}, got ${error && error.code}`);
    return;
  }
  throw new AssertionFailure(`expected ${code}, but the call succeeded`);
}

function settle() {
  return new Promise((resolve) => setTimeout(resolve, 50));
}

/** Sends one raw message directly to `worker` (bypassing the client wrapper) and resolves with the matching `vault-response`. */
function rawRequest(worker, message) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      worker.removeEventListener("message", onMessage);
      reject(new AssertionFailure(`no reply to hostile request ${message.id}`));
    }, 5000);
    const onMessage = (event) => {
      const data = event.data;
      if (data && typeof data === "object" && data.kind === "vault-response" && data.id === message.id) {
        clearTimeout(timer);
        worker.removeEventListener("message", onMessage);
        resolve(data);
      }
    };
    worker.addEventListener("message", onMessage);
    worker.postMessage(message);
  });
}
