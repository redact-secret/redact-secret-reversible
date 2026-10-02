// What a `logger` in the AWS SDK v3 client configuration writes for the three calls of this provider (issue #145,
// the JavaScript counterpart of the Python `botocore` DEBUG finding). The real `KMSClient` runs with a logger that
// records every call of every level, against a loopback HTTP server that answers with synthetic bodies. No AWS service,
// credential, or key is involved. The finding is recorded in docs/research/aws-sdk-v3-logger-and-key-material.md.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { inspect } from "node:util";
import test from "node:test";

import { KMSClient } from "@aws-sdk/client-kms";

import { createAwsKmsKeyProvider } from "../dist/index.js";
import { arnFor, EXPECTED } from "./fake-kms.mjs";
import { CONTEXT, SCOPE } from "./helpers.mjs";

const KEY_ARN = arnFor("00000000-0000-4000-8000-0000000000aa");
const OTHER_ARN = arnFor("00000000-0000-4000-8000-0000000000bb");
const DATA_KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1));
const WRAPPED = Buffer.concat([Buffer.from("SYNTHETIC-WRAPPED-KEY-"), Buffer.from(Array.from({ length: 40 }, (_, i) => i + 40))]);

/** Answers like KMS, from the request's operation and key id. Counts the requests. */
function startServer() {
  const requests = [];
  const server = createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      const operation = String(request.headers["x-amz-target"]).split(".").pop();
      const asked = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      requests.push(operation);
      const body =
        operation === "ReEncrypt"
          ? { KeyId: asked.DestinationKeyId, SourceKeyId: asked.SourceKeyId, CiphertextBlob: WRAPPED.toString("base64") }
          : { KeyId: asked.KeyId, Plaintext: DATA_KEY.toString("base64"), ...(operation === "GenerateDataKey" ? { CiphertextBlob: WRAPPED.toString("base64") } : {}) };
      response.writeHead(200, { "content-type": "application/x-amz-json-1.1" });
      response.end(JSON.stringify(body));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ server, requests, endpoint: `http://127.0.0.1:${server.address().port}` }));
  });
}

/** Every method of every level, recording arguments exactly as the SDK passes them. */
function recordingLogger() {
  const calls = [];
  const logger = {};
  for (const level of ["trace", "debug", "info", "warn", "error", "log"]) {
    logger[level] = (...args) => calls.push({ level, args });
  }
  return { logger, calls };
}

/** Text a console, pino, or JSON logger could produce from the recorded arguments. */
function textOf(calls) {
  return calls
    .map(({ level, args }) => {
      const json = JSON.stringify(args, (_key, value) => (value instanceof Uint8Array ? { bytes: Buffer.from(value).toString("base64") } : value));
      return `${level} ${json} ${inspect(args, { depth: 10 })}`;
    })
    .join("\n");
}

const SECRETS = {
  "data key (base64)": DATA_KEY.toString("base64"),
  "data key (hex)": DATA_KEY.toString("hex"),
  "wrapped key (base64)": WRAPPED.toString("base64"),
  "key ARN": KEY_ARN,
};

async function runProvider(logger) {
  const { server, requests, endpoint } = await startServer();
  const client = new KMSClient({
    region: "us-east-1",
    endpoint,
    credentials: { accessKeyId: "AKIASYNTHETICSYNTHET", secretAccessKey: "synthetic-secret-synthetic-secret-0000" },
    maxAttempts: 1,
    ...(logger === undefined ? {} : { logger }),
  });
  try {
    const provider = createAwsKmsKeyProvider({
      client,
      keys: [
        { keyArn: KEY_ARN, state: "active" },
        { keyArn: OTHER_ARN, state: "decrypt-only" },
      ],
      expected: EXPECTED,
      scope: SCOPE,
    });
    const key = await provider.generateDataKey(CONTEXT);
    const unwrapped = await provider.unwrapDataKey({ ...key, context: CONTEXT });
    await provider.rewrapDataKey({ keyRef: `aws-kms:${OTHER_ARN}`, wrappedKey: key.wrappedKey, context: CONTEXT });
    assert.deepEqual(Buffer.from(unwrapped), DATA_KEY);
    return requests;
  } finally {
    client.destroy();
    server.close();
  }
}

test("a logger in the client config receives the key ARN and the wrapped key, never the plaintext data key or an identifier", async () => {
  const { logger, calls } = recordingLogger();
  const requests = await runProvider(logger);
  assert.deepEqual(requests, ["GenerateDataKey", "Decrypt", "ReEncrypt"]);
  assert.ok(calls.length > 0, "the SDK did log through the configured logger");
  const text = textOf(calls);
  const seen = Object.fromEntries(Object.entries(SECRETS).map(([name, value]) => [name, text.includes(value)]));
  // Plaintext is marked sensitive in the KMS model: the SDK's own filter replaces it before the logger sees it.
  assert.equal(seen["data key (base64)"], false);
  assert.equal(seen["data key (hex)"], false);
  assert.ok(text.includes("***SensitiveInformation***"), "the data key is replaced by the SDK's sensitive marker");
  // What the logger does receive, recorded so a change of the SDK's model shows up here: the key ARN and the wrapped
  // key (ciphertext, which the store holds anyway), at info level, from the SDK's logger middleware.
  assert.equal(seen["key ARN"], true);
  assert.equal(seen["wrapped key (base64)"], true);
  assert.ok(calls.some((c) => c.level === "info"));
  // The encryption context carries only the digest: no identifier of the caller is in any record.
  for (const identifier of [CONTEXT.namespace, CONTEXT.tenant, CONTEXT.captureId]) assert.equal(text.includes(identifier), false);
});

test("without a logger in the client config the SDK writes no log record", async () => {
  const written = [];
  const spy = (stream) => {
    const original = stream.write.bind(stream);
    stream.write = (chunk, ...rest) => {
      written.push(String(chunk));
      return original(chunk, ...rest);
    };
    return () => {
      stream.write = original;
    };
  };
  const restore = [spy(process.stdout), spy(process.stderr)];
  try {
    await runProvider(undefined);
  } finally {
    for (const undo of restore) undo();
  }
  const text = written.join("");
  for (const value of Object.values(SECRETS)) assert.equal(text.includes(value), false);
});
