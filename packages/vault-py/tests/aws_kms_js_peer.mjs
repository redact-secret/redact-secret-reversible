// Test tooling for the Python AWS KMS provider: the JavaScript provider as the other side of an interoperation run
// against a real AWS KMS key. Reads one JSON request on standard input, writes one JSON answer on standard output.
// The data key never leaves this process: only its SHA-256 is written. No ARN, account id, or credential is printed.
//
//   { "op": "generate" | "unwrap" | "rewrap", "keys": [{ "keyArn", "state" }], "context": { namespace, tenant, captureId },
//     "keyRef": "...", "wrapped": "<base64>" }
//
// The client is built here, as the provider's own integration test does: `new KMSClient({ region })` with the default
// credential chain of this process (AWS_PROFILE, or the environment).
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { KMSClient } from "@aws-sdk/client-kms";
import { KeyProviderError } from "@redact-secret/vault-contracts";

import { createAwsKmsKeyProvider } from "../../key-provider-aws-kms/dist/index.js";

const request = JSON.parse(readFileSync(0, "utf8"));
const active = request.keys.find((key) => key.state === "active").keyArn;
// arn:<partition>:kms:<region>:<account>:key/<id>
const [, partition, , region, accountId] = active.split(":");
const client = new KMSClient({ region });
const provider = createAwsKmsKeyProvider({
  client,
  keys: request.keys,
  expected: { region, accountId, partition },
  scope: { namespaces: [request.context.namespace] },
});
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const unb64 = (text) => new Uint8Array(Buffer.from(text, "base64"));

let answer;
try {
  if (request.op === "generate") {
    const key = await provider.generateDataKey(request.context);
    answer = { keyRef: key.keyRef, wrapped: b64(key.wrappedKey), plaintextSha256: sha256(key.plaintextKey) };
    key.plaintextKey.fill(0);
  } else if (request.op === "unwrap") {
    const dek = await provider.unwrapDataKey({ keyRef: request.keyRef, wrappedKey: unb64(request.wrapped), context: request.context });
    answer = { plaintextSha256: sha256(dek) };
    dek.fill(0);
  } else if (request.op === "rewrap") {
    const moved = await provider.rewrapDataKey({ keyRef: request.keyRef, wrappedKey: unb64(request.wrapped), context: request.context });
    answer = { keyRef: moved.keyRef, wrapped: b64(moved.wrappedKey) };
  } else {
    answer = { error: "UNSUPPORTED_OP" };
  }
} catch (thrown) {
  answer = { error: thrown instanceof KeyProviderError ? thrown.code : "FOREIGN" };
}
process.stdout.write(`${JSON.stringify(answer)}\n`);
