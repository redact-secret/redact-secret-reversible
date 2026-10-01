// A hand-written fake of the three AWS KMS operations this package uses.
// Every ARN, account id, and key here is synthetic. It is not a KMS emulator:
// it reproduces the semantics the provider depends on (context binding, key
// selection by KeyId or by the blob, key states, error names).
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from "node:crypto";

export const ACCOUNT = "111122223333";
export const REGION = "us-east-1";
export const EXPECTED = Object.freeze({ region: REGION, accountId: ACCOUNT });
/** Text a real SDK error could carry. None of it may reach a thrown error. */
export const SDK_TEXT = "SYNTHETIC-SDK-ERROR-TEXT";
export const SDK_REQUEST_ID = "synthetic-request-id-0f1e2d3c";

export const arnFor = (keyId, { region = REGION, account = ACCOUNT } = {}) => `arn:aws:kms:${region}:${account}:key/${keyId}`;

/** Shaped like an SDK v3 service exception: a name, a message naming the key, and response metadata. */
export class FakeSdkError extends Error {
  constructor(name, arn = "", extra = {}) {
    super(`${SDK_TEXT}: ${name} for ${arn}`);
    this.name = name;
    this.$fault = "client";
    this.$metadata = { httpStatusCode: 400, requestId: SDK_REQUEST_ID };
    this.cause = new Error(`${SDK_TEXT} inner cause`);
    Object.assign(this, extra);
  }
}

const TAG_BYTES = 16;
const IV_BYTES = 12;
const AUTH_BYTES = 16;

function canonical(context) {
  if (context === undefined) return Buffer.alloc(0);
  return Buffer.from(JSON.stringify(Object.keys(context).sort().map((key) => [key, context[key]])));
}

export function createFakeKms() {
  /** arn -> { material, tag, state } where state is Enabled | Disabled | PendingDeletion | PendingImport */
  const keys = new Map();
  const calls = [];
  let nextFailure = null;
  let hang = false;
  let transform = null;
  let delayMs = 0;
  /** Buffers handed out as `Plaintext`, so a test can see they were overwritten. */
  const plaintexts = [];

  function createKey() {
    const arn = arnFor(randomUUID());
    keys.set(arn, { material: randomBytes(32), tag: randomBytes(TAG_BYTES), state: "Enabled" });
    return arn;
  }

  function usable(arn) {
    const key = keys.get(arn);
    if (key === undefined) throw new FakeSdkError("NotFoundException", arn);
    if (key.state === "Disabled") throw new FakeSdkError("DisabledException", arn);
    if (key.state !== "Enabled") throw new FakeSdkError("KMSInvalidStateException", arn);
    return key;
  }

  function encrypt(key, plaintext, context) {
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv("aes-256-gcm", key.material, iv);
    cipher.setAAD(canonical(context));
    const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return new Uint8Array(Buffer.concat([key.tag, iv, body, cipher.getAuthTag()]));
  }

  /** Decrypts as KMS does: with `keyId` when given (it must be the blob's key), else with the key the blob names. */
  function decrypt(blob, keyId, context) {
    const bytes = Buffer.from(blob ?? []);
    if (bytes.length < TAG_BYTES + IV_BYTES + AUTH_BYTES) throw new FakeSdkError("InvalidCiphertextException");
    const tag = bytes.subarray(0, TAG_BYTES);
    let blobArn;
    for (const [arn, key] of keys) if (key.tag.equals(tag)) blobArn = arn;
    if (keyId !== undefined) {
      usable(keyId);
      if (blobArn === undefined) throw new FakeSdkError("InvalidCiphertextException", keyId);
      if (blobArn !== keyId) throw new FakeSdkError("IncorrectKeyException", keyId);
    } else if (blobArn === undefined) {
      throw new FakeSdkError("InvalidCiphertextException");
    }
    const key = usable(blobArn);
    try {
      const decipher = createDecipheriv("aes-256-gcm", key.material, bytes.subarray(TAG_BYTES, TAG_BYTES + IV_BYTES));
      decipher.setAAD(canonical(context));
      decipher.setAuthTag(bytes.subarray(bytes.length - AUTH_BYTES));
      const plaintext = Buffer.concat([decipher.update(bytes.subarray(TAG_BYTES + IV_BYTES, bytes.length - AUTH_BYTES)), decipher.final()]);
      return { arn: blobArn, plaintext: new Uint8Array(plaintext) };
    } catch {
      throw new FakeSdkError("InvalidCiphertextException", blobArn);
    }
  }

  function handle(name, input) {
    if (name === "GenerateDataKeyCommand") {
      const key = usable(input.KeyId);
      if (input.KeySpec !== "AES_256") throw new FakeSdkError("ValidationException", input.KeyId);
      const Plaintext = new Uint8Array(randomBytes(32));
      plaintexts.push(Plaintext);
      return { KeyId: input.KeyId, Plaintext, CiphertextBlob: encrypt(key, Plaintext, input.EncryptionContext) };
    }
    if (name === "DecryptCommand") {
      const { arn, plaintext } = decrypt(input.CiphertextBlob, input.KeyId, input.EncryptionContext);
      plaintexts.push(plaintext);
      return { KeyId: arn, Plaintext: plaintext, EncryptionAlgorithm: "SYMMETRIC_DEFAULT" };
    }
    if (name === "ReEncryptCommand") {
      const destination = usable(input.DestinationKeyId);
      const { arn, plaintext } = decrypt(input.CiphertextBlob, input.SourceKeyId, input.SourceEncryptionContext);
      const CiphertextBlob = encrypt(destination, plaintext, input.DestinationEncryptionContext);
      plaintext.fill(0);
      return { KeyId: input.DestinationKeyId, SourceKeyId: arn, CiphertextBlob };
    }
    throw new FakeSdkError("UnknownOperationException");
  }

  const client = {
    async send(command, options) {
      const name = command.constructor.name;
      const input = structuredClone(command.input);
      calls.push({ name, input, options });
      const signal = options?.abortSignal;
      if (hang) {
        return new Promise((_resolve, reject) => {
          signal?.addEventListener("abort", () => reject(Object.assign(new Error(`${SDK_TEXT} aborted`), { name: "AbortError" })), { once: true });
        });
      }
      if (delayMs > 0) await new Promise((resolve) => setTimeout(resolve, delayMs));
      if (nextFailure !== null) {
        const { error } = nextFailure;
        nextFailure = null;
        throw error;
      }
      const output = handle(name, input);
      return transform === null ? output : transform(output, name);
    },
  };

  return {
    client,
    calls,
    plaintexts,
    createKey,
    setState(arn, state) {
      keys.get(arn).state = state;
    },
    /** The next call throws `error`. */
    failNext(error) {
      nextFailure = { error };
    },
    /** Calls never answer until the abort signal fires. */
    setHang(value) {
      hang = value;
    },
    setDelay(ms) {
      delayMs = ms;
    },
    /** Rewrites every successful response. */
    setTransform(fn) {
      transform = fn;
    },
  };
}
