// Shared by setup.mjs and demo.mjs. Everything here is for a local,
// disposable database: the passwords are synthetic.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const ADMIN_URL = process.env.RSV_PG_ADMIN_URL ?? "postgres://postgres:synthetic-local-only@127.0.0.1:55432/rsv";
export const APP_URL = process.env.RSV_PG_APP_URL ?? "postgres://rsv_app:synthetic-local-only@127.0.0.1:55432/rsv";
export const SCHEMA = "rsv";
export const NAMESPACE = "example-dev";
export const RECOVERY_EPOCH = 1;
export const KEYS_FILE = fileURLToPath(new URL(".dev-keys.json", import.meta.url));

/**
 * Development-only: reads the two 32-byte keys setup.mjs generated. A real
 * server loads its keys from a secret manager, never from a file like this.
 */
export function loadDevKeys() {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(KEYS_FILE, "utf8"));
  } catch {
    throw new Error("no development keys yet: run `node examples/persistent/setup.mjs` first");
  }
  return {
    wrappingKey: Uint8Array.from(Buffer.from(parsed.wrappingKey, "hex")),
    digestKey: Uint8Array.from(Buffer.from(parsed.digestKey, "hex")),
  };
}
