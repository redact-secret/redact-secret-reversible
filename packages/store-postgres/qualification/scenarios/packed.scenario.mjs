// The packed artifact in a clean consumer project.
//
// `npm pack` of this package and of `@redact-secret/vault-contracts`, both
// installed with the `pg` driver into an empty project outside the
// workspace. The consumer imports the package by name and runs one capture,
// one commit, and one read against the database of this run. It shows the
// tarball is complete and resolves on its own; the behavior is covered by
// the suites that run against the build output.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import { join } from "node:path";
import { after, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { evidence, prepareDatabase, randomNamespace, SCHEMA } from "../lib/harness.mjs";

const exec = promisify(execFile);
const ADMIN_URL = process.env.RSV_PG_ADMIN_URL;
const APP_URL = process.env.RSV_PG_APP_URL;
const SKIP = typeof ADMIN_URL === "string" && typeof APP_URL === "string" ? false : "RSV_PG_ADMIN_URL and RSV_PG_APP_URL are not set";
const packageRoot = fileURLToPath(new URL("../..", import.meta.url));
const contractsRoot = fileURLToPath(new URL("../../../vault-contracts", import.meta.url));

const CONSUMER = `
import pg from "pg";
import * as api from "@redact-secret/store-postgres";

const pool = new pg.Pool({ connectionString: process.env.RSV_PG_APP_URL, max: 2 });
const store = await api.createPostgresStore({ pool, schema: process.env.RSV_PG_SCHEMA });
const namespace = process.env.RSVQ_NAMESPACE;
const scope = { namespace, tenant: "tenant-synthetic-a" };
const now = Date.now();
const out = { exports: Object.keys(api).sort(), capabilities: store.capabilities() };
out.initialized = (await store.initializeNamespace({ namespace, epoch: 1 })).outcome;
const captureId = "cap_" + "a".repeat(26);
const entryId = "ab".repeat(32);
out.created = (await store.createCapture({ scope, epoch: 1, now,
  capture: { captureId, sessionTag: null, createdAt: now, expiresAt: now + 60000, lookupVersion: 1, keyRef: "local:synthetic-1", wrappedKey: new Uint8Array(61).fill(7) },
  entries: [{ entryId, maxUses: 1, envelope: new Uint8Array(80).fill(9) }] })).outcome;
out.committed = (await store.commitRestore({ scope, epoch: 1, now: Date.now(), attempt: { attemptId: "att_packed", requestDigest: new Uint8Array(32).fill(3) },
  receiptExpiresAt: now + 60000 + 3600000, captures: [{ captureId, generation: 1 }],
  uses: [{ entryId, captureId, count: 1, lifecycleRevision: 1, ciphertextRevision: 1 }] })).outcome;
out.used = (await store.readEntries({ scope, entryIds: [entryId] })).entries[0].used;
store.close();
await pool.end();
console.log(JSON.stringify(out));
`;

describe("packed artifact in a clean consumer project", { skip: SKIP }, () => {
  let directory;

  after(() => {
    if (directory !== undefined) rmSync(directory, { recursive: true, force: true });
  });

  test("the tarball holds only the build output, and a consumer outside the workspace can use it", async (t) => {
    await prepareDatabase({ adminUrl: ADMIN_URL, appUrl: APP_URL });
    directory = mkdtempSync(join(os.tmpdir(), "rsvq-consumer-"));
    for (const root of [contractsRoot, packageRoot]) await exec("npm", ["pack", "--pack-destination", directory, "--ignore-scripts"], { cwd: root });
    const tarballs = readdirSync(directory).filter((name) => name.endsWith(".tgz"));
    assert.equal(tarballs.length, 2);
    const store = tarballs.find((name) => name.includes("store-postgres"));
    const { stdout: listing } = await exec("tar", ["-tzf", join(directory, store)]);
    const files = listing.trim().split("\n").map((file) => file.replace(/^package\//, "")).sort();
    for (const file of files) assert.match(file, /^(LICENSE|README\.md|package\.json|dist\/[a-z]+\.(js|d\.ts))$/, `unexpected packed file ${file}`);
    for (const required of ["LICENSE", "README.md", "package.json", "dist/index.js", "dist/index.d.ts", "dist/store.js", "dist/schema.js"]) assert.ok(files.includes(required), `missing ${required}`);
    const packed = JSON.parse((await exec("tar", ["-xzOf", join(directory, store), "package/package.json"])).stdout);
    assert.deepEqual(Object.keys(packed.dependencies), ["@redact-secret/vault-contracts"]);
    assert.deepEqual(Object.keys(packed.peerDependencies), ["pg"]);
    const built = readFileSync(join(packageRoot, "dist/store.js"), "utf8") + readFileSync(join(packageRoot, "dist/index.js"), "utf8") + readFileSync(join(packageRoot, "dist/schema.js"), "utf8");
    const imports = [...built.matchAll(/from\s+"([^"]+)"/g)].map((match) => match[1]).filter((specifier) => !specifier.startsWith("./"));
    assert.deepEqual([...new Set(imports)], ["@redact-secret/vault-contracts"], "the build imports the contracts and no driver, node: module, or child_process");

    writeFileSync(join(directory, "package.json"), JSON.stringify({ name: "rsvq-consumer", private: true, type: "module" }));
    const pgVersion = JSON.parse(readFileSync(fileURLToPath(new URL("../../../../node_modules/pg/package.json", import.meta.url)), "utf8")).version;
    try {
      await exec("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--prefer-offline", ...tarballs.map((name) => `./${name}`), `pg@${pgVersion}`], { cwd: directory, timeout: 240_000 });
    } catch {
      t.skip("the pg driver could not be installed into the consumer project (no registry access)");
      return;
    }
    writeFileSync(join(directory, "consumer.mjs"), CONSUMER);
    const { stdout } = await exec("node", ["consumer.mjs"], {
      cwd: directory,
      env: { ...process.env, RSV_PG_SCHEMA: SCHEMA, RSVQ_NAMESPACE: randomNamespace("packed") },
      timeout: 60_000,
    });
    const out = JSON.parse(stdout.trim().split("\n").at(-1));
    assert.deepEqual(out.exports, ["SCHEMA_VERSION", "createPostgresStore", "grantStatements", "migrate", "migrationStatements"]);
    assert.deepEqual([out.initialized, out.created, out.committed, out.used], ["initialized", "created", "committed", 1]);
    assert.equal(out.capabilities.adapter, "store-postgres");
    evidence("packed", "clean-consumer", { files, pg: pgVersion, node: process.version, exports: out.exports, profile: out.capabilities.profile });
  });
});
