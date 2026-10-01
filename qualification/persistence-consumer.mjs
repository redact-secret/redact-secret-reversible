// Clean-consumer qualification of the persistence packages (#112).
//
// Packs every package, installs the tarballs into throwaway projects outside
// the repository, and runs real code there. Nothing below resolves from the
// workspace: what passes is what a consumer would install.
//
// Consumer A installs only @redact-secret/vault and @redact-secret/vault-server
// and shows that no database driver, key-service SDK, crypto layer, or store
// is installed or loaded by them.
// Consumer B installs the persistence packages and runs capture, restore,
// revoke, and deletion through the persistent server profile over the
// reference memory store, over SQLite files, and over PostgreSQL when
// RSV_PG_ADMIN_URL and RSV_PG_APP_URL name a disposable database. The SQLite
// flow runs over node:sqlite where this Node.js bundles SQLite 3.51.3 or later,
// and over better-sqlite3 only when RSV_QUALIFY_BETTER_SQLITE3=1: that driver
// has an install script, so the default run installs it nowhere.
// Consumer C installs store-sqlite alone and shows that it imports and loads
// no driver, and refuses to start without one the application passes.
import { execFileSync } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { CORE_VERSION, REPORTS, ROOT, run, WORK } from "./lib.mjs";

const PACKAGES = ["vault-contracts", "vault", "vault-crypto", "vault-conformance", "store-memory", "store-postgres", "store-sqlite", "key-provider-aws-kms", "vault-server"];

const packDir = join(WORK, "persistence-pack");
rmSync(packDir, { recursive: true, force: true });
mkdirSync(packDir, { recursive: true });
run("npm", ["run", "build"], ROOT);
const tarballs = {};
const versions = {};
for (const directory of PACKAGES) {
  const pkg = JSON.parse(readFileSync(join(ROOT, "packages", directory, "package.json"), "utf8"));
  const before = new Set(readdirSync(packDir));
  run("npm", ["pack", "-w", pkg.name, "--pack-destination", packDir], ROOT);
  const tarball = readdirSync(packDir).find((file) => !before.has(file) && file.endsWith(".tgz"));
  if (!tarball) throw new Error(`npm pack produced no tarball for ${pkg.name}`);
  tarballs[directory] = join(packDir, tarball);
  versions[pkg.name] = pkg.version;
}

function consumer(name, install, script) {
  const dir = join(WORK, name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: `qualify-${name}`, private: true, type: "module" }, null, 2));
  run("npm", ["install", "--no-audit", "--no-fund", "--save-exact", ...install], dir);
  writeFileSync(join(dir, "main.mjs"), script);
  const output = execFileSync(process.execPath, ["main.mjs"], { cwd: dir, encoding: "utf8", env: process.env });
  return { dir, result: JSON.parse(output.trim().split("\n").at(-1)) };
}

function installedPackages(dir) {
  const names = [];
  const root = join(dir, "node_modules");
  for (const entry of readdirSync(root)) {
    if (entry.startsWith(".")) continue;
    if (entry.startsWith("@")) for (const scoped of readdirSync(join(root, entry))) names.push(`${entry}/${scoped}`);
    else names.push(entry);
  }
  return names.sort();
}

const failures = [];
const check = (ok, message) => ok || failures.push(message);

// ---------------------------------------------------------------- consumer A
const a = consumer(
  "persistence-base",
  // vault-contracts is a dependency of the server and is not on the registry
  // before the first release, so its tarball is installed beside it.
  [tarballs["vault-contracts"], tarballs.vault, tarballs["vault-server"], `@redact-secret/core@${CORE_VERSION}`],
  `
import { createVault } from "@redact-secret/vault";
import { createServerVault } from "@redact-secret/vault-server";
const SECRET = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000";
const vault = await createVault({ pii: [] });
const captured = vault.capture("token " + SECRET, { release: [{ sink: "reply", paths: ["body"] }] });
const restored = vault.restore({ sink: "reply", captures: [captured.captureId], fields: { body: captured.text } });
vault.dispose();
const server = await createServerVault({ resolvePrincipal: () => ({ id: "user-synthetic", tenant: "tenant-acme-synthetic" }), policy: () => ({ allow: true }) });
const c = await server.capture("token " + SECRET, { issuedTenant: "tenant-acme-synthetic", release: [{ sink: "reply", paths: ["body"] }] });
const r = await server.restore({ context: {}, sink: "reply", purpose: "support", captures: [c.captureId], fields: { body: c.text } });
await server.dispose();
// What the two root entry points actually loaded.
const loaded = process.moduleLoadList ?? [];
let capturePlanFromBrowser = "resolved";
try { await import("@redact-secret/vault/internal/capture-plan"); capturePlanFromBrowser = "node-resolved"; } catch { capturePlanFromBrowser = "blocked"; }
console.log(JSON.stringify({
  inMemory: restored.fields.body === "token " + SECRET,
  server: r.fields.body === "token " + SECRET,
  redacted: !captured.text.includes(SECRET) && !c.text.includes(SECRET),
  capturePlan: capturePlanFromBrowser,
}));
`,
);
const installedA = installedPackages(a.dir);
check(a.result.inMemory && a.result.server && a.result.redacted, "consumer A: in-memory vault and server round trips");
for (const name of installedA) {
  check(
    // The three base packages, plus the core and the core's own artifacts (its WASM build and per-platform addons).
    ["@redact-secret/vault", "@redact-secret/vault-server", "@redact-secret/vault-contracts", "@redact-secret/core", "@redact-secret/wasm"].includes(name) || /^@redact-secret\/(node|core)-/.test(name),
    `consumer A: unexpected installed package ${name}`,
  );
}
check(!installedA.some((name) => /^pg|@aws-sdk|store-|key-provider-|vault-crypto|better-sqlite3/.test(name.replace("@redact-secret/", ""))), "consumer A: a driver, SDK, store, provider, or crypto layer was installed");

// The server's default entry must not load the contracts package or the persistent profile.
const graph = execFileSync(
  process.execPath,
  [
    "--input-type=module",
    "-e",
    `import { registerHooks } from "node:module";
     const seen = [];
     registerHooks({ resolve(specifier, context, next) { const r = next(specifier, context); seen.push(r.url); return r; } });
     await import("@redact-secret/vault");
     await import("@redact-secret/vault-server");
     console.log(JSON.stringify(seen.filter((url) => url.startsWith("file:"))));`,
  ],
  { cwd: a.dir, encoding: "utf8" },
);
let loadedUrls = null;
try {
  loadedUrls = JSON.parse(graph.trim().split("\n").at(-1));
} catch {
  loadedUrls = null;
}
if (loadedUrls === null) {
  check(false, "consumer A: could not observe the module graph (node:module registerHooks unavailable)");
} else {
  check(!loadedUrls.some((url) => /vault-contracts|\/persistent\//.test(url)), "consumer A: importing the root entry points loaded the contracts package or the persistent profile");
  check(!loadedUrls.some((url) => /internal-capture-plan/.test(url)), "consumer A: importing the root entry points loaded the internal capture-plan entry");
}

// ---------------------------------------------------------------- consumer B
const withBetterSqlite3 = process.env.RSV_QUALIFY_BETTER_SQLITE3 === "1";
const withPostgres = typeof process.env.RSV_PG_ADMIN_URL === "string" && typeof process.env.RSV_PG_APP_URL === "string";
const b = consumer(
  "persistence-full",
  [...PACKAGES.map((directory) => tarballs[directory]), `@redact-secret/core@${CORE_VERSION}`, "pg@8.23.1", ...(withBetterSqlite3 ? ["better-sqlite3@12.11.1"] : []), "@aws-sdk/client-kms@3.1144.0"],
  `
import { createPersistentServerVault } from "@redact-secret/vault-server/persistent";
import { createRecordCrypto } from "@redact-secret/vault-crypto";
import { createLocalKeyProvider } from "@redact-secret/vault-crypto/local-key-provider";
import { createMemoryStore } from "@redact-secret/store-memory";
import { createPostgresStore, grantStatements, migrate } from "@redact-secret/store-postgres";
import { betterSqlite3Driver, createSqliteStore, migrate as migrateSqlite, nodeSqliteDriver, sqliteVersionAcceptable } from "@redact-secret/store-sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as contracts from "@redact-secret/vault-contracts";
import * as conformance from "@redact-secret/vault-conformance";
import * as kms from "@redact-secret/key-provider-aws-kms";
import pg from "pg";

const SECRET = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000";
// Synthetic key material, generated for this run only.
const material = crypto.getRandomValues(new Uint8Array(32));
const digestKey = crypto.getRandomValues(new Uint8Array(32));

async function exercise(store, namespace, extra) {
  await store.initializeNamespace({ namespace, epoch: 1 });
  const open = () => createPersistentServerVault({
    namespace, recoveryEpoch: 1, store, digestKey,
    crypto: createRecordCrypto({ keyProvider: createLocalKeyProvider({ keys: [{ id: "k1", material, state: "active" }], scope: { namespaces: [namespace] } }) }),
    resolvePrincipal: (context) => ({ id: context.user, tenant: context.tenant }),
    policy: () => ({ allow: true }),
    lifecyclePolicy: () => ({ allow: true }),
    pii: [],
    ...extra,
  });
  const first = await open();
  const second = await open(); // a second instance over the same store
  const context = { user: "user-synthetic", tenant: "tenant-acme-synthetic" };
  const captured = await first.capture("rotate " + SECRET + " now", { context, release: [{ sink: "reply", paths: ["body"] }] });
  const restored = await second.restore({ context, sink: "reply", purpose: "support", captures: [captured.captureId], fields: { body: captured.text } });
  const again = await second.restore({ context, sink: "reply", purpose: "support", captures: [captured.captureId], fields: { body: captured.text } }).then(() => "released", (error) => error.reason ?? error.code);
  const other = await first.capture("rotate " + SECRET + " now", { context, release: [{ sink: "reply", paths: ["body"] }] });
  const wrongTenant = await second.restore({ context: { user: "user-b", tenant: "tenant-northwind-synthetic" }, sink: "reply", purpose: "support", captures: [other.captureId], fields: { body: other.text } }).then(() => "released", (error) => error.reason ?? error.code);
  const revoked = await first.revoke({ context, captureId: other.captureId });
  const afterRevoke = await second.restore({ context, sink: "reply", purpose: "support", captures: [other.captureId], fields: { body: other.text } }).then(() => "released", (error) => error.reason ?? error.code);
  const deleted = await first.deleteCaptureCiphertext({ context, captureId: other.captureId });
  await first.close(); await second.close();
  return {
    redacted: !captured.text.includes(SECRET),
    restored: restored.fields.body === "rotate " + SECRET + " now",
    again, wrongTenant, revoked: revoked.outcome, afterRevoke, deleted: deleted.outcome, keyRetired: deleted.keyRetired,
  };
}

const memory = await exercise(createMemoryStore().store, "consumer-memory", { allowNonDurableStore: true });

let postgres = null;
if (process.env.RSV_PG_ADMIN_URL && process.env.RSV_PG_APP_URL) {
  const admin = new pg.Pool({ connectionString: process.env.RSV_PG_ADMIN_URL, max: 1 });
  await migrate(admin, "rsv");
  for (const statement of grantStatements("rsv", new URL(process.env.RSV_PG_APP_URL).username)) await admin.query(statement);
  await admin.end();
  const pool = new pg.Pool({ connectionString: process.env.RSV_PG_APP_URL, max: 4 });
  const store = await createPostgresStore({ pool });
  postgres = await exercise(store, "consumer-" + Date.now().toString(36), {});
  postgres.profile = store.capabilities().profile;
  await pool.end();
}

async function sqliteFlow(driver) {
  const dir = mkdtempSync(join(tmpdir(), "rsv-consumer-sqlite-"));
  const filename = join(dir, "vault.sqlite");
  try {
    await migrateSqlite({ driver, filename });
    const store = await createSqliteStore({ driver, filename });
    const flow = await exercise(store, "consumer-sqlite-" + (driver.name === "node:sqlite" ? "nodesqlite" : "bettersqlite3"), {});
    flow.profile = store.capabilities().profile;
    flow.restoreDetection = store.capabilities().restoreDetection;
    store.close();
    return flow;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
const sqlite = {};
try {
  const nodeSqlite = await import("node:sqlite");
  sqlite["node:sqlite"] = sqliteVersionAcceptable(process.versions.sqlite)
    ? await sqliteFlow(nodeSqliteDriver(nodeSqlite))
    : "not run: this Node.js bundles SQLite " + process.versions.sqlite;
} catch {
  sqlite["node:sqlite"] = "not run: no node:sqlite in this Node.js";
}
try {
  const better = (await import("better-sqlite3")).default;
  sqlite["better-sqlite3"] = await sqliteFlow(betterSqlite3Driver(better));
} catch (error) {
  sqlite["better-sqlite3"] = error?.code === "ERR_MODULE_NOT_FOUND" ? "not run: not installed" : "failed: " + (error?.code ?? error?.name);
}

console.log(JSON.stringify({
  memory, sqlite, postgres,
  exports: {
    contracts: Object.keys(contracts).sort(),
    conformance: Object.keys(conformance).sort(),
    kms: Object.keys(kms).sort(),
  },
}));
`,
);
const expectFlow = (label, flow) => {
  check(flow.redacted === true, `${label}: the captured text still holds the value`);
  check(flow.restored === true, `${label}: capture on one instance, restore on another`);
  check(flow.again === "budget", `${label}: a second restore of a single-use value was ${flow.again}`);
  check(flow.wrongTenant === "unknown-token", `${label}: another tenant's restore was ${flow.wrongTenant}`);
  check(flow.revoked === "revoked" && flow.afterRevoke === "revoked", `${label}: revoke then restore was ${flow.afterRevoke}`);
  check(flow.deleted === "deleted" && flow.keyRetired === false, `${label}: ciphertext deletion reported ${flow.deleted}, keyRetired ${flow.keyRetired}`);
};
expectFlow("consumer B (store-memory)", b.result.memory);
const installedB = installedPackages(b.dir);
const sqliteRan = [];
for (const [driverName, flow] of Object.entries(b.result.sqlite)) {
  if (typeof flow === "string") {
    check(!flow.startsWith("failed"), `consumer B (store-sqlite over ${driverName}): ${flow}`);
    continue;
  }
  sqliteRan.push(driverName);
  expectFlow(`consumer B (store-sqlite over ${driverName})`, flow);
  check(flow.profile === "sqlite-local-wal/synchronous=FULL", `consumer B (store-sqlite over ${driverName}): profile was ${flow.profile}`);
}
if (withBetterSqlite3) check(sqliteRan.includes("better-sqlite3"), `consumer B: the better-sqlite3 flow did not run: ${b.result.sqlite["better-sqlite3"]}`);
check(!installedB.includes("better-sqlite3") || withBetterSqlite3, "consumer B: better-sqlite3 was installed without RSV_QUALIFY_BETTER_SQLITE3=1");

// ---------------------------------------------------------------- consumer C
// store-sqlite alone: it imports no driver and installs none; the application passes one.
const c = consumer(
  "persistence-sqlite-without-driver",
  [tarballs["vault-contracts"], tarballs["store-sqlite"]],
  `
import { createSqliteStore } from "@redact-secret/store-sqlite";
const outcome = await createSqliteStore({ filename: "vault-without-driver.sqlite" }).then(() => "started", (error) => error.code);
console.log(JSON.stringify({ outcome }));
`,
);
const installedC = installedPackages(c.dir);
check(c.result.outcome === "STORE_INVALID_ARGUMENT", `consumer C: store-sqlite without a driver reported ${c.result.outcome}`);
check(!installedC.includes("better-sqlite3"), "consumer C: a driver was installed");
if (withPostgres) expectFlow("consumer B (store-postgres)", b.result.postgres);
for (const required of ["StoreError", "KeyProviderError", "RecordCryptoError", "LIMITS", "missingCapabilities"]) {
  check(b.result.exports.contracts.includes(required), `vault-contracts does not export ${required}`);
}
for (const required of ["storeConformanceCases", "keyProviderConformanceCases", "createFaultyStore", "createInsecureTestKeyProvider", "runWithNodeTest"]) {
  check(b.result.exports.conformance.includes(required), `vault-conformance does not export ${required}`);
}
check(b.result.exports.kms.includes("createAwsKmsKeyProvider"), "key-provider-aws-kms does not export createAwsKmsKeyProvider");

// Each installed package declares the exact core and workspace versions it was built with.
const serverPkg = JSON.parse(readFileSync(join(b.dir, "node_modules/@redact-secret/vault-server/package.json"), "utf8"));
check(serverPkg.peerDependencies["@redact-secret/core"] === CORE_VERSION, "vault-server does not pin the tested core exactly");
check(serverPkg.dependencies["@redact-secret/vault"] === versions["@redact-secret/vault"], "vault-server does not pin the vault it was built with");

mkdirSync(REPORTS, { recursive: true });
const report = {
  node: process.version,
  platform: `${process.platform}/${process.arch}`,
  core: CORE_VERSION,
  versions,
  consumerA: { installed: installedA, result: a.result },
  consumerC: { installed: installedC, result: c.result },
  consumerB: { memory: b.result.memory, sqlite: b.result.sqlite, postgres: withPostgres ? b.result.postgres : "not run: RSV_PG_ADMIN_URL and RSV_PG_APP_URL are not set" },
  failures,
};
writeFileSync(join(REPORTS, "persistence-consumer.json"), `${JSON.stringify(report, null, 2)}\n`);

if (failures.length) {
  console.error(`persistence consumer qualification failed:\n- ${failures.join("\n- ")}`);
  process.exit(1);
}
console.log(`persistence consumer qualification passed on ${process.version}: base packages install ${installedA.length} package(s) and no driver or SDK; persistent flow over store-memory and SQLite (${sqliteRan.length === 0 ? "no driver usable on this Node.js" : sqliteRan.join(", ")})${withPostgres ? ` and ${b.result.postgres.profile}` : " (PostgreSQL not run: no database configured)"}`);
