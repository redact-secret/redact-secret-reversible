// The AWS SDK belongs to this package and to no other (issue #113):
// - no other workspace package, and not the repository root, names an
//   `@aws-sdk/` or `@smithy/` package in any dependency field;
// - no other package's built `dist` or `src` mentions `@aws-sdk/`;
// - this package's `dist` imports only `@aws-sdk/client-kms` and
//   `@redact-secret/vault-contracts`, constructs no client, and reads no
//   environment.
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const packageDir = join(here, "..");
const packagesDir = join(packageDir, "..");
const repoRoot = join(packagesDir, "..");
const SELF = "key-provider-aws-kms";
const FIELDS = ["dependencies", "peerDependencies", "devDependencies", "optionalDependencies", "bundledDependencies", "bundleDependencies"];
const SDK = /^@(aws-sdk|smithy)\//;

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules") continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path, out);
    else out.push(path);
  }
  return out;
}

/** Every module specifier a file imports or re-exports, statically or dynamically. */
function specifiers(source) {
  const found = new Set();
  const patterns = [
    /\bfrom\s*["']([^"']+)["']/g,
    /\bimport\s*["']([^"']+)["']/g,
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
    /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,
  ];
  for (const pattern of patterns) for (const match of source.matchAll(pattern)) found.add(match[1]);
  return [...found];
}

const others = readdirSync(packagesDir).filter((name) => name !== SELF && existsSync(join(packagesDir, name, "package.json")));

test("there are other workspace packages to check", () => {
  assert.ok(others.length >= 5, "the workspace layout changed: this test found too few packages");
  for (const name of ["vault", "vault-contracts", "vault-crypto", "vault-server"]) assert.ok(others.includes(name), `missing ${name}`);
});

test("no other package, and not the repository root, depends on the AWS SDK", () => {
  const manifests = [join(repoRoot, "package.json"), ...others.map((name) => join(packagesDir, name, "package.json"))];
  for (const path of manifests) {
    const manifest = JSON.parse(readFileSync(path, "utf8"));
    for (const field of FIELDS) {
      const value = manifest[field];
      const names = Array.isArray(value) ? value : Object.keys(value ?? {});
      for (const name of names) assert.equal(SDK.test(name), false, `${relative(repoRoot, path)} ${field} names ${name}`);
      assert.equal(names.includes(`@redact-secret/${SELF}`), false, `${relative(repoRoot, path)} ${field} depends on this package`);
    }
    assert.equal(JSON.stringify(manifest).includes("@aws-sdk/"), false, `${relative(repoRoot, path)} mentions @aws-sdk/`);
  }
});

test("no other package's dist or src mentions the AWS SDK", () => {
  let scanned = 0;
  for (const name of others) {
    for (const part of ["dist", "src"]) {
      const dir = join(packagesDir, name, part);
      if (!existsSync(dir)) continue;
      for (const file of walk(dir)) {
        if (!/\.(js|mjs|cjs|ts|mts|cts|json|py)$/.test(file)) continue;
        scanned += 1;
        const source = readFileSync(file, "utf8");
        assert.equal(source.includes("@aws-sdk/"), false, `${relative(repoRoot, file)} mentions @aws-sdk/`);
        assert.equal(source.includes("@smithy/"), false, `${relative(repoRoot, file)} mentions @smithy/`);
      }
    }
  }
  assert.ok(scanned > 20, "too few files were scanned: build the workspace first");
  for (const name of ["vault-contracts", "vault-crypto", "vault-conformance"]) {
    assert.ok(existsSync(join(packagesDir, name, "dist")), `${name} is not built, so its dist was not checked`);
  }
});

test("this package's dist imports only @aws-sdk/client-kms and @redact-secret/vault-contracts", () => {
  const dist = join(packageDir, "dist");
  const files = walk(dist).filter((file) => /\.(js|d\.ts)$/.test(file));
  assert.ok(files.some((file) => file.endsWith("index.js")));
  const allowed = new Set(["@aws-sdk/client-kms", "@redact-secret/vault-contracts"]);
  const seen = new Set();
  for (const file of files) {
    for (const specifier of specifiers(readFileSync(file, "utf8"))) {
      if (specifier.startsWith("./")) {
        assert.ok(existsSync(join(dirname(file), specifier.replace(/\.js$/, file.endsWith(".d.ts") ? ".d.ts" : ".js"))), `${specifier} does not resolve`);
        continue;
      }
      assert.ok(allowed.has(specifier), `${relative(repoRoot, file)} imports ${specifier}`);
      seen.add(specifier);
    }
  }
  assert.deepEqual([...seen].sort(), [...allowed].sort());
});

test("this package's dist constructs no client and reads no environment, region, or credential", () => {
  const forbidden = [/\bnew\s+KMSClient\b/, /\bKMSClient\b/, /\bKMS\s*\(/, /process\s*\.\s*env/, /\bprocess\b/, /AWS_(REGION|DEFAULT_REGION|PROFILE|ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|CONFIG_FILE|SHARED_CREDENTIALS_FILE)/, /fromEnv|fromIni|fromNodeProviderChain|defaultProvider/, /credential/i, /\bconsole\s*\./, /node:/];
  for (const file of walk(join(packageDir, "dist")).filter((path) => path.endsWith(".js"))) {
    const source = readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\/|^\s*\/\/.*$/gm, "");
    for (const pattern of forbidden) assert.equal(pattern.test(source), false, `${relative(repoRoot, file)} matches ${pattern}`);
    const imported = [...source.matchAll(/import\s*\{([^}]*)\}\s*from\s*["']@aws-sdk\/client-kms["']/g)].flatMap((match) => match[1].split(",").map((name) => name.trim()).filter(Boolean));
    for (const name of imported) assert.ok(["DecryptCommand", "GenerateDataKeyCommand", "ReEncryptCommand"].includes(name), `unexpected SDK import ${name}`);
  }
});

test("the manifest declares the SDK as a peer, pins it for development, and has one runtime dependency", () => {
  const manifest = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8"));
  assert.deepEqual(manifest.dependencies, { "@redact-secret/vault-contracts": "0.1.0-alpha.1" });
  assert.deepEqual(manifest.peerDependencies, { "@aws-sdk/client-kms": "^3" });
  assert.match(manifest.devDependencies["@aws-sdk/client-kms"], /^3\.\d+\.\d+$/);
  assert.equal(manifest.sideEffects, false);
  assert.equal(manifest.type, "module");
  assert.equal(manifest.publishConfig.tag, "alpha");
  assert.equal(manifest.version, "0.1.0-alpha.1");
  for (const script of Object.keys(manifest.scripts)) assert.equal(/install|prepare|prepack|postpack/.test(script), false);
});
