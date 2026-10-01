// scripts/pin-readme-links.mjs (#138): the rewrite rules, and a real
// `npm pack` between pin and restore: the tarball README is pinned, and the
// working tree is as it was afterwards.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { npmPackages, pin, pinLinks, releaseRef, restore, savedOriginal } from "../pin-readme-links.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const REPO = "https://github.com/redact-secret/redact-secret-vault";
const options = { packageDir: "packages/vault", ref: "v9.9.9", isDirectory: (path) => path === "docs/guides" };

test("blob/main and tree/main links of this repository move to the tag", () => {
  assert.equal(
    pinLinks(`[a](${REPO}/blob/main/docs/x.md#frag) [b](${REPO}/tree/main/packages/vault#readme)`, options),
    `[a](${REPO}/blob/v9.9.9/docs/x.md#frag) [b](${REPO}/tree/v9.9.9/packages/vault#readme)`,
  );
});

test("links that are already pinned, or point elsewhere, are left alone", () => {
  const text = [
    `[commit](${REPO}/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/x.md)`,
    `[issue](${REPO}/issues/14)`,
    "[npm](https://www.npmjs.com/package/@redact-secret/core)",
    "[other](https://github.com/redact-secret/redact-secret/blob/main/README.md)",
    "[anchor](#use) [mail](mailto:synthetic@example.invalid) [abs](/x)",
  ].join("\n");
  assert.equal(pinLinks(text, options), text);
});

test("relative links become absolute links at the tag", () => {
  assert.equal(
    pinLinks("[a](../../docs/reference/vault.md#api) [b](test/x.mjs) [c](../../docs/guides) [d](../vault-server/README.md)", options),
    `[a](${REPO}/blob/v9.9.9/docs/reference/vault.md#api) [b](${REPO}/blob/v9.9.9/packages/vault/test/x.mjs) ` +
      `[c](${REPO}/tree/v9.9.9/docs/guides) [d](${REPO}/blob/v9.9.9/packages/vault-server/README.md)`,
  );
});

test("a relative link that leaves the repository is left alone", () => {
  assert.equal(pinLinks("[out](../../../elsewhere.md)", options), "[out](../../../elsewhere.md)");
});

test("fenced code is not rewritten", () => {
  const text = ["```ts", `// see ${REPO}/blob/main/docs/x.md and [x](../../docs/x.md)`, "```", "[x](../../docs/x.md)"].join("\n");
  const lines = pinLinks(text, options).split("\n");
  assert.equal(lines[1], text.split("\n")[1]);
  assert.equal(lines[3], `[x](${REPO}/blob/v9.9.9/docs/x.md)`);
});

test("the default ref is the vault version's tag, and RSV_README_REF overrides it", () => {
  const { version } = JSON.parse(readFileSync(join(ROOT, "packages/vault/package.json"), "utf8"));
  const saved = process.env.RSV_README_REF;
  delete process.env.RSV_README_REF;
  try {
    assert.equal(releaseRef(), `v${version}`);
    process.env.RSV_README_REF = "v0.0.0-synthetic";
    assert.equal(releaseRef(), "v0.0.0-synthetic");
  } finally {
    if (saved === undefined) delete process.env.RSV_README_REF;
    else process.env.RSV_README_REF = saved;
  }
});

for (const name of ["vault", "vault-server", "store-postgres"]) {
  test(`pin, npm pack, restore (${name}): the tarball README is pinned, the working tree is unchanged`, () => {
    const packagePath = join(ROOT, "packages", name);
    const readme = join(packagePath, "README.md");
    const before = readFileSync(readme, "utf8");
    const out = mkdtempSync(join(tmpdir(), "rsv-pin-"));
    try {
      pin(packagePath);
      const [{ filename }] = JSON.parse(
        execFileSync("npm", ["pack", "--json", "--pack-destination", out], { cwd: packagePath, encoding: "utf8" }),
      );
      const packed = execFileSync("tar", ["-xOf", join(out, filename), "package/README.md"], { encoding: "utf8" });
      assert.ok(!packed.includes("/blob/main/") && !packed.includes("/tree/main/"), "a link to main was packed");
      assert.ok(packed.includes(`/blob/${releaseRef()}/`), "no link was pinned to the release tag");
      const relativeLinks = [...packed.replace(/```[\s\S]*?```/g, "").matchAll(/\]\(([^)\s]+)\)/g)]
        .map((match) => match[1])
        .filter((target) => !/^([a-z][a-z0-9+.-]*:|#)/i.test(target));
      assert.deepEqual(relativeLinks, [], "a relative link was packed");
      const files = execFileSync("tar", ["-tf", join(out, filename)], { encoding: "utf8" }).split("\n");
      assert.equal(files.filter((file) => /readme/i.test(file)).join(), "package/README.md", "only one README is packed");
    } finally {
      restore(packagePath);
      rmSync(out, { recursive: true, force: true });
    }
    assert.equal(readFileSync(readme, "utf8"), before, "the working tree README changed");
    assert.ok(!existsSync(savedOriginal(packagePath)), "the saved original was left behind");
  });
}

test("pin recovers from a leftover original, and restore without one does nothing", () => {
  const packagePath = join(ROOT, "packages/vault-contracts");
  const readme = join(packagePath, "README.md");
  const before = readFileSync(readme, "utf8");
  try {
    pin(packagePath);
    pin(packagePath); // as after a pack that never reached postpack
    assert.equal(readFileSync(savedOriginal(packagePath), "utf8"), before, "the second pin started from a pinned file");
  } finally {
    restore(packagePath);
  }
  assert.equal(readFileSync(readme, "utf8"), before);
  restore(packagePath);
  assert.equal(readFileSync(readme, "utf8"), before);
});

test("the command line pins and restores every npm package", () => {
  const script = join(ROOT, "scripts/pin-readme-links.mjs");
  const readmes = npmPackages().map((path) => join(path, "README.md"));
  assert.ok(readmes.length >= 8);
  const before = readmes.map((path) => readFileSync(path, "utf8"));
  try {
    execFileSync(process.execPath, [script, "pin"], { stdio: "ignore" });
    for (const path of readmes) assert.ok(!readFileSync(path, "utf8").includes("](../"), `${path} still has a relative link`);
  } finally {
    execFileSync(process.execPath, [script, "restore"], { stdio: "ignore" });
  }
  assert.deepEqual(readmes.map((path) => readFileSync(path, "utf8")), before);
});
