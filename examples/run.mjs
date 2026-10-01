#!/usr/bin/env node
// Runs every example and fails if one fails. Usage: npm run examples
// The Python example runs only when `--python=<interpreter>` is given.
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const python = process.argv.slice(2).find((arg) => arg.startsWith("--python="))?.slice("--python=".length);

let failed = 0;
for (const file of readdirSync(here).sort()) {
  if (!/^\d\d-.*\.(mjs|py)$/.test(file)) continue;
  const isPython = file.endsWith(".py");
  if (isPython && !python) {
    console.log(`\n--- ${file}: skipped (pass --python=<interpreter> to run it)`);
    continue;
  }
  console.log(`\n--- ${file}`);
  const result = spawnSync(isPython ? python : process.execPath, [join(here, file)], { stdio: "inherit" });
  if (result.status !== 0) {
    failed += 1;
    console.log(`FAILED: ${file} (exit ${result.status ?? result.signal})`);
  }
}
if (failed > 0) {
  console.log(`\n${failed} example(s) failed`);
  process.exit(1);
}
console.log("\nall examples passed");
