// Writes schedules.json: the language-neutral schedule corpus (plan §6.3).
//
//   node conformance/persistent/v1/generate-schedules.mjs          # writes schedules.json
//   node conformance/persistent/v1/generate-schedules.mjs --check  # compares, writes nothing
//
// The cases are authored here, with loops for the variant lists, and the
// result is plain data: nothing in schedules.json is code. The JavaScript
// store harness (packages/vault-conformance) is the source of the `store`
// level cases; each converted case names its native counterpart in `native`.
//
// Every identifier, byte, and value in the corpus is synthetic.
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { cases as storeCases } from "./schedules/store-cases.mjs";
import { cases as lifecycleCases } from "./schedules/lifecycle-cases.mjs";
import { cases as concurrencyCases } from "./schedules/concurrency-cases.mjs";
import { cases as faultCases } from "./schedules/fault-cases.mjs";
import { cases as serverCases } from "./schedules/server-cases.mjs";

export const VERSION = "1.0.0";

export function build() {
  const all = [...storeCases, ...lifecycleCases, ...concurrencyCases, ...faultCases, ...serverCases];
  const ids = new Set();
  for (const item of all) {
    if (ids.has(item.id)) throw new Error(`duplicate case id ${item.id}`);
    ids.add(item.id);
  }
  return {
    version: VERSION,
    description:
      "Language-neutral schedules for the persistent vault Store contract and server profile. See README.md in this directory.",
    fixtures: {
      tenantA: "tenant-acme-synthetic",
      tenantB: "tenant-globex-synthetic",
      keyRef: "synthetic-key:v1",
      // The server-level cases. Identities are resolved by the driver from a fixed table; sessions are opaque ids.
      contexts: {
        a1: { principal: "principal-a1" },
        a2: { principal: "principal-a2" },
        b1: { principal: "principal-b1" },
        a1s1: { principal: "principal-a1", session: "session-synthetic-one" },
        a1s2: { principal: "principal-a1", session: "session-synthetic-two" },
        nobody: { principal: "principal-unknown" },
      },
      values: {
        SECRET_A: "ghp_SYNTHETICxREVOKEDxTESTx0000000000000",
        SINK: "sink-a",
        PURPOSE: "purpose-synthetic-support-reply",
      },
    },
    holdPoints: ["before-commit"],
    faultPoints: ["unavailable", "before-first-write", "drop-connection", "after-commit-before-ack"],
    cases: all,
  };
}

const target = new URL("./schedules.json", import.meta.url);

/** JSON with one step per line: reviewable, and a few thousand lines instead of twenty thousand. */
export function serialize(doc) {
  const { cases, ...head } = doc;
  const lines = ["{"];
  for (const [key, value] of Object.entries(head)) lines.push(` ${JSON.stringify(key)}: ${JSON.stringify(value)},`);
  lines.push(' "cases": [');
  cases.forEach((item, index) => {
    const { steps, ...fields } = item;
    const header = JSON.stringify(fields).slice(0, -1);
    lines.push(`  ${header},"steps":[`);
    steps.forEach((step, at) => lines.push(`   ${JSON.stringify(step)}${at === steps.length - 1 ? "" : ","}`));
    lines.push(`  ]}${index === cases.length - 1 ? "" : ","}`);
  });
  lines.push(" ]", "}");
  return `${lines.join("\n")}\n`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const text = serialize(build());
  if (process.argv.includes("--check")) {
    const current = await readFile(target, "utf8");
    if (current !== text) {
      process.stderr.write("schedules.json is out of date: run node conformance/persistent/v1/generate-schedules.mjs\n");
      process.exit(1);
    }
    process.stdout.write(`schedules.json is up to date (${build().cases.length} cases)\n`);
  } else {
    await writeFile(target, text);
    process.stdout.write(`wrote schedules.json (${build().cases.length} cases)\n`);
  }
}
