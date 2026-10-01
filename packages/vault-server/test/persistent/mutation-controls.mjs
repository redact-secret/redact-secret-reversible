// Mutation controls for the persistent server profile (issue #110: "Mutation
// tests remove each major fence/check and demonstrate the tests fail").
//
// Run on demand, after a build, from anywhere:
//
//   node packages/vault-server/test/persistent/mutation-controls.mjs
//   node packages/vault-server/test/persistent/mutation-controls.mjs --only a,e,l
//   node packages/vault-server/test/persistent/mutation-controls.mjs --list
//
// For each mutation it copies the built `dist/` to a scratch directory next
// to it, removes one check from the copy of `persistent/server.js` by string
// replacement (which must match exactly once), runs every `*.test.mjs` of
// this directory against the copy, and requires at least one test to fail.
// The real `dist/` is never modified, and every copy is removed afterwards,
// also when a run fails or is interrupted.
//
// A mutation that no test catches is a missing test: the script exits 1.
//
// This is not a test file. The Node test runner may still pick it up by
// directory (Node 20) or by glob (`**/test/**`), so it does nothing when it
// is started by the runner.
import { spawn } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { availableParallelism } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE = resolve(HERE, "..", "..");
const DIST = join(PACKAGE, "dist");
const TARGET = join("persistent", "server.js");
const TEST_TIMEOUT_MS = 60_000;
const RUN_TIMEOUT_MS = 240_000;

/**
 * Each mutation: `steps` are [pattern, replacement] pairs; every pattern must
 * match the build output exactly once. `layer` records what, if anything,
 * still stops the attack with the check gone, and so what the failing tests
 * are actually detecting.
 */
const MUTATIONS = [
  {
    id: "a",
    name: "skip the `sources.has(capture.captureId)` check (capture not named by the request)",
    steps: [[/if \(!parsed\.sources\.has\(capture\.captureId\)\)/, "if (false)"]],
    layer: "none: fields are released for a capture the request never named",
  },
  {
    id: "b",
    name: "skip the session-tag comparison in restore",
    steps: [[/if \(!equalTags\(expected, capture\.sessionTag\)\)(\s+)return deny\("source"\);/, 'if (false)$1return deny("source");']],
    layer: "AAD: the wrong session fails authentication (integrity-failure), but only after a key unwrap",
  },
  {
    id: "b2",
    name: "skip the whole session block in restore (tag and missing-session checks)",
    steps: [[/if \(capture\.sessionTag === null\)(\s+)continue;/, "if (true)$1continue;"]],
    layer: "AAD: a wrong or missing session fails authentication, after a key unwrap",
  },
  {
    id: "c",
    name: "skip the server-side expiry check",
    steps: [[/if \(now >= capture\.expiresAt\)/, "if (false)"]],
    layer: "store: commitRestore still rejects `expired` on the store's clock; the tests detect the unwrap and the commit that should not have happened",
  },
  {
    id: "d",
    name: "skip the row budget check",
    steps: [[/if \(entry\.used \+ use\.count > entry\.maxUses\)/, "if (false)"]],
    layer: "store: commitRestore still rejects `budget`; the tests detect the unwrap and the commit that should not have happened",
  },
  {
    id: "e",
    name: "return the staged fields on any interpretable outcome, not only `committed`",
    steps: [[/if \(outcome === "committed"\) \{/, "if (outcome !== undefined) {"]],
    layer: "none: fields are released on rejected, already-committed, and attempt-mismatch",
  },
  {
    id: "e2",
    name: "return the staged fields whatever the commit result is, including an uninterpretable one",
    steps: [[/if \(outcome === "committed"\) \{/, "if (true) {"]],
    layer: "none",
  },
  {
    id: "f",
    name: "treat a thrown commit error as success",
    steps: [
      [
        /\/\/ Unknown outcome: release nothing, retry nothing \(§7\.3\)\.(\s+)return fail\("COMMIT_AMBIGUOUS"\);/,
        '$1committed = { outcome: "committed" };',
      ],
    ],
    layer: "none: fields are released without a confirmed commit",
  },
  {
    id: "g",
    name: "skip the grant (sink and path) check",
    steps: [[/if \(grant === undefined \|\| !grant\.paths\.includes\(path\)\)/, "if (false)"]],
    layer: "none: the application's policy still runs, but grants are not enforced",
  },
  {
    id: "h",
    name: "skip policy evaluation",
    steps: [[/decision = await withTimeout\(this\.#i\.policy\(decisionInput\), this\.#i\.timeouts\.policy\);/, "decision = { allow: true };"]],
    layer: "none",
  },
  {
    id: "i",
    name: "inspectRead: accept an entry that was not asked for, or a duplicate",
    steps: [[/if \(!uses\.has\(entry\.entryId\) \|\| entryMap\.has\(entry\.entryId\)\)/, "if (false)"]],
    layer: "later checks: the foreign entry's capture is not named (source); the server would otherwise act on a row it did not request",
  },
  {
    id: "i2",
    name: "inspectRead: accept a live capture of another epoch",
    steps: [[/if \(capture\.epoch !== recovery\.epoch\)/, "if (false)"]],
    layer: "store: commitRestore treats a lower-epoch capture as revoked",
  },
  {
    id: "i3",
    name: "inspectRead: accept an entry whose capture was not returned",
    steps: [[/if \(!isCaptureId\(entry\.captureId\) \|\| !captureMap\.has\(entry\.captureId\)\)/, "if (false)"]],
    layer: "none designed: the server then fails with an unsanitized TypeError",
  },
  {
    id: "i4",
    name: "inspectRead: accept any `used` value from the store (a string, a negative number)",
    steps: [[/if \(!Number\.isSafeInteger\(entry\.used\) \|\| entry\.used < 0\)/, "if (false)"]],
    layer: "store: the commit checks its own counter; the server's preflight arithmetic would run on a non-number",
  },
  {
    id: "i5",
    name: "inspectRead: accept any `maxUses` value from the store",
    steps: [[/if \(!positive\(entry\.maxUses\) \|\| entry\.maxUses > LIMITS\.maxUses\)/, "if (false)"]],
    layer: "AAD: maxUses is authenticated, so a changed value fails decryption (integrity-failure), after a key unwrap",
  },
  {
    id: "j",
    name: "drop the session from the record binding (capture and restore): the session is no longer authenticated",
    steps: [
      [/entryId: entryIds\[index\],(\s+)sessionId: who\.sessionId,/, "entryId: entryIds[index],$1sessionId: null,"],
      [/sessionId: capture\.sessionTag === null \? null : resolved\.sessionId,/, "sessionId: null,"],
    ],
    layer: "session tag only: a store writer who strips the tag makes a session-bound capture restorable from any session",
  },
  {
    id: "k",
    name: "skip lifecyclePolicy for revoke and deleteCaptureCiphertext",
    steps: [[/await this\.#lifecycle\(\{(\s+)operation,/, "await (async () => undefined)({$1operation,"]],
    layer: "none",
  },
  {
    id: "k2",
    name: "skip lifecyclePolicy for capture",
    steps: [[/await this\.#lifecycle\(\{(\s+)operation: "capture",/, 'await (async () => undefined)({$1operation: "capture",']],
    layer: "none",
  },
  {
    id: "k3",
    name: "skip lifecyclePolicy for resolveAttempt",
    steps: [[/await this\.#lifecycle\(\{(\s+)operation: "resolve-attempt",/, 'await (async () => undefined)({$1operation: "resolve-attempt",']],
    layer: "none",
  },
  {
    id: "l",
    name: "retry automatically after an ambiguous commit (same attempt)",
    steps: [
      [
        /\/\/ Unknown outcome: release nothing, retry nothing \(§7\.3\)\.(\s+)return fail\("COMMIT_AMBIGUOUS"\);/,
        '$1return "stale";',
      ],
    ],
    layer: "store: the receipt deduplicates an applied commit, so the retry is `already-committed`; an unapplied one is silently committed and released",
  },
  {
    id: "l2",
    name: "treat an uninterpretable commit result as stale and retry",
    steps: [[/\/\/ A result this server cannot interpret is not a commit\.(\s+)return fail\("COMMIT_AMBIGUOUS"\);/, '$1return "stale";']],
    layer: "store: the receipt",
  },
  // Further controls beyond the list in the issue.
  {
    id: "m",
    name: "skip the revoked check in preflight",
    steps: [[/if \(capture\.state !== "live"\)(\s+)return deny\("revoked"\);/, 'if (false)$1return deny("revoked");']],
    layer: "store: commitRestore still rejects `revoked`; the tests detect the unwrap",
  },
  {
    id: "n",
    name: "skip the missing-purpose check",
    steps: [[/if \(purpose\.length === 0\)/, "if (false)"]],
    layer: "none",
  },
  {
    id: "o",
    name: "write no fence after an ambiguous createCapture",
    steps: [[/await fence\(\);(\s+)return fail\("STORE_UNAVAILABLE", who\);/, '$1return fail("STORE_UNAVAILABLE", who);']],
    layer: "none: a created capture stays live (its tokens never left the server)",
  },
  {
    id: "o2",
    name: "write no fence after an uninterpretable createCapture result",
    steps: [[/await fence\(\);(\s+)return fail\("INVARIANT_VIOLATION", who\);/, '$1return fail("INVARIANT_VIOLATION", who);']],
    layer: "none",
  },
  {
    id: "p",
    name: "skip the recovery state and epoch check in preflight",
    steps: [[/if \(view\.recovery\.state !== "serving" \|\| view\.recovery\.epoch !== this\.#i\.recoveryEpoch\)/, "if (false)"]],
    layer: "store: commitRestore still rejects `quarantined`; the tests detect the unwrap",
  },
  {
    id: "q",
    name: "skip the session-tag comparison for revoke and deleteCaptureCiphertext",
    steps: [[/if \(!equalTags\(expected, capture\.sessionTag\)\)(\s+)return fail\("LIFECYCLE_DENIED", who\);/, 'if (false)$1return fail("LIFECYCLE_DENIED", who);']],
    layer: "none",
  },
  {
    id: "r",
    name: "skip the stale-policy comparison",
    steps: [[/if \(revisionBefore !== undefined && currentRevision\(\) !== revisionBefore\)/, "if (false)"]],
    layer: "none",
  },
  {
    id: "s",
    name: "resolveAttempt: report committed without comparing the request digest",
    steps: [[/result = equalBytes\(inspected\.requestDigest, digest\)/, "result = true"]],
    layer: "none",
  },
  {
    id: "t",
    name: "skip the closed check",
    steps: [[/if \(this\.#closed\)/, "if (false)"]],
    layer: "none",
  },
  {
    id: "u",
    name: "skip the required-capability check at creation",
    steps: [[/if \(missingCapabilities\(capabilities\)\.length > 0\)/, "if (false)"]],
    layer: "none",
  },
  {
    id: "v",
    name: "skip the recovery check at creation",
    steps: [[/await vault\.assertServing\(\);/, ""]],
    layer: "store: every capture and commit is still rejected `quarantined`",
  },
  {
    id: "w",
    name: "accept a store that is volatile or single-process without the waiver",
    steps: [[/&& options\.allowNonDurableStore !== true\)/, "&& false)"]],
    layer: "none",
  },
  {
    id: "x",
    name: "accept a missing digest key without the waiver (silently unkeyed digests)",
    steps: [[/if \(options\.allowUnkeyedDigests !== true\)(\s+)throw new VaultServerError\("INVALID_ARGUMENT"\);/, "if (false)$1throw new VaultServerError(\"INVALID_ARGUMENT\");"]],
    layer: "none",
  },
  {
    id: "y",
    name: "capture: do not check the store's maxCreateEntries before sealing",
    steps: [[/if \(plan\.retained\.length > capabilities\.maxCreateEntries\)/, "if (false)"]],
    layer: "store: createCapture throws STORE_CAPABILITY before any write",
  },
  {
    id: "aa",
    name: "restore: do not overwrite decrypted values when the call ends",
    steps: [[/finally \{(\s+)release\(\);(\s+)\}/, "finally {$2}"]],
    layer: "none: plaintext bytes of a denied request stay in memory until collected",
  },
  {
    id: "ab",
    name: "capture: accept a sink or path with a lone surrogate as far as the crypto layer",
    steps: [[/if \(!isIdentifier\(grant\.sink\) \|\| !grant\.paths\.every\(\(path\) => isIdentifier\(path\)\)\)/, "if (false)"]],
    layer: "crypto layer: the record format refuses it, reported as INVARIANT_VIOLATION instead of INVALID_ARGUMENT",
  },
  {
    id: "ac",
    name: "factory: accept a lifetime and receipt grace that exceed the store's receipt horizon",
    steps: [[/if \(limits\.entryTtlMs \+ 2 \* capabilities\.maxClockSkewMs \+ receiptGraceMs > LIMITS\.maxReceiptHorizonMs\)/, "if (false)"]],
    layer: "store: commitRestore throws STORE_INVALID_ARGUMENT, so restores of a fresh capture fail INVARIANT_VIOLATION",
  },
  {
    id: "z",
    name: "restore: return fields unchanged for a token the store does not have (skip unknown-token)",
    steps: [[/if \(!view\.entries\.has\(use\.entryId\)\)/, "if (false)"]],
    layer: "none designed: the server then fails with an unsanitized TypeError",
  },
];

function parseArguments(argv) {
  const options = { only: undefined, list: false, concurrency: Math.max(1, Math.min(3, Math.floor(availableParallelism() / 4))) };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--list") options.list = true;
    else if (argv[i] === "--only") options.only = new Set(String(argv[(i += 1)]).split(","));
    else if (argv[i] === "--concurrency") options.concurrency = Math.max(1, Number(argv[(i += 1)]) || 1);
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  return options;
}

function mutate(source, mutation) {
  let text = source;
  for (const [pattern, replacement] of mutation.steps) {
    const global = new RegExp(pattern.source, `${pattern.flags.replace("g", "")}g`);
    const matches = text.match(global) ?? [];
    if (matches.length !== 1) {
      throw new Error(`mutation ${mutation.id}: pattern ${pattern} matched ${matches.length} times in the build output, expected exactly 1`);
    }
    text = text.replace(pattern, replacement);
  }
  if (text === source) throw new Error(`mutation ${mutation.id}: the replacement changed nothing`);
  return text;
}

function runTests(distDirectory, files) {
  return new Promise((done, failed) => {
    // A mutation can make a test wait for something that now never happens: a per-test timeout turns that
    // into a failure, and the kill timer covers a child that still does not exit.
    const child = spawn(process.execPath, ["--test", "--test-reporter=tap", `--test-timeout=${TEST_TIMEOUT_MS}`, ...files], {
      cwd: PACKAGE,
      env: { ...process.env, RSV_PERSISTENT_DIST: distDirectory, NODE_TEST_CONTEXT: undefined },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const killer = setTimeout(() => child.kill("SIGKILL"), RUN_TIMEOUT_MS);
    let output = "";
    child.stdout.on("data", (chunk) => {
      output += chunk;
    });
    child.stderr.on("data", (chunk) => {
      output += chunk;
    });
    child.on("error", failed);
    child.on("close", (code, signal) => {
      clearTimeout(killer);
      const failing = new Set();
      if (signal !== null) failing.add(`(the test run did not finish within ${RUN_TIMEOUT_MS} ms and was killed)`);
      for (const line of output.split("\n")) {
        const match = /^\s*not ok \d+ - (.*?)(?: # .*)?$/.exec(line);
        // With one process per file, a failing file is itself reported as a failing entry.
        if (match !== null && !match[1].endsWith(".test.mjs")) failing.add(match[1]);
      }
      const passed = /^# pass (\d+)/m.exec(output);
      done({ code, failing: [...failing], passed: passed === null ? 0 : Number(passed[1]) });
    });
  });
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.list) {
    for (const mutation of MUTATIONS) process.stdout.write(`${mutation.id.padEnd(3)} ${mutation.name}\n`);
    return 0;
  }
  if (!existsSync(join(DIST, TARGET))) throw new Error("no build output: run `npm run build` first");
  const source = readFileSync(join(DIST, TARGET), "utf8");
  const files = readdirSync(HERE)
    .filter((name) => name.endsWith(".test.mjs"))
    .sort()
    .map((name) => relative(PACKAGE, join(HERE, name)));
  const selected = MUTATIONS.filter((mutation) => options.only === undefined || options.only.has(mutation.id));
  if (selected.length === 0) throw new Error("no mutation selected");
  // Every pattern is checked before anything runs, so a build that drifted fails fast.
  const mutated = new Map(selected.map((mutation) => [mutation.id, mutate(source, mutation)]));

  const scratch = join(PACKAGE, `.mutation-controls-${process.pid}`);
  const cleanup = () => rmSync(scratch, { recursive: true, force: true });
  process.on("SIGINT", () => {
    cleanup();
    process.exit(130);
  });
  process.on("SIGTERM", () => {
    cleanup();
    process.exit(143);
  });

  const prepare = (name, text) => {
    const directory = join(scratch, name, "dist");
    mkdirSync(dirname(directory), { recursive: true });
    cpSync(DIST, directory, { recursive: true });
    if (text !== undefined) writeFileSync(join(directory, TARGET), text);
    return directory;
  };

  try {
    // Control: the unmutated copy must pass, or a failure under mutation means nothing.
    const baseline = await runTests(prepare("baseline"), files);
    if (baseline.code !== 0 || baseline.failing.length > 0 || baseline.passed === 0) {
      process.stdout.write(`baseline: the unmutated build does not pass (${baseline.failing.length} failing, ${baseline.passed} passing)\n`);
      for (const name of baseline.failing) process.stdout.write(`  - ${name}\n`);
      return 1;
    }
    process.stdout.write(`baseline: ${baseline.passed} tests pass against an unmutated copy of dist/ (${files.length} files)\n\n`);

    const results = new Map();
    const queue = [...selected];
    const worker = async () => {
      for (let mutation = queue.shift(); mutation !== undefined; mutation = queue.shift()) {
        const outcome = await runTests(prepare(`mutation-${mutation.id}`, mutated.get(mutation.id)), files);
        results.set(mutation.id, outcome);
        rmSync(join(scratch, `mutation-${mutation.id}`), { recursive: true, force: true });
      }
    };
    await Promise.all(Array.from({ length: Math.min(options.concurrency, selected.length) }, worker));

    let survivors = 0;
    process.stdout.write("| id | mutation | caught | failing tests | with the check gone, what still stops it |\n");
    process.stdout.write("| --- | --- | --- | --- | --- |\n");
    for (const mutation of selected) {
      const { failing } = results.get(mutation.id);
      if (failing.length === 0) survivors += 1;
      process.stdout.write(
        `| ${mutation.id} | ${mutation.name} | ${failing.length === 0 ? "NO" : "yes"} | ${failing.length} | ${mutation.layer} |\n`,
      );
    }
    process.stdout.write("\n");
    for (const mutation of selected) {
      const { failing } = results.get(mutation.id);
      process.stdout.write(`${mutation.id}: ${mutation.name}\n`);
      if (failing.length === 0) process.stdout.write("    NOT CAUGHT: no test fails with this check removed\n");
      for (const name of failing.slice(0, 12)) process.stdout.write(`    - ${name}\n`);
      if (failing.length > 12) process.stdout.write(`    ... and ${failing.length - 12} more\n`);
    }
    process.stdout.write(`\n${selected.length - survivors} of ${selected.length} mutations caught.\n`);
    return survivors === 0 ? 0 : 1;
  } finally {
    cleanup();
  }
}

if (process.env.NODE_TEST_CONTEXT === undefined) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 2;
    },
  );
}
