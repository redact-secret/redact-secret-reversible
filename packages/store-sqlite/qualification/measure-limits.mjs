// Measures what `maxCreateBytes` should be, and what one writer's commit costs,
// on the machine that runs it. Synthetic random bytes only. Prints JSON.
//
//   npm run build && npm run install:sqlite-driver && node packages/store-sqlite/qualification/measure-limits.mjs
//
// The figures describe this machine, this file system, and this run. They are
// the basis of the default, not a claim about any deployment.
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { cpus, platform, release, tmpdir } from "node:os";
import { join } from "node:path";

import { createSqliteStore, migrate } from "../dist/index.js";
import { selectedDriver } from "../support/drivers.mjs";
import { initialized, rawCapture, rawCommit, randomNamespace } from "../support/fixtures.mjs";

const MIB = 1024 * 1024;
const dir = mkdtempSync(join(tmpdir(), "rsv-sqlite-measure-"));
const filename = join(dir, "vault.sqlite");

const median = (values) => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
const ms = (start) => Number(process.hrtime.bigint() - start) / 1e6;

try {
  const { driver, name: driverName } = await selectedDriver();
await migrate({ driver, filename, busyTimeoutMs: 60_000 });
  const store = await createSqliteStore({
    driver,
    filename,
    busyTimeoutMs: 60_000,
    maxClockSkewMs: 60_000,
    maxCreateBytes: 256 * MIB,
    restoreMarker: false,
  });
  const namespace = randomNamespace("measure");
  await initialized(store, namespace, 1);

  const envelope = 64 * 1024;
  const sizes = [1, 4, 16, 64, 128];
  const create = [];
  for (const totalMiB of sizes) {
    const entries = Math.min(1024, Math.ceil((totalMiB * MIB) / envelope));
    const per = Math.floor((totalMiB * MIB) / entries);
    const samples = [];
    for (let run = 0; run < 3; run += 1) {
      const input = rawCapture({ namespace, entries, maxUses: 1 });
      const filler = new Uint8Array(randomBytes(per));
      const sized = { ...input, entries: input.entries.map((entry) => ({ ...entry, envelope: filler })) };
      const start = process.hrtime.bigint();
      const result = await store.createCapture(sized);
      samples.push(ms(start));
      if (result.outcome !== "created") throw new Error(`create failed: ${result.reason}`);
    }
    create.push({ totalMiB, entries, envelopeBytes: per, medianMs: Math.round(median(samples)), runs: samples.map(Math.round) });
  }

  // One writer's small commits: the throughput bound of the profile.
  const small = rawCapture({ namespace, entries: 200, maxUses: 1 });
  await store.createCapture(small);
  const commits = await Promise.all(small.entries.map((entry, index) => rawCommit(store, small, { entries: [entry], attemptId: `m-${index}` })));
  const start = process.hrtime.bigint();
  for (const commit of commits) {
    const result = await store.commitRestore(commit);
    if (result.outcome !== "committed") throw new Error(`commit failed: ${result.reason}`);
  }
  const elapsed = ms(start);

  // The largest restore the contract allows: 1024 entries in one transaction.
  const wide = rawCapture({ namespace, entries: 1024, maxUses: 1 });
  await store.createCapture(wide);
  const wideCommit = await rawCommit(store, wide);
  const wideStart = process.hrtime.bigint();
  await store.commitRestore(wideCommit);
  const wideMs = ms(wideStart);

  store.close();
  console.log(
    JSON.stringify(
      {
        machine: { platform: platform(), release: release(), cpu: cpus()[0]?.model, node: process.version },
        profile: "sqlite-local-wal/synchronous=FULL",
        driver: driverName,
        create,
        singleEntryCommits: { count: commits.length, totalMs: Math.round(elapsed), perCommitMs: Number((elapsed / commits.length).toFixed(2)) },
        restore1024Entries: { ms: Math.round(wideMs) },
      },
      null,
      2,
    ),
  );
} finally {
  rmSync(dir, { recursive: true, force: true });
}
