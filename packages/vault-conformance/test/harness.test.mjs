// Self-tests of the harness plumbing: case list shape, skips, runners,
// reproducibility, sanitized failure messages, and the package boundary.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";

import {
  ConformanceFailure,
  ConformanceSkip,
  ReferenceModel,
  runCases,
  runWithNodeTest,
  STORE_CASE_GROUPS,
  storeConformanceCases,
} from "../dist/index.js";
import { createModelStore, modelFactory } from "./model-store.mjs";

const SMALL = { parallelism: 8, modelSequences: 1, modelSteps: 120 };

test("the case list is well-formed: unique names, known groups, every group present", (t) => {
  const cases = storeConformanceCases(modelFactory());
  assert.equal(new Set(cases.map((item) => item.name)).size, cases.length);
  const counts = new Map();
  for (const item of cases) {
    assert.ok(STORE_CASE_GROUPS.includes(item.group));
    assert.ok(item.name.startsWith(`${item.group}: `));
    assert.equal(typeof item.run, "function");
    counts.set(item.group, (counts.get(item.group) ?? 0) + 1);
  }
  assert.deepEqual([...counts.keys()], [...STORE_CASE_GROUPS]);
  t.diagnostic(`store cases by group: ${[...counts].map(([group, count]) => `${group}=${count}`).join(", ")}; total ${cases.length}`);
});

test("options are validated", () => {
  assert.throws(() => storeConformanceCases(undefined), TypeError);
  for (const options of [{ parallelism: 0 }, { parallelism: 7 }, { parallelism: 1001 }, { modelSteps: 0 }, { modelSequences: 1.5 }, { seed: 0.5 }]) {
    assert.throws(() => storeConformanceCases(modelFactory(), options), TypeError);
  }
});

test("a store whose clock cannot be moved (clock: null) runs, and every time-travel case is skipped with a reason", async () => {
  const factory = async () => {
    const { store } = createModelStore({ realClock: true });
    return { store, clock: null };
  };
  const results = await runCases(storeConformanceCases(factory, SMALL));
  assert.deepEqual(results.filter((result) => result.status === "failed"), []);
  const skipped = results.filter((result) => result.status === "skipped");
  const forClock = skipped.filter((result) => /no controllable store clock/.test(result.detail));
  const forInterleave = skipped.filter((result) => /no interleave capability/.test(result.detail));
  assert.equal(forClock.length + forInterleave.length, skipped.length);
  assert.ok(forClock.length >= 8, "time-travel cases are skipped, not passed");
  assert.equal(forInterleave.length, results.filter((result) => result.group === "interleave").length);
  // Everything that does not need time travel still ran, in every group but interleave.
  for (const group of STORE_CASE_GROUPS) {
    if (group === "interleave") continue;
    assert.ok(results.some((result) => result.group === group && result.status === "passed"), `group ${group} ran`);
  }
});

test("the factory is called once per case and dispose runs whatever the outcome", async () => {
  let opened = 0;
  let disposed = 0;
  class Broken extends ReferenceModel {
    recoveryOf() {
      return { epoch: 99, state: "serving" };
    }
  }
  const factory = async () => {
    opened += 1;
    const { store, clock } = createModelStore({ Model: Broken });
    return {
      store,
      clock,
      dispose: async () => {
        disposed += 1;
      },
    };
  };
  const cases = storeConformanceCases(factory, SMALL);
  const results = await runCases(cases);
  assert.equal(opened, cases.length);
  assert.equal(disposed, cases.length);
  assert.ok(results.some((result) => result.status === "failed"));
  assert.ok(results.some((result) => result.status === "skipped"));
});

test("runWithNodeTest registers every case and reports a skip through the runner", async () => {
  const cases = [
    { name: "synthetic: passes", group: "synthetic", run: async () => {} },
    { name: "synthetic: skips", group: "synthetic", run: async () => { throw new ConformanceSkip("a synthetic reason"); } },
    { name: "synthetic: fails", group: "synthetic", run: async () => { throw new ConformanceFailure("a synthetic failure"); } },
  ];
  const registered = [];
  runWithNodeTest(cases, (name, fn) => registered.push({ name, fn }));
  assert.deepEqual(registered.map((item) => item.name), cases.map((item) => item.name));
  const skips = [];
  const context = { skip: (reason) => skips.push(reason) };
  await registered[0].fn(context);
  await registered[1].fn(context);
  assert.deepEqual(skips, ["a synthetic reason"]);
  await assert.rejects(registered[2].fn(context), ConformanceFailure);
  assert.deepEqual(await runCases(cases), [
    { name: "synthetic: passes", group: "synthetic", status: "passed" },
    { name: "synthetic: skips", group: "synthetic", status: "skipped", detail: "a synthetic reason" },
    { name: "synthetic: fails", group: "synthetic", status: "failed", detail: "a synthetic failure" },
  ]);
});

test("a seed reproduces the same operation sequence, and another seed gives another", async () => {
  const record = async (seed) => {
    const operations = [];
    const factory = async () => {
      const { store, clock } = createModelStore();
      const spied = { capabilities: store.capabilities };
      for (const name of Object.keys(store)) {
        if (name === "capabilities") continue;
        spied[name] = (input) => {
          operations.push(`${name}:${input.capture?.captureId ?? input.captureId ?? input.attempt?.attemptId ?? ""}`);
          return store[name](input);
        };
      }
      return { store: spied, clock };
    };
    const cases = storeConformanceCases(factory, { ...SMALL, seed }).filter((item) => item.group === "model");
    assert.deepEqual((await runCases(cases)).filter((result) => result.status !== "passed"), []);
    return operations.join("\n");
  };
  const first = await record(7);
  assert.equal(await record(7), first);
  assert.notEqual(await record(8), first);
});

test("failure messages name the case, the expectation, and the seed, and never dump stored bytes", async () => {
  class Mutant extends ReferenceModel {
    viewEntry(entry) {
      return { ...super.viewEntry(entry), used: 0, envelope: new Uint8Array(entry.envelope).reverse() };
    }

    viewCapture(capture) {
      return { ...super.viewCapture(capture), wrappedKey: new Uint8Array(40).fill(0xab) };
    }
  }
  const results = await runCases(storeConformanceCases(modelFactory({ Model: Mutant }), { ...SMALL, seed: 4242 }));
  const failed = results.filter((result) => result.status === "failed");
  assert.ok(failed.length > 10);
  for (const result of failed) {
    assert.ok(result.detail.startsWith(`${result.name}: `));
    assert.ok(result.detail.endsWith("[seed 4242]"));
    assert.match(result.detail, /^[\x20-\x7e§]+$/);
    assert.doesNotMatch(result.detail, /[0-9a-f]{24}|(ab){8}|\d+(,\d+){7}/i);
    assert.doesNotMatch(result.detail, /cap_[a-z2-7]{26}/);
  }
});

test("an exception from a store is reported by shape only", async () => {
  const factory = async () => {
    const { store, clock } = createModelStore();
    return {
      clock,
      store: {
        ...store,
        readEntries: async () => {
          throw new Error("synthetic driver text: credential=SYNTHETIC-NOT-A-SECRET-0000");
        },
      },
    };
  };
  const failed = (await runCases(storeConformanceCases(factory, SMALL))).filter((result) => result.status === "failed");
  assert.ok(failed.length > 0);
  for (const result of failed) assert.doesNotMatch(result.detail, /SYNTHETIC-NOT-A-SECRET|credential/);
});

test("the built package imports no test runner, no node: built-in, and uses no Buffer", () => {
  const dist = new URL("../dist/", import.meta.url);
  const files = readdirSync(dist).filter((name) => name.endsWith(".js"));
  assert.ok(files.length >= 10);
  for (const name of files) {
    const source = readFileSync(new URL(name, dist), "utf8");
    const imports = [...source.matchAll(/from\s+"([^"]+)"/g)].map((match) => match[1]);
    for (const specifier of imports) {
      assert.ok(specifier.startsWith("./") || specifier === "@redact-secret/vault-contracts", `${name} imports ${specifier}`);
    }
    assert.doesNotMatch(source, /\bBuffer\b|\brequire\(|import\(/, name);
  }
});
