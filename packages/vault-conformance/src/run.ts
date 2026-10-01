/**
 * The store case list and two ways to run any case list. Neither imports a
 * test runner.
 */
import { addConcurrencyCases, addInterleaveCases } from "./concurrency-cases.js";
import { addAliasingCases, addRecoveryCases, addSweepCases } from "./lifecycle-cases.js";
import { addModelCases } from "./model-cases.js";
import {
  addCapabilityCases,
  addCommitCases,
  addCreateCases,
  addDeleteCases,
  addInspectCases,
  addReadCases,
  addRekeyCases,
  addRevokeCases,
  addValidationCases,
} from "./store-cases.js";
import { caseBuilder } from "./support.js";
import { ConformanceSkip } from "./types.js";
import type { CaseResult, ConformanceCase, StoreConformanceOptions, StoreFactory, TestFunction } from "./types.js";

/** The case groups of `storeConformanceCases`, in order. */
export const STORE_CASE_GROUPS = Object.freeze([
  "capabilities",
  "validation",
  "create",
  "read",
  "commit",
  "revoke",
  "inspect",
  "rekey",
  "delete",
  "sweep",
  "recovery",
  "aliasing",
  "concurrency",
  "interleave",
  "model",
] as const);

function positive(value: number | undefined, fallback: number, name: string): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`storeConformanceCases: ${name} must be a positive integer.`);
  return value;
}

/**
 * Every store conformance case. `factory` is called once per case. A case
 * that needs a capability the factory does not supply rejects with
 * `ConformanceSkip`; it never passes silently.
 */
export function storeConformanceCases(factory: StoreFactory, options: StoreConformanceOptions = {}): ConformanceCase[] {
  if (typeof factory !== "function") throw new TypeError("storeConformanceCases: factory must be a function.");
  const seed = options.seed ?? 20261001;
  if (!Number.isSafeInteger(seed)) throw new TypeError("storeConformanceCases: seed must be an integer.");
  const parallelism = positive(options.parallelism, 100, "parallelism");
  if (parallelism < 8 || parallelism > 1000) throw new TypeError("storeConformanceCases: parallelism must be from 8 to 1000.");
  const cases: ConformanceCase[] = [];
  const add = caseBuilder(factory, seed, cases);
  addCapabilityCases(add);
  addValidationCases(add);
  addCreateCases(add);
  addReadCases(add);
  addCommitCases(add);
  addRevokeCases(add);
  addInspectCases(add);
  addRekeyCases(add);
  addDeleteCases(add);
  addSweepCases(add);
  addRecoveryCases(add);
  addAliasingCases(add);
  addConcurrencyCases(add, parallelism);
  addInterleaveCases(add);
  addModelCases(add, positive(options.modelSequences, 4, "modelSequences"), positive(options.modelSteps, 400, "modelSteps"));
  return cases;
}

/** Runs the cases one after another and reports each as passed, failed, or skipped. It never throws for a case. */
export async function runCases(cases: readonly ConformanceCase[]): Promise<CaseResult[]> {
  const results: CaseResult[] = [];
  for (const item of cases) {
    try {
      await item.run();
      results.push({ name: item.name, group: item.group, status: "passed" });
    } catch (error) {
      if (error instanceof ConformanceSkip) {
        results.push({ name: item.name, group: item.group, status: "skipped", detail: error.reason });
      } else {
        const detail = error instanceof Error ? error.message : "a non-Error value was thrown";
        results.push({ name: item.name, group: item.group, status: "failed", detail });
      }
    }
  }
  return results;
}

/**
 * Registers each case with a runner's `test` function, passed in so that this
 * package imports no runner. A skipped case is reported through the runner's
 * `skip` with its reason. With Node's runner, pass the default export of its
 * test module: `runWithNodeTest(storeConformanceCases(factory), test)`.
 */
export function runWithNodeTest(cases: readonly ConformanceCase[], test: TestFunction): void {
  for (const item of cases) {
    test(item.name, async (context) => {
      try {
        await item.run();
      } catch (error) {
        if (error instanceof ConformanceSkip) {
          context.skip(error.reason);
          return;
        }
        throw error;
      }
    });
  }
}
