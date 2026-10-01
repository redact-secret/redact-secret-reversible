/**
 * `@redact-secret/vault-conformance`: runner-agnostic conformance harnesses
 * for `Store` and `KeyProvider` implementations of
 * docs/specs/persistent-vault.md, a fault-injecting store wrapper, the
 * reference model the store harness uses as its oracle, and an insecure
 * deterministic key provider for tests.
 */
export { createFaultyStore, SYNTHETIC_SECRET_MARKER } from "./faulty-store.js";
export type {
  Fault,
  FaultControl,
  FaultLogEntry,
  FaultPlan,
  FaultRule,
  FaultyStore,
  MalformedShape,
  StoreOperation,
} from "./faulty-store.js";
export { createInsecureTestKeyProvider } from "./insecure-test-key-provider.js";
export type {
  InsecureTestKeyProvider,
  InsecureTestKeyProviderControl,
  InsecureTestKeyProviderOptions,
} from "./insecure-test-key-provider.js";
export { keyProviderConformanceCases } from "./key-provider-cases.js";
export { ReferenceModel } from "./model.js";
export type { ModelCapture, ModelEntry, ModelReceipt, ModelRecovery } from "./model.js";
export { runCases, runWithNodeTest, STORE_CASE_GROUPS, storeConformanceCases } from "./run.js";
export { ConformanceFailure, ConformanceSkip } from "./types.js";
export type {
  CaseResult,
  CaseStatus,
  ConformanceCase,
  ConformanceClock,
  Interleave,
  InterleaveRequest,
  KeyProviderFactory,
  KeyProviderScope,
  KeyProviderUnderTest,
  StoreConformanceOptions,
  StoreFactory,
  StoreUnderTest,
  TestFunction,
} from "./types.js";
