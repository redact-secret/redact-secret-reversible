// The shared KeyProvider conformance cases against the provider over the fake KMS.
// Rotation and retirement are supplied, so no case is skipped.
import { test } from "node:test";

import { keyProviderConformanceCases, runWithNodeTest } from "@redact-secret/vault-conformance";

import { createAwsKmsKeyProvider } from "../dist/index.js";
import { createFakeKms, EXPECTED } from "./fake-kms.mjs";
import { assertCommands } from "./helpers.mjs";

function factory(cache) {
  return async ({ scope }) => {
    const fake = createFakeKms();
    let keys = [{ keyArn: fake.createKey(), state: "active" }];
    const build = () => createAwsKmsKeyProvider({ client: fake.client, keys, expected: EXPECTED, scope, ...(cache ? { cache } : {}) });
    let provider = build();
    const rebuild = () => {
      provider.close();
      provider = build();
    };
    return {
      provider: {
        get profile() {
          return provider.profile;
        },
        generateDataKey: (...args) => provider.generateDataKey(...args),
        unwrapDataKey: (...args) => provider.unwrapDataKey(...args),
        rewrapDataKey: (...args) => provider.rewrapDataKey(...args),
      },
      // Rotation in this provider is a new KMS key: the new ARN becomes active, the old one decrypt-only.
      async rotate() {
        keys = [...keys.map((key) => ({ ...key, state: key.state === "active" ? "decrypt-only" : key.state })), { keyArn: fake.createKey(), state: "active" }];
        rebuild();
      },
      async retire(keyRef) {
        keys = keys.map((key) => (`aws-kms:${key.keyArn}` === keyRef ? { ...key, state: "retired" } : key));
        rebuild();
      },
      async dispose() {
        provider.close();
        // Every command of the case: digest-only context, explicit key ARNs, no identifier.
        assertCommands(fake.calls, [...scope.namespaces, ...scope.tenants, "tenant-initech-synthetic"]);
      },
    };
  };
}

runWithNodeTest(keyProviderConformanceCases(factory(undefined)), test);

// The same cases with the opt-in cache on: a cache must not change any contract outcome.
runWithNodeTest(
  keyProviderConformanceCases(factory({ maxEntries: 8, maxAgeMs: 60_000, perTenantMaxEntries: 4 })),
  (name, fn) => test(`${name} [cache on]`, fn),
);
