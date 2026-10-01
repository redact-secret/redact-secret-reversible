// The shared KeyProvider conformance cases against the local provider.
import { test } from "node:test";

import { keyProviderConformanceCases, runWithNodeTest } from "@redact-secret/vault-conformance";

import { createLocalKeyProvider } from "../dist/local-key-provider.js";

const material = (fill) => new Uint8Array(32).fill(fill);

runWithNodeTest(
  keyProviderConformanceCases(async ({ scope }) => {
    // Synthetic key material. Rotation adds a new active key and keeps the old ones decrypt-only.
    let keys = [{ id: "k1", material: material(1), state: "active" }];
    let provider = createLocalKeyProvider({ keys, scope });
    const facade = {
      get profile() {
        return provider.profile;
      },
      generateDataKey: (...args) => provider.generateDataKey(...args),
      unwrapDataKey: (...args) => provider.unwrapDataKey(...args),
      rewrapDataKey: (...args) => provider.rewrapDataKey(...args),
    };
    const rebuild = () => {
      provider = createLocalKeyProvider({ keys, scope });
    };
    return {
      provider: facade,
      async rotate() {
        const next = keys.length + 1;
        keys = [...keys.map((key) => ({ ...key, state: key.state === "active" ? "decrypt-only" : key.state })), { id: `k${next}`, material: material(next), state: "active" }];
        rebuild();
      },
      async retire(keyRef) {
        keys = keys.map((key) => (`local:${key.id}` === keyRef ? { ...key, state: "retired" } : key));
        rebuild();
      },
    };
  }),
  test,
);
