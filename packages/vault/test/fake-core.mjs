// A deterministic stand-in for @redact-secret/core, used only by the unit
// tests to exercise the PII activation and retention contract
// (docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md)
// without a beta.10 core installed. It models the public surface the vault
// uses: `initialize`, `piiActivation` (only when `pii: true`), `scan`,
// `redact`, and `defaultPlaceholderFormatter`.
//
// Activation mirrors the core's documented rules: realm-global and one-shot,
// `"pii"` canonicalizes to `"pii:global"`, a plain `initialize()` is the
// "PII off" selection, a different later selection rejects with
// PII_ACTIVATION_CONFLICT, and `piiActivation()` throws NOT_INITIALIZED
// before initialization.
//
// Every value it detects is unmistakably synthetic: `FAKEPII-…` markers and
// the repository's usual revoked-looking GitHub token shape. Nothing here is
// a real credential or real personal data.

class FakeCoreError extends Error {
  constructor(code) {
    super(`fake core: ${code}`);
    this.name = "SecretScanError";
    this.code = code;
  }
}

const RULES = [
  { pattern: /ghp_[A-Za-z0-9]{36}/g, type: "github_token", action: "redact", confidence: "high", pii: false },
  // High confidence PII: the core's default action is `redact`.
  { pattern: /FAKEPII-IBAN-\d{4}/g, type: "pii_global_iban", action: "redact", confidence: "high", pii: true },
  { pattern: /FAKEPII-SSN-\d{4}/g, type: "pii_jurisdiction_us_ssn", action: "redact", confidence: "high", pii: true },
  // Medium confidence PII: the core's default action is `warn`.
  { pattern: /FAKEPII-PHONE-\d{4}/g, type: "pii_global_phone", action: "warn", confidence: "medium", pii: true },
];

const SELECTOR = /^pii(:[a-z0-9-]+){0,2}$/;

export function createFakeCore({ pii = true } = {}) {
  let active; // canonical selector key once initialized; "" is PII off
  const calls = { initialize: [], piiActivation: 0 };

  function canonical(selectors) {
    return [...new Set(selectors.map((s) => (s === "pii" ? "pii:global" : s)))].sort().join(",");
  }

  async function initialize(options) {
    calls.initialize.push(options === undefined ? undefined : { pii: options.pii === undefined ? undefined : [...options.pii] });
    if (!pii) {
      // A beta.9-shaped core: takes no options, has no PII selection to lock.
      active = "";
      return;
    }
    const selectors = options?.pii ?? [];
    for (const selector of selectors) {
      if (typeof selector !== "string" || !SELECTOR.test(selector)) throw new FakeCoreError("PII_SELECTOR_INVALID");
      if (selector.startsWith("pii:zz")) throw new FakeCoreError("PII_SELECTOR_UNSUPPORTED");
    }
    const key = canonical(selectors);
    if (active === undefined) {
      active = key;
      return;
    }
    if (active !== key) throw new FakeCoreError("PII_ACTIVATION_CONFLICT");
  }

  function piiActivation() {
    calls.piiActivation += 1;
    if (active === undefined) throw new FakeCoreError("NOT_INITIALIZED");
    const families = active === "" ? "" : "pii:global:iban,pii:global:phone,pii:us:ssn";
    return `credentials=full;selectors=${active === "" ? "off" : active};families=${families};vocabulary=pii-context/v1`;
  }

  function scan(input, options = {}) {
    if (active === undefined) throw new FakeCoreError("NOT_INITIALIZED");
    const piiOn = pii && active !== "";
    const found = [];
    for (const rule of RULES) {
      if (rule.pii && !piiOn) continue;
      rule.pattern.lastIndex = 0;
      for (const match of input.matchAll(rule.pattern)) {
        found.push({ rule, start: match.index, end: match.index + match[0].length });
      }
    }
    found.sort((a, b) => a.start - b.start);
    return found.map(({ rule, start, end }, index) => {
      const detected = {
        id: `f${index}`,
        type: rule.type,
        detector: `fake-${rule.type}`,
        confidence: rule.confidence,
        obfuscation: "none",
        start,
        end,
      };
      const action = options.policy === undefined
        ? rule.action
        : options.policy.evaluate(detected, { findingIndex: index, findingCount: found.length });
      return Object.freeze({ ...detected, action });
    });
  }

  function defaultPlaceholderFormatter(_finding, context) {
    return `<SECRET_${context.placeholderIndex}>`;
  }

  function redact(input, findings, options = {}) {
    if (active === undefined) throw new FakeCoreError("NOT_INITIALIZED");
    const format = options.placeholderFormatter ?? defaultPlaceholderFormatter;
    let out = "";
    let cursor = 0;
    let index = 0;
    for (const finding of findings) {
      if (finding.action !== "redact") continue;
      index += 1;
      let label;
      try {
        label = format(finding, { placeholderIndex: index });
      } catch {
        throw new FakeCoreError("PLACEHOLDER_FAILURE");
      }
      out += input.slice(cursor, finding.start) + label;
      cursor = finding.end;
    }
    return out + input.slice(cursor);
  }

  const module = { initialize, scan, redact, defaultPlaceholderFormatter };
  if (pii) module.piiActivation = piiActivation;
  return { module, calls };
}
