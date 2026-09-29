// The per-release results archive (#83): one `docs/research/perf/<version>.json`
// per released vault version, holding that release's A/B compare results
// against the previous release (one per PII mode), each still a valid
// `redact-secret-vault/bench-result@1`.
//
// {
//   schema: "redact-secret-vault/bench-archive@1",
//   version,                 // the released @redact-secret/vault version (the candidate)
//   baseline,                // the published version it was compared against
//   gitSha,                  // the candidate's commit, as the results record it
//   summary: [{ pii, tier, corpus, runner, node, rounds, comparisons, warn, fail, failedMetrics }],
//   results: [bench-result@1, ...]   // kind "compare", one per PII mode
// }
//
// Only full (not quick) compare runs of a clean workspace candidate against a
// published baseline qualify, and every result must name the same candidate
// commit, candidate version, baseline version, and corpus.

import { RESULT_SCHEMA, validateResult } from "./schema.mjs";

export const ARCHIVE_SCHEMA = "redact-secret-vault/bench-archive@1";

const ARCHIVE_KEYS = new Set(["schema", "version", "baseline", "gitSha", "summary", "results"]);

function sidesOf(result) {
  const candidate = result.sides?.find((s) => s.label === "candidate");
  const baseline = result.sides?.find((s) => s.label === "baseline");
  return { candidate, baseline };
}

/** Problems that keep one compare result out of a release archive. */
export function archiveProblems(result, { allowLocal = false } = {}) {
  const schemaErrors = validateResult(result);
  if (schemaErrors.length > 0) return [`not a valid ${RESULT_SCHEMA}: ${schemaErrors[0]}`];
  const problems = [];
  if (result.kind !== "compare") problems.push('kind must be "compare"');
  if (result.mode.quick) problems.push("quick runs are smoke tests and are not archived");
  const { candidate, baseline } = sidesOf(result);
  if (candidate?.source !== "workspace") problems.push("the candidate must be the workspace build");
  else if (candidate.gitSha === undefined || candidate.gitSha.endsWith("-dirty")) {
    problems.push("the candidate must be a clean commit (no gitSha or -dirty)");
  }
  if (baseline?.source !== "npm") problems.push("the baseline must be a published version");
  if (!allowLocal && !result.environment.runner.startsWith("github-actions/")) {
    problems.push(`runner ${result.environment.runner} is not a GitHub Actions runner (use --allow-local to override)`);
  }
  return problems;
}

function summarize(result) {
  const gating = result.comparisons.filter((c) => c.gating);
  return {
    pii: result.mode.pii,
    tier: result.mode.tier ?? "extended",
    corpus: result.corpus.version,
    runner: result.environment.runner,
    node: result.environment.node,
    rounds: result.mode.rounds,
    comparisons: result.comparisons.length,
    warn: gating.filter((c) => c.verdict === "warn").length,
    fail: gating.filter((c) => c.verdict === "fail").length,
    failedMetrics: result.metrics.filter((m) => m.status === "failed").length,
  };
}

/**
 * Builds an archive from compare results. `version`, when given, must equal
 * the candidate's vault version. Throws with every problem found.
 */
export function buildArchive(results, { version, allowLocal = false } = {}) {
  if (!Array.isArray(results) || results.length === 0) throw new Error("no results to archive");
  const problems = [];
  results.forEach((result, i) => {
    for (const p of archiveProblems(result, { allowLocal })) problems.push(`result ${i + 1}: ${p}`);
  });
  if (problems.length > 0) throw new Error(`cannot archive:\n  ${problems.join("\n  ")}`);

  const first = sidesOf(results[0]);
  const expected = {
    version: first.candidate.vault.version,
    baseline: first.baseline.vault.version,
    gitSha: first.candidate.gitSha,
    corpus: results[0].corpus.version,
  };
  if (version !== undefined && version !== expected.version) {
    problems.push(`--version ${version} does not match the candidate's vault version ${expected.version}`);
  }
  if (expected.version === expected.baseline) {
    problems.push(`candidate and baseline are both ${expected.version}: an A/A run is not a release result`);
  }
  const seenModes = new Set();
  results.forEach((result, i) => {
    const { candidate, baseline } = sidesOf(result);
    const where = `result ${i + 1}`;
    if (candidate.vault.version !== expected.version) problems.push(`${where}: candidate version differs`);
    if (baseline.vault.version !== expected.baseline) problems.push(`${where}: baseline version differs`);
    if (candidate.gitSha !== expected.gitSha) problems.push(`${where}: candidate commit differs`);
    if (result.corpus.version !== expected.corpus) problems.push(`${where}: corpus version differs`);
    if (seenModes.has(result.mode.pii)) problems.push(`${where}: PII ${result.mode.pii} appears twice`);
    seenModes.add(result.mode.pii);
  });
  if (problems.length > 0) throw new Error(`cannot archive:\n  ${problems.join("\n  ")}`);

  const ordered = [...results].sort((a, b) => a.mode.pii.localeCompare(b.mode.pii));
  return {
    schema: ARCHIVE_SCHEMA,
    version: expected.version,
    baseline: expected.baseline,
    gitSha: expected.gitSha,
    summary: ordered.map(summarize),
    results: ordered,
  };
}

/** Returns a list of archive errors; empty means valid. */
export function validateArchive(archive) {
  if (archive === null || typeof archive !== "object" || Array.isArray(archive)) return ["archive must be an object"];
  const errors = [];
  for (const key of Object.keys(archive)) if (!ARCHIVE_KEYS.has(key)) errors.push(`unexpected key "${key}"`);
  if (archive.schema !== ARCHIVE_SCHEMA) errors.push(`schema must be "${ARCHIVE_SCHEMA}"`);
  if (!Array.isArray(archive.results) || archive.results.length === 0) return [...errors, "results must be a non-empty array"];
  try {
    const rebuilt = buildArchive(archive.results, { version: archive.version, allowLocal: true });
    for (const key of ["version", "baseline", "gitSha"]) {
      if (archive[key] !== rebuilt[key]) errors.push(`${key} does not match the results`);
    }
    if (JSON.stringify(archive.summary) !== JSON.stringify(rebuilt.summary)) errors.push("summary does not match the results");
  } catch (error) {
    errors.push(error.message);
  }
  return errors;
}
