// Results, logs, and artifacts carry timings, counts, and sizes only (#74).
// This guard runs on every serialized result before it is written or
// printed: it refuses output containing any corpus value, any issued vault
// token marker, or the synthetic-value marker. Reasons name the rule, never
// the matched text.

const TOKEN_MARKER = /rsv_/i;
const SYNTHETIC_MARKER = /SYNTHETIC/;

/** Returns value-free reasons the text is unsafe to emit (empty when safe). */
export function findLeaks(text, sensitiveValues) {
  const reasons = [];
  if (TOKEN_MARKER.test(text)) reasons.push("contains an issued-token marker");
  if (SYNTHETIC_MARKER.test(text)) reasons.push("contains a synthetic-value marker");
  sensitiveValues.forEach((value, index) => {
    if (value.length > 0 && text.includes(value)) reasons.push(`contains corpus sensitive value #${index}`);
  });
  return reasons;
}

export function assertNoLeaks(text, sensitiveValues) {
  const reasons = findLeaks(text, sensitiveValues);
  if (reasons.length > 0) throw new Error(`refusing to emit benchmark output: ${reasons.join("; ")}`);
}
