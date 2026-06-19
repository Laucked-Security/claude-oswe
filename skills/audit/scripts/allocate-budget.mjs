// SP3 budget allocator. PURE function of count vectors — no FS, no LLM, no network.
// Scores each scannable partition and splits at the budget into analyze[] + classified gaps[].
// CLI: node allocate-budget.mjs --file <input.json> --out <allocation.json>
//   input: { "budget": 12, "vectors": [ <count vector> ], "sarifLeadsByPartition"?: { "<pid>": { "count": <n> } } }
//   exit 0 ok / 1 invalid input / 2 IO|usage.
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";

// Documented weights (§4). Tests assert the INDUCED ORDERING, not these magnitudes — they are tunable.
const W_SOURCE = 1, W_SINK = 2, W_COPRESENT = 3, W_UNAUTH = 4, W_DENSITY = 1, W_LEAD = 2;
const DENSITY_CAP = 10, LEAD_CAP = 10;

// Score a scannable vector. Presence-binary structure + capped sink-density + per-file co-location
// unauth fail-safe + additive (zero-when-absent) SARIF term. Size never proxies for danger.
export function scoreVector(v, sarif) {
  const hasSource = (v.sources || 0) > 0;
  const hasSink = (v.sinks || 0) > 0;
  let score = (hasSource ? W_SOURCE : 0) + (hasSink ? W_SINK : 0);
  if (hasSource && hasSink) score += W_COPRESENT;
  // unauth fail-safe: at least one source-bearing file has NO auth marker of its own (co-location,
  // not the global auth_markers<sources ratio — auth in non-source files must not suppress this).
  if (hasSource && hasSink && (v.source_and_auth_files || 0) < (v.sources || 0)) score += W_UNAUTH;
  score += W_DENSITY * Math.min(v.sink_hits || 0, DENSITY_CAP);              // capped: concentration, not size
  const leads = sarif ? (sarif.count || 0) : 0;                              // additive backstop, 0 when absent
  score += W_LEAD * Math.min(leads, LEAD_CAP);
  // sanitizers deliberately do NOT subtract (a sanitizer's presence does not prove safety).
  return score;
}

const cmpStr = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const countsOf = (v) => ({
  sources: v.sources || 0, sinks: v.sinks || 0, sanitizers: v.sanitizers || 0,
  auth_markers: v.auth_markers || 0, source_and_auth_files: v.source_and_auth_files || 0,
  sink_hits: v.sink_hits || 0
});

// An empty `vectors` array with a valid budget legitimately returns { ok:true, analyze:[], gaps:[] }
// (no scannable partitions to dispatch). Matches the house pattern (aggregateFindings([]) does the same).
export function allocate(vectors, budget, sarifLeadsByPartition = {}) {
  if (!Array.isArray(vectors)) return { ok: false, error: "vectors must be an array", analyze: [], gaps: [] };
  if (!Number.isInteger(budget) || budget < 1) return { ok: false, error: "budget must be a positive integer", analyze: [], gaps: [] };

  // `!== false` (not `=== true`): a vector without an explicit `scannable` field defaults to scannable.
  // Do NOT "tighten" this to `=== true` — that would silently flip undefined-scannable vectors to gaps.
  const scannable = vectors.filter((v) => v.scannable !== false);
  const unscannable = vectors.filter((v) => v.scannable === false);

  const scored = scannable.map((v) => ({ v, score: scoreVector(v, sarifLeadsByPartition[v.partition_id]) }));
  // Total deterministic order: score DESC, then content_key ASC (pure-content tie-break — never input order).
  scored.sort((a, b) => (b.score - a.score) || cmpStr(a.v.content_key, b.v.content_key));

  const analyze = [], gaps = [];
  scored.forEach((s, i) => {
    if (i < budget) analyze.push({ partition_id: s.v.partition_id, score: s.score });
    else gaps.push({
      partition_id: s.v.partition_id, gap_class: "deprioritized", score: s.score,
      counts: countsOf(s.v),
      reason: "deprioritized: analyzer budget exhausted; lower predicted attack surface"
    });
  });
  // Unscannable partitions do NOT compete for budget (no reference -> the analyzer can't help) and are
  // reported as a DISTINCT prominent class: surface UNKNOWN, never folded into "low surface".
  for (const v of unscannable) {
    gaps.push({ partition_id: v.partition_id, gap_class: "unsupported-stack", stack: v.stack || "unknown",
      reason: `unsupported stack "${v.stack || "unknown"}" — surface not assessed; not covered by this audit` });
  }
  return { ok: true, error: null, analyze, gaps };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const fi = args.indexOf("--file"), oi = args.indexOf("--out");
  if (fi === -1 || !args[fi + 1] || oi === -1 || !args[oi + 1]) {
    process.stderr.write("usage: allocate-budget.mjs --file <input.json> --out <allocation.json>\n"); process.exit(2);
  }
  let input;
  try { input = JSON.parse(readFileSync(args[fi + 1], "utf8")); }
  catch (e) { process.stderr.write("cannot read --file: " + e.message + "\n"); process.exit(2); }
  const r = allocate(input.vectors, input.budget, input.sarifLeadsByPartition || {});
  try { writeFileSync(args[oi + 1], JSON.stringify(r, null, 2)); }
  catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
  process.exit(r.ok ? 0 : 1);
}
