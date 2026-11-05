// Deterministic benchmark metrics for the hybrid auditor. Zero runtime deps, Node >= 20.
// computeMetrics(ledger, truthMap) -> { ok, error, semgrep_raw, oswe_over_semgrep, hybrid, excluded, deltas, cwe_mismatches, total, quality }
// quality gains structural_proof_rate / candidate_path_hit_rate / call_resolution_ratio (SP10) only when the
// ledger carries SP10 data (an entry with findings[] or a top-level app_graph_stats[]).
// CLI: node metrics.mjs --ledger <ledger.json> --truth <expectedresults.csv> --out <report.json> [--md <report.md>]
//   exit 0 ok / 1 ledger<->truth or schema/coherence violation / 2 IO|usage.
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";

const ADJ = new Set(["promoted", "refuted", "inconclusive", "not-analyzed", "no-lead"]);

// --- SP10 graph metrics (spec §3.3 / §4.2), shared with score-nodegoat.mjs. ---
// A report "carries SP10 data" when it has an app_graph key or any finding with structural_path /
// candidate_path_ids. Only then are the graph metrics emitted, so SP9-era inputs score byte-identically.
export const carriesGraphData = (report) =>
  Boolean(report) && ("app_graph" in report ||
    (report.findings || []).some((f) => f && ("structural_path" in f || "candidate_path_ids" in f)));
const ACTIVE = new Set(["accepted", "downgraded"]);
const ratio = (n, d) => (d > 0 ? n / d : null);
// structural_proof_rate   = active findings with structural_path "proven" / active findings;
// candidate_path_hit_rate = active findings with non-empty candidate_path_ids / active findings
//   (findings the graph could not see count against it, on purpose). active = accepted or downgraded.
export function graphFindingRates(findings) {
  const active = (findings || []).filter((f) => f && ACTIVE.has(f.verification_status));
  return {
    structural_proof_rate: ratio(active.filter((f) => f.structural_path === "proven").length, active.length),
    candidate_path_hit_rate: ratio(active.filter((f) => Array.isArray(f.candidate_path_ids) && f.candidate_path_ids.length > 0).length, active.length)
  };
}
// call_resolution_ratio = calls_exact / calls_total, summed over the given app_graph.stats objects;
// null when there are none or calls_total is 0.
export function callResolutionRatio(statsList) {
  let exact = 0, total = 0;
  for (const s of statsList || []) { exact += s.calls_exact; total += s.calls_total; }
  return ratio(exact, total);
}

const STRUCTURAL_PATHS = new Set(["proven", "absent", "n/a"]);
const FINDING_KEYS = new Set(["finding_id", "verification_status", "structural_path", "candidate_path_ids", "verification_notes"]);
const isCount = (n) => Number.isInteger(n) && n >= 0;
const isStringArray = (a) => Array.isArray(a) && a.every((x) => typeof x === "string");
function validateGraphFinding(f, where) {
  if (!f || typeof f !== "object" || Array.isArray(f)) return `${where}: finding record must be an object`;
  for (const k of Object.keys(f)) if (!FINDING_KEYS.has(k)) return `${where}: unknown finding field: ${k}`;
  if (typeof f.verification_status !== "string") return `${where}: verification_status not a string`;
  if (f.structural_path !== null && !STRUCTURAL_PATHS.has(f.structural_path)) return `${where}: bad structural_path`;
  if (!isStringArray(f.candidate_path_ids)) return `${where}: candidate_path_ids not a string array`;
  if (!isStringArray(f.verification_notes)) return `${where}: verification_notes not a string array`;
  return null;
}

export function parseTruthCsv(text) {
  const map = new Map();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const p = line.split(",").map((s) => s.trim());
    if (p.length < 4 || !/^BenchmarkTest\d{5}$/.test(p[0])) continue;
    map.set(p[0], { real: p[2].toLowerCase() === "true", cwe: parseInt(p[3], 10), category: p[1] });
  }
  return map;
}

function validateLedger(ledger, truth) {
  if (!ledger || typeof ledger !== "object" || !Array.isArray(ledger.entries)) return "ledger.entries[] missing";
  // Top level: additionalProperties:false + required string metadata (spec §3.7.1).
  const topAllowed = new Set(["dataset", "subset", "generated", "entries", "app_graph_stats"]);
  for (const k of Object.keys(ledger)) if (!topAllowed.has(k)) return `unknown top-level ledger field: ${k}`;
  for (const k of ["dataset", "subset", "generated"]) if (typeof ledger[k] !== "string" || !ledger[k]) return `ledger.${k} must be a non-empty string`;
  // SP10: optional per-report app_graph.stats objects (only the call counters are read here).
  if ("app_graph_stats" in ledger) {
    if (!Array.isArray(ledger.app_graph_stats)) return "ledger.app_graph_stats must be an array";
    for (const st of ledger.app_graph_stats) {
      if (!st || typeof st !== "object" || !isCount(st.calls_total) || !isCount(st.calls_exact) || st.calls_exact > st.calls_total)
        return "ledger.app_graph_stats: each entry needs integer calls_exact <= calls_total";
    }
  }
  const seen = new Set();
  const allowed = new Set(["test_id", "semgrep_flagged", "oswe_covered", "oswe_adjudication", "oswe_independent", "cwe",
    "oswe_attempted", "accepted_high_findings", "proof_complete_high_findings", "ce_resolved_high_findings",
    "accepted_critical_chains", "proof_complete_critical_chains", "chain_reached_rce", "hygiene_findings", "findings"]);
  for (const e of ledger.entries) {
    for (const k of Object.keys(e)) if (!allowed.has(k)) return `unknown ledger field: ${k}`;
    if ("findings" in e) {
      if (!Array.isArray(e.findings)) return `${e.test_id}: findings must be an array`;
      for (const f of e.findings) { const fe = validateGraphFinding(f, e.test_id); if (fe) return fe; }
    }
    if (!/^BenchmarkTest\d{5}$/.test(e.test_id)) return `bad test_id: ${e.test_id}`;
    if (seen.has(e.test_id)) return `duplicate test_id: ${e.test_id}`;
    seen.add(e.test_id);
    if (typeof e.semgrep_flagged !== "boolean") return `${e.test_id}: semgrep_flagged not boolean`;
    if (typeof e.oswe_covered !== "boolean") return `${e.test_id}: oswe_covered not boolean`;
    if (typeof e.oswe_independent !== "boolean") return `${e.test_id}: oswe_independent not boolean`;
    if (!ADJ.has(e.oswe_adjudication)) return `${e.test_id}: bad oswe_adjudication`;
    // coherence keyed on semgrep_flagged
    if (e.semgrep_flagged) {
      if (e.oswe_adjudication === "no-lead") return `${e.test_id}: flagged lead cannot be "no-lead"`;
      const notAnalyzed = e.oswe_adjudication === "not-analyzed";
      if (notAnalyzed !== (e.oswe_covered === false)) return `${e.test_id}: not-analyzed <=> !covered violated`;
    } else if (e.oswe_adjudication !== "no-lead") {
      return `${e.test_id}: semgrep_flagged=false requires adjudication "no-lead"`;
    }
    if (!truth.has(e.test_id)) return `${e.test_id}: absent from truth CSV`;
  }
  return null;
}

const emptyCM = () => ({ tp: 0, fp: 0, fn: 0, tn: 0 });
function add(cm, predVuln, real) {
  if (predVuln && real) cm.tp++;
  else if (predVuln && !real) cm.fp++;
  else if (!predVuln && real) cm.fn++;
  else cm.tn++;
}
function finalize(cm) {
  const { tp, fp, fn, tn } = cm;
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const fpr = fp + tn ? fp / (fp + tn) : 0;
  const youden = recall - fpr;
  return { tp, fp, fn, tn, precision, recall, fpr, youden };
}

export function computeMetrics(ledger, truth) {
  const err = validateLedger(ledger, truth);
  if (err) return { ok: false, error: err };
  const m1 = emptyCM(), m2 = emptyCM(), m3 = emptyCM();
  const excluded = { inconclusive: 0, not_analyzed: 0, not_covered: 0 };
  const deltas = { fp_refuted: 0, recall_cost: 0, fn_recovered: 0 };
  let cwe_mismatches = 0;
  for (const e of ledger.entries) {
    const t = truth.get(e.test_id);
    const real = t.real;
    if (real && Number.isInteger(e.cwe) && e.cwe !== t.cwe) cwe_mismatches++;
    add(m1, e.semgrep_flagged, real);
    if (e.semgrep_flagged) {
      if (e.oswe_adjudication === "promoted" || e.oswe_adjudication === "refuted") {
        const pred = e.oswe_adjudication === "promoted";
        add(m2, pred, real); add(m3, pred, real);
        if (!real && !pred) deltas.fp_refuted++;
        if (real && !pred) deltas.recall_cost++;
      } else if (e.oswe_adjudication === "inconclusive") excluded.inconclusive++;
      else excluded.not_analyzed++;
    } else if (e.oswe_covered) {
      const pred = e.oswe_independent === true;
      add(m3, pred, real);
      if (real && pred) deltas.fn_recovered++;
    } else {
      excluded.not_covered++;
    }
  }
  // --- SP6 quality block: counter-based (proof/ce), attempt-aware (structural FN). Independent of the
  // m1/m2/m3 matrices, so un-run cases never inflate the structural diagnostic (#R2.2, #R2.3, #5). ---
  let acc_high = 0, proof_high = 0, ce_high = 0, acc_chain = 0, proof_chain = 0, hygiene = 0;
  let real_total = 0, real_attempted = 0, real_independent = 0, real_not_found = 0, covered_fn = 0, structural_fn = 0;
  // Per-category real-case coverage: the revised SP6 gate reads structural_fn_share only once EVERY
  // category has enough attempted real cases (the declared stratified sample), not a global 0.80 share.
  const attempted_per_category = {};
  for (const e of ledger.entries) {
    acc_high += e.accepted_high_findings || 0;
    proof_high += e.proof_complete_high_findings || 0;
    ce_high += e.ce_resolved_high_findings || 0;
    acc_chain += e.accepted_critical_chains || 0;
    proof_chain += e.proof_complete_critical_chains || 0;
    hygiene += e.hygiene_findings || 0;
    const t = truth.get(e.test_id);
    if (!t || !t.real) continue;
    real_total++;
    if (t.category && !(t.category in attempted_per_category)) attempted_per_category[t.category] = 0;
    if (e.oswe_attempted) real_attempted++;
    if (e.oswe_attempted && t.category) attempted_per_category[t.category]++;
    if (e.oswe_independent === true) real_independent++;
    const found = (e.semgrep_flagged && e.oswe_adjudication === "promoted") || (!e.semgrep_flagged && e.oswe_independent === true);
    if (e.oswe_attempted && !found) {
      real_not_found++;
      if (e.oswe_covered) covered_fn++; else structural_fn++;
    }
  }
  const rate = (n, d) => (d > 0 ? n / d : null);
  const quality = {
    finding_proof_complete_rate: rate(proof_high, acc_high),
    chain_proof_complete_rate: rate(proof_chain, acc_chain),
    ce_resolved_rate: rate(ce_high, acc_high),
    independent_discovery_rate: rate(real_independent, real_total),
    attempted_real_share: rate(real_attempted, real_total),
    real_not_found, covered_fn, structural_fn,
    structural_fn_share: rate(structural_fn, real_not_found),
    attempted_per_category,
    min_attempted_per_category: Object.keys(attempted_per_category).length ? Math.min(...Object.values(attempted_per_category)) : 0,
    hygiene_findings: hygiene
  };
  // --- SP10 graph block: only when the ledger carries SP10 data (an entry with findings[] or a
  // top-level app_graph_stats[]), so a pre-SP10 ledger scores byte-identically. ---
  if ("app_graph_stats" in ledger || ledger.entries.some((e) => "findings" in e)) {
    Object.assign(quality, graphFindingRates(ledger.entries.flatMap((e) => e.findings || [])));
    quality.call_resolution_ratio = callResolutionRatio(ledger.app_graph_stats);
  }

  return {
    ok: true, error: null,
    semgrep_raw: finalize(m1), oswe_over_semgrep: finalize(m2), hybrid: finalize(m3),
    excluded, deltas, cwe_mismatches, total: ledger.entries.length, quality
  };
}

function toMarkdown(r) {
  const row = (name, m) => `| ${name} | ${m.tp} | ${m.fp} | ${m.fn} | ${m.tn} | ${m.precision.toFixed(3)} | ${m.recall.toFixed(3)} | ${m.fpr.toFixed(3)} | ${m.youden.toFixed(3)} |`;
  return [
    "# OSWE Hybrid Benchmark", "",
    `Total scored entries: ${r.total} — excluded: inconclusive ${r.excluded.inconclusive}, not-analyzed ${r.excluded.not_analyzed}, not-covered ${r.excluded.not_covered}.`,
    `CWE mismatches (diagnostic): ${r.cwe_mismatches}.`, "",
    "| matrix | tp | fp | fn | tn | precision | recall | fpr | youden |",
    "|---|---|---|---|---|---|---|---|---|",
    row("semgrep_raw", r.semgrep_raw),
    row("oswe_over_semgrep", r.oswe_over_semgrep),
    row("hybrid", r.hybrid), "",
    `Deltas: FP refuted **${r.deltas.fp_refuted}**, recall cost **${r.deltas.recall_cost}**, FN recovered **${r.deltas.fn_recovered}**.`, ""
  ].join("\n");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const get = (flag) => { const i = args.indexOf(flag); return i === -1 ? null : args[i + 1]; };
  const ledgerPath = get("--ledger"), truthPath = get("--truth"), outPath = get("--out"), mdPath = get("--md");
  if (!ledgerPath || !truthPath || !outPath) {
    process.stderr.write("usage: metrics.mjs --ledger <l.json> --truth <t.csv> --out <r.json> [--md <r.md>]\n"); process.exit(2);
  }
  let ledger, truth;
  try { ledger = JSON.parse(readFileSync(ledgerPath, "utf8")); }
  catch (e) { process.stderr.write("cannot read --ledger: " + e.message + "\n"); process.exit(2); }
  try { truth = parseTruthCsv(readFileSync(truthPath, "utf8")); }
  catch (e) { process.stderr.write("cannot read --truth: " + e.message + "\n"); process.exit(2); }
  const r = computeMetrics(ledger, truth);
  try {
    writeFileSync(outPath, JSON.stringify(r, null, 2));
    if (mdPath && r.ok) writeFileSync(mdPath, toMarkdown(r));
  } catch (e) { process.stderr.write("cannot write output: " + e.message + "\n"); process.exit(2); }
  if (!r.ok) { process.stderr.write("metrics error: " + r.error + "\n"); process.exit(1); }
  process.exit(0);
}
