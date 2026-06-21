// Deterministic benchmark metrics for the hybrid auditor. Zero runtime deps, Node >= 20.
// computeMetrics(ledger, truthMap) -> { ok, error, semgrep_raw, oswe_over_semgrep, hybrid, excluded, deltas, cwe_mismatches, total }
// CLI: node metrics.mjs --ledger <ledger.json> --truth <expectedresults.csv> --out <report.json> [--md <report.md>]
//   exit 0 ok / 1 ledger<->truth or schema/coherence violation / 2 IO|usage.
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";

const ADJ = new Set(["promoted", "refuted", "inconclusive", "not-analyzed", "no-lead"]);

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
  const topAllowed = new Set(["dataset", "subset", "generated", "entries"]);
  for (const k of Object.keys(ledger)) if (!topAllowed.has(k)) return `unknown top-level ledger field: ${k}`;
  for (const k of ["dataset", "subset", "generated"]) if (typeof ledger[k] !== "string" || !ledger[k]) return `ledger.${k} must be a non-empty string`;
  const seen = new Set();
  const allowed = new Set(["test_id", "semgrep_flagged", "oswe_covered", "oswe_adjudication", "oswe_independent", "cwe",
    "oswe_attempted", "accepted_high_findings", "proof_complete_high_findings", "ce_resolved_high_findings",
    "accepted_critical_chains", "proof_complete_critical_chains", "chain_reached_rce"]);
  for (const e of ledger.entries) {
    for (const k of Object.keys(e)) if (!allowed.has(k)) return `unknown ledger field: ${k}`;
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
  return {
    ok: true, error: null,
    semgrep_raw: finalize(m1), oswe_over_semgrep: finalize(m2), hybrid: finalize(m3),
    excluded, deltas, cwe_mismatches, total: ledger.entries.length
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
