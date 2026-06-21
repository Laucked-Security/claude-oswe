// Compute the raw-Semgrep baseline on OWASP BenchmarkJava from a Semgrep SARIF, CWE-matched per the
// OWASP Benchmark methodology (a flag counts only if it carries the test case's expected CWE).
// Zero deps, Node >= 20. Emits the per-subset-case "semgrep_flagged" map that build-ledger.mjs consumes.
//
// CLI:
//   node benchmark/score-semgrep.mjs --sarif <s.sarif> --truth <expectedresults-1.2.csv> \
//        --subset benchmark/subset-owasp.json --out <flagged.json> [--md <baseline.md>]
//   exit 0 ok / 1 bad input (no runs / empty) / 2 IO|usage.
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";
import { parseTruthCsv } from "./metrics.mjs";

// CWE equivalence sets (OWASP Benchmark scores a category by a CWE *family*, not exact id). A Semgrep
// flag counts as CWE-matched if its CWE is in the accepted set for the case's expected CWE. The only
// equivalence the official Java rules actually need: weak-crypto cases are labelled CWE-327 (broken
// algorithm) while Semgrep's `des(ede)-is-deprecated` rules tag CWE-326 (inadequate strength) — sibling
// crypto-strength weaknesses; DES is legitimately both. Without this, a real Semgrep detection on the
// 4 crypto cases would be scored as a MISS, which would falsely inflate oswe's recall-recovery delta.
export const CWE_EQUIV = { 326: new Set([326, 327]), 327: new Set([326, 327]) };
const accepts = (expectedCwe, flaggedSet) => {
  const ok = CWE_EQUIV[expectedCwe] || new Set([expectedCwe]);
  for (const c of flaggedSet) if (ok.has(c)) return true;
  return false;
};

// rule id -> Set(cwe numbers), parsed from rule.properties.tags entries like "CWE-78: ...".
export function ruleCweMap(run) {
  const m = new Map();
  for (const r of (run && run.tool && run.tool.driver && run.tool.driver.rules) || []) {
    const cwes = new Set();
    for (const t of (r.properties && r.properties.tags) || []) {
      const mm = /^CWE-(\d+)/.exec(t);
      if (mm) cwes.add(Number(mm[1]));
    }
    m.set(r.id, cwes);
  }
  return m;
}

// SARIF -> Map(test_id -> Set(cwe)) of CWEs Semgrep flagged in each BenchmarkTestNNNNN file.
export function flaggedByCase(sarif) {
  const run = (sarif.runs || [])[0];
  const rc = ruleCweMap(run);
  const out = new Map();
  for (const res of (run && run.results) || []) {
    const uri = (((res.locations || [])[0] || {}).physicalLocation || {}).artifactLocation;
    const m = /BenchmarkTest(\d{5})/.exec((uri && uri.uri) || "");
    if (!m) continue;
    const id = "BenchmarkTest" + m[1];
    if (!out.has(id)) out.set(id, new Set());
    for (const c of rc.get(res.ruleId) || []) out.get(id).add(c);
  }
  return out;
}

// Confusion matrix of CWE-matched Semgrep flags vs ground truth, over the given test ids.
export function scoreRaw(ids, flagged, truth) {
  let tp = 0, fp = 0, fn = 0, tn = 0;
  for (const id of ids) {
    const t = truth.get(id);
    if (!t) continue;
    const pred = accepts(t.cwe, flagged.get(id) || new Set());
    if (pred && t.real) tp++;
    else if (pred && !t.real) fp++;
    else if (!pred && t.real) fn++;
    else tn++;
  }
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const fpr = fp + tn ? fp / (fp + tn) : 0;
  const r3 = (x) => Number(x.toFixed(3));
  return { tp, fp, fn, tn, precision: r3(precision), recall: r3(recall), fpr: r3(fpr), youden: r3(recall - fpr) };
}

function toMd(full, sub, subCount) {
  const row = (n, m) => `| ${n} | ${m.tp} | ${m.fp} | ${m.fn} | ${m.tn} | ${m.precision.toFixed(3)} | ${m.recall.toFixed(3)} | ${m.fpr.toFixed(3)} | ${m.youden.toFixed(3)} |`;
  return [
    "# Semgrep raw baseline — OWASP BenchmarkJava (CWE-matched)", "",
    "Official `semgrep-rules/java/lang/security`; a flag counts only if it carries the case's expected CWE.", "",
    "| scope | tp | fp | fn | tn | precision | recall | fpr | youden |",
    "|---|---|---|---|---|---|---|---|---|",
    row(`full (${full.tp + full.fp + full.fn + full.tn})`, full),
    row(`subset (${subCount})`, sub), "",
    `The **${sub.fp} false positives** in the subset (**${full.fp}** full) are the noise the oswe adjudication layer must refute to beat this baseline on precision.`, ""
  ].join("\n");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const get = (f) => { const i = args.indexOf(f); return i === -1 ? null : args[i + 1]; };
  const sarifPath = get("--sarif"), truthPath = get("--truth"), subsetPath = get("--subset"), outPath = get("--out"), mdPath = get("--md");
  const all = args.includes("--all");
  if (!sarifPath || !truthPath || !outPath || (!subsetPath && !all)) {
    process.stderr.write("usage: score-semgrep.mjs --sarif <s> --truth <csv> (--subset <json> | --all) --out <flagged.json> [--md <md>]\n");
    process.exit(2);
  }
  let sarif, truth, subset = null;
  try { sarif = JSON.parse(readFileSync(sarifPath, "utf8")); } catch (e) { process.stderr.write("cannot read --sarif: " + e.message + "\n"); process.exit(2); }
  try { truth = parseTruthCsv(readFileSync(truthPath, "utf8")); } catch (e) { process.stderr.write("cannot read --truth: " + e.message + "\n"); process.exit(2); }
  if (subsetPath) { try { subset = JSON.parse(readFileSync(subsetPath, "utf8")); } catch (e) { process.stderr.write("cannot read --subset: " + e.message + "\n"); process.exit(2); } }
  if (!Array.isArray(sarif.runs) || !sarif.runs.length) { process.stderr.write("SARIF has no runs[]\n"); process.exit(1); }
  if (subset && (!Array.isArray(subset.test_ids) || !subset.test_ids.length)) { process.stderr.write("subset has no test_ids[]\n"); process.exit(1); }

  const flagged = flaggedByCase(sarif);
  const full = scoreRaw([...truth.keys()], flagged, truth);
  // --all scores every truth case; otherwise the subset. The case list drives the emitted ledger input.
  const caseIds = all ? [...truth.keys()] : subset.test_ids;
  const sub = scoreRaw(caseIds, flagged, truth);
  const cases = caseIds
    .filter((id) => truth.has(id))
    .map((id) => ({ test_id: id, semgrep_flagged: accepts(truth.get(id).cwe, flagged.get(id) || new Set()), cwe: truth.get(id).cwe }));
  const out = { dataset: (subset && subset.dataset) || "owasp-benchmark-java-1.2", generated: new Date().toISOString().slice(0, 10), semgrep_raw: { full, subset: sub }, cases };
  try {
    writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n");
    if (mdPath) writeFileSync(mdPath, toMd(full, sub, cases.length));
  } catch (e) { process.stderr.write("cannot write output: " + e.message + "\n"); process.exit(2); }
  process.stdout.write(`semgrep_raw full=${JSON.stringify(full)}\nsemgrep_raw subset=${JSON.stringify(sub)}\nwrote ${outPath} (${cases.length} subset cases)\n`);
  process.exit(0);
}
