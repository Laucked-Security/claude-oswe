// Score a NodeGoat audit report against the documented-vuln ground truth.
// Zero deps, Node >= 20. Deterministic.
//
// CLI:
//   node benchmark/score-nodegoat.mjs --report <report.json> --truth <nodegoat-truth.json> --out <score.json>
//   exit 0 ok / 2 IO|usage.
// SP10: a report carrying graph data also gets structural_proof_rate, candidate_path_hit_rate and
// call_resolution_ratio (definitions in metrics.mjs); an SP9 report scores exactly as before.
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";
import { carriesGraphData, graphFindingRates, callResolutionRatio } from "./metrics.mjs";

// ---------------------------------------------------------------------------
// vuln_class synonym groups (lowercased). A finding class compatible with a
// truth class if both appear in the same group, or if they are equal.
// ---------------------------------------------------------------------------
const SYNONYMS = [
  ["code-injection","ssjs","rce","eval-injection","remote-code-execution"],
  ["nosql-injection","nosqli"],
  ["sql-injection","sqli"],
  ["xss","cross-site-scripting","stored-xss","reflected-xss"],
  ["redos","regex-dos","regular-expression-dos"],
  ["ssrf","server-side-request-forgery"],
  ["open-redirect","unvalidated-redirect","redirect"],
  ["access-control","broken-access-control","authz","idor","missing-authorization","missing-function-level-access-control"]
];

// Build a lookup: token -> group index, for O(1) group resolution.
const TOKEN_GROUP = new Map();
for (let i = 0; i < SYNONYMS.length; i++) {
  for (const t of SYNONYMS[i]) TOKEN_GROUP.set(t, i);
}

/** Returns true if vuln_class a and b are compatible (exact or synonym group). */
function classMatch(a, b) {
  const an = (a || "").toLowerCase();
  const bn = (b || "").toLowerCase();
  if (an === bn) return true;
  const ga = TOKEN_GROUP.get(an);
  const gb = TOKEN_GROUP.get(bn);
  return ga !== undefined && ga === gb;
}

/** Normalize a file path: backslash -> forward slash, lowercase. */
function norm(p) {
  return (p || "").replace(/\\/g, "/").toLowerCase();
}

/**
 * Returns true if a report path matches a truth file path.
 * Truth files are repo-root-relative (e.g. "app/routes/contributions.js").
 * Report paths may be staging-prefixed (e.g. "external/NodeGoat/app/routes/contributions.js").
 * A segment-bounded suffix after normalization handles both cases.
 */
function pathMatch(reportPath, truthFile) {
  const report = norm(reportPath);
  const truth = norm(truthFile);
  return report === truth || report.endsWith(`/${truth}`);
}

/**
 * Returns true if the truth file is covered by coverage.analyzed.
 */
function isCovered(analyzed, truthFile) {
  return (analyzed || []).some((a) => pathMatch(a, truthFile));
}

/**
 * Returns true if a finding (with accepted/downgraded status) matches a truth vuln
 * (file match on source OR sink, AND class compatibility).
 */
function findingMatchesTruth(finding, vuln) {
  const fileOk =
    pathMatch(finding.source && finding.source.file, vuln.file) ||
    pathMatch(finding.sink && finding.sink.file, vuln.file);
  const classOk = classMatch(finding.vuln_class, vuln.vuln_class);
  return fileOk && classOk;
}

const ACCEPTED_STATUSES = new Set(["accepted", "downgraded"]);

/**
 * Score a NodeGoat audit report against the truth.
 *
 * @param {object} report  - Canonical audit report.json
 * @param {object} truth   - nodegoat-truth.json { app, vulns:[] }
 * @returns {object}       - Scoring result
 */
export function scoreNodegoat(report, truth) {
  const vulns = (truth && truth.vulns) || [];
  const total = vulns.length;
  const analyzed = (report.coverage && report.coverage.analyzed) || [];

  // Accepted/downgraded findings only participate in recall.
  const activefindings = (report.findings || []).filter(
    (f) => ACCEPTED_STATUSES.has(f.verification_status)
  );

  // --- Match each truth vuln to findings. ---
  const found = [];
  const missed = [];

  for (const vuln of vulns) {
    const matched = activefindings.some((f) => findingMatchesTruth(f, vuln));
    if (matched) {
      found.push({ id: vuln.id, vuln_class: vuln.vuln_class, file: vuln.file });
    } else {
      missed.push({ id: vuln.id, vuln_class: vuln.vuln_class, file: vuln.file });
    }
  }

  const recall = total > 0 ? found.length / total : 0;

  // --- Extra findings: accepted/downgraded but matched NO truth vuln. ---
  const extra = activefindings
    .filter((f) => !vulns.some((v) => findingMatchesTruth(f, v)))
    .map((f) => ({
      vuln_class: f.vuln_class,
      file: (f.sink && f.sink.file) || (f.source && f.source.file) || null
    }));

  // --- Chain stats. ---
  const acceptedChains = (report.chains || []).filter(
    (c) => ACCEPTED_STATUSES.has(c.verification_status)
  );
  const chains = acceptedChains.length;

  const multi_file_chains = acceptedChains.filter((c) => {
    const files = new Set();
    for (const tr of (c.transitions || [])) {
      for (const ev of (tr.evidence || [])) {
        if (ev.file) files.add(norm(ev.file));
      }
    }
    return files.size >= 2;
  }).length;

  // --- Structural vs reasoning miss breakdown. ---
  const structural_missed = missed.filter((m) => !isCovered(analyzed, m.file));
  const reasoning_missed = missed.filter((m) => isCovered(analyzed, m.file));
  const structural_missed_share =
    missed.length > 0 ? structural_missed.length / missed.length : null;

  const result = {
    total,
    found,
    missed,
    recall,
    extra,
    chains,
    multi_file_chains,
    structural_missed,
    reasoning_missed,
    structural_missed_share
  };

  // --- SP10 graph metrics: only for a report carrying graph data (an app_graph key, or a finding with
  // structural_path / candidate_path_ids), so re-scoring an SP9 report stays byte-identical. ---
  if (carriesGraphData(report)) {
    Object.assign(result, graphFindingRates(report.findings));
    const stats = report.app_graph && report.app_graph.stats;
    result.call_resolution_ratio = callResolutionRatio(stats ? [stats] : []);
  }
  return result;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const get = (flag) => { const i = args.indexOf(flag); return i === -1 ? null : args[i + 1]; };
  const reportPath = get("--report");
  const truthPath = get("--truth");
  const outPath = get("--out");

  if (!reportPath || !truthPath || !outPath) {
    process.stderr.write(
      "usage: score-nodegoat.mjs --report <report.json> --truth <nodegoat-truth.json> --out <score.json>\n"
    );
    process.exit(2);
  }

  let report, truth;
  try { report = JSON.parse(readFileSync(reportPath, "utf8")); }
  catch (e) { process.stderr.write("cannot read --report: " + e.message + "\n"); process.exit(2); }
  try { truth = JSON.parse(readFileSync(truthPath, "utf8")); }
  catch (e) { process.stderr.write("cannot read --truth: " + e.message + "\n"); process.exit(2); }

  const result = scoreNodegoat(report, truth);

  try { writeFileSync(outPath, JSON.stringify(result, null, 2) + "\n"); }
  catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }

  process.stdout.write(
    `recall=${result.recall.toFixed(3)} found=${result.found.length}/${result.total} ` +
    `chains=${result.chains} multi_file_chains=${result.multi_file_chains} ` +
    `structural_missed=${result.structural_missed.length} reasoning_missed=${result.reasoning_missed.length}\n`
  );
  process.exit(0);
}
