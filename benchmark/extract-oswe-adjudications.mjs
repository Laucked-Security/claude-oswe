// Deterministic bridge: canonical report.json[] -> the oswe-adjudications map keyed by BenchmarkTestNNNNN
// that build-ledger.mjs consumes. Reads ONLY the report artifact — nothing is derived by hand. Zero deps.
//
// Per-case fields produced:
//   adjudication        : "promoted"|"refuted"|"inconclusive" — from lead_adjudications (promoted wins)
//   oswe_attempted      : the case's coverage.benchmark_cases status is "analyzed" (NOT the staged set)
//   covered             : same as attempted (a case is "covered" iff actually analyzed)
//   independent         : a finding with origin "llm-discovered" resolved to this case
//   accepted_high_findings / proof_complete_high_findings / ce_resolved_high_findings
//   accepted_critical_chains / proof_complete_critical_chains / chain_reached_rce
//
// Test-id resolution: BenchmarkTestNNNNN parsed from a finding/chain/lead file path (or an explicit
// lead.test_id), with an optional run.path_map override.
//
// CLI: node extract-oswe-adjudications.mjs --dir <reportsDir> --out <oswe-adjudications.json>
//   exit 0 ok / 2 IO|usage.
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const TID_RE = /BenchmarkTest(\d{5})/;
const ADJ_RANK = { refuted: 1, inconclusive: 1, promoted: 2 }; // promoted wins; otherwise first-seen.

function initEntry() {
  return {
    oswe_attempted: false, covered: false, independent: false,
    accepted_high_findings: 0, proof_complete_high_findings: 0, ce_resolved_high_findings: 0,
    accepted_critical_chains: 0, proof_complete_critical_chains: 0, chain_reached_rce: false
  };
}

function resolveTid(file, report) {
  if (typeof file === "string") {
    const m = TID_RE.exec(file);
    if (m) return "BenchmarkTest" + m[1];
    const pm = report.run && report.run.path_map;
    if (pm && typeof pm[file] === "string") return pm[file];
  }
  return null;
}

const proofComplete = (f) =>
  (Array.isArray(f.transformations) && f.transformations.length > 0) || f.direct_flow === true;

export function extractAdjudications(reports) {
  const map = {};
  const ensure = (tid) => (map[tid] = map[tid] || initEntry());

  for (const report of reports || []) {
    // 1. Per-case analysis status is authoritative for attempted/covered (#R4.1, #R3.1).
    for (const bc of (report.coverage && report.coverage.benchmark_cases) || []) {
      const e = ensure(bc.test_id);
      const analyzed = bc.status === "analyzed";
      e.oswe_attempted = analyzed;
      e.covered = analyzed;
    }

    const findingById = new Map((report.findings || []).map((f) => [f.finding_id, f]));
    const verdictByFid = new Map(
      (report.verdicts || []).filter((v) => v.target_type === "finding").map((v) => [v.target_id, v])
    );

    // 2. Findings: counters + independent discovery.
    for (const f of report.findings || []) {
      const tid = resolveTid(f.source && f.source.file, report);
      if (!tid) continue;
      const e = ensure(tid);
      if (f.origin === "llm-discovered") e.independent = true;
      if (f.verification_status === "accepted" && f.final_severity === "High") {
        e.accepted_high_findings++;
        if (proofComplete(f)) e.proof_complete_high_findings++;
        const vd = verdictByFid.get(f.finding_id);
        if (vd && Array.isArray(vd.counterexamples) && vd.counterexamples.length > 0 &&
            vd.counterexamples.every((c) => c.checked === true && c.refuted === true)) {
          e.ce_resolved_high_findings++;
        }
      }
    }

    // 3. Chains: critical counters + RCE reach.
    for (const c of report.chains || []) {
      const tid = resolveTid(c.entry_point && c.entry_point.file, report);
      if (!tid) continue;
      const e = ensure(tid);
      if (c.final_impact === "unauth-rce") e.chain_reached_rce = true;
      if (c.verification_status === "accepted" && c.severity === "Critical") {
        e.accepted_critical_chains++;
        const allProof = (c.finding_ids || []).every((id) => {
          const mf = findingById.get(id);
          return mf && proofComplete(mf);
        });
        if (allProof) e.proof_complete_critical_chains++;
      }
    }

    // 4. Lead adjudications: resolve each to its own case (promoted wins).
    for (const la of report.lead_adjudications || []) {
      const tid = la.test_id || resolveTid(la.location && la.location.file, report);
      if (!tid) continue;
      const e = ensure(tid);
      const prev = e.adjudication;
      if (!prev || (ADJ_RANK[la.outcome] || 0) > (ADJ_RANK[prev] || 0)) e.adjudication = la.outcome;
    }
  }
  return map;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const get = (f) => { const i = args.indexOf(f); return i === -1 ? null : args[i + 1]; };
  const dir = get("--dir"), outPath = get("--out");
  if (!dir || !outPath) {
    process.stderr.write("usage: extract-oswe-adjudications.mjs --dir <reportsDir> --out <map.json>\n");
    process.exit(2);
  }
  let reports;
  try {
    reports = readdirSync(dir).filter((f) => f.endsWith(".json"))
      .map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")));
  } catch (e) { process.stderr.write("cannot read reports: " + e.message + "\n"); process.exit(2); }
  const map = extractAdjudications(reports);
  try { writeFileSync(outPath, JSON.stringify(map, null, 2) + "\n"); }
  catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
  process.stdout.write(`wrote ${outPath}: ${Object.keys(map).length} cases\n`);
  process.exit(0);
}
