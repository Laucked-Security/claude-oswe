// Assemble a §3.7.1 benchmark ledger from (a) score-semgrep.mjs's flagged.json (which cases Semgrep
// CWE-matched-flagged) and (b) the maintainer's oswe-adjudication map (gathered from /oswe:audit --sarif
// runs over the subset). The ledger is what metrics.mjs consumes. Zero deps, Node >= 20.
//
// oswe map shape (keyed by test_id):
//   flagged case  : { adjudication: "promoted"|"refuted"|"inconclusive" }   // how oswe judged the lead
//   missed case   : { covered: <bool>, independent: <bool> }                // did oswe analyze it / find it on its own
// Any case absent from the map degrades safely (flagged->not-analyzed/uncovered; missed->no-lead/uncovered).
//
// CLI:
//   node benchmark/build-ledger.mjs --flagged <flagged.json> --oswe <oswe-adjudications.json> \
//        --out <ledger.json> [--subset-path benchmark/subset-owasp.json]
//   exit 0 ok / 1 bad input / 2 IO|usage.
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";

const ADJ_FLAGGED = new Set(["promoted", "refuted", "inconclusive"]);
const SP6_COUNTERS = ["accepted_high_findings", "proof_complete_high_findings", "ce_resolved_high_findings", "accepted_critical_chains", "proof_complete_critical_chains", "hygiene_findings"];

export function buildLedger(flagged, oswe, opts = {}) {
  const entries = [];
  for (const c of flagged.cases || []) {
    const o = (oswe && oswe[c.test_id]) || {};
    const e = { test_id: c.test_id, semgrep_flagged: !!c.semgrep_flagged, cwe: c.cwe };
    if (c.semgrep_flagged) {
      // There is a Semgrep lead; oswe must adjudicate it. Absent / unknown -> not-analyzed (uncovered).
      if (ADJ_FLAGGED.has(o.adjudication)) {
        e.oswe_adjudication = o.adjudication;
        e.oswe_covered = true;
      } else {
        e.oswe_adjudication = "not-analyzed";
        e.oswe_covered = false;
      }
      e.oswe_independent = false; // not meaningful for a flagged lead; metrics ignores it here
    } else {
      // No Semgrep lead: adjudication is "no-lead"; coverage + independent discovery carry the signal.
      e.oswe_adjudication = "no-lead";
      e.oswe_covered = o.covered === true;
      e.oswe_independent = e.oswe_covered && o.independent === true;
    }
    // SP6: attempt status + finding/chain quality counters (from extract-oswe-adjudications.mjs).
    // Absent map entry degrades safely to not-attempted with zero counters.
    e.oswe_attempted = o.oswe_attempted === true;
    for (const k of SP6_COUNTERS) e[k] = Number.isInteger(o[k]) ? o[k] : 0;
    e.chain_reached_rce = o.chain_reached_rce === true;
    entries.push(e);
  }
  return {
    dataset: flagged.dataset || "owasp-benchmark-java-1.2",
    subset: opts.subset || "benchmark/subset-owasp.json",
    generated: new Date().toISOString().slice(0, 10),
    entries
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const get = (f) => { const i = args.indexOf(f); return i === -1 ? null : args[i + 1]; };
  const flaggedPath = get("--flagged"), oswePath = get("--oswe"), outPath = get("--out"), subset = get("--subset-path");
  if (!flaggedPath || !oswePath || !outPath) {
    process.stderr.write("usage: build-ledger.mjs --flagged <f.json> --oswe <o.json> --out <ledger.json> [--subset-path <p>]\n");
    process.exit(2);
  }
  let flagged, oswe;
  try { flagged = JSON.parse(readFileSync(flaggedPath, "utf8")); } catch (e) { process.stderr.write("cannot read --flagged: " + e.message + "\n"); process.exit(2); }
  try { oswe = JSON.parse(readFileSync(oswePath, "utf8")); } catch (e) { process.stderr.write("cannot read --oswe: " + e.message + "\n"); process.exit(2); }
  if (!Array.isArray(flagged.cases) || !flagged.cases.length) { process.stderr.write("--flagged has no cases[]\n"); process.exit(1); }
  const ledger = buildLedger(flagged, oswe, subset ? { subset } : {});
  try { writeFileSync(outPath, JSON.stringify(ledger, null, 2) + "\n"); }
  catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
  const adj = ledger.entries.reduce((a, e) => { a[e.oswe_adjudication] = (a[e.oswe_adjudication] || 0) + 1; return a; }, {});
  process.stdout.write(`wrote ${outPath}: ${ledger.entries.length} entries; adjudications ${JSON.stringify(adj)}\n`);
  process.exit(0);
}
