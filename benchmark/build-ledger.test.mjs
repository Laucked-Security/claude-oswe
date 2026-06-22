import { test } from "node:test";
import assert from "node:assert/strict";
import { buildLedger } from "./build-ledger.mjs";
import { computeMetrics, parseTruthCsv } from "./metrics.mjs";

// flagged.json shape (from score-semgrep.mjs): per subset case, was it CWE-matched-flagged by Semgrep.
const flagged = {
  dataset: "owasp-benchmark-java-1.2",
  cases: [
    { test_id: "BenchmarkTest00001", semgrep_flagged: true, cwe: 78 },  // real cmdi, flagged
    { test_id: "BenchmarkTest00002", semgrep_flagged: true, cwe: 78 },  // NOT real, flagged (a Semgrep FP)
    { test_id: "BenchmarkTest00003", semgrep_flagged: false, cwe: 89 }, // real sqli, missed by Semgrep
    { test_id: "BenchmarkTest00004", semgrep_flagged: false, cwe: 89 }  // NOT real, not flagged
  ]
};
// oswe adjudication output the maintainer assembles from /oswe:audit --sarif runs.
// Flagged cases get an adjudication; for missed cases oswe records coverage + independent discovery.
const oswe = {
  "BenchmarkTest00001": { adjudication: "promoted" },              // correctly promotes the real one
  "BenchmarkTest00002": { adjudication: "refuted" },               // correctly refutes the Semgrep FP
  "BenchmarkTest00003": { covered: true, independent: true },      // oswe finds what Semgrep missed
  "BenchmarkTest00004": { covered: true, independent: false }      // correctly stays silent
};
const truth = parseTruthCsv(
  "# h\nBenchmarkTest00001,cmdi,true,78\nBenchmarkTest00002,cmdi,false,78\nBenchmarkTest00003,sqli,true,89\nBenchmarkTest00004,sqli,false,89\n"
);

test("buildLedger produces a §3.7.1-valid ledger that metrics.mjs accepts", () => {
  const ledger = buildLedger(flagged, oswe, { subset: "benchmark/subset-owasp.json" });
  const r = computeMetrics(ledger, truth);
  assert.equal(r.ok, true, r.error);
});

test("flagged case -> semgrep_flagged true, adjudication carried, coherence ok", () => {
  const ledger = buildLedger(flagged, oswe, {});
  const e1 = ledger.entries.find((e) => e.test_id === "BenchmarkTest00001");
  assert.equal(e1.semgrep_flagged, true);
  assert.equal(e1.oswe_adjudication, "promoted");
  assert.equal(e1.oswe_covered, true);   // a flagged+adjudicated case is covered
});

test("missed case -> semgrep_flagged false, adjudication 'no-lead', coverage+independent carried", () => {
  const ledger = buildLedger(flagged, oswe, {});
  const e3 = ledger.entries.find((e) => e.test_id === "BenchmarkTest00003");
  assert.equal(e3.semgrep_flagged, false);
  assert.equal(e3.oswe_adjudication, "no-lead");
  assert.equal(e3.oswe_covered, true);
  assert.equal(e3.oswe_independent, true);
});

test("the assembled ledger yields the expected perfect-adjudication metrics", () => {
  const ledger = buildLedger(flagged, oswe, {});
  const r = computeMetrics(ledger, truth);
  // oswe_over_semgrep (flagged only: T1 promoted+real=tp, T2 refuted+!real=tn) -> precision 1.0, no fp
  assert.deepEqual([r.oswe_over_semgrep.tp, r.oswe_over_semgrep.fp, r.oswe_over_semgrep.fn, r.oswe_over_semgrep.tn], [1, 0, 0, 1]);
  // headline deltas: 1 Semgrep FP refuted, 0 recall cost, 1 FN recovered
  assert.deepEqual(r.deltas, { fp_refuted: 1, recall_cost: 1 - 1, fn_recovered: 1 });
});

test("a flagged case missing from the oswe map defaults to not-analyzed (covered:false)", () => {
  const partial = { "BenchmarkTest00001": { adjudication: "promoted" } }; // others absent
  const ledger = buildLedger(flagged, partial, {});
  const e2 = ledger.entries.find((e) => e.test_id === "BenchmarkTest00002");
  assert.equal(e2.semgrep_flagged, true);
  assert.equal(e2.oswe_adjudication, "not-analyzed");
  assert.equal(e2.oswe_covered, false);
});

test("SP6: ledger carries oswe_attempted + finding/chain counters from the map", () => {
  const m = {
    "BenchmarkTest00001": { adjudication: "promoted", oswe_attempted: true, accepted_high_findings: 2, proof_complete_high_findings: 2, ce_resolved_high_findings: 1, accepted_critical_chains: 1, proof_complete_critical_chains: 1, chain_reached_rce: true }
  };
  const e1 = buildLedger(flagged, m, {}).entries.find((e) => e.test_id === "BenchmarkTest00001");
  assert.equal(e1.oswe_attempted, true);
  assert.equal(e1.accepted_high_findings, 2);
  assert.equal(e1.proof_complete_high_findings, 2);
  assert.equal(e1.ce_resolved_high_findings, 1);
  assert.equal(e1.accepted_critical_chains, 1);
  assert.equal(e1.proof_complete_critical_chains, 1);
  assert.equal(e1.chain_reached_rce, true);
});

test("SP6: a case absent from the map degrades to oswe_attempted:false, counters 0", () => {
  const e2 = buildLedger(flagged, {}, {}).entries.find((e) => e.test_id === "BenchmarkTest00002");
  assert.equal(e2.oswe_attempted, false);
  assert.equal(e2.accepted_high_findings, 0);
  assert.equal(e2.chain_reached_rce, false);
});

test("SP6: the enriched ledger still passes metrics.mjs validation", () => {
  const m = { "BenchmarkTest00001": { adjudication: "promoted", oswe_attempted: true, accepted_high_findings: 1, proof_complete_high_findings: 1, ce_resolved_high_findings: 1 } };
  const r = computeMetrics(buildLedger(flagged, m, {}), truth);
  assert.equal(r.ok, true, r.error);
});

test("a missed case absent from the oswe map -> no-lead, not covered", () => {
  const partial = {};
  const ledger = buildLedger(flagged, partial, {});
  const e3 = ledger.entries.find((e) => e.test_id === "BenchmarkTest00003");
  assert.equal(e3.oswe_adjudication, "no-lead");
  assert.equal(e3.oswe_covered, false);
  assert.equal(e3.oswe_independent, false);
});
