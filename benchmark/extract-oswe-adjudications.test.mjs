import { test } from "node:test";
import assert from "node:assert/strict";
import { extractAdjudications } from "./extract-oswe-adjudications.mjs";

const f8 = (id) => ({
  finding_id: id, partition_id: "p", title: "t", vuln_class: "sqli",
  source: { file: "org/owasp/benchmark/testcode/BenchmarkTest00008.java", line: 40, symbol: "x", kind: "http-param" },
  sink: { file: "org/owasp/benchmark/testcode/BenchmarkTest00008.java", line: 60, symbol: "q", kind: "query" },
  auth: "unauthenticated", provisional_severity: "High", confidence: "strong static proof",
  verification_status: "accepted", final_severity: "High", final_confidence: "strong static proof",
  direct_flow: true, partitions: ["p"], source_finding_ids: ["p-F001"]
});

const REPORT = {
  run: { run_id: "r1", generated: "2026-06-21", scope: ["src"],
    benchmark_test_ids: ["BenchmarkTest00008", "BenchmarkTest00010", "BenchmarkTest00012", "BenchmarkTest00011", "BenchmarkTest00013"] },
  coverage: {
    analyzed: [], skipped: [],
    benchmark_cases: [
      { test_id: "BenchmarkTest00008", status: "analyzed" },
      { test_id: "BenchmarkTest00010", status: "analyzed" },
      { test_id: "BenchmarkTest00012", status: "deprioritized" },
      { test_id: "BenchmarkTest00011", status: "analyzed" },
      { test_id: "BenchmarkTest00013", status: "analyzed" }
    ]
  },
  findings: [f8("OSWE-1"), f8("OSWE-2")],
  chains: [],
  verdicts: [
    { target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x", counterexamples: [{ hypothesis: "auth blocks", checked: true, refuted: true }] },
    { target_type: "finding", target_id: "OSWE-2", verdict: "accepted", justification: "x", counterexamples: [{ hypothesis: "sanitizer", checked: true, refuted: true }] }
  ],
  lead_adjudications: [
    { lead_id: "L001", outcome: "refuted", reason: "input is constant", test_id: "BenchmarkTest00011" },
    { lead_id: "L002", outcome: "promoted", finding_id: "OSWE-9", test_id: "BenchmarkTest00013" }
  ]
};

test("analyzed case with findings: counters + attempted/covered", () => {
  const map = extractAdjudications([REPORT]);
  assert.equal(map.BenchmarkTest00008.oswe_attempted, true);
  assert.equal(map.BenchmarkTest00008.covered, true);
  assert.equal(map.BenchmarkTest00008.accepted_high_findings, 2);
  assert.equal(map.BenchmarkTest00008.proof_complete_high_findings, 2);
  assert.equal(map.BenchmarkTest00008.ce_resolved_high_findings, 2);
});

test("zero-finding analyzed case is attempted+covered with zero counters (#R3.1)", () => {
  const map = extractAdjudications([REPORT]);
  assert.equal(map.BenchmarkTest00010.oswe_attempted, true);
  assert.equal(map.BenchmarkTest00010.covered, true);
  assert.equal(map.BenchmarkTest00010.accepted_high_findings, 0);
});

test("staged-but-deprioritized case is not attempted (#R4.1)", () => {
  const map = extractAdjudications([REPORT]);
  assert.equal(map.BenchmarkTest00012.oswe_attempted, false);
  assert.equal(map.BenchmarkTest00012.covered, false);
});

test("refuted/promoted leads resolve to their own case, not mixed (#R3.2, #R4.2)", () => {
  const map = extractAdjudications([REPORT]);
  assert.equal(map.BenchmarkTest00011.adjudication, "refuted");
  assert.equal(map.BenchmarkTest00013.adjudication, "promoted");
});

test("refuted + inconclusive leads on one case -> inconclusive, order-independent (#R5.3)", () => {
  const base = { run: { run_id: "r", generated: "g", scope: [] }, coverage: { analyzed: [], skipped: [], benchmark_cases: [{ test_id: "BenchmarkTest00020", status: "analyzed" }] }, findings: [], chains: [], verdicts: [] };
  const ref = { lead_id: "L001", outcome: "refuted", reason: "r", test_id: "BenchmarkTest00020" };
  const inc = { lead_id: "L002", outcome: "inconclusive", reason: "r", test_id: "BenchmarkTest00020" };
  const a = extractAdjudications([{ ...base, lead_adjudications: [ref, inc] }]);
  const b = extractAdjudications([{ ...base, lead_adjudications: [inc, ref] }]);
  assert.equal(a.BenchmarkTest00020.adjudication, "inconclusive");
  assert.equal(b.BenchmarkTest00020.adjudication, "inconclusive");
});

test("a case is refuted only when every lead is refuted; promoted always wins (#R5.3)", () => {
  const base = { run: { run_id: "r", generated: "g", scope: [] }, coverage: { analyzed: [], skipped: [], benchmark_cases: [{ test_id: "BenchmarkTest00021", status: "analyzed" }] }, findings: [], chains: [], verdicts: [] };
  const allRefuted = extractAdjudications([{ ...base, lead_adjudications: [
    { lead_id: "L001", outcome: "refuted", reason: "r", test_id: "BenchmarkTest00021" },
    { lead_id: "L002", outcome: "refuted", reason: "r", test_id: "BenchmarkTest00021" }] }]);
  assert.equal(allRefuted.BenchmarkTest00021.adjudication, "refuted");
  const withPromoted = extractAdjudications([{ ...base, lead_adjudications: [
    { lead_id: "L001", outcome: "refuted", reason: "r", test_id: "BenchmarkTest00021" },
    { lead_id: "L002", outcome: "promoted", finding_id: "OSWE-9", test_id: "BenchmarkTest00021" }] }]);
  assert.equal(withPromoted.BenchmarkTest00021.adjudication, "promoted");
});

test("a promoted lead whose finding the verifier rejected is net 'refuted' (#R6.1)", () => {
  const report = {
    run: { run_id: "r", generated: "g", scope: [], benchmark_test_ids: ["BenchmarkTest00177"] },
    coverage: { analyzed: [], skipped: [], benchmark_cases: [{ test_id: "BenchmarkTest00177", status: "analyzed" }] },
    findings: [{ finding_id: "OSWE-11", verification_status: "rejected", source: { file: "x/BenchmarkTest00177.java", line: 1 } }],
    chains: [], verdicts: [],
    lead_adjudications: [{ lead_id: "L022", outcome: "promoted", finding_id: "OSWE-11", test_id: "BenchmarkTest00177", reason: "analyzer promoted but verifier rejected" }]
  };
  const m = extractAdjudications([report]);
  assert.equal(m.BenchmarkTest00177.adjudication, "refuted"); // oswe ultimately dismissed it
});

test("a rejected chain with unauth-rce impact does NOT set chain_reached_rce (#R6.2)", () => {
  const base = (vs) => ({
    run: { run_id: "r", generated: "g", scope: [] },
    coverage: { analyzed: [], skipped: [], benchmark_cases: [{ test_id: "BenchmarkTest00177", status: "analyzed" }] },
    findings: [], verdicts: [], lead_adjudications: [],
    chains: [{ chain_id: "CHAIN-7", entry_point: { file: "x/BenchmarkTest00177.java", line: 1 }, final_impact: "unauth-rce", severity: "Critical", verification_status: vs, finding_ids: [] }]
  });
  assert.equal(extractAdjudications([base("rejected")]).BenchmarkTest00177.chain_reached_rce, false);
  assert.equal(extractAdjudications([base("accepted")]).BenchmarkTest00177.chain_reached_rce, true);
});

test("an unrefuted counterexample does not count toward ce_resolved", () => {
  const r = { ...REPORT, verdicts: [
    { target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x", counterexamples: [{ hypothesis: "h", checked: true, refuted: false }] },
    { target_type: "finding", target_id: "OSWE-2", verdict: "accepted", justification: "x", counterexamples: [{ hypothesis: "h", checked: true, refuted: true }] }
  ] };
  const map = extractAdjudications([r]);
  assert.equal(map.BenchmarkTest00008.ce_resolved_high_findings, 1);
});
