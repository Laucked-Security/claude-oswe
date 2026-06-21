import { test } from "node:test";
import assert from "node:assert/strict";
import { buildReport, validateReport } from "../write-report.mjs";
import { validate } from "../validate-output.mjs";

// --- fixtures (reuse the shapes the other schemas already accept) ---
const run = (over = {}) => ({ run_id: "r1", generated: "2026-06-21", scope: ["src"], ...over });
const coverage = (over = {}) => ({ analyzed: ["src/a.java"], skipped: [], ...over });

const finalFinding = {
  finding_id: "OSWE-3", partition_id: "auth", title: "t", vuln_class: "sqli",
  source: { file: "a", line: 1, symbol: "s", kind: "http-param" },
  sink: { file: "b", line: 2, symbol: "q", kind: "query" },
  auth: "unauthenticated", provisional_severity: "High", confidence: "strong static proof",
  verification_status: "accepted", final_severity: "High", final_confidence: "strong static proof",
  direct_flow: true, partitions: ["auth"], source_finding_ids: ["auth-F001"]
};
const chain = {
  chain_id: "CHAIN-1",
  entry_point: { file: "a", line: 1, route: "POST /login", auth: "unauthenticated" },
  finding_ids: ["OSWE-3"],
  transitions: [{ from: "entry", to: "OSWE-3", how: "x", evidence: [{ file: "a", line: 1 }] }],
  final_impact: "unauth-rce", severity: "Critical", confidence: "strong static proof",
  verification_status: "accepted"
};
const verdict = { target_type: "finding", target_id: "OSWE-3", verdict: "accepted", justification: "src->sink a:1->b:2", counterexamples: [{ hypothesis: "auth blocks", checked: true, refuted: true }] };

test("buildReport assembles a report that validates", () => {
  const r = buildReport({ run: run(), coverage: coverage(), findings: [finalFinding], chains: [chain], verdicts: [verdict] });
  const res = validateReport(r);
  assert.equal(res.valid, true, JSON.stringify(res.errors));
});

test('validate("report", ...) is wired into the generated validators', () => {
  const r = buildReport({ run: run(), coverage: coverage(), findings: [], chains: [], verdicts: [] });
  assert.equal(validate("report", r).valid, true, JSON.stringify(validate("report", r).errors));
});

test("missing run.run_id fails", () => {
  const r = buildReport({ run: { generated: "2026-06-21", scope: ["src"] }, coverage: coverage(), findings: [], chains: [], verdicts: [] });
  assert.equal(validateReport(r).valid, false);
});

test("coverage.benchmark_cases accepts a known status and rejects an unknown one", () => {
  const ok = buildReport({ run: run(), coverage: coverage({ benchmark_cases: [{ test_id: "BenchmarkTest00010", status: "analyzed" }] }), findings: [], chains: [], verdicts: [] });
  assert.equal(validateReport(ok).valid, true, JSON.stringify(validateReport(ok).errors));
  const bad = buildReport({ run: run(), coverage: coverage({ benchmark_cases: [{ test_id: "BenchmarkTest00010", status: "audited" }] }), findings: [], chains: [], verdicts: [] });
  assert.equal(validateReport(bad).valid, false);
});

test("lead_adjudications: refuted lead with a test_id resolver and reason validates", () => {
  const r = buildReport({
    run: run(), coverage: coverage(), findings: [], chains: [], verdicts: [],
    lead_adjudications: [{ lead_id: "L001", outcome: "refuted", reason: "input is constant", test_id: "BenchmarkTest00011" }]
  });
  assert.equal(validateReport(r).valid, true, JSON.stringify(validateReport(r).errors));
});

test("lead_adjudications: a promoted lead still requires finding_id", () => {
  const r = buildReport({
    run: run(), coverage: coverage(), findings: [], chains: [], verdicts: [],
    lead_adjudications: [{ lead_id: "L001", outcome: "promoted", test_id: "BenchmarkTest00013" }]
  });
  assert.equal(validateReport(r).valid, false);
});
