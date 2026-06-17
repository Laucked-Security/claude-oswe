import { test } from "node:test";
import assert from "node:assert/strict";
import { computeMetrics, parseTruthCsv } from "./metrics.mjs";

// truth: T1 real(cwe89), T2 not-real, T3 real(cwe78), T4 real(cwe22), T5 not-real
const truth = parseTruthCsv(
  "# test name, category, real vulnerability, cwe\n" +
  "BenchmarkTest00001,sqli,true,89\n" +
  "BenchmarkTest00002,sqli,false,89\n" +
  "BenchmarkTest00003,cmdi,true,78\n" +
  "BenchmarkTest00004,pathtraver,true,22\n" +
  "BenchmarkTest00005,xss,false,79\n"
);

const ledger = {
  dataset: "owasp-benchmark-1.2", subset: "benchmark/subset-owasp.json", generated: "2026-06-17",
  entries: [
    // flagged TP, oswe promotes -> correct
    { test_id: "BenchmarkTest00001", semgrep_flagged: true, oswe_covered: true, oswe_adjudication: "promoted", oswe_independent: false, cwe: 89 },
    // flagged FP, oswe refutes -> fp_refuted
    { test_id: "BenchmarkTest00002", semgrep_flagged: true, oswe_covered: true, oswe_adjudication: "refuted", oswe_independent: false, cwe: 89 },
    // flagged TP, oswe refutes -> recall_cost
    { test_id: "BenchmarkTest00003", semgrep_flagged: true, oswe_covered: true, oswe_adjudication: "refuted", oswe_independent: false, cwe: 78 },
    // missed real, oswe covered + independent -> fn_recovered (hybrid tp)
    { test_id: "BenchmarkTest00004", semgrep_flagged: false, oswe_covered: true, oswe_adjudication: "no-lead", oswe_independent: true, cwe: 22 },
    // missed not-real, oswe covered, not independent -> hybrid tn
    { test_id: "BenchmarkTest00005", semgrep_flagged: false, oswe_covered: true, oswe_adjudication: "no-lead", oswe_independent: false, cwe: 79 }
  ]
};

test("semgrep_raw matrix", () => {
  const m = computeMetrics(ledger, truth).semgrep_raw;
  // flagged: T1(real)->tp, T2(!real)->fp, T3(real)->tp ; missed: T4(real)->fn, T5(!real)->tn
  assert.deepEqual([m.tp, m.fp, m.fn, m.tn], [2, 1, 1, 1]);
});

test("oswe_over_semgrep matrix (flagged only)", () => {
  const m = computeMetrics(ledger, truth).oswe_over_semgrep;
  // T1 promoted+real->tp ; T2 refuted+!real->tn ; T3 refuted+real->fn
  assert.deepEqual([m.tp, m.fp, m.fn, m.tn], [1, 0, 1, 1]);
});

test("hybrid matrix (flagged group a + covered-missed group b)", () => {
  const m = computeMetrics(ledger, truth).hybrid;
  // group a: T1 tp, T2 tn, T3 fn ; group b: T4 tp, T5 tn
  assert.deepEqual([m.tp, m.fp, m.fn, m.tn], [2, 0, 1, 2]);
});

test("headline deltas", () => {
  const d = computeMetrics(ledger, truth).deltas;
  assert.deepEqual(d, { fp_refuted: 1, recall_cost: 1, fn_recovered: 1 });
});

test("denominator identity holds for hybrid", () => {
  const r = computeMetrics(ledger, truth);
  const m = r.hybrid;
  assert.equal(m.tp + m.fp + m.fn + m.tn, r.total - (r.excluded.inconclusive + r.excluded.not_analyzed + r.excluded.not_covered));
});

test("inconclusive and not-analyzed flagged leads are excluded, not scored", () => {
  const l = { ...ledger, entries: [
    { test_id: "BenchmarkTest00001", semgrep_flagged: true, oswe_covered: true, oswe_adjudication: "inconclusive", oswe_independent: false, cwe: 89 },
    { test_id: "BenchmarkTest00002", semgrep_flagged: true, oswe_covered: false, oswe_adjudication: "not-analyzed", oswe_independent: false, cwe: 89 }
  ] };
  const r = computeMetrics(l, truth);
  assert.equal(r.excluded.inconclusive, 1);
  assert.equal(r.excluded.not_analyzed, 1);
  assert.equal(r.oswe_over_semgrep.tp + r.oswe_over_semgrep.fp + r.oswe_over_semgrep.fn + r.oswe_over_semgrep.tn, 0);
});

test("uncovered Semgrep-missed case is excluded (not_covered), never an fn", () => {
  const l = { ...ledger, entries: [
    { test_id: "BenchmarkTest00004", semgrep_flagged: false, oswe_covered: false, oswe_adjudication: "no-lead", oswe_independent: false, cwe: 22 }
  ] };
  const r = computeMetrics(l, truth);
  assert.equal(r.excluded.not_covered, 1);
  assert.equal(r.hybrid.fn, 0);
});

test("a covered Semgrep-missed real vuln NOT found is an honest hybrid fn (regression guard)", () => {
  const l = { ...ledger, entries: [
    { test_id: "BenchmarkTest00004", semgrep_flagged: false, oswe_covered: true, oswe_adjudication: "no-lead", oswe_independent: false, cwe: 22 }
  ] };
  const r = computeMetrics(l, truth);
  assert.equal(r.ok, true);
  assert.equal(r.hybrid.fn, 1);
});

test("coherence: flagged with no-lead adjudication is rejected", () => {
  const l = { ...ledger, entries: [{ test_id: "BenchmarkTest00001", semgrep_flagged: true, oswe_covered: true, oswe_adjudication: "no-lead", oswe_independent: false, cwe: 89 }] };
  assert.equal(computeMetrics(l, truth).ok, false);
});

test("coherence: missed without no-lead adjudication is rejected", () => {
  const l = { ...ledger, entries: [{ test_id: "BenchmarkTest00005", semgrep_flagged: false, oswe_covered: true, oswe_adjudication: "refuted", oswe_independent: false, cwe: 79 }] };
  assert.equal(computeMetrics(l, truth).ok, false);
});

test("coherence: flagged not-analyzed must be uncovered", () => {
  const l = { ...ledger, entries: [{ test_id: "BenchmarkTest00001", semgrep_flagged: true, oswe_covered: true, oswe_adjudication: "not-analyzed", oswe_independent: false, cwe: 89 }] };
  assert.equal(computeMetrics(l, truth).ok, false);
});

test("a ledger test_id absent from truth is rejected", () => {
  const l = { ...ledger, entries: [{ test_id: "BenchmarkTest99999", semgrep_flagged: true, oswe_covered: true, oswe_adjudication: "promoted", oswe_independent: false, cwe: 1 }] };
  assert.equal(computeMetrics(l, truth).ok, false);
});

test("an unknown TOP-LEVEL ledger field is rejected", () => {
  const l = { ...ledger, bogus: 1 };
  assert.equal(computeMetrics(l, truth).ok, false);
});

test("a missing/empty dataset (top-level metadata) is rejected", () => {
  const { dataset, ...rest } = ledger;
  assert.equal(computeMetrics(rest, truth).ok, false);
});

test("cwe mismatch is non-fatal and only bumps cwe_mismatches", () => {
  const l = { ...ledger, entries: [{ test_id: "BenchmarkTest00001", semgrep_flagged: true, oswe_covered: true, oswe_adjudication: "promoted", oswe_independent: false, cwe: 999 }] };
  const r = computeMetrics(l, truth);
  assert.equal(r.ok, true);
  assert.equal(r.cwe_mismatches, 1);
});
