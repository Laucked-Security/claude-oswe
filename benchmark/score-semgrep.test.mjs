import { test } from "node:test";
import assert from "node:assert/strict";
import { ruleCweMap, flaggedByCase, scoreRaw } from "./score-semgrep.mjs";
import { parseTruthCsv } from "./metrics.mjs";

// Minimal synthetic SARIF: 2 rules (CWE-78 cmdi, CWE-89 sqli), results on 3 test cases.
const sarif = {
  version: "2.1.0",
  runs: [{
    tool: { driver: { name: "Semgrep", rules: [
      { id: "r.cmdi", properties: { tags: ["CWE-78: OS Command Injection", "HIGH"] } },
      { id: "r.sqli", properties: { tags: ["CWE-89: SQL Injection"] } },
      { id: "r.nocwe", properties: { tags: ["LOW CONFIDENCE"] } }
    ] } },
    results: [
      // T00001 (cmdi, real) flagged with matching CWE-78  -> tp
      { ruleId: "r.cmdi", locations: [{ physicalLocation: { artifactLocation: { uri: "x\\BenchmarkTest00001.java" } } }] },
      // T00002 (cmdi, NOT real) flagged with CWE-78        -> fp
      { ruleId: "r.cmdi", locations: [{ physicalLocation: { artifactLocation: { uri: "x/BenchmarkTest00002.java" } } }] },
      // T00003 (sqli, real) flagged only with CWE-78 (WRONG cwe) -> not a CWE-matched flag -> fn
      { ruleId: "r.cmdi", locations: [{ physicalLocation: { artifactLocation: { uri: "BenchmarkTest00003.java" } } }] }
      // T00004 (sqli, NOT real) not flagged at all          -> tn
    ]
  }]
};
const truth = parseTruthCsv(
  "# h\nBenchmarkTest00001,cmdi,true,78\nBenchmarkTest00002,cmdi,false,78\nBenchmarkTest00003,sqli,true,89\nBenchmarkTest00004,sqli,false,89\n"
);
const ids = ["BenchmarkTest00001", "BenchmarkTest00002", "BenchmarkTest00003", "BenchmarkTest00004"];

test("ruleCweMap extracts CWE numbers from rule tags", () => {
  const m = ruleCweMap(sarif.runs[0]);
  assert.deepEqual([...m.get("r.cmdi")], [78]);
  assert.deepEqual([...m.get("r.sqli")], [89]);
  assert.deepEqual([...m.get("r.nocwe")], []);
});

test("flaggedByCase maps each test case to its flagged CWE set (uri separator agnostic)", () => {
  const f = flaggedByCase(sarif);
  assert.deepEqual([...f.get("BenchmarkTest00001")], [78]); // backslash uri
  assert.deepEqual([...f.get("BenchmarkTest00002")], [78]); // forward-slash uri
  assert.deepEqual([...f.get("BenchmarkTest00003")], [78]); // bare uri
  assert.equal(f.has("BenchmarkTest00004"), false);
});

test("scoreRaw is CWE-matched: right-CWE flag counts, wrong-CWE does not", () => {
  const m = scoreRaw(ids, flaggedByCase(sarif), truth);
  // T1 tp, T2 fp, T3 fn (flagged but wrong CWE), T4 tn
  assert.deepEqual([m.tp, m.fp, m.fn, m.tn], [1, 1, 1, 1]);
  assert.equal(m.precision, 0.5);
  assert.equal(m.recall, 0.5);
  assert.equal(m.fpr, 0.5);
});

test("crypto CWE equivalence: a CWE-326 Semgrep flag counts for a CWE-327 case", () => {
  // a real crypto case labelled CWE-327, flagged by a rule tagged CWE-326 (des-is-deprecated)
  const cryptoSarif = {
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "Semgrep", rules: [{ id: "r.des", properties: { tags: ["CWE-326: Inadequate Encryption Strength"] } }] } },
      results: [{ ruleId: "r.des", locations: [{ physicalLocation: { artifactLocation: { uri: "x/BenchmarkTest05000.java" } } }] }]
    }]
  };
  const cryptoTruth = parseTruthCsv("# h\nBenchmarkTest05000,crypto,true,327\n");
  const m = scoreRaw(["BenchmarkTest05000"], flaggedByCase(cryptoSarif), cryptoTruth);
  // 326 must be accepted for the 327 case -> this is a true positive, NOT a false negative
  assert.deepEqual([m.tp, m.fp, m.fn, m.tn], [1, 0, 0, 0]);
});

test("a flagged map entry per subset case is derivable for the ledger", () => {
  const f = flaggedByCase(sarif);
  const cases = ids.map((id) => ({ test_id: id, semgrep_flagged: (f.get(id) || new Set()).has(truth.get(id).cwe), cwe: truth.get(id).cwe }));
  assert.deepEqual(cases.map((c) => c.semgrep_flagged), [true, true, false, false]);
});
