import { test } from "node:test";
import assert from "node:assert/strict";
import { reportSummary } from "../validators.mjs";

const ok = (data) => Boolean(reportSummary(data));

const validSummary = (overrides = {}) => ({
  meta: { target: "t", stack: "s", date: "2026-06-16 10:15", verdict: "unauth-rce", proof_level: "preuve statique forte" },
  severity_counts: { Critique: 1, Haute: 2, Moyenne: 0, Basse: 0, Info: 0 },
  finding_status_counts: { accepted: 2, downgraded: 0, rejected: 0, "not-requested": 0 },
  coverage: { analyzed: 2, skipped: 0 },
  chains: [{ id: "CHAIN-1", severity: "Critique", entry_auth: "unauthenticated", final_impact: "unauth-rce",
             nodes: ["entry", "OSWE-1", "OSWE-2", "RCE"],
             edges: [{ from: "entry", to: "OSWE-1", verdict: "accepted" }, { from: "OSWE-1", to: "OSWE-2", verdict: "accepted" }] }],
  ...overrides
});

test("report-summary: valid summary passes", () => {
  assert.equal(ok(validSummary()), true);
});
test("report-summary: empty chains + zero counts passes (safe report)", () => {
  assert.equal(ok(validSummary({
    severity_counts: { Critique: 0, Haute: 0, Moyenne: 0, Basse: 0, Info: 0 },
    chains: []
  })), true);
});
test("report-summary: free-text node label is rejected", () => {
  const s = validSummary();
  s.chains[0].nodes = ["<img onerror=x>", "RCE"];
  assert.equal(ok(s), false);
});
test("report-summary: fewer than 2 nodes is rejected (minItems)", () => {
  const s = validSummary();
  s.chains[0].nodes = ["entry"];
  assert.equal(ok(s), false);
});
test("report-summary: duplicate nodes are rejected (uniqueItems)", () => {
  const s = validSummary();
  s.chains[0].nodes = ["entry", "entry"];
  assert.equal(ok(s), false);
});
test("report-summary: empty edges is rejected (minItems)", () => {
  const s = validSummary();
  s.chains[0].edges = [];
  assert.equal(ok(s), false);
});
test("report-summary: final_impact outside enum is rejected", () => {
  const s = validSummary();
  s.chains[0].final_impact = "rce";
  assert.equal(ok(s), false);
});
test("report-summary: additionalProperties is rejected", () => {
  const s = validSummary();
  s.extra = 1;
  assert.equal(ok(s), false);
});
test("report-summary: missing a severity key is rejected", () => {
  const s = validSummary();
  delete s.severity_counts.Info;
  assert.equal(ok(s), false);
});
