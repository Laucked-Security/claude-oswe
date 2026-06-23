import { test } from "node:test";
import assert from "node:assert/strict";
import { buildSarif } from "../export-sarif.mjs";
import { ingestSarif } from "../ingest-sarif.mjs";

const report = {
  run: { run_id: "r", generated: "2026-06-23", scope: ["src"] },
  coverage: { analyzed: [], skipped: [] },
  findings: [
    { finding_id:"OSWE-1", vuln_class:"sqli", final_severity:"High", verification_status:"accepted", title:"SQLi", source:{file:"a.js",line:10,symbol:"q",kind:"http"}, sink:{file:"b.js",line:20,symbol:"query",kind:"sql"}, direct_flow:true, partitions:["p"], source_finding_ids:["p-F1"] },
    { finding_id:"OSWE-2", vuln_class:"trust-boundary", final_severity:"Low", verification_status:"accepted", title:"CWE-501", source:{file:"c.js",line:5,symbol:"p",kind:"http"}, sink:{file:"c.js",line:7,symbol:"setAttribute",kind:"session"}, direct_flow:true, partitions:["p"], source_finding_ids:["p-F2"] },
    { finding_id:"OSWE-3", vuln_class:"xss", verification_status:"rejected", title:"refuted", source:{file:"d.js",line:1,symbol:"x",kind:"http"}, sink:{file:"d.js",line:2,symbol:"w",kind:"html"}, partitions:["p"], source_finding_ids:["p-F3"] }
  ],
  chains: [
    { chain_id:"CHAIN-1", entry_point:{file:"a.js",line:1,route:"POST /x",auth:"unauthenticated"}, finding_ids:["OSWE-1"], transitions:[{from:"entry",to:"OSWE-1",how:"sqli",evidence:[{file:"b.js",line:20}]}], final_impact:"unauth-rce", severity:"Critical", verification_status:"accepted" }
  ],
  verdicts: []
};

test("SARIF envelope is 2.1.0 with oswe driver", () => {
  const s = buildSarif(report);
  assert.equal(s.version, "2.1.0");
  assert.equal(s.runs[0].tool.driver.name, "oswe");
});
test("non-rejected findings become results; rejected does not", () => {
  const s = buildSarif(report);
  const findingResults = s.runs[0].results.filter(r => r.ruleId !== "exploit-chain" && !String(r.ruleId).startsWith("sast-lead"));
  assert.equal(findingResults.length, 2); // OSWE-1, OSWE-2 (OSWE-3 rejected -> excluded)
});
test("severity maps to SARIF level (High->error, Low->note)", () => {
  const s = buildSarif(report);
  const sqli = s.runs[0].results.find(r => r.ruleId === "sqli");
  const tb = s.runs[0].results.find(r => r.ruleId === "trust-boundary");
  assert.equal(sqli.level, "error");
  assert.equal(tb.level, "note");
});
test("every finding result carries a stable oswe/v1 partialFingerprint", () => {
  const s = buildSarif(report);
  for (const r of s.runs[0].results) assert.match(r.partialFingerprints["oswe/v1"], /^[0-9a-f]{16}$/);
});
test("hygiene finding tagged lane=hygiene", () => {
  const s = buildSarif(report);
  const tb = s.runs[0].results.find(r => r.ruleId === "trust-boundary");
  assert.equal(tb.properties.lane, "hygiene");
});
test("Critical chain becomes an exploit-chain result with a non-empty codeFlow", () => {
  const s = buildSarif(report);
  const ch = s.runs[0].results.find(r => r.ruleId === "exploit-chain");
  assert.equal(ch.level, "error");
  assert.ok(ch.codeFlows[0].threadFlows[0].locations.length >= 1);
});
test("rules are declared for each emitted vuln_class", () => {
  const s = buildSarif(report);
  const ids = s.runs[0].tool.driver.rules.map(r => r.id);
  assert.ok(ids.includes("sqli") && ids.includes("trust-boundary"));
});
test("output parses back through ingest-sarif without throwing (round-trip)", () => {
  const s = buildSarif(report);
  assert.doesNotThrow(() => ingestSarif(".", JSON.stringify(s)));
});
test("deterministic: same report -> identical SARIF", () => {
  assert.equal(JSON.stringify(buildSarif(report)), JSON.stringify(buildSarif(report)));
});

const reportWithLeads = {
  ...report,
  lead_adjudications: [
    { lead_id:"L1", outcome:"refuted", reason:"input is a constant", test_id:"BenchmarkTest00001", location:{file:"a.js",line:9} },
    { lead_id:"L2", outcome:"promoted", finding_id:"OSWE-1", test_id:"BenchmarkTest00002", location:{file:"a.js",line:10} },
    { lead_id:"L3", outcome:"inconclusive", reason:"cannot resolve", location:{file:"e.js",line:3} }
  ]
};
test("refuted lead -> sast-lead-refuted note with a suppression carrying the reason", () => {
  const s = buildSarif(reportWithLeads);
  const r = s.runs[0].results.find(x => x.ruleId === "sast-lead-refuted");
  assert.equal(r.level, "note");
  assert.equal(r.suppressions[0].kind, "external");
  assert.match(r.message.text, /constant/);
});
test("promoted lead is NOT double-emitted (no sast-lead-promoted result)", () => {
  const s = buildSarif(reportWithLeads);
  assert.equal(s.runs[0].results.filter(x => String(x.ruleId).startsWith("sast-lead") && x.ruleId !== "sast-lead-refuted" && x.ruleId !== "sast-lead-inconclusive").length, 0);
  assert.ok(!s.runs[0].results.some(x => x.ruleId === "sast-lead-promoted"));
});
test("inconclusive lead -> sast-lead-inconclusive note, no suppression", () => {
  const s = buildSarif(reportWithLeads);
  const r = s.runs[0].results.find(x => x.ruleId === "sast-lead-inconclusive");
  assert.equal(r.level, "note");
  assert.ok(!r.suppressions);
});
test("lead-adjudication results carry NO partialFingerprints (reserved for finding/chain content fps)", () => {
  const s = buildSarif(reportWithLeads);
  const leadResults = s.runs[0].results.filter(r => String(r.ruleId).startsWith("sast-lead"));
  assert.ok(leadResults.length >= 1);
  for (const r of leadResults) assert.ok(!("partialFingerprints" in r), `lead result ${r.ruleId} must not have partialFingerprints`);
});
test("finding & chain results still DO carry a 16-hex partialFingerprint", () => {
  const s = buildSarif(reportWithLeads);
  const fps = s.runs[0].results.filter(r => r.ruleId === "sqli" || r.ruleId === "trust-boundary" || r.ruleId === "exploit-chain");
  for (const r of fps) assert.match(r.partialFingerprints["oswe/v1"], /^[0-9a-f]{16}$/);
});
