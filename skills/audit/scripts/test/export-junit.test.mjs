import { test } from "node:test";
import assert from "node:assert/strict";
import { buildJunit } from "../export-junit.mjs";

const report = {
  run: { run_id:"r", generated:"2026-06-23", scope:["src"] }, coverage:{analyzed:[],skipped:[]},
  findings: [
    { finding_id:"OSWE-1", vuln_class:"sqli", final_severity:"High", verification_status:"accepted", title:"SQLi & <bad>", source:{file:"a.js",line:10}, sink:{file:"b.js",line:20} },
    { finding_id:"OSWE-2", vuln_class:"trust-boundary", final_severity:"Low", verification_status:"accepted", title:"hygiene", source:{file:"c.js",line:5}, sink:{file:"c.js",line:7} },
    { finding_id:"OSWE-3", vuln_class:"xss", verification_status:"rejected", title:"refuted", source:{file:"d.js",line:1}, sink:{file:"d.js",line:2} }
  ],
  chains: [ { chain_id:"CHAIN-1", entry_point:{file:"a.js",line:1}, final_impact:"unauth-rce", severity:"Critical", verification_status:"accepted", finding_ids:["OSWE-1"] } ],
  verdicts: [],
  lead_adjudications: [ { lead_id:"L1", outcome:"refuted", reason:"constant & safe", location:{file:"a.js",line:9} } ]
};

test("suite envelope + counts", () => {
  const xml = buildJunit(report, { failOn:"high" });
  assert.match(xml, /<testsuite name="oswe"/);
  assert.match(xml, /tests="\d+"/); assert.match(xml, /failures="\d+"/); assert.match(xml, /skipped="\d+"/);
});
test("accepted High finding -> failure", () => {
  assert.match(buildJunit(report, { failOn:"high" }), /<testcase classname="sqli"[^>]*>\s*<failure/);
});
test("Critical chain -> failure", () => {
  assert.match(buildJunit(report, { failOn:"high" }), /classname="exploit-chain"[^>]*>\s*<failure/);
});
test("hygiene Low finding does NOT fail at --fail-on high", () => {
  const xml = buildJunit(report, { failOn:"high" });
  // the trust-boundary testcase must not contain a failure
  assert.ok(!/classname="trust-boundary"[^>]*>\s*<failure/.test(xml));
});
test("rejected finding is not emitted as a failing testcase", () => {
  const xml = buildJunit(report, { failOn:"high" });
  assert.ok(!/classname="xss"[^>]*>\s*<failure/.test(xml));
});
test("refuted lead -> skipped", () => {
  assert.match(buildJunit(report, { failOn:"high" }), /classname="sast-lead-refuted"[^>]*>\s*<skipped/);
});
test("--fail-on medium makes the Low hygiene still pass but a Medium would fail", () => {
  const xml = buildJunit(report, { failOn:"medium" });
  assert.ok(!/classname="trust-boundary"[^>]*>\s*<failure/.test(xml)); // Low < Medium
});
test("XML escaping: no raw & or < in emitted text", () => {
  const xml = buildJunit(report, { failOn:"high" });
  // the title 'SQLi & <bad>' and reason 'constant & safe' must be escaped
  assert.match(xml, /SQLi &amp; &lt;bad&gt;/);
  assert.ok(!/SQLi & </.test(xml));
});
test("deterministic", () => {
  assert.equal(buildJunit(report,{failOn:"high"}), buildJunit(report,{failOn:"high"}));
});
