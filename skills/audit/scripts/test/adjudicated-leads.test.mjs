import { test } from "node:test";
import assert from "node:assert/strict";
import { validate } from "../validate-output.mjs";

const finding = {
  finding_id: "auth-F001", partition_id: "auth", title: "t", vuln_class: "sqli",
  source: { file: "a", line: 1, symbol: "s", kind: "http-param" },
  sink: { file: "b", line: 2, symbol: "q", kind: "query" },
  auth: "unauthenticated", provisional_severity: "High", confidence: "likely",
  verification_status: "not-requested"
};
const resp = (over = {}) => ({
  partition_id: "auth", status: "ok", findings: [], coverage: { analyzed: ["auth"], skipped: [] }, ...over
});

test("adjudicated_leads with a promoted entry validates", () => {
  const r = resp({
    findings: [{ ...finding, origin: "sast-lead", source_lead_ids: ["L001"] }],
    adjudicated_leads: [{ lead_id: "L001", outcome: "promoted", finding_id: "auth-F001" }]
  });
  assert.equal(validate("analyzer-response", r).valid, true, JSON.stringify(validate("analyzer-response", r).errors));
});

test("a refuted lead requires a reason", () => {
  const bad = resp({ adjudicated_leads: [{ lead_id: "L001", outcome: "refuted" }] });
  assert.equal(validate("analyzer-response", bad).valid, false);
  const good = resp({ adjudicated_leads: [{ lead_id: "L001", outcome: "refuted", reason: "input is constant" }] });
  assert.equal(validate("analyzer-response", good).valid, true);
});

test("a promoted lead requires finding_id", () => {
  const bad = resp({ adjudicated_leads: [{ lead_id: "L001", outcome: "promoted" }] });
  assert.equal(validate("analyzer-response", bad).valid, false);
});

test("a raw analyzer finding with origin:both is rejected", () => {
  const r = resp({ findings: [{ ...finding, origin: "both" }] });
  assert.equal(validate("analyzer-response", r).valid, false);
});

test("a raw analyzer finding with origin:sast-lead is accepted", () => {
  const r = resp({ findings: [{ ...finding, origin: "sast-lead" }] });
  assert.equal(validate("analyzer-response", r).valid, true, JSON.stringify(validate("analyzer-response", r).errors));
});

test("absent adjudicated_leads is still valid (backward compat)", () => {
  assert.equal(validate("analyzer-response", resp()).valid, true);
});
