import { test } from "node:test";
import assert from "node:assert/strict";
import { validate } from "../validate-output.mjs";

const base = {
  finding_id: "OSWE-1", partition_id: "auth", title: "t", vuln_class: "sqli",
  source: { file: "a", line: 1, symbol: "s", kind: "http-param" },
  sink: { file: "b", line: 2, symbol: "q", kind: "query" },
  auth: "unauthenticated", provisional_severity: "High", confidence: "likely",
  verification_status: "not-requested", partitions: ["auth"], source_finding_ids: ["auth-F001"]
};

test("origin and source_lead_ids are accepted on a finding", () => {
  const f = { ...base, origin: "both", source_lead_ids: ["L001", "L002"] };
  assert.equal(validate("finding", f).valid, true, JSON.stringify(validate("finding", f).errors));
});

test("a finding with NO origin is still valid (backward compat)", () => {
  assert.equal(validate("finding", base).valid, true);
});

test("origin outside the enum is rejected", () => {
  assert.equal(validate("finding", { ...base, origin: "guessed" }).valid, false);
});

test("source_lead_ids must match ^L[0-9]{3,}$", () => {
  assert.equal(validate("finding", { ...base, source_lead_ids: ["nope"] }).valid, false);
});

test("final-finding inherits origin via its $ref to finding (no separate edit needed)", () => {
  const ff = { ...base, verification_status: "accepted", final_severity: "High", final_confidence: "likely", direct_flow: true, origin: "sast-lead", source_lead_ids: ["L001"] };
  assert.equal(validate("final-finding", ff).valid, true, JSON.stringify(validate("final-finding", ff).errors));
});
