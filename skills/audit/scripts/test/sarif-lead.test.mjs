import { test } from "node:test";
import assert from "node:assert/strict";
import { sarifLead } from "../validators.mjs";

const ok = {
  lead_id: "L001", tool: "semgrep", rule_id: "java.lang.security.audit.command-injection",
  vuln_class_hint: "command-injection", location: { file: "src/Foo.java", line: 42 },
  message: "Detected command injection"
};

test("a well-formed sarif-lead validates", () => {
  assert.equal(Boolean(sarifLead(ok)), true, JSON.stringify(sarifLead.errors));
});

test("optional codeflow validates", () => {
  assert.equal(Boolean(sarifLead({ ...ok, codeflow: [{ file: "src/A.java", line: 1 }, { file: "src/B.java", line: 9 }] })), true);
});

test("lead_id must match ^L[0-9]{3,}$", () => {
  assert.equal(Boolean(sarifLead({ ...ok, lead_id: "X1" })), false);
});

test("line < 1 is rejected", () => {
  assert.equal(Boolean(sarifLead({ ...ok, location: { file: "a", line: 0 } })), false);
});

test("unknown property is rejected (additionalProperties:false)", () => {
  assert.equal(Boolean(sarifLead({ ...ok, level: "error" })), false);
});

test("over-long rule_id is rejected (maxLength 256)", () => {
  assert.equal(Boolean(sarifLead({ ...ok, rule_id: "x".repeat(257) })), false);
});
