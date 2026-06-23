import { test } from "node:test";
import assert from "node:assert/strict";
import { fingerprintFinding, fingerprintChain } from "../finding-fingerprint.mjs";

const f = (over = {}) => ({ vuln_class: "sqli", source: { file: "a.js", line: 10 }, sink: { file: "b.js", line: 20 }, ...over });

test("same content -> same fingerprint regardless of positional finding_id", () => {
  assert.equal(fingerprintFinding({ ...f(), finding_id: "OSWE-1" }), fingerprintFinding({ ...f(), finding_id: "OSWE-9" }));
});
test("different sink line -> different fingerprint", () => {
  assert.notEqual(fingerprintFinding(f()), fingerprintFinding(f({ sink: { file: "b.js", line: 21 } })));
});
test("different vuln_class -> different fingerprint", () => {
  assert.notEqual(fingerprintFinding(f()), fingerprintFinding(f({ vuln_class: "xss" })));
});
test("fingerprint is 16 lowercase hex chars", () => {
  assert.match(fingerprintFinding(f()), /^[0-9a-f]{16}$/);
});
test("chain fingerprint is stable and order-independent over members", () => {
  const findings = [f({ finding_id: "OSWE-1" }), f({ finding_id: "OSWE-2", sink: { file: "c.js", line: 5 } })];
  const c  = { entry_point: { file: "a.js", line: 1 }, final_impact: "unauth-rce", finding_ids: ["OSWE-1", "OSWE-2"] };
  const c2 = { entry_point: { file: "a.js", line: 1 }, final_impact: "unauth-rce", finding_ids: ["OSWE-2", "OSWE-1"] };
  assert.equal(fingerprintChain(c, findings), fingerprintChain(c2, findings));
});
test("chain fingerprint is 16 lowercase hex chars", () => {
  const findings = [f({ finding_id: "OSWE-1" })];
  const c = { entry_point: { file: "a.js", line: 1 }, final_impact: "unauth-rce", finding_ids: ["OSWE-1"] };
  assert.match(fingerprintChain(c, findings), /^[0-9a-f]{16}$/);
});
