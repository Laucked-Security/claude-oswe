import { test } from "node:test";
import assert from "node:assert/strict";
import { validate } from "../validate-output.mjs";

const loc = (file, line, symbol, kind) => ({ file, line, symbol, kind });

const baseFinding = (overrides = {}) => ({
  finding_id: "auth-F001",
  partition_id: "auth",
  title: "Loose comparison auth bypass",
  vuln_class: "type-juggling",
  source: loc("login.php", 12, "$_POST['password']", "http-param"),
  sink: loc("login.php", 15, "==", "comparison"),
  auth: "unauthenticated",
  provisional_severity: "Haute",
  confidence: "preuve statique forte",
  verification_status: "not-requested",
  ...overrides
});

const analyzerResponse = (findings) => ({
  partition_id: "auth",
  status: "ok",
  findings,
  coverage: { analyzed: ["login.php"], skipped: [] }
});

test("valid analyzer-response passes", () => {
  const r = validate("analyzer-response", analyzerResponse([baseFinding()]));
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("analyzer finding with non-'not-requested' status fails (const invariant)", () => {
  const r = validate("analyzer-response", analyzerResponse([baseFinding({ verification_status: "accepted" })]));
  assert.equal(r.valid, false);
});

test("finding with provisional_severity Critique fails (enum excludes Critique)", () => {
  const r = validate("finding", baseFinding({ provisional_severity: "Critique" }));
  assert.equal(r.valid, false);
});

test("finding_id accepts canonical OSWE-<n> after aggregation", () => {
  const r = validate("finding", baseFinding({ finding_id: "OSWE-7", verification_status: "accepted", partitions: ["auth", "upload"] }));
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("finding without optional partitions passes", () => {
  const f = baseFinding();
  assert.equal(Object.prototype.hasOwnProperty.call(f, "partitions"), false);
  assert.equal(validate("finding", f).valid, true);
});

test("finding with bad finding_id pattern fails", () => {
  const r = validate("finding", baseFinding({ finding_id: "nope" }));
  assert.equal(r.valid, false);
});

const validCriticalChain = {
  chain_id: "CHAIN-1",
  entry_point: { file: "login.php", line: 1, route: "POST /login", auth: "unauthenticated" },
  finding_ids: ["OSWE-1", "OSWE-2"],
  transitions: [
    { from: "entry", to: "OSWE-1", how: "loose compare bypass", evidence: [{ file: "login.php", line: 15 }] },
    { from: "OSWE-1", to: "OSWE-2", how: "upload web shell", evidence: [{ file: "upload.php", line: 8 }] }
  ],
  final_impact: "unauth-rce",
  severity: "Critique",
  confidence: "preuve statique forte",
  verification_status: "accepted"
};

test("Critique chain with accepted + preuve statique forte + unauth-rce passes", () => {
  const r = validate("chain", validCriticalChain);
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("Critique chain not yet accepted fails (if/then invariant)", () => {
  const r = validate("chain", { ...validCriticalChain, verification_status: "not-requested" });
  assert.equal(r.valid, false);
});

test("Critique chain with non-unauth-rce impact fails", () => {
  const r = validate("chain", { ...validCriticalChain, final_impact: "auth-rce" });
  assert.equal(r.valid, false);
});

test("Critique chain with authenticated entry point fails (gating invariant)", () => {
  const r = validate("chain", { ...validCriticalChain, entry_point: { ...validCriticalChain.entry_point, auth: "authenticated" } });
  assert.equal(r.valid, false);
});

test("non-Critique chain is unconstrained on those fields", () => {
  const r = validate("chain", { ...validCriticalChain, severity: "Haute", verification_status: "not-requested", final_impact: "auth-rce", confidence: "probable" });
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("verifier-response with multiple verdicts passes", () => {
  const r = validate("verifier-response", {
    status: "ok",
    verdicts: [
      { target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "src->sink confirmed login.php:15" },
      { target_type: "finding", target_id: "OSWE-2", verdict: "downgraded", new_severity: "Moyenne", new_confidence: "probable", justification: "sanitizer partially blocks, upload.php:40" }
    ]
  });
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("chain verdict without transition_verdicts fails", () => {
  const r = validate("verdict", { target_type: "chain", target_id: "CHAIN-1", verdict: "accepted", justification: "all transitions hold" });
  assert.equal(r.valid, false);
});

test("downgraded verdict without new_severity/new_confidence fails", () => {
  const r = validate("verdict", { target_type: "finding", target_id: "OSWE-1", verdict: "downgraded", justification: "weaker than claimed" });
  assert.equal(r.valid, false);
});

test("finding rejects Critique final_severity (Critique is reserved for chains)", () => {
  const r = validate("finding", baseFinding({ finding_id: "OSWE-3", verification_status: "accepted", final_severity: "Critique", final_confidence: "preuve statique forte" }));
  assert.equal(r.valid, false);
});

test("finding accepts Haute final_severity with source_finding_ids", () => {
  const r = validate("finding", baseFinding({ finding_id: "OSWE-3", verification_status: "accepted", final_severity: "Haute", final_confidence: "preuve statique forte", source_finding_ids: ["auth-F001", "upload-F002"] }));
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("finding with invalid final_severity fails", () => {
  const r = validate("finding", baseFinding({ final_severity: "Catastrophic" }));
  assert.equal(r.valid, false);
});

// --- final-finding lifecycle (post-orchestration, phase 6b) ---
// A final finding always carries a canonical id + aggregated provenance.
const finalBase = (overrides = {}) => baseFinding({ finding_id: "OSWE-3", partitions: ["auth"], source_finding_ids: ["auth-F001"], ...overrides });

test("final-finding: accepted requires final fields", () => {
  const ok = validate("final-finding", finalBase({ verification_status: "accepted", final_severity: "Haute", final_confidence: "preuve statique forte" }));
  assert.equal(ok.valid, true, JSON.stringify(ok.errors));
  const missing = validate("final-finding", finalBase({ verification_status: "accepted" }));
  assert.equal(missing.valid, false);
});

test("final-finding: rejected forbids final fields", () => {
  const okRejected = validate("final-finding", finalBase({ verification_status: "rejected" }));
  assert.equal(okRejected.valid, true, JSON.stringify(okRejected.errors));
  const badRejected = validate("final-finding", finalBase({ verification_status: "rejected", final_severity: "Haute", final_confidence: "probable" }));
  assert.equal(badRejected.valid, false);
});

test("final-finding: not-requested still requires final fields", () => {
  const r = validate("final-finding", finalBase({ verification_status: "not-requested" }));
  assert.equal(r.valid, false);
});

test("final-finding: missing provenance fails", () => {
  const noProv = validate("final-finding", baseFinding({ finding_id: "OSWE-3", verification_status: "accepted", final_severity: "Haute", final_confidence: "preuve statique forte" }));
  assert.equal(noProv.valid, false); // no partitions / source_finding_ids
});

test("final-finding: non-canonical id fails", () => {
  const r = validate("final-finding", finalBase({ finding_id: "auth-F001", verification_status: "accepted", final_severity: "Haute", final_confidence: "preuve statique forte" }));
  assert.equal(r.valid, false);
});

test("final-finding: empty provenance arrays fail", () => {
  const r = validate("final-finding", finalBase({ partitions: [], source_finding_ids: [], verification_status: "accepted", final_severity: "Haute", final_confidence: "preuve statique forte" }));
  assert.equal(r.valid, false);
});
