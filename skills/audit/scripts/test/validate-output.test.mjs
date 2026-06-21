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
  provisional_severity: "High",
  confidence: "strong static proof",
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

test("finding with provisional_severity Critical fails (enum excludes Critical)", () => {
  const r = validate("finding", baseFinding({ provisional_severity: "Critical" }));
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
  severity: "Critical",
  confidence: "strong static proof",
  verification_status: "accepted"
};

test("Critical chain with accepted + strong static proof + unauth-rce passes", () => {
  const r = validate("chain", validCriticalChain);
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("Critical chain not yet accepted fails (if/then invariant)", () => {
  const r = validate("chain", { ...validCriticalChain, verification_status: "not-requested" });
  assert.equal(r.valid, false);
});

test("Critical chain with non-unauth-rce impact fails", () => {
  const r = validate("chain", { ...validCriticalChain, final_impact: "auth-rce" });
  assert.equal(r.valid, false);
});

test("Critical chain with authenticated entry point fails (gating invariant)", () => {
  const r = validate("chain", { ...validCriticalChain, entry_point: { ...validCriticalChain.entry_point, auth: "authenticated" } });
  assert.equal(r.valid, false);
});

test("non-Critical chain is unconstrained on those fields", () => {
  const r = validate("chain", { ...validCriticalChain, severity: "High", verification_status: "not-requested", final_impact: "auth-rce", confidence: "likely" });
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("verifier-response with multiple verdicts passes", () => {
  const r = validate("verifier-response", {
    status: "ok",
    verdicts: [
      { target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "src->sink confirmed login.php:15", counterexamples: [{ hypothesis: "auth blocks", checked: true, refuted: true }] },
      { target_type: "finding", target_id: "OSWE-2", verdict: "downgraded", new_severity: "Medium", new_confidence: "likely", justification: "sanitizer partially blocks, upload.php:40", counterexamples: [{ hypothesis: "sanitizer blocks", checked: true, refuted: false }] }
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

test("finding rejects Critical final_severity (Critical is reserved for chains)", () => {
  const r = validate("finding", baseFinding({ finding_id: "OSWE-3", verification_status: "accepted", final_severity: "Critical", final_confidence: "strong static proof" }));
  assert.equal(r.valid, false);
});

test("finding accepts High final_severity with source_finding_ids", () => {
  const r = validate("finding", baseFinding({ finding_id: "OSWE-3", verification_status: "accepted", final_severity: "High", final_confidence: "strong static proof", source_finding_ids: ["auth-F001", "upload-F002"] }));
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
  const ok = validate("final-finding", finalBase({ verification_status: "accepted", final_severity: "High", final_confidence: "strong static proof", direct_flow: true }));
  assert.equal(ok.valid, true, JSON.stringify(ok.errors));
  const missing = validate("final-finding", finalBase({ verification_status: "accepted" }));
  assert.equal(missing.valid, false);
});

test("final-finding: rejected forbids final fields", () => {
  const okRejected = validate("final-finding", finalBase({ verification_status: "rejected" }));
  assert.equal(okRejected.valid, true, JSON.stringify(okRejected.errors));
  const badRejected = validate("final-finding", finalBase({ verification_status: "rejected", final_severity: "High", final_confidence: "likely" }));
  assert.equal(badRejected.valid, false);
});

test("final-finding: not-requested still requires final fields", () => {
  const r = validate("final-finding", finalBase({ verification_status: "not-requested" }));
  assert.equal(r.valid, false);
});

test("final-finding: missing provenance fails", () => {
  const noProv = validate("final-finding", baseFinding({ finding_id: "OSWE-3", verification_status: "accepted", final_severity: "High", final_confidence: "strong static proof" }));
  assert.equal(noProv.valid, false); // no partitions / source_finding_ids
});

test("final-finding: non-canonical id fails", () => {
  const r = validate("final-finding", finalBase({ finding_id: "auth-F001", verification_status: "accepted", final_severity: "High", final_confidence: "strong static proof" }));
  assert.equal(r.valid, false);
});

test("final-finding: empty provenance arrays fail", () => {
  const r = validate("final-finding", finalBase({ partitions: [], source_finding_ids: [], verification_status: "accepted", final_severity: "High", final_confidence: "strong static proof" }));
  assert.equal(r.valid, false);
});

// --- SP6 Task 8: structured counterexamples on a verdict ---
const ceVerdict = (counterexamples) => ({ target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x", counterexamples });

test("verdict: a well-formed counterexamples[] validates", () => {
  const r = validate("verdict", ceVerdict([{ hypothesis: "auth blocks the path", checked: true, refuted: true, evidence: [{ file: "a", line: 1 }] }]));
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("verdict: a counterexample missing hypothesis fails", () => {
  const r = validate("verdict", ceVerdict([{ checked: true, refuted: true }]));
  assert.equal(r.valid, false);
});

test("verdict: a counterexample with non-boolean checked fails", () => {
  const r = validate("verdict", ceVerdict([{ hypothesis: "h", checked: "yes", refuted: true }]));
  assert.equal(r.valid, false);
});

test("verdict: accepted finding REQUIRES non-empty counterexamples (#R5.1)", () => {
  assert.equal(validate("verdict", { target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x" }).valid, false);
  assert.equal(validate("verdict", { target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x", counterexamples: [] }).valid, false);
});

test("verdict: downgraded finding REQUIRES non-empty counterexamples (#R5.1)", () => {
  assert.equal(validate("verdict", { target_type: "finding", target_id: "OSWE-1", verdict: "downgraded", new_severity: "Medium", new_confidence: "likely", justification: "x" }).valid, false);
});

test("verdict: rejected finding does not require counterexamples", () => {
  const r = validate("verdict", { target_type: "finding", target_id: "OSWE-1", verdict: "rejected", justification: "x" });
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("verdict: a chain verdict does not require counterexamples", () => {
  const r = validate("verdict", { target_type: "chain", target_id: "CHAIN-1", verdict: "accepted", justification: "x", transition_verdicts: [{ from: "entry", to: "OSWE-1", verdict: "accepted", justification: "x" }] });
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

// --- SP6 Task 11: accepted High findings require a complete proof chain ---
test("final-finding: accepted High without transformations or direct_flow fails", () => {
  const r = validate("final-finding", finalBase({ verification_status: "accepted", final_severity: "High", final_confidence: "strong static proof" }));
  assert.equal(r.valid, false);
});

test("final-finding: accepted High with direct_flow:true passes", () => {
  const r = validate("final-finding", finalBase({ verification_status: "accepted", final_severity: "High", final_confidence: "strong static proof", direct_flow: true }));
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("final-finding: accepted High with a non-empty transformations passes", () => {
  const r = validate("final-finding", finalBase({ verification_status: "accepted", final_severity: "High", final_confidence: "strong static proof", transformations: [{ file: "a", line: 1, desc: "decode then exec" }] }));
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("final-finding: accepted Medium is exempt from proof-completeness", () => {
  const r = validate("final-finding", finalBase({ verification_status: "accepted", final_severity: "Medium", final_confidence: "likely" }));
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("validate-output accepts a well-formed checkpoint-manifest", () => {
  const ok = validate("checkpoint-manifest", {
    schema_version: 1,
    run_id: "0123456789abcdef",
    started_at: "2026-06-20T12:00:00Z",
    completed: false,
    scope_realpath: null,
    sarif_realpath: null,
    concurrency: 4,
    invocation_digest: "f".repeat(64)
  });
  assert.equal(ok.valid, true);
});

test("validate-output rejects a checkpoint-manifest with additionalProperties", () => {
  const bad = validate("checkpoint-manifest", {
    schema_version: 1,
    run_id: "0123456789abcdef",
    started_at: "2026-06-20T12:00:00Z",
    completed: false,
    scope_realpath: null,
    sarif_realpath: null,
    concurrency: 4,
    invocation_digest: "f".repeat(64),
    surprise: "extra"
  });
  assert.equal(bad.valid, false);
});

test("validate-output rejects a checkpoint-manifest with bad concurrency range", () => {
  const bad = validate("checkpoint-manifest", {
    schema_version: 1,
    run_id: "0123456789abcdef",
    started_at: "2026-06-20T12:00:00Z",
    completed: false,
    scope_realpath: null,
    sarif_realpath: null,
    concurrency: 99,
    invocation_digest: "f".repeat(64)
  });
  assert.equal(bad.valid, false);
});
