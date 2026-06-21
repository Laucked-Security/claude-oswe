import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { applyVerdicts, validateBoundBatch } from "../apply-verdicts.mjs";
import { validate } from "../validate-output.mjs";

const CLI = fileURLToPath(new URL("../apply-verdicts.mjs", import.meta.url));
const loc = (file, line, symbol, kind) => ({ file, line, symbol, kind });
const ids = (...x) => new Set(x);

// Findings/chains reaching applyVerdicts are POST-aggregation → canonical OSWE-* ids WITH provenance.
const finding = (id, sev = "High") => ({
  finding_id: id,
  partition_id: "auth",
  title: id,
  vuln_class: "auth-bypass",
  source: loc("a.php", 1, "$_POST", "http-param"),
  sink: loc("a.php", 2, "==", "comparison"),
  auth: "unauthenticated",
  provisional_severity: sev,
  confidence: "strong static proof",
  verification_status: "not-requested",
  direct_flow: true, // SP6: accepted High final-findings need a complete proof; this is a raw source->sink
  partitions: ["auth"],
  source_finding_ids: ["src-" + id]
});

// A successful run must yield findings/chains that satisfy the FINAL schemas.
function assertResultSchemaValid(r) {
  for (const f of r.findings) {
    const v = validate("final-finding", f);
    assert.equal(v.valid, true, "final-finding invalid: " + JSON.stringify(v.errors) + " for " + JSON.stringify(f));
  }
  for (const c of r.chains) {
    const v = validate("chain", c);
    assert.equal(v.valid, true, "chain invalid: " + JSON.stringify(v.errors) + " for " + JSON.stringify(c));
  }
}

const chain = (overrides = {}) => ({
  chain_id: "CHAIN-1",
  entry_point: { file: "a.php", line: 1, route: "POST /login", auth: "unauthenticated" },
  finding_ids: ["OSWE-1", "OSWE-2"],
  transitions: [
    { from: "entry", to: "OSWE-1", how: "bypass", evidence: [{ file: "a.php", line: 2 }] },
    { from: "OSWE-1", to: "OSWE-2", how: "upload", evidence: [{ file: "u.php", line: 4 }] }
  ],
  final_impact: "unauth-rce",
  severity: "High",
  confidence: "likely",
  verification_status: "not-requested",
  ...overrides
});

const bothFindings = () => [finding("OSWE-1"), finding("OSWE-2")];

// Build COMPOSITION-COMPLIANT batches from a flat verdict list: findings go in one batch
// (≤5), each chain in its own batch (1..5 findings XOR exactly 1 chain per batch).
let _bid = 0;
const nb = () => "B" + ++_bid;
function vresp(verdicts, opts = {}) {
  const status = (typeof opts === "string" ? opts : opts.status) || "ok";
  const fv = verdicts.filter((v) => v.target_type === "finding");
  const cv = verdicts.filter((v) => v.target_type === "chain");
  const out = [];
  if (fv.length) out.push({ batch_id: nb(), expected_targets: fv.map((v) => ({ target_type: "finding", target_id: v.target_id })), response: { status, verdicts: fv } });
  for (const c of cv) out.push({ batch_id: nb(), expected_targets: [{ target_type: "chain", target_id: c.target_id }], response: { status, verdicts: [c] } });
  return out;
}

const acceptBoth = [
  { target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "a.php:2" },
  { target_type: "finding", target_id: "OSWE-2", verdict: "accepted", justification: "u.php:4" }
];
const acceptChain = {
  target_type: "chain", target_id: "CHAIN-1", verdict: "accepted",
  transition_verdicts: [
    { from: "entry", to: "OSWE-1", verdict: "accepted", justification: "a.php:2" },
    { from: "OSWE-1", to: "OSWE-2", verdict: "accepted", justification: "u.php:4" }
  ],
  justification: "all hold"
};

test("fully accepted unauth-rce chain is promoted to Critical", () => {
  const r = applyVerdicts({ findings: bothFindings(), chains: [chain()], batches: vresp([...acceptBoth, acceptChain]) });
  assert.equal(r.ok, true);
  assert.equal(r.chains[0].severity, "Critical");
  assert.equal(r.chains[0].verification_status, "accepted");
  assert.equal(r.chains[0].confidence, "strong static proof");
  assertResultSchemaValid(r); // results must satisfy the final schemas
});

test("accepted chain with a downgraded member is NOT Critical", () => {
  const verdicts = [
    { target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x" },
    { target_type: "finding", target_id: "OSWE-2", verdict: "downgraded", new_severity: "Medium", new_confidence: "likely", justification: "x" },
    acceptChain
  ];
  const r = applyVerdicts({ findings: bothFindings(), chains: [chain()], batches: vresp(verdicts) });
  assert.notEqual(r.chains[0].severity, "Critical");
  assert.equal(r.chains[0].verification_status, "accepted");
});

test("chain whose member is rejected is itself rejected", () => {
  const verdicts = [
    { target_type: "finding", target_id: "OSWE-1", verdict: "rejected", justification: "x" },
    { target_type: "finding", target_id: "OSWE-2", verdict: "accepted", justification: "x" },
    acceptChain
  ];
  const r = applyVerdicts({ findings: bothFindings(), chains: [chain()], batches: vresp(verdicts) });
  assert.equal(r.chains[0].verification_status, "rejected");
  assert.notEqual(r.chains[0].severity, "Critical");
  const rejected = r.findings.find((f) => f.finding_id === "OSWE-1");
  assert.equal("final_severity" in rejected, false);
  const d = r.decisions.find((d) => d.target_type === "chain" && d.target_id === "CHAIN-1");
  assert.match(d.reason, /member finding\(s\) rejected/); // implicit-rejection reason preserved
  assertResultSchemaValid(r); // a rejected finding (no final fields) must still pass final-finding
});

test("a chain with an UNVERIFIED member (gap) stays not-requested, not rejected", () => {
  // OSWE-2 IS dispatched (required) but its batch errors → not-requested. The member was NOT refuted,
  // only unverified → the chain must be not-requested + a coverage gap (never a false rejection).
  const batches = [
    { batch_id: "Bf1", expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }], response: { status: "ok", verdicts: [acceptBoth[0]] } },
    { batch_id: "Bf2", expected_targets: [{ target_type: "finding", target_id: "OSWE-2" }], response: { status: "error", verdicts: [] } },
    { batch_id: "Bc", expected_targets: [{ target_type: "chain", target_id: "CHAIN-1" }], response: { status: "ok", verdicts: [acceptChain] } }
  ];
  const r = applyVerdicts({ findings: bothFindings(), chains: [chain()], batches });
  assert.equal(r.ok, true);
  assert.equal(r.chains[0].verification_status, "not-requested"); // NOT rejected
  assert.ok(r.gaps.some((g) => g.target_type === "chain" && g.target_id === "CHAIN-1"));
  const d = r.decisions.find((d) => d.target_type === "chain" && d.target_id === "CHAIN-1");
  assert.match(d.reason, /unverified/);
});

test("a required target not dispatched to any batch is an orchestrator-input error", () => {
  // OSWE-2 is a chain member (required) but only OSWE-1 + the chain are dispatched.
  const batches = [
    { batch_id: "Bf1", expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }], response: { status: "ok", verdicts: [acceptBoth[0]] } },
    { batch_id: "Bc", expected_targets: [{ target_type: "chain", target_id: "CHAIN-1" }], response: { status: "ok", verdicts: [acceptChain] } }
  ];
  const r = applyVerdicts({ findings: bothFindings(), chains: [chain()], batches });
  assert.equal(r.ok, false);
  assert.match(r.error, /required target finding:OSWE-2 was not dispatched/);
  assert.equal(r.error_kind, "orchestrator-input");
});

test("explicit chain verdict=rejected is honoured despite accepted transitions", () => {
  const rejectChain = { ...acceptChain, verdict: "rejected" };
  const r = applyVerdicts({ findings: bothFindings(), chains: [chain()], batches: vresp([...acceptBoth, rejectChain]) });
  assert.equal(r.chains[0].verification_status, "rejected");
  assert.notEqual(r.chains[0].severity, "Critical");
});

test("explicit chain verdict=downgraded applies new severity/confidence", () => {
  const dnChain = { ...acceptChain, verdict: "downgraded", new_severity: "High", new_confidence: "likely" };
  const r = applyVerdicts({ findings: bothFindings(), chains: [chain()], batches: vresp([...acceptBoth, dnChain]) });
  assert.equal(r.chains[0].verification_status, "downgraded");
  assert.equal(r.chains[0].severity, "High");
  assert.equal(r.chains[0].confidence, "likely");
});

// An accepted/downgraded chain verdict whose transition_verdicts don't exactly match the chain's
// transitions is a verifier PROTOCOL violation (it reported the wrong transition set) → retryable.
const mismatchErr = (transition_verdicts) => {
  const r = applyVerdicts({ findings: bothFindings(), chains: [chain()], batches: vresp([...acceptBoth, { ...acceptChain, transition_verdicts }]) });
  assert.equal(r.ok, false);
  assert.equal(r.error_kind, "verifier-output");
  assert.match(r.error, /transition_verdicts do not match/);
  assert.ok(r.error_batch_id);
};

test("empty transition_verdicts is a verifier-output error", () => mismatchErr([]));
test("missing transition is a verifier-output error", () => mismatchErr([acceptChain.transition_verdicts[0]]));
test("extra transition is a verifier-output error", () => mismatchErr([...acceptChain.transition_verdicts, { from: "OSWE-2", to: "ghost", verdict: "accepted", justification: "x" }]));
test("duplicated transition is a verifier-output error", () => mismatchErr([acceptChain.transition_verdicts[0], acceptChain.transition_verdicts[0]]));

test("a rejected transition with an 'accepted' chain verdict is a verifier-output contradiction", () => {
  const tv = [acceptChain.transition_verdicts[0], { ...acceptChain.transition_verdicts[1], verdict: "rejected" }];
  const r = applyVerdicts({ findings: bothFindings(), chains: [chain()], batches: vresp([...acceptBoth, { ...acceptChain, transition_verdicts: tv }]) });
  assert.equal(r.ok, false);
  assert.equal(r.error_kind, "verifier-output");
  assert.match(r.error, /rejected transition but its verdict is/);
});

test("authenticated entry is not promoted to Critical", () => {
  const c = chain({ entry_point: { file: "a.php", line: 1, route: "POST /x", auth: "authenticated" } });
  const r = applyVerdicts({ findings: bothFindings(), chains: [c], batches: vresp([...acceptBoth, acceptChain]) });
  assert.notEqual(r.chains[0].severity, "Critical");
  assert.equal(r.chains[0].verification_status, "accepted"); // accepted but capped below Critical
});

test("status=error batch yields gaps (ok:true, no verdicts applied)", () => {
  const batches = [{ batch_id: "B1", expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }], response: { status: "error", verdicts: [] } }];
  const r = applyVerdicts({ findings: [finding("OSWE-1")], chains: [], batches });
  assert.equal(r.ok, true);
  assert.equal(r.findings[0].verification_status, "not-requested");
  assert.ok(r.gaps.some((g) => g.target_id === "OSWE-1"));
});

test("status=error batch carrying verdicts is a verifier-output error (with batch id)", () => {
  const batches = [{ batch_id: "B1", expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }], response: { status: "error", verdicts: [{ target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x" }] } }];
  const r = applyVerdicts({ findings: [finding("OSWE-1")], chains: [], batches });
  assert.equal(r.ok, false);
  assert.equal(r.error_kind, "verifier-output");
  assert.equal(r.error_batch_id, "B1");
});

test("status=ok batch missing an expected target is a verifier-output error", () => {
  const batches = [{ batch_id: "B7", expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }, { target_type: "finding", target_id: "OSWE-2" }], response: { status: "ok", verdicts: [{ target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x" }] } }];
  const r = applyVerdicts({ findings: bothFindings(), chains: [], batches });
  assert.equal(r.ok, false);
  assert.match(r.error, /must cover all expected/);
  assert.equal(r.error_batch_id, "B7");
});

test("a verdict for an UNEXPECTED target is a verifier-output error (cross-batch leakage)", () => {
  const batches = [{ batch_id: "B3", expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }], response: { status: "ok", verdicts: [{ target_type: "finding", target_id: "OSWE-2", verdict: "accepted", justification: "x" }] } }];
  const r = applyVerdicts({ findings: bothFindings(), chains: [], batches });
  assert.equal(r.ok, false);
  assert.match(r.error, /unexpected target/);
  assert.equal(r.error_kind, "verifier-output");
  assert.equal(r.error_batch_id, "B3");
});

test("a batch expecting an unknown target is an orchestrator-input error", () => {
  const batches = [{ batch_id: "B4", expected_targets: [{ target_type: "finding", target_id: "OSWE-9" }], response: { status: "error", verdicts: [] } }];
  const r = applyVerdicts({ findings: [finding("OSWE-1")], chains: [], batches });
  assert.equal(r.ok, false);
  assert.match(r.error, /expects unknown/);
  assert.equal(r.error_kind, "orchestrator-input");
});

test("overlapping expected_targets across batches is an orchestrator-input error", () => {
  const mk = (bid) => ({ batch_id: bid, expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }], response: { status: "ok", verdicts: [{ target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x" }] } });
  const r = applyVerdicts({ findings: [finding("OSWE-1")], chains: [], batches: [mk("B1"), mk("B2")] });
  assert.equal(r.ok, false);
  assert.match(r.error, /multiple batches/);
  assert.equal(r.error_kind, "orchestrator-input");
});

test("duplicate verdict target within a batch is a verifier-output error", () => {
  const dup = [
    { target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x" },
    { target_type: "finding", target_id: "OSWE-1", verdict: "rejected", justification: "x" }
  ];
  // expected lists OSWE-1 once; the verifier returns two verdicts for it (a verifier bug).
  const batches = [{ batch_id: "B9", expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }], response: { status: "ok", verdicts: dup } }];
  const r = applyVerdicts({ findings: [finding("OSWE-1")], chains: [], batches });
  assert.equal(r.ok, false);
  assert.match(r.error, /duplicate/);
  assert.equal(r.error_kind, "verifier-output");
  assert.equal(r.error_batch_id, "B9");
});

test("chain referencing an unknown finding is an orchestrator-input error", () => {
  const c = chain({ finding_ids: ["OSWE-1", "OSWE-9"] });
  const r = applyVerdicts({ findings: [finding("OSWE-1"), finding("OSWE-2")], chains: [c], batches: [] });
  assert.equal(r.ok, false);
  assert.match(r.error, /unknown finding/);
  assert.equal(r.error_kind, "orchestrator-input");
});

test("duplicate canonical finding_id in input is an orchestrator-input error", () => {
  const r = applyVerdicts({ findings: [finding("OSWE-1"), finding("OSWE-1")], chains: [], batches: [] });
  assert.equal(r.ok, false);
  assert.match(r.error, /duplicate canonical finding_id/);
  assert.equal(r.error_kind, "orchestrator-input");
});

test("malformed input (non-array / missing / null elements) yields a structured error, not a throw", () => {
  const cases = [
    undefined, {},
    { findings: null, chains: [], batches: [] },
    { findings: [], chains: [], batches: "nope" },
    { findings: [null], chains: [], batches: [] },                 // null finding element
    { findings: [finding("OSWE-1")], chains: [null], batches: [] }, // null chain element
    { findings: [finding("OSWE-1")], chains: [], batches: [null] }  // null batch element
  ];
  for (const arg of cases) {
    const r = applyVerdicts(arg);
    assert.equal(r.ok, false, JSON.stringify(arg));
    assert.equal(r.error_kind, "orchestrator-input");
  }
});

test("a chain whose own batch errored is a coverage gap, left not-requested", () => {
  // findings batch ok; the chain's dedicated batch errors (0 verdicts) → chain → gap.
  const batches = [
    ...vresp(acceptBoth),
    { batch_id: nb(), expected_targets: [{ target_type: "chain", target_id: "CHAIN-1" }], response: { status: "error", verdicts: [] } }
  ];
  const r = applyVerdicts({ findings: bothFindings(), chains: [chain()], batches });
  assert.equal(r.ok, true);
  assert.equal(r.chains[0].verification_status, "not-requested"); // NOT rejected
  assert.notEqual(r.chains[0].severity, "Critical");
  assert.ok(r.gaps.some((g) => g.target_type === "chain" && g.target_id === "CHAIN-1"));
  assertResultSchemaValid(r); // not-requested finding keeps final fields; chain stays schema-valid
});

test("a batch mixing findings and a chain violates composition (orchestrator-input)", () => {
  const batches = [{
    batch_id: "Bmix",
    expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }, { target_type: "chain", target_id: "CHAIN-1" }],
    response: { status: "ok", verdicts: [acceptBoth[0], acceptChain] }
  }];
  const r = applyVerdicts({ findings: bothFindings(), chains: [chain()], batches });
  assert.equal(r.ok, false);
  assert.match(r.error, /composition must be/);
  assert.equal(r.error_kind, "orchestrator-input");
});

test("duplicate batch_id is an orchestrator-input error", () => {
  const mk = () => ({ batch_id: "DUP", expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }], response: { status: "ok", verdicts: [acceptBoth[0]] } });
  const r = applyVerdicts({ findings: bothFindings(), chains: [], batches: [mk(), mk()] });
  assert.equal(r.ok, false);
  assert.match(r.error, /duplicate batch_id/);
  assert.equal(r.error_kind, "orchestrator-input");
});

test("rejecting a low-severity chain does not raise its severity", () => {
  const c = chain({ severity: "Low", confidence: "likely" });
  const rej = { ...acceptChain, verdict: "rejected" };
  const r = applyVerdicts({ findings: bothFindings(), chains: [c], batches: vresp([...acceptBoth, rej]) });
  assert.equal(r.chains[0].verification_status, "rejected");
  assert.equal(r.chains[0].severity, "Low"); // min(Low, Medium) = Low — never raised
});

test("finding downgraded gets new final severity/confidence", () => {
  const v = [{ target_type: "finding", target_id: "OSWE-1", verdict: "downgraded", new_severity: "Medium", new_confidence: "likely", justification: "x" }];
  const r = applyVerdicts({ findings: [finding("OSWE-1")], chains: [], batches: vresp(v) });
  const f = r.findings[0];
  assert.equal(f.verification_status, "downgraded");
  assert.equal(f.final_severity, "Medium");
  assert.equal(f.final_confidence, "likely");
});

test("a downgraded FINDING that raises severity is an error", () => {
  const v = [{ target_type: "finding", target_id: "OSWE-1", verdict: "downgraded", new_severity: "High", new_confidence: "strong static proof", justification: "x" }];
  // provisional is Medium; "downgrading" to High is an increase -> reject the batch
  const r = applyVerdicts({ findings: [finding("OSWE-1", "Medium")], chains: [], batches: vresp(v) });
  assert.equal(r.ok, false);
  assert.match(r.error, /raises severity/);
});

test("a chain with broken topology is an orchestrator error (ok:false)", () => {
  // transitions do NOT form entry->OSWE-1->OSWE-2 (second hop is entry->OSWE-2)
  const c = chain({
    transitions: [
      { from: "entry", to: "OSWE-1", how: "x", evidence: [{ file: "a.php", line: 2 }] },
      { from: "entry", to: "OSWE-2", how: "x", evidence: [{ file: "u.php", line: 4 }] }
    ]
  });
  const v = {
    target_type: "chain", target_id: "CHAIN-1", verdict: "accepted",
    transition_verdicts: [
      { from: "entry", to: "OSWE-1", verdict: "accepted", justification: "x" },
      { from: "entry", to: "OSWE-2", verdict: "accepted", justification: "x" }
    ],
    justification: "x"
  };
  const r = applyVerdicts({ findings: bothFindings(), chains: [c], batches: vresp([...acceptBoth, v]) });
  assert.equal(r.ok, false);
  assert.match(r.error, /invalid topology/);
  assert.equal(r.error_kind, "orchestrator-input");
});

test("a malformed-topology chain is an error even when its batch errored (no verdict)", () => {
  const c = chain({
    transitions: [
      { from: "entry", to: "OSWE-1", how: "x", evidence: [{ file: "a.php", line: 2 }] },
      { from: "entry", to: "OSWE-2", how: "x", evidence: [{ file: "u.php", line: 4 }] }
    ]
  });
  const batches = [
    ...vresp(acceptBoth),
    { batch_id: "Bce", expected_targets: [{ target_type: "chain", target_id: "CHAIN-1" }], response: { status: "error", verdicts: [] } }
  ];
  const r = applyVerdicts({ findings: bothFindings(), chains: [c], batches });
  assert.equal(r.ok, false);
  assert.match(r.error, /invalid topology/);
  assert.equal(r.error_kind, "orchestrator-input");
});

test("a chain downgrade above the CANDIDATE severity is an error", () => {
  // Candidate claims Medium but is naturally Critical; downgrading to High exceeds c.severity.
  const c = chain({ severity: "Medium", confidence: "likely" });
  const dn = { ...acceptChain, verdict: "downgraded", new_severity: "High", new_confidence: "likely" };
  const r = applyVerdicts({ findings: bothFindings(), chains: [c], batches: vresp([...acceptBoth, dn]) });
  assert.equal(r.ok, false);
  assert.match(r.error, /raises severity/);
  assert.equal(r.error_kind, "verifier-output");
  assert.ok(r.error_batch_id, "chain downgrade-raise must name the offending batch");
});

test("a 'likely' member caps the accepted chain confidence (no Critical, not strong)", () => {
  // OSWE-2 is downgraded to 'likely' confidence; chain must not become Critical nor claim strong proof.
  const verdicts = [
    { target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x" },
    { target_type: "finding", target_id: "OSWE-2", verdict: "downgraded", new_severity: "High", new_confidence: "likely", justification: "x" },
    acceptChain
  ];
  const r = applyVerdicts({ findings: bothFindings(), chains: [chain()], batches: vresp(verdicts) });
  assert.equal(r.chains[0].verification_status, "accepted");
  assert.notEqual(r.chains[0].severity, "Critical");
  assert.equal(r.chains[0].confidence, "likely");
});

test("a downgraded CHAIN that raises severity is an error", () => {
  // authenticated entry + members Medium -> natural severity is Medium; downgrading to High increases.
  const findingsM = [finding("OSWE-1", "Medium"), finding("OSWE-2", "Medium")];
  const c = chain({ entry_point: { file: "a.php", line: 1, route: "POST /x", auth: "authenticated" } });
  const dnChain = { ...acceptChain, verdict: "downgraded", new_severity: "High", new_confidence: "likely" };
  const r = applyVerdicts({ findings: findingsM, chains: [c], batches: vresp([...acceptBoth, dnChain]) });
  assert.equal(r.ok, false);
  assert.match(r.error, /raises severity/);
  assert.ok(r.error_batch_id, "chain downgrade-raise must name the offending batch");
});

// --- validateBoundBatch (the shared pre-retry contract check; takes Maps of full objects) ---
const fbatch = (status, verdicts, expected) => ({ batch_id: "B1", expected_targets: expected, response: { status, verdicts } });
const fmap = (...fs) => new Map(fs.map((f) => [f.finding_id, f]));
const cmap = (...cs) => new Map(cs.map((c) => [c.chain_id, c]));

test("validateBoundBatch: ok batch covering its targets passes", () => {
  const b = fbatch("ok", [{ target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x" }], [{ target_type: "finding", target_id: "OSWE-1" }]);
  assert.equal(validateBoundBatch(b, { findingById: fmap(finding("OSWE-1")), chainById: cmap() }).ok, true);
});

test("validateBoundBatch: unexpected target → verifier-output", () => {
  const b = fbatch("ok", [{ target_type: "finding", target_id: "OSWE-2", verdict: "accepted", justification: "x" }], [{ target_type: "finding", target_id: "OSWE-1" }]);
  const r = validateBoundBatch(b, { findingById: fmap(finding("OSWE-1"), finding("OSWE-2")), chainById: cmap() });
  assert.equal(r.ok, false);
  assert.equal(r.error_kind, "verifier-output");
});

test("validateBoundBatch: mixed composition → orchestrator-input", () => {
  const b = fbatch("ok", [], [{ target_type: "finding", target_id: "OSWE-1" }, { target_type: "chain", target_id: "CHAIN-1" }]);
  const r = validateBoundBatch(b, { findingById: fmap(finding("OSWE-1")), chainById: cmap(chain()) });
  assert.equal(r.ok, false);
  assert.match(r.error, /composition must be/);
});

test("validateBoundBatch: missing response.verdicts → orchestrator-input (defensive shape)", () => {
  const b = { batch_id: "B1", expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }], response: { status: "ok" } };
  const r = validateBoundBatch(b, { findingById: fmap(finding("OSWE-1")), chainById: cmap() });
  assert.equal(r.ok, false);
  assert.equal(r.error_kind, "orchestrator-input");
});

test("validateBoundBatch: missing/empty batch_id → orchestrator-input", () => {
  const b = { expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }], response: { status: "ok", verdicts: [{ target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x" }] } };
  const r = validateBoundBatch(b, { findingById: fmap(finding("OSWE-1")), chainById: cmap() });
  assert.equal(r.ok, false);
  assert.match(r.error, /non-empty batch_id/);
});

test("validateBoundBatch: null expected_target element → orchestrator-input (no throw)", () => {
  const b = { batch_id: "B1", expected_targets: [null], response: { status: "error", verdicts: [] } };
  const r = validateBoundBatch(b, { findingById: fmap(finding("OSWE-1")), chainById: cmap() });
  assert.equal(r.ok, false);
  assert.equal(r.error_kind, "orchestrator-input");
});

test("validateBoundBatch: null verdict element → verifier-output (no throw)", () => {
  const b = { batch_id: "B1", expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }], response: { status: "ok", verdicts: [null] } };
  const r = validateBoundBatch(b, { findingById: fmap(finding("OSWE-1")), chainById: cmap() });
  assert.equal(r.ok, false);
  assert.equal(r.error_kind, "verifier-output");
});

test("validateBoundBatch: unknown status → verifier-output (not treated as partial)", () => {
  const b = fbatch("done", [{ target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x" }], [{ target_type: "finding", target_id: "OSWE-1" }]);
  const r = validateBoundBatch(b, { findingById: fmap(finding("OSWE-1")), chainById: cmap() });
  assert.equal(r.ok, false);
  assert.equal(r.error_kind, "verifier-output");
});

test("validateBoundBatch: chain transition mismatch is caught pre-retry", () => {
  const cv = { target_type: "chain", target_id: "CHAIN-1", verdict: "accepted", transition_verdicts: [], justification: "x" };
  const b = fbatch("ok", [cv], [{ target_type: "chain", target_id: "CHAIN-1" }]);
  const r = validateBoundBatch(b, { findingById: fmap(finding("OSWE-1"), finding("OSWE-2")), chainById: cmap(chain()) });
  assert.equal(r.ok, false);
  assert.match(r.error, /transition_verdicts do not match/);
});

test("validateBoundBatch: a rejected chain verdict STILL needs the exact transition set", () => {
  const cv = { target_type: "chain", target_id: "CHAIN-1", verdict: "rejected", transition_verdicts: [], justification: "x" };
  const b = fbatch("ok", [cv], [{ target_type: "chain", target_id: "CHAIN-1" }]);
  const r = validateBoundBatch(b, { findingById: fmap(finding("OSWE-1"), finding("OSWE-2")), chainById: cmap(chain()) });
  assert.equal(r.ok, false);
  assert.match(r.error, /transition_verdicts do not match/);
});

test("validateBoundBatch: finding downgrade-raise is caught pre-retry", () => {
  const v = { target_type: "finding", target_id: "OSWE-1", verdict: "downgraded", new_severity: "High", new_confidence: "strong static proof", justification: "x" };
  const b = fbatch("ok", [v], [{ target_type: "finding", target_id: "OSWE-1" }]);
  const r = validateBoundBatch(b, { findingById: fmap(finding("OSWE-1", "Medium")), chainById: cmap() });
  assert.equal(r.ok, false);
  assert.match(r.error, /raises severity/);
});

test("validateBoundBatch and applyVerdicts agree on a coverage mismatch", () => {
  const expected = [{ target_type: "finding", target_id: "OSWE-1" }, { target_type: "finding", target_id: "OSWE-2" }];
  const b = fbatch("ok", [{ target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x" }], expected);
  assert.equal(validateBoundBatch(b, { findingById: fmap(finding("OSWE-1"), finding("OSWE-2")), chainById: cmap() }).ok, false);
  const r = applyVerdicts({ findings: bothFindings(), chains: [], batches: [b] });
  assert.equal(r.ok, false);
  assert.equal(r.error_kind, "verifier-output");
});

test("CLI exits 0/1/2 (spawnSync)", () => {
  const dir = mkdtempSync(join(tmpdir(), "oswe-cli-"));
  const inOk = join(dir, "ok.json");
  const out = join(dir, "out.json");
  writeFileSync(inOk, JSON.stringify({ findings: [finding("OSWE-1")], chains: [], batches: vresp([{ target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x" }]) }));
  const ok = spawnSync(process.execPath, [CLI, "--file", inOk, "--out", out]);
  assert.equal(ok.status, 0);
  assert.equal(JSON.parse(readFileSync(out, "utf8")).ok, true);

  const inBad = join(dir, "bad.json");
  writeFileSync(inBad, JSON.stringify({ findings: [finding("OSWE-1")], chains: [], batches: vresp([{ target_type: "finding", target_id: "OSWE-9", verdict: "accepted", justification: "x" }]) }));
  const bad = spawnSync(process.execPath, [CLI, "--file", inBad, "--out", out]);
  assert.equal(bad.status, 1); // result.ok === false

  const usage = spawnSync(process.execPath, [CLI, "--file", inOk]); // missing --out
  assert.equal(usage.status, 2);
});

test("validate-batch.mjs CLI exits 0/1/2 (spawnSync)", () => {
  const VB = fileURLToPath(new URL("../validate-batch.mjs", import.meta.url));
  const dir = mkdtempSync(join(tmpdir(), "oswe-vb-"));
  const okIn = join(dir, "ok.json");
  writeFileSync(okIn, JSON.stringify({
    findings: [finding("OSWE-1")], chains: [],
    batch: { batch_id: "B1", expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }], response: { status: "ok", verdicts: [{ target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x" }] } }
  }));
  assert.equal(spawnSync(process.execPath, [VB, "--file", okIn]).status, 0);

  const badIn = join(dir, "bad.json");
  writeFileSync(badIn, JSON.stringify({
    findings: [finding("OSWE-1"), finding("OSWE-2")], chains: [],
    batch: { batch_id: "B1", expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }], response: { status: "ok", verdicts: [{ target_type: "finding", target_id: "OSWE-2", verdict: "accepted", justification: "x" }] } }
  }));
  assert.equal(spawnSync(process.execPath, [VB, "--file", badIn]).status, 1); // unexpected target

  // Same id preflight as applyVerdicts: a duplicate canonical finding_id is rejected, not merged.
  const dupIn = join(dir, "dup.json");
  writeFileSync(dupIn, JSON.stringify({
    findings: [finding("OSWE-1"), finding("OSWE-1")], chains: [],
    batch: { batch_id: "B1", expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }], response: { status: "ok", verdicts: [{ target_type: "finding", target_id: "OSWE-1", verdict: "accepted", justification: "x" }] } }
  }));
  const dup = spawnSync(process.execPath, [VB, "--file", dupIn], { encoding: "utf8" });
  assert.equal(dup.status, 1);
  assert.match(dup.stdout, /duplicate canonical finding_id/);

  assert.equal(spawnSync(process.execPath, [VB]).status, 2); // missing --file
});

const CLI_AV = fileURLToPath(new URL("../apply-verdicts.mjs", import.meta.url));

function runAV(input, checkpointDir) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-av-cache-")));
  const inP = join(dir, "in.json");
  const outP = join(dir, "out.json");
  writeFileSync(inP, JSON.stringify(input));
  const args = [CLI_AV, "--file", inP, "--out", outP];
  if (checkpointDir) args.push("--checkpoint-dir", checkpointDir);
  const r = spawnSync(process.execPath, args, { encoding: "utf8" });
  return { code: r.status, stderr: r.stderr, out: existsSync(outP) ? JSON.parse(readFileSync(outP, "utf8")) : null };
}

// apply-verdicts CLI input per apply-verdicts.mjs:348: { findings: [...], chains: [...], batches: [...] }
function minimalAVInput() {
  return { findings: [], chains: [], batches: [] };
}

test("apply-verdicts --checkpoint-dir miss writes cache file", () => {
  const ckpt = realpathSync(mkdtempSync(join(tmpdir(), "oswe-av-ckpt-")));
  const r = runAV(minimalAVInput(), ckpt);
  assert.equal(r.code, 0);
  const files = readdirSync(join(ckpt, "apply-verdicts"));
  assert.equal(files.length, 1);
});

test("apply-verdicts --checkpoint-dir hit on second call short-circuits with same output", () => {
  const ckpt = realpathSync(mkdtempSync(join(tmpdir(), "oswe-av-ckpt-")));
  const first = runAV(minimalAVInput(), ckpt);
  const second = runAV(minimalAVInput(), ckpt);
  assert.match(second.stderr, /cache hit/i);
  assert.deepEqual(second.out, first.out);
});
