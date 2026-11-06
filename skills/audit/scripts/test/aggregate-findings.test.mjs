import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { aggregateFindings } from "../aggregate-findings.mjs";
import { validate } from "../validate-output.mjs";

const CLI = fileURLToPath(new URL("../aggregate-findings.mjs", import.meta.url));
const loc = (file, line, symbol, kind) => ({ file, line, symbol, kind });

// A raw per-partition analyzer finding (partition-scoped id, no provenance/final fields).
const raw = (id, partition, over = {}) => ({
  finding_id: id,
  partition_id: partition,
  title: id,
  vuln_class: "sqli",
  source: loc("a.php", 10, "$_GET['q']", "http-param"),
  sink: loc("db.php", 20, "query", "query"),
  auth: "authenticated",
  evidence: [{ file: "db.php", line: 20 }],
  provisional_severity: "Medium",
  confidence: "likely",
  verification_status: "not-requested",
  ...over
});

test("a unique finding gets single-element provenance and OSWE-1", () => {
  const r = aggregateFindings([raw("auth-F001", "auth")]);
  assert.equal(r.ok, true);
  assert.equal(r.findings[0].finding_id, "OSWE-1");
  assert.deepEqual(r.findings[0].partitions, ["auth"]);
  assert.deepEqual(r.findings[0].source_finding_ids, ["auth-F001"]);
  assert.equal(validate("finding", r.findings[0]).valid, true, JSON.stringify(validate("finding", r.findings[0]).errors));
});

test("two findings with the same source/sink/class are merged with worst-case fields", () => {
  const a = raw("auth-F001", "auth", { provisional_severity: "Medium", confidence: "likely", auth: "authenticated" });
  const b = raw("api-F003", "api", { provisional_severity: "High", confidence: "strong static proof", auth: "unauthenticated", evidence: [{ file: "db.php", line: 21 }] });
  const r = aggregateFindings([a, b]);
  assert.equal(r.findings.length, 1);
  const f = r.findings[0];
  assert.equal(f.provisional_severity, "High");          // max severity (worst impact)
  assert.equal(f.confidence, "likely");                 // MIN confidence (conservative)
  assert.equal(f.auth, "unauthenticated");                // most-exposed
  assert.deepEqual(f.partitions, ["api", "auth"]);        // sorted unique
  assert.deepEqual(f.source_finding_ids, ["api-F003", "auth-F001"]);
  assert.equal(f.evidence.length, 2);                     // union
});

test("direct_flow:true is propagated through aggregation (SP6)", () => {
  const r = aggregateFindings([raw("auth-F001", "auth", { direct_flow: true })]);
  assert.equal(r.ok, true);
  assert.equal(r.findings[0].direct_flow, true);
  assert.equal(validate("finding", r.findings[0]).valid, true, JSON.stringify(validate("finding", r.findings[0]).errors));
});

test("direct_flow absent stays absent (no default injection)", () => {
  const r = aggregateFindings([raw("auth-F001", "auth")]);
  assert.equal("direct_flow" in r.findings[0], false);
});

test("direct_flow:true wins if any merged member has it", () => {
  const a = raw("auth-F001", "auth");
  const b = raw("api-F003", "api", { direct_flow: true });
  const r = aggregateFindings([a, b]);
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].direct_flow, true);
});

test("aggregation is independent of input order", () => {
  const a = raw("auth-F001", "auth");
  const b = raw("api-F003", "api", { source: loc("b.php", 5, "$_POST['x']", "http-param") });
  const r1 = aggregateFindings([a, b]);
  const r2 = aggregateFindings([b, a]);
  assert.deepEqual(r1.findings, r2.findings); // identical canonical output + identical OSWE-N
});

test("stable numbering follows (source.file, source.line, sink.file, sink.line, vuln_class)", () => {
  const early = raw("p-F001", "p", { source: loc("a.php", 1, "s", "http-param") });
  const late = raw("p-F002", "p", { source: loc("z.php", 1, "s", "http-param") });
  const r = aggregateFindings([late, early]);
  assert.equal(r.findings.find((f) => f.source.file === "a.php").finding_id, "OSWE-1");
  assert.equal(r.findings.find((f) => f.source.file === "z.php").finding_id, "OSWE-2");
});

test("duplicate analyzer finding_id is an error", () => {
  const r = aggregateFindings([raw("p-F001", "p"), raw("p-F001", "p", { source: loc("c.php", 9, "s", "http-param") })]);
  assert.equal(r.ok, false);
  assert.match(r.error, /duplicate analyzer finding_id/);
});

test("numbering is total-ordered even when groups share file+line but differ in symbol/kind", () => {
  // Same source file+line and same sink, but different source.symbol → two distinct groups.
  const a = raw("p-F001", "p", { source: loc("a.php", 10, "aaa", "http-param") });
  const b = raw("p-F002", "p", { source: loc("a.php", 10, "zzz", "http-param") });
  const r1 = aggregateFindings([a, b]);
  const r2 = aggregateFindings([b, a]); // reversed input
  assert.equal(r1.findings.length, 2);
  assert.deepEqual(r1.findings, r2.findings); // identical numbering regardless of order
  assert.equal(r1.findings.find((f) => f.source.symbol === "aaa").finding_id, "OSWE-1");
});

test("CLI exits 0/1/2 (spawnSync)", () => {
  const dir = mkdtempSync(join(tmpdir(), "oswe-agg-"));
  const inOk = join(dir, "in.json");
  const out = join(dir, "out.json");
  writeFileSync(inOk, JSON.stringify({ findings: [raw("p-F001", "p")] }));
  const ok = spawnSync(process.execPath, [CLI, "--file", inOk, "--out", out]);
  assert.equal(ok.status, 0);
  assert.equal(JSON.parse(readFileSync(out, "utf8")).findings[0].finding_id, "OSWE-1");

  const inBad = join(dir, "bad.json");
  writeFileSync(inBad, JSON.stringify({ findings: [raw("p-F001", "p"), raw("p-F001", "p")] }));
  assert.equal(spawnSync(process.execPath, [CLI, "--file", inBad, "--out", out]).status, 1);
  assert.equal(spawnSync(process.execPath, [CLI, "--file", inOk]).status, 2); // missing --out
});

test("origin is carried through; same-origin merge keeps its origin", () => {
  const a = raw("auth-F001", "auth", { origin: "sast-lead", source_lead_ids: ["L001"] });
  const r = aggregateFindings([a]);
  assert.equal(r.findings[0].origin, "sast-lead");
  assert.deepEqual(r.findings[0].source_lead_ids, ["L001"]);
});

test("an llm finding and a sast-lead finding on the same key merge to origin:both", () => {
  const a = raw("auth-F001", "auth", { origin: "llm-discovered" });
  const b = raw("api-F003", "api", { origin: "sast-lead", source_lead_ids: ["L002"] });
  const r = aggregateFindings([a, b]);
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].origin, "both");
  assert.deepEqual(r.findings[0].source_lead_ids, ["L002"]);
});

test("absent origin defaults to llm-discovered, and source_lead_ids is OMITTED when no lead", () => {
  const r = aggregateFindings([raw("auth-F001", "auth")]);
  assert.equal(r.findings[0].origin, "llm-discovered");
  assert.equal(r.findings[0].source_lead_ids, undefined);   // omitted, not [] (spec §3.5)
});

const CLI_AGG = fileURLToPath(new URL("../aggregate-findings.mjs", import.meta.url));

function runAgg(input, checkpointDir) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-agg-cache-")));
  const inP = join(dir, "in.json");
  const outP = join(dir, "out.json");
  writeFileSync(inP, JSON.stringify(input));
  const args = [CLI_AGG, "--file", inP, "--out", outP];
  if (checkpointDir) args.push("--checkpoint-dir", checkpointDir);
  const r = spawnSync(process.execPath, args, { encoding: "utf8" });
  return { code: r.status, stderr: r.stderr, out: existsSync(outP) ? JSON.parse(readFileSync(outP, "utf8")) : null };
}

// aggregate-findings CLI input: { findings: [...rawFindings] } (per aggregate-findings.mjs:89).
function minimalAggInput() {
  return { findings: [] };
}

test("aggregate-findings --checkpoint-dir miss writes cache file", () => {
  const ckpt = realpathSync(mkdtempSync(join(tmpdir(), "oswe-agg-ckpt-")));
  const r = runAgg(minimalAggInput(), ckpt);
  assert.equal(r.code, 0);
  const files = readdirSync(join(ckpt, "aggregate-findings"));
  assert.equal(files.length, 1);
});

test("aggregate-findings --checkpoint-dir hit on second call short-circuits with same output", () => {
  const ckpt = realpathSync(mkdtempSync(join(tmpdir(), "oswe-agg-ckpt-")));
  const first = runAgg(minimalAggInput(), ckpt);
  const second = runAgg(minimalAggInput(), ckpt);
  assert.match(second.stderr, /cache hit/i);
  assert.deepEqual(second.out, first.out);
});

// --- SP10: candidate_path_id (raw, per member) -> candidate_path_ids (merged union) ---
test("members carrying different candidate_path_id merge to a sorted candidate_path_ids union", () => {
  const a = raw("auth-F001", "p", { candidate_path_id: "CP-p-2" });
  const b = raw("api-F003", "p", { candidate_path_id: "CP-p-1" });
  const r = aggregateFindings([a, b]);
  assert.equal(r.findings.length, 1);
  assert.deepEqual(r.findings[0].candidate_path_ids, ["CP-p-1", "CP-p-2"]);
  assert.equal("candidate_path_id" in r.findings[0], false);   // the merged finding never carries the singular key
  assert.equal(validate("finding", r.findings[0]).valid, true, JSON.stringify(validate("finding", r.findings[0]).errors));
});

test("candidate_path_ids is a unique union (the same id cited twice appears once) and input-order independent", () => {
  const a = raw("auth-F001", "p", { candidate_path_id: "CP-p-1" });
  const b = raw("api-F003", "p", { candidate_path_id: "CP-p-1" });
  const c = raw("api-F004", "p", { candidate_path_id: "CP-p-3" });
  const r1 = aggregateFindings([a, b, c]);
  const r2 = aggregateFindings([c, b, a]);
  assert.deepEqual(r1.findings[0].candidate_path_ids, ["CP-p-1", "CP-p-3"]);
  assert.deepEqual(r1.findings, r2.findings);
});

test("a single member's candidate_path_id becomes a one-element candidate_path_ids", () => {
  const r = aggregateFindings([raw("auth-F001", "p", { candidate_path_id: "CP-p-4" })]);
  assert.deepEqual(r.findings[0].candidate_path_ids, ["CP-p-4"]);
  assert.equal("candidate_path_id" in r.findings[0], false);
});

test("one member with a candidate_path_id and one without still yields candidate_path_ids", () => {
  const r = aggregateFindings([raw("auth-F001", "p"), raw("api-F003", "p", { candidate_path_id: "CP-p-1" })]);
  assert.equal(r.findings.length, 1);
  assert.deepEqual(r.findings[0].candidate_path_ids, ["CP-p-1"]);
});

test("no member with a candidate_path_id => the key is ABSENT and the merged key set is unchanged", () => {
  const r = aggregateFindings([raw("auth-F001", "auth"), raw("api-F003", "api")]);
  assert.equal(r.findings.length, 1);
  assert.equal("candidate_path_ids" in r.findings[0], false);
  assert.equal("candidate_path_id" in r.findings[0], false);
  // Byte-identity guard for every pre-SP10 fixture: the exact merged key set, in order.
  assert.deepEqual(Object.keys(r.findings[0]), [
    "finding_id", "partition_id", "title", "vuln_class", "source", "sink", "auth", "transformations", "sanitizers",
    "prerequisites", "evidence", "provisional_severity", "confidence", "verification_status", "partitions",
    "source_finding_ids", "origin"
  ]);
  assert.equal(JSON.stringify(r.findings).includes("candidate_path"), false);
});

test("candidate_path_ids rides along on the CLI output (spawnSync)", () => {
  const dir = mkdtempSync(join(tmpdir(), "oswe-agg-cp-"));
  const inP = join(dir, "in.json");
  const outP = join(dir, "out.json");
  writeFileSync(inP, JSON.stringify({ findings: [raw("p-F001", "p", { candidate_path_id: "CP-p-2" }), raw("p-F002", "p", { candidate_path_id: "CP-p-1" })] }));
  assert.equal(spawnSync(process.execPath, [CLI, "--file", inP, "--out", outP]).status, 0);
  assert.deepEqual(JSON.parse(readFileSync(outP, "utf8")).findings[0].candidate_path_ids, ["CP-p-1", "CP-p-2"]);
});

// --- I5: a raw finding's candidate_path_id must name a path of ITS partition ---
test("I5: a candidate_path_id not starting with CP-<that finding's partition_id>- is dropped", () => {
  const ok = raw("auth-F001", "auth", { candidate_path_id: "CP-auth-3" });
  const foreign = raw("api-F003", "api", { candidate_path_id: "CP-auth-1" }); // another partition's path
  const prefixOnly = raw("api-F004", "api", { candidate_path_id: "CP-api2-1" }); // "CP-api2-" is not "CP-api-"
  const r = aggregateFindings([ok, foreign, prefixOnly]);
  assert.equal(r.ok, true);
  assert.deepEqual(r.findings[0].candidate_path_ids, ["CP-auth-3"]);
  const none = aggregateFindings([foreign]);
  assert.equal("candidate_path_ids" in none.findings[0], false);
  const g = aggregateFindings([raw("auth-F001", "g-node-unauthenticated-root", { candidate_path_id: "CP-g-node-unauthenticated-root-12" })]);
  assert.deepEqual(g.findings[0].candidate_path_ids, ["CP-g-node-unauthenticated-root-12"]);
});
