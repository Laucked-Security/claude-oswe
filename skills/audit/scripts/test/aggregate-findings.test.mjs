import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
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
  provisional_severity: "Moyenne",
  confidence: "probable",
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
  const a = raw("auth-F001", "auth", { provisional_severity: "Moyenne", confidence: "probable", auth: "authenticated" });
  const b = raw("api-F003", "api", { provisional_severity: "Haute", confidence: "preuve statique forte", auth: "unauthenticated", evidence: [{ file: "db.php", line: 21 }] });
  const r = aggregateFindings([a, b]);
  assert.equal(r.findings.length, 1);
  const f = r.findings[0];
  assert.equal(f.provisional_severity, "Haute");          // max severity (worst impact)
  assert.equal(f.confidence, "probable");                 // MIN confidence (conservative)
  assert.equal(f.auth, "unauthenticated");                // most-exposed
  assert.deepEqual(f.partitions, ["api", "auth"]);        // sorted unique
  assert.deepEqual(f.source_finding_ids, ["api-F003", "auth-F001"]);
  assert.equal(f.evidence.length, 2);                     // union
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
