import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildReport, validateReport } from "../write-report.mjs";
import { validate } from "../validate-output.mjs";

// --- fixtures (reuse the shapes the other schemas already accept) ---
const run = (over = {}) => ({ run_id: "r1", generated: "2026-06-21", scope: ["src"], ...over });
const coverage = (over = {}) => ({ analyzed: ["src/a.java"], skipped: [], ...over });

const finalFinding = {
  finding_id: "OSWE-3", partition_id: "auth", title: "t", vuln_class: "sqli",
  source: { file: "a", line: 1, symbol: "s", kind: "http-param" },
  sink: { file: "b", line: 2, symbol: "q", kind: "query" },
  auth: "unauthenticated", provisional_severity: "High", confidence: "strong static proof",
  verification_status: "accepted", final_severity: "High", final_confidence: "strong static proof",
  direct_flow: true, partitions: ["auth"], source_finding_ids: ["auth-F001"]
};
const chain = {
  chain_id: "CHAIN-1",
  entry_point: { file: "a", line: 1, route: "POST /login", auth: "unauthenticated" },
  finding_ids: ["OSWE-3"],
  transitions: [{ from: "entry", to: "OSWE-3", how: "x", evidence: [{ file: "a", line: 1 }] }],
  final_impact: "unauth-rce", severity: "Critical", confidence: "strong static proof",
  verification_status: "accepted"
};
const verdict = { target_type: "finding", target_id: "OSWE-3", verdict: "accepted", justification: "src->sink a:1->b:2", counterexamples: [{ hypothesis: "auth blocks", checked: true, refuted: true }] };

test("buildReport assembles a report that validates", () => {
  const r = buildReport({ run: run(), coverage: coverage(), findings: [finalFinding], chains: [chain], verdicts: [verdict] });
  const res = validateReport(r);
  assert.equal(res.valid, true, JSON.stringify(res.errors));
});

test('validate("report", ...) is wired into the generated validators', () => {
  const r = buildReport({ run: run(), coverage: coverage(), findings: [], chains: [], verdicts: [] });
  assert.equal(validate("report", r).valid, true, JSON.stringify(validate("report", r).errors));
});

test("missing run.run_id fails", () => {
  const r = buildReport({ run: { generated: "2026-06-21", scope: ["src"] }, coverage: coverage(), findings: [], chains: [], verdicts: [] });
  assert.equal(validateReport(r).valid, false);
});

test("coverage.benchmark_cases accepts a known status and rejects an unknown one", () => {
  const ok = buildReport({ run: run(), coverage: coverage({ benchmark_cases: [{ test_id: "BenchmarkTest00010", status: "analyzed" }] }), findings: [], chains: [], verdicts: [] });
  assert.equal(validateReport(ok).valid, true, JSON.stringify(validateReport(ok).errors));
  const bad = buildReport({ run: run(), coverage: coverage({ benchmark_cases: [{ test_id: "BenchmarkTest00010", status: "audited" }] }), findings: [], chains: [], verdicts: [] });
  assert.equal(validateReport(bad).valid, false);
});

test("lead_adjudications: refuted lead with a test_id resolver and reason validates", () => {
  const r = buildReport({
    run: run(), coverage: coverage(), findings: [], chains: [], verdicts: [],
    lead_adjudications: [{ lead_id: "L001", outcome: "refuted", reason: "input is constant", test_id: "BenchmarkTest00011" }]
  });
  assert.equal(validateReport(r).valid, true, JSON.stringify(validateReport(r).errors));
});

test("lead_adjudications: a promoted lead still requires finding_id", () => {
  const r = buildReport({
    run: run(), coverage: coverage(), findings: [], chains: [], verdicts: [],
    lead_adjudications: [{ lead_id: "L001", outcome: "promoted", test_id: "BenchmarkTest00013" }]
  });
  assert.equal(validateReport(r).valid, false);
});

// --- SP10: app_graph (report.schema.json + buildReport) ---
const GRAPH_FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..", "test-fixtures", "graph");
const goldenStats = (stack) => JSON.parse(readFileSync(join(GRAPH_FIXTURES, stack, "graph.expected.json"), "utf8")).stats;
const base = () => ({ run: run(), coverage: coverage(), findings: [], chains: [], verdicts: [] });

test('validate("report") accepts app_graph { available: false, reason, multi_file_chain_count }', () => {
  const r = { ...base(), app_graph: { available: false, reason: "x", multi_file_chain_count: 0 } };
  const res = validate("report", r);
  assert.equal(res.valid, true, JSON.stringify(res.errors));
});

test("a report without app_graph is unchanged (buildReport omits the key)", () => {
  const r = buildReport(base());
  assert.equal("app_graph" in r, false);
  assert.deepEqual(Object.keys(r), ["run", "coverage", "findings", "chains", "verdicts"]);
});

test("app_graph.stats equal to every committed golden's stats validates", () => {
  const stacks = readdirSync(GRAPH_FIXTURES, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
  assert.deepEqual(stacks, ["dotnet", "java", "node", "php", "python"]);
  for (const stack of stacks) {
    const r = { ...base(), app_graph: { available: true, stats: goldenStats(stack), multi_file_chain_count: 0 } };
    const res = validate("report", r);
    assert.equal(res.valid, true, `${stack}: ${JSON.stringify(res.errors)}`);
  }
});

test("app_graph rejects unknown keys, missing required keys and bad types", () => {
  const withAg = (ag) => ({ ...base(), app_graph: ag });
  assert.equal(validate("report", withAg({ available: false, multi_file_chain_count: 0, extra: 1 })).valid, false);
  assert.equal(validate("report", withAg({ multi_file_chain_count: 0 })).valid, false);                       // available required
  assert.equal(validate("report", withAg({ available: false })).valid, false);                                // multi_file_chain_count required
  assert.equal(validate("report", withAg({ available: "no", multi_file_chain_count: 0 })).valid, false);
  assert.equal(validate("report", withAg({ available: false, reason: 5, multi_file_chain_count: 0 })).valid, false);
  assert.equal(validate("report", withAg({ available: false, multi_file_chain_count: -1 })).valid, false);
  assert.equal(validate("report", withAg({ available: false, multi_file_chain_count: 1.5 })).valid, false);
  assert.equal(validate("report", withAg({ available: true, stats: { files_total: 1 }, multi_file_chain_count: 0 })).valid, false);   // stats is the full graph stats shape
  assert.equal(validate("report", withAg({ available: true, stats: goldenStats("node"), multi_file_chain_count: 0 })).valid, true);
});

test("app_graph.stats rejects a coverage_matrix stack key outside the five stack ids", () => {
  const stats = goldenStats("node");
  const entry = Object.values(stats.coverage_matrix)[0];
  assert.ok(entry, "node golden has a coverage_matrix entry");
  stats.coverage_matrix = { javascript: entry };
  const res = validate("report", { ...base(), app_graph: { available: true, stats, multi_file_chain_count: 0 } });
  assert.equal(res.valid, false);
});

test("buildReport round-trips app_graph (available:false with reason)", () => {
  const ag = { available: false, reason: "tree-sitter grammars missing", multi_file_chain_count: 0 };
  const r = buildReport({ ...base(), app_graph: ag });
  assert.deepEqual(r.app_graph, ag);
  assert.equal(validateReport(r).valid, true, JSON.stringify(validateReport(r).errors));
  assert.deepEqual(JSON.parse(JSON.stringify(r)).app_graph, ag);
});

test("buildReport round-trips app_graph with stats and does not mutate its argument", () => {
  const ag = { available: true, stats: goldenStats("java"), multi_file_chain_count: 99 };
  const snapshot = JSON.stringify(ag);
  const r = buildReport({ ...base(), app_graph: ag });
  assert.deepEqual(r.app_graph.stats, goldenStats("java"));
  assert.equal(JSON.stringify(ag), snapshot);                       // caller's object untouched (the supplied 99 is overridden in the copy)
  assert.equal(validateReport(r).valid, true, JSON.stringify(validateReport(r).errors));
});

// multi_file_chain_count mirrors benchmark/score-nodegoat.mjs (multi_file_chains): chains in
// ACCEPTED_STATUSES (accepted | downgraded) whose transitions[].evidence[].file set (backslash->slash,
// lowercased) has >= 2 distinct files. buildReport computes it; a supplied value is never trusted.
const mfChain = (id, status, files) => ({
  ...chain, chain_id: id, verification_status: status, severity: "High", final_impact: "x",
  transitions: [{ from: "entry", to: "OSWE-3", how: "x", evidence: files.map((file, i) => ({ file, line: i + 1 })) }]
});
const countFor = (chains, supplied = 0) =>
  buildReport({ ...base(), findings: [finalFinding], chains, app_graph: { available: true, multi_file_chain_count: supplied } }).app_graph.multi_file_chain_count;

test("multi_file_chain_count: an accepted chain whose evidence spans two files counts 1", () => {
  assert.equal(countFor([mfChain("CHAIN-1", "accepted", ["a", "b"])]), 1);
});

test("multi_file_chain_count: 0 when the evidence stays in one file (path normalisation included)", () => {
  assert.equal(countFor([mfChain("CHAIN-1", "accepted", ["src/a.js", "src/a.js"])]), 0);
  assert.equal(countFor([mfChain("CHAIN-1", "accepted", ["src\\A.js", "src/a.js"])]), 0);   // norm: backslash->slash, lowercase
});

test("multi_file_chain_count: 0 when the chain is not accepted (rejected / not-requested)", () => {
  assert.equal(countFor([mfChain("CHAIN-1", "rejected", ["a", "b"]), mfChain("CHAIN-2", "not-requested", ["a", "b"])]), 0);
});

test("multi_file_chain_count: downgraded chains count (score-nodegoat ACCEPTED_STATUSES) and counts add up", () => {
  const chains = [
    mfChain("CHAIN-1", "accepted", ["a", "b"]),
    mfChain("CHAIN-2", "downgraded", ["a", "c"]),
    mfChain("CHAIN-3", "accepted", ["a"]),
    mfChain("CHAIN-4", "rejected", ["a", "b"])
  ];
  assert.equal(countFor(chains), 2);
});

test("multi_file_chain_count is computed, never trusted: a supplied value is overridden", () => {
  assert.equal(countFor([mfChain("CHAIN-1", "accepted", ["a"])], 7), 0);
  assert.equal(countFor([mfChain("CHAIN-1", "accepted", ["a", "b"])], 0), 1);
});

test("multi_file_chain_count with app_graph passed but no chains is 0", () => {
  assert.equal(countFor([], 5), 0);
});
