// M1: one repo-path normal form (graph/text.mjs pathKey) shared by check-chain-structure,
// partition-graph, enumerate-paths and write-report's multi-file chain count — so the four agree on
// `./x.js` and `A\b.js`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { pathKey, pathKeyFor, normalizeRepoPath } from "../graph/text.mjs";
import { checkChainStructure } from "../check-chain-structure.mjs";
import { partitionGraph } from "../partition-graph.mjs";
import { enumeratePaths } from "../enumerate-paths.mjs";
import { countMultiFileChains } from "../write-report.mjs";
import { validate } from "../validate-output.mjs";

const WIN = process.platform === "win32";
const STATS = {
  files_total: 0, files_parsed: 0, files_error: 0, files_skipped: 0, functions: 0, calls_total: 0, calls_exact: 0,
  calls_name_only: 0, calls_unresolved: 0, routes_by_auth: { unauthenticated: 0, authenticated: 0, unknown: 0 },
  coverage_matrix: {}, config_errors: []
};

// x.js: route GET /x -> h (line 1-5), h calls g in A/b.js (exact); g holds an eval sink at line 12.
function graph() {
  const g = {
    version: 1, generated_by: "test", stats: STATS,
    nodes: [
      { type: "file", id: "f00000000001", path: "x.js", stack: "node", lang: "javascript", parse_status: "ok" },
      { type: "file", id: "f00000000002", path: "A/b.js", stack: "node", lang: "javascript", parse_status: "ok" },
      { type: "function", id: "a00000000001", file: "x.js", name: "h", qualified_name: "h", line_start: 1, line_end: 5, kind: "function", exported: false },
      { type: "function", id: "a00000000002", file: "A/b.js", name: "g", qualified_name: "g", line_start: 10, line_end: 15, kind: "function", exported: true },
      { type: "route", id: "c00000000001", file: "x.js", line: 7, http_method: "GET", path_pattern: "/x", handler: "a00000000001", middlewares: [], framework: "express", auth: "unauthenticated" },
      { type: "sink", id: "d00000000001", file: "A/b.js", line: 12, enclosing_fn: "a00000000002", class: "eval", callee: "eval", pattern: "eval(" }
    ],
    edges: [
      { type: "calls", from: "a00000000001", to: "a00000000002", line: 3, callee_text: "g", confidence: "exact" },
      { type: "handles", from: "c00000000001", to: "a00000000001" }
    ]
  };
  assert.equal(validate("graph", g).valid, true);
  return g;
}

test("pathKey: backslashes -> '/', leading './' stripped, case folded on win32 only", () => {
  assert.equal(normalizeRepoPath("./x.js"), "x.js");
  assert.equal(normalizeRepoPath("././A\\b.js"), "A/b.js");
  assert.equal(pathKeyFor("linux")("A\\b.js"), "A/b.js");
  assert.equal(pathKeyFor("darwin")("./A/B.js"), "A/B.js");
  assert.equal(pathKeyFor("win32")("./A\\B.js"), "a/b.js");
  assert.equal(pathKey("A\\b.js"), WIN ? "a/b.js" : "A/b.js");
  assert.equal(pathKey(null), "");
});

test("check-chain-structure maps './x.js' and 'A\\\\b.js' onto the graph's x.js / A/b.js", () => {
  const out = checkChainStructure({
    graph: graph(),
    findings: [{ finding_id: "OSWE-1", source: { file: "./x.js", line: 2 }, sink: { file: "A\\b.js", line: 12 } }],
    chains: []
  });
  assert.deepEqual(out.findings["OSWE-1"], { structural_path: "proven", reason: "forward exact path (1 edges)" });
});

test("partition-graph claims './x.js' and 'A\\\\b.js' fallback entries as the graph's files (no orphans)", () => {
  const out = partitionGraph({ graph: graph(), fallback_partitions: [{ partition_id: "p1", stack: "node", files: ["./x.js", "A\\b.js"] }] });
  assert.equal(out.mode, "graph");
  assert.deepEqual(out.orphan_partition_ids, []);
  assert.deepEqual(out.partitions.map((p) => p.files), [["A/b.js", "x.js"]]);
});

test("enumerate-paths treats a partition listing './x.js' and 'A\\\\b.js' as holding x.js and A/b.js", () => {
  const out = enumeratePaths({ graph: graph(), partition: { partition_id: "p", stack: "node", files: ["./x.js", "A\\b.js"] } });
  assert.deepEqual(out.candidate_paths.map((c) => [c.route.path_pattern, c.hops.map((h) => h.function), c.sink.class]), [["/x", ["h", "g"], "eval"]]);
});

test("write-report's multi-file count agrees: './x.js' = 'x.js', 'A\\\\b.js' = 'A/b.js', case folded on win32 only", () => {
  const chain = (files) => ({ verification_status: "accepted", transitions: [{ evidence: files.map((file) => ({ file, line: 1 })) }] });
  assert.equal(countMultiFileChains([chain(["./x.js", "x.js"])]), 0);
  assert.equal(countMultiFileChains([chain(["A\\b.js", "A/b.js"])]), 0);
  assert.equal(countMultiFileChains([chain(["a/B.js", "A/b.js"])]), WIN ? 0 : 1);
});
