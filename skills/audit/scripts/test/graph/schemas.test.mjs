import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "../../validate-output.mjs";

const ID = (n) => n.toString(16).padStart(12, "0");

function minimalStats() {
  return {
    files_total: 0, files_parsed: 0, files_error: 0, files_skipped: 0,
    functions: 0, calls_total: 0, calls_exact: 0, calls_name_only: 0, calls_unresolved: 0,
    routes_by_auth: { unauthenticated: 0, authenticated: 0, unknown: 0 },
    coverage_matrix: {},
    config_errors: []
  };
}

function minimalGraph() {
  return { version: 1, generated_by: "build-graph", stats: minimalStats(), nodes: [], edges: [] };
}

// One valid node of each type, one valid edge of each type.
function fullGraph() {
  const g = minimalGraph();
  g.nodes = [
    { type: "file", id: ID(1), path: "src/app.js", stack: "node", lang: "javascript", parse_status: "ok" },
    { type: "file", id: ID(2), path: "src/big.js", stack: "node", lang: "javascript", parse_status: "skipped", skip_reason: "too large" },
    { type: "function", id: ID(3), file: "src/app.js", name: "handler", qualified_name: "Ctl.handler", line_start: 3, line_end: 9, kind: "method", exported: true, class: "Ctl" },
    { type: "function", id: ID(4), file: "src/app.js", name: "helper", qualified_name: "helper", line_start: 11, line_end: 12, kind: "function", exported: false },
    { type: "route", id: ID(5), file: "src/app.js", line: 2, http_method: "GET", path_pattern: "/users/:id", handler: ID(3), middlewares: [ID(4), "authRequired"], framework: "express", auth: "unknown" },
    { type: "route", id: ID(6), file: "src/app.js", line: 20, http_method: "ANY", path_pattern: "/x", handler: null, middlewares: [], framework: "express", auth: "unauthenticated" },
    { type: "source", id: ID(7), file: "src/app.js", line: 4, enclosing_fn: ID(3), kind: "params", pattern: "req.params" },
    { type: "source", id: ID(8), file: "src/app.js", line: 30, enclosing_fn: null, kind: "env", pattern: "process.env" },
    { type: "sink", id: ID(9), file: "src/app.js", line: 6, enclosing_fn: ID(3), class: "sql", callee: "db.query", pattern: "db.query(" }
  ];
  g.edges = [
    { type: "imports", from: ID(1), to: ID(2), confidence: "exact", specifier: "./big" },
    { type: "calls", from: ID(3), to: ID(4), line: 7, callee_text: "helper", confidence: "exact" },
    { type: "calls", from: ID(3), to: null, line: 8, callee_text: "mystery", confidence: "unresolved" },
    { type: "handles", from: ID(5), to: ID(3) },
    { type: "uses_middleware", from: ID(5), to: ID(4), order: 0 },
    { type: "nests", from: ID(3), to: ID(4) }
  ];
  g.stats.coverage_matrix = {
    node: { frameworks_detected: ["express"], extractors_applied: ["routes"], not_extracted: [], patterns_unmatched: [] }
  };
  g.stats.config_errors = [{ file: "oswe-graph.json", message: "bad pattern" }];
  return g;
}

test("graph: minimal graph validates", () => {
  const r = validate("graph", minimalGraph());
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("graph: one node of each type and one edge of each type validates", () => {
  const r = validate("graph", fullGraph());
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("graph: edge with confidence 'maybe' is rejected", () => {
  const g = fullGraph();
  g.edges[0].confidence = "maybe";
  assert.equal(validate("graph", g).valid, false);
});

test("graph: calls edge missing confidence is rejected", () => {
  const g = fullGraph();
  delete g.edges[1].confidence;
  assert.equal(validate("graph", g).valid, false);
});

test("graph: a nests edge carries only from and to (no confidence, no null target)", () => {
  const withConfidence = fullGraph();
  withConfidence.edges.push({ type: "nests", from: ID(3), to: ID(4), confidence: "exact" });
  assert.equal(validate("graph", withConfidence).valid, false);
  const nullTarget = fullGraph();
  nullTarget.edges.push({ type: "nests", from: ID(3), to: null });
  assert.equal(validate("graph", nullTarget).valid, false);
});

test("graph: node with an unknown type is rejected", () => {
  const g = fullGraph();
  g.nodes[0] = { type: "module", id: ID(1), path: "src/app.js" };
  assert.equal(validate("graph", g).valid, false);
});

test("graph: additional properties are rejected on nodes, edges, stats and top level", () => {
  const withNode = fullGraph();
  withNode.nodes[0].extra = 1;
  assert.equal(validate("graph", withNode).valid, false);
  const withEdge = fullGraph();
  withEdge.edges[3].extra = 1;
  assert.equal(validate("graph", withEdge).valid, false);
  const withStats = fullGraph();
  withStats.stats.extra = 1;
  assert.equal(validate("graph", withStats).valid, false);
  const withTop = fullGraph();
  withTop.extra = 1;
  assert.equal(validate("graph", withTop).valid, false);
});

test("graph: node ids must be 12 lowercase hex characters", () => {
  for (const bad of ["xyz", "ABCDEF012345", "0123456789a", "0123456789abc"]) {
    const g = fullGraph();
    g.nodes[0].id = bad;
    assert.equal(validate("graph", g).valid, false, `id ${bad} should be rejected`);
  }
});

test("graph: enum fields reject out-of-vocabulary values", () => {
  const cases = [
    (g) => { g.nodes[0].stack = "ruby"; },
    (g) => { g.nodes[0].lang = "rust"; },
    (g) => { g.nodes[0].parse_status = "partial"; },
    (g) => { g.nodes[2].kind = "closure"; },
    (g) => { g.nodes[4].http_method = "TRACE"; },
    (g) => { g.nodes[4].framework = "rails"; },
    (g) => { g.nodes[4].auth = "admin"; },
    (g) => { g.nodes[6].kind = "socket"; },
    (g) => { g.nodes[8].class = "xss"; },
    (g) => { g.edges[1].confidence = "exact-ish"; }
  ];
  for (const mutate of cases) {
    const g = fullGraph();
    mutate(g);
    assert.equal(validate("graph", g).valid, false, mutate.toString());
  }
});

test("graph: every route framework id is accepted, servlet included", () => {
  for (const framework of ["express", "nest", "flask", "django", "fastapi", "spring", "servlet", "laravel", "symfony", "aspnet"]) {
    const g = fullGraph();
    g.nodes[4].framework = framework;
    assert.equal(validate("graph", g).valid, true, framework);
  }
});

test("graph: version must be 1 and stats counters must be non-negative integers", () => {
  const v = minimalGraph();
  v.version = 2;
  assert.equal(validate("graph", v).valid, false);
  const neg = minimalGraph();
  neg.stats.functions = -1;
  assert.equal(validate("graph", neg).valid, false);
  const frac = minimalGraph();
  frac.stats.calls_total = 1.5;
  assert.equal(validate("graph", frac).valid, false);
  const missing = minimalGraph();
  delete missing.stats.config_errors;
  assert.equal(validate("graph", missing).valid, false);
});

test("graph: line numbers start at 1 and uses_middleware order starts at 0", () => {
  const line0 = fullGraph();
  line0.nodes[2].line_start = 0;
  assert.equal(validate("graph", line0).valid, false);
  const callLine0 = fullGraph();
  callLine0.edges[1].line = 0;
  assert.equal(validate("graph", callLine0).valid, false);
  const orderNeg = fullGraph();
  orderNeg.edges[4].order = -1;
  assert.equal(validate("graph", orderNeg).valid, false);
});

test("structural-check: empty findings and transitions validate", () => {
  const r = validate("structural-check", { findings: {}, transitions: {} });
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("structural-check: populated findings and transitions validate", () => {
  const r = validate("structural-check", {
    findings: {
      "OSWE-1": { structural_path: "proven", reason: "route R -> handler -> sink" },
      "OSWE-2": { structural_path: "absent", reason: "" },
      "OSWE-3": { structural_path: "n/a", reason: "no route to anchor" }
    },
    transitions: {
      "CHAIN-1": [
        { index: 0, structural_path: "proven", reason: "reachable" },
        { index: 1, structural_path: "absent", reason: "no call path" }
      ]
    }
  });
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("structural-check: a finding with structural_path 'yes' is rejected", () => {
  const r = validate("structural-check", {
    findings: { "OSWE-1": { structural_path: "yes", reason: "x" } },
    transitions: {}
  });
  assert.equal(r.valid, false);
});

test("structural-check: unknown top-level key is rejected", () => {
  assert.equal(validate("structural-check", { findings: {}, transitions: {}, extra: {} }).valid, false);
});

test("structural-check: malformed keys, missing fields and extra entry fields are rejected", () => {
  const bad = [
    { findings: { "FINDING-1": { structural_path: "proven", reason: "" } }, transitions: {} },
    { findings: { "OSWE-1": { structural_path: "proven" } }, transitions: {} },
    { findings: { "OSWE-1": { structural_path: "proven", reason: "", extra: 1 } }, transitions: {} },
    { findings: {}, transitions: { "CHAIN-1": [{ index: -1, structural_path: "proven", reason: "" }] } },
    { findings: {}, transitions: { "CHAIN-1": [{ index: 0, structural_path: "maybe", reason: "" }] } },
    { findings: {}, transitions: { "T-1": [] } },
    { findings: {} }
  ];
  for (const doc of bad) assert.equal(validate("structural-check", doc).valid, false, JSON.stringify(doc));
});

// --- SP10 Task 14: coverage_matrix keys are the five stack ids ---
const STACK_ENTRY = { frameworks_detected: [], extractors_applied: [], not_extracted: [], patterns_unmatched: [] };

test("graph: coverage_matrix accepts each of the five stack ids as a key", () => {
  const g = minimalGraph();
  g.stats.coverage_matrix = Object.fromEntries(["php", "node", "python", "java", "dotnet"].map((s) => [s, STACK_ENTRY]));
  const r = validate("graph", g);
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

test("graph: coverage_matrix rejects a key outside the five stack ids (ruby, javascript)", () => {
  for (const key of ["ruby", "javascript", "Node", ""]) {
    const g = minimalGraph();
    g.stats.coverage_matrix = { [key]: STACK_ENTRY };
    assert.equal(validate("graph", g).valid, false, `key ${JSON.stringify(key)} should be rejected`);
  }
});

test("graph: every committed golden still validates (they use the stack-id keys)", () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..", "..", "test-fixtures", "graph");
  const stacks = readdirSync(root, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
  assert.deepEqual(stacks, ["dotnet", "java", "node", "php", "python"]);
  for (const stack of stacks) {
    const g = JSON.parse(readFileSync(join(root, stack, "graph.expected.json"), "utf8"));
    const r = validate("graph", g);
    assert.equal(r.valid, true, `${stack}: ${JSON.stringify(r.errors)}`);
  }
});
