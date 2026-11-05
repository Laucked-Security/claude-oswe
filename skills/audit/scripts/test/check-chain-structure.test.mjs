import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { checkChainStructure, enclosingFn, InputError } from "../check-chain-structure.mjs";
import { validate } from "../validate-output.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPTS_DIR = join(HERE, "..");
const REPO_ROOT = join(SCRIPTS_DIR, "..", "..", "..");
const FIXTURES_DIR = join(REPO_ROOT, "test-fixtures", "graph");
const CLI = join(SCRIPTS_DIR, "check-chain-structure.mjs");

const golden = (stack) => JSON.parse(readFileSync(join(FIXTURES_DIR, stack, "graph.expected.json"), "utf8"));

let nextId = 0;
const hex12 = () => (++nextId).toString(16).padStart(12, "0");
const ZERO_STATS = {
  files_total: 0, files_parsed: 0, files_error: 0, files_skipped: 0, functions: 0, calls_total: 0, calls_exact: 0,
  calls_name_only: 0, calls_unresolved: 0, routes_by_auth: { unauthenticated: 0, authenticated: 0, unknown: 0 },
  coverage_matrix: {}, config_errors: []
};

// Schema-valid synthetic graph from a compact description:
//   fns:   { name: [file, line_start, line_end] }   (ids derive from the name, in declaration order)
//   calls: [[fromName, toName | null, confidence]]
function synth({ fns = {}, calls = [] }) {
  const fnId = Object.fromEntries(Object.keys(fns).map((name) => [name, hex12()]));
  const files = [...new Set(Object.values(fns).map(([file]) => file))];
  const nodes = files.map((path) => ({ type: "file", id: hex12(), path, stack: "node", lang: "javascript", parse_status: "ok" }));
  for (const [name, [file, line_start, line_end]] of Object.entries(fns)) {
    nodes.push({ type: "function", id: fnId[name], file, name, qualified_name: name, line_start, line_end, kind: "function", exported: false });
  }
  const edges = calls.map(([from, to, confidence]) => ({ type: "calls", from: fnId[from], to: to ? fnId[to] : null, line: 1, callee_text: to ?? "unknown", confidence }));
  const graph = { version: 1, generated_by: "test", stats: ZERO_STATS, nodes, edges };
  assert.deepEqual(validate("graph", graph), { valid: true, errors: [] }, "the synthetic graph must itself be schema-valid");
  return graph;
}

const loc = ([file, line]) => ({ file, line, symbol: "x", kind: "k" });
const finding = (id, source, sink) => ({ finding_id: id, source: loc(source), sink: loc(sink) });
const transition = (from, to, extra = {}) => ({ from, to, how: "h", evidence: [{ file: "a.js", line: 1 }], ...extra });
const chain = (id, transitions, finding_ids = ["OSWE-1"]) => ({
  chain_id: id,
  entry_point: { file: "a.js", line: 1, route: "GET /x", auth: "unauthenticated" },
  finding_ids,
  transitions,
  final_impact: "auth-rce",
  severity: "High",
  confidence: "likely",
  verification_status: "not-requested"
});

// One finding through the API: returns its { structural_path, reason }.
const one = (graph, source, sink, opts = {}) =>
  checkChainStructure({ graph, findings: [finding("OSWE-1", source, sink)], chains: [], ...opts }).findings["OSWE-1"];

// A line of functions a(1-3) b(5-7) c(9-11) d(13-15) in a.js plus e(1-3) in e.js.
const LINE = { a: ["a.js", 1, 3], b: ["a.js", 5, 7], c: ["a.js", 9, 11], d: ["a.js", 13, 15], e: ["e.js", 1, 3] };

// ---- per-finding decision table ---------------------------------------------------------------------

test("forward exact path => proven, with the edge count", () => {
  const graph = synth({ fns: LINE, calls: [["a", "b", "exact"], ["b", "c", "exact"]] });
  assert.deepEqual(one(graph, ["a.js", 2], ["a.js", 10]), { structural_path: "proven", reason: "forward exact path (2 edges)" });
  assert.deepEqual(one(graph, ["a.js", 2], ["a.js", 6]), { structural_path: "proven", reason: "forward exact path (1 edges)" });
});

test("source and sink in the same function => proven (same function), even with no edges at all", () => {
  const graph = synth({ fns: LINE });
  assert.deepEqual(one(graph, ["a.js", 1], ["a.js", 3]), { structural_path: "proven", reason: "same function" });
});

test("no forward exact path but a reverse exact path => n/a (return-value flow not modelled)", () => {
  // the source is read in c, which is called (exactly) by the sink's function a: a -> b -> c
  const graph = synth({ fns: LINE, calls: [["a", "b", "exact"], ["b", "c", "exact"]] });
  assert.deepEqual(one(graph, ["a.js", 10], ["a.js", 2]), { structural_path: "n/a", reason: "return-value flow not modelled" });
});

test("a forward path through one name-only edge => n/a; the same in reverse => n/a", () => {
  const graph = synth({ fns: LINE, calls: [["a", "b", "exact"], ["b", "c", "name-only"]] });
  assert.deepEqual(one(graph, ["a.js", 2], ["a.js", 10]), { structural_path: "n/a", reason: "only non-exact edges connect source and sink" });
  assert.deepEqual(one(graph, ["a.js", 10], ["a.js", 2]), { structural_path: "n/a", reason: "only non-exact edges connect source and sink" });
});

test("a forward exact path wins over a shorter name-only one; a reverse exact path wins over a forward name-only one", () => {
  const both = synth({ fns: LINE, calls: [["a", "d", "name-only"], ["a", "b", "exact"], ["b", "c", "exact"], ["c", "d", "exact"]] });
  assert.deepEqual(one(both, ["a.js", 2], ["a.js", 14]), { structural_path: "proven", reason: "forward exact path (3 edges)" });
  const mixed = synth({ fns: LINE, calls: [["a", "b", "name-only"], ["b", "a", "exact"]] });
  assert.deepEqual(one(mixed, ["a.js", 2], ["a.js", 6]), { structural_path: "n/a", reason: "return-value flow not modelled" });
});

test("a source or sink line outside any function => n/a, the source checked first", () => {
  const graph = synth({ fns: LINE, calls: [["a", "b", "exact"]] });
  assert.deepEqual(one(graph, ["a.js", 2], ["a.js", 4]), { structural_path: "n/a", reason: "sink line maps to no function" });
  assert.deepEqual(one(graph, ["a.js", 4], ["a.js", 6]), { structural_path: "n/a", reason: "source line maps to no function" });
  assert.deepEqual(one(graph, ["a.js", 99], ["zz.js", 1]), { structural_path: "n/a", reason: "source line maps to no function" });
  assert.deepEqual(one(graph, ["a.js", 2], ["not-in-graph.js", 2]), { structural_path: "n/a", reason: "sink line maps to no function" });
});

test("both ends mapped and no connection in either direction => absent", () => {
  const graph = synth({ fns: LINE, calls: [["a", "b", "exact"], ["c", "d", "name-only"]] });
  assert.deepEqual(one(graph, ["a.js", 2], ["e.js", 2]), { structural_path: "absent", reason: "no connection within 6 edges" });
  assert.deepEqual(one(graph, ["a.js", 6], ["a.js", 10]), { structural_path: "absent", reason: "no connection within 6 edges" });
});

test("unresolved edges are never followed, even one that carries a target; null targets are skipped", () => {
  const graph = synth({ fns: LINE, calls: [["a", "b", "unresolved"], ["a", null, "unresolved"]] });
  assert.deepEqual(one(graph, ["a.js", 2], ["a.js", 6]), { structural_path: "absent", reason: "no connection within 6 edges" });
});

test("max_depth bounds the search in edges: a 3-edge exact path is absent at 2 and proven at 3", () => {
  const graph = synth({ fns: LINE, calls: [["a", "b", "exact"], ["b", "c", "exact"], ["c", "d", "exact"]] });
  assert.deepEqual(one(graph, ["a.js", 2], ["a.js", 14], { max_depth: 2 }), { structural_path: "absent", reason: "no connection within 2 edges" });
  assert.deepEqual(one(graph, ["a.js", 2], ["a.js", 14], { max_depth: 3 }), { structural_path: "proven", reason: "forward exact path (3 edges)" });
  assert.deepEqual(one(graph, ["a.js", 2], ["a.js", 14]), { structural_path: "proven", reason: "forward exact path (3 edges)" });
});

test("cycles terminate", () => {
  const graph = synth({ fns: LINE, calls: [["a", "b", "exact"], ["b", "a", "exact"], ["b", "b", "name-only"], ["c", "c", "exact"]] });
  assert.deepEqual(one(graph, ["a.js", 2], ["a.js", 10]), { structural_path: "absent", reason: "no connection within 6 edges" });
});

// ---- location mapping -------------------------------------------------------------------------------

test("enclosingFn: the innermost function containing the line (greatest line_start, then smallest line_end); none => null", () => {
  const graph = synth({ fns: { outer: ["a.js", 1, 20], inner: ["a.js", 5, 10], tight: ["a.js", 5, 8], other: ["b.js", 1, 20] } });
  const name = (f) => (f === null ? null : f.qualified_name);
  assert.equal(name(enclosingFn(graph, "a.js", 2)), "outer");
  assert.equal(name(enclosingFn(graph, "a.js", 9)), "inner");
  assert.equal(name(enclosingFn(graph, "a.js", 5)), "tight");
  assert.equal(name(enclosingFn(graph, "a.js", 8)), "tight");
  assert.equal(name(enclosingFn(graph, "a.js", 20)), "outer");
  assert.equal(name(enclosingFn(graph, "a.js", 21)), null);
  assert.equal(name(enclosingFn(graph, "c.js", 1)), null);
  // the innermost choice decides the verdict: inner -> other is exact, outer -> other is not
  const g2 = synth({ fns: { outer: ["a.js", 1, 20], inner: ["a.js", 5, 10], t: ["b.js", 1, 3] }, calls: [["inner", "t", "exact"]] });
  assert.equal(one(g2, ["a.js", 6], ["b.js", 2]).structural_path, "proven");
  assert.equal(one(g2, ["a.js", 2], ["b.js", 2]).structural_path, "absent");
});

test("finding paths are normalised (backslashes -> /, leading ./ stripped) before comparing with graph paths", () => {
  const graph = synth({ fns: { h: ["routes/a.js", 1, 3], s: ["svc/s.js", 1, 3] }, calls: [["h", "s", "exact"]] });
  assert.deepEqual(one(graph, ["routes\\a.js", 2], ["./svc/s.js", 2]), { structural_path: "proven", reason: "forward exact path (1 edges)" });
  assert.equal(enclosingFn(graph, ".\\routes\\a.js", 2).qualified_name, "h");
});

// ---- per-transition ---------------------------------------------------------------------------------

// Findings: OSWE-1 sink in a, OSWE-2 source in b, OSWE-3 source in e.  Calls a -> b exact, c -> d exact.
const TGRAPH = () => synth({ fns: LINE, calls: [["a", "b", "exact"], ["c", "d", "exact"]] });
const TFINDINGS = [
  finding("OSWE-1", ["a.js", 1], ["a.js", 2]),
  finding("OSWE-2", ["a.js", 6], ["a.js", 7]),
  finding("OSWE-3", ["e.js", 2], ["e.js", 3])
];
const tr = (chains, graph = TGRAPH()) => checkChainStructure({ graph, findings: TFINDINGS, chains }).transitions;

test("transition kind shared-state / auth-gain => n/a (not structurally checkable); no kind => n/a", () => {
  const out = tr([
    chain("CHAIN-1", [
      transition("OSWE-1", "OSWE-2", { kind: "shared-state" }),
      transition("OSWE-1", "OSWE-2", { kind: "auth-gain" }),
      transition("OSWE-1", "OSWE-2")
    ])
  ]);
  assert.deepEqual(out, {
    "CHAIN-1": [
      { index: 0, structural_path: "n/a", reason: "transition kind shared-state not structurally checkable" },
      { index: 1, structural_path: "n/a", reason: "transition kind auth-gain not structurally checkable" },
      { index: 2, structural_path: "n/a", reason: "transition has no kind" }
    ]
  });
});

test("call-path without anchors => the table between the from-finding's sink and the to-finding's source", () => {
  const out = tr([chain("CHAIN-1", [transition("OSWE-1", "OSWE-2", { kind: "call-path" }), transition("OSWE-1", "OSWE-3", { kind: "call-path" })])]);
  assert.deepEqual(out["CHAIN-1"], [
    { index: 0, structural_path: "proven", reason: "forward exact path (1 edges)" }, // a -> b
    { index: 1, structural_path: "absent", reason: "no connection within 6 edges" } // a .. e
  ]);
});

test("call-path with both anchors => evaluated between the anchors, not the findings' locations", () => {
  // the findings alone would give proven (a -> b); the anchors c -> d are also exact, d -> c is reverse, e is disconnected
  const anchors = (from, to) => ({ kind: "call-path", from_anchor: { file: "a.js", line: from }, to_anchor: { file: to[0], line: to[1] } });
  const out = tr([
    chain("CHAIN-1", [
      transition("OSWE-1", "OSWE-2", anchors(10, ["a.js", 14])),
      transition("OSWE-1", "OSWE-2", anchors(14, ["a.js", 10])),
      transition("OSWE-1", "OSWE-2", anchors(10, ["e.js", 2])),
      transition("OSWE-1", "OSWE-2", anchors(4, ["a.js", 6]))
    ])
  ]);
  assert.deepEqual(out["CHAIN-1"], [
    { index: 0, structural_path: "proven", reason: "forward exact path (1 edges)" },
    { index: 1, structural_path: "n/a", reason: "return-value flow not modelled" },
    { index: 2, structural_path: "absent", reason: "no connection within 6 edges" },
    { index: 3, structural_path: "n/a", reason: "source line maps to no function" }
  ]);
  // anchors make the finding lookup unnecessary: unknown ids are fine when both anchors are present
  const ghost = tr([chain("CHAIN-2", [transition("entry", "OSWE-99", anchors(10, ["a.js", 14]))])]);
  assert.deepEqual(ghost["CHAIN-2"], [{ index: 0, structural_path: "proven", reason: "forward exact path (1 edges)" }]);
});

test("call-path with only one anchor falls back to the findings' locations", () => {
  const out = tr([
    chain("CHAIN-1", [
      transition("OSWE-1", "OSWE-3", { kind: "call-path", from_anchor: { file: "a.js", line: 10 } }),
      transition("OSWE-1", "OSWE-2", { kind: "call-path", to_anchor: { file: "e.js", line: 2 } })
    ])
  ]);
  assert.deepEqual(out["CHAIN-1"], [
    { index: 0, structural_path: "absent", reason: "no connection within 6 edges" }, // OSWE-1 sink (a) .. OSWE-3 source (e)
    { index: 1, structural_path: "proven", reason: "forward exact path (1 edges)" } // OSWE-1 sink (a) -> OSWE-2 source (b)
  ]);
});

test("call-path referencing an unknown finding (from or to, e.g. the 'entry' pseudo-id) => n/a", () => {
  const out = tr([
    chain("CHAIN-1", [
      transition("entry", "OSWE-1", { kind: "call-path" }),
      transition("OSWE-1", "OSWE-42", { kind: "call-path" }),
      transition("entry", "OSWE-1", { kind: "shared-state" })
    ])
  ]);
  assert.deepEqual(out["CHAIN-1"], [
    { index: 0, structural_path: "n/a", reason: "transition references unknown finding" },
    { index: 1, structural_path: "n/a", reason: "transition references unknown finding" },
    { index: 2, structural_path: "n/a", reason: "transition kind shared-state not structurally checkable" }
  ]);
});

// ---- graph unavailable, output shape and order ------------------------------------------------------

test("graph null => every finding and every transition is n/a (graph unavailable)", () => {
  const out = checkChainStructure({
    graph: null,
    findings: TFINDINGS,
    chains: [chain("CHAIN-1", [transition("OSWE-1", "OSWE-2", { kind: "call-path" }), transition("OSWE-1", "OSWE-2")]), chain("CHAIN-2", [transition("x", "y")])]
  });
  const na = { structural_path: "n/a", reason: "graph unavailable" };
  assert.deepEqual(out, {
    findings: { "OSWE-1": na, "OSWE-2": na, "OSWE-3": na },
    transitions: { "CHAIN-1": [{ index: 0, ...na }, { index: 1, ...na }], "CHAIN-2": [{ index: 0, ...na }] }
  });
  assert.deepEqual(validate("structural-check", out), { valid: true, errors: [] });
});

test("output: findings keys in OSWE-N numeric order, transitions keys in CHAIN-N numeric order, schema-valid", () => {
  const graph = TGRAPH();
  const findings = ["OSWE-10", "OSWE-2", "OSWE-1"].map((id) => finding(id, ["a.js", 2], ["a.js", 2]));
  const chains = [chain("CHAIN-10", [transition("OSWE-1", "OSWE-2")]), chain("CHAIN-9", [transition("OSWE-1", "OSWE-2")]), chain("CHAIN-1", [transition("OSWE-1", "OSWE-2")])];
  const out = checkChainStructure({ graph, findings, chains });
  assert.deepEqual(Object.keys(out), ["findings", "transitions"]);
  assert.deepEqual(Object.keys(out.findings), ["OSWE-1", "OSWE-2", "OSWE-10"]);
  assert.deepEqual(Object.keys(out.transitions), ["CHAIN-1", "CHAIN-9", "CHAIN-10"]);
  assert.deepEqual(validate("structural-check", out), { valid: true, errors: [] });
  assert.deepEqual(checkChainStructure({ graph, findings: [], chains: [] }), { findings: {}, transitions: {} });
});

// ---- the real node golden ---------------------------------------------------------------------------

test("node golden: run -> UserService.run (exact) -> UserService.exec (name-only) and the unreachable DAO", () => {
  const out = checkChainStructure({
    graph: golden("node"),
    findings: [
      finding("OSWE-1", ["routes/users.js", 6], ["services/userService.js", 10]), // through the name-only this.exec edge
      finding("OSWE-2", ["services/userService.js", 5], ["services/userService.js", 7]), // both in UserService.run
      finding("OSWE-3", ["routes/users.js", 6], ["dao/userDao.js", 3]), // the nosql sink nothing reaches
      finding("OSWE-4", ["routes/users.js", 7], ["services/userService.js", 6]), // run -> UserService.run, exact
      finding("OSWE-5", ["services/userService.js", 6], ["routes/users.js", 7]) // reverse of OSWE-4
    ],
    chains: []
  });
  assert.deepEqual(out.findings, {
    "OSWE-1": { structural_path: "n/a", reason: "only non-exact edges connect source and sink" },
    "OSWE-2": { structural_path: "proven", reason: "same function" },
    "OSWE-3": { structural_path: "absent", reason: "no connection within 6 edges" },
    "OSWE-4": { structural_path: "proven", reason: "forward exact path (1 edges)" },
    "OSWE-5": { structural_path: "n/a", reason: "return-value flow not modelled" }
  });
});

test("determinism: two runs are byte-identical, and reversing graph.nodes / graph.edges changes nothing", () => {
  const reversed = (g) => ({ ...g, nodes: [...g.nodes].reverse(), edges: [...g.edges].reverse() });
  const nested = synth({ fns: { outer: ["a.js", 1, 20], inner: ["a.js", 5, 10], twin: ["a.js", 5, 10], t: ["b.js", 1, 3] }, calls: [["inner", "t", "exact"], ["twin", "t", "name-only"]] });
  const cases = [
    [golden("node"), [finding("OSWE-1", ["routes/users.js", 6], ["services/userService.js", 10]), finding("OSWE-2", ["routes/users.js", 6], ["dao/userDao.js", 3])]],
    [nested, [finding("OSWE-1", ["a.js", 6], ["b.js", 2]), finding("OSWE-2", ["a.js", 2], ["b.js", 2])]]
  ];
  for (const [graph, findings] of cases) {
    const chains = [chain("CHAIN-1", [transition("OSWE-1", "OSWE-2", { kind: "call-path" }), transition("OSWE-2", "OSWE-1")])];
    const a = JSON.stringify(checkChainStructure({ graph, findings, chains }));
    assert.equal(JSON.stringify(checkChainStructure({ graph, findings, chains })), a);
    assert.equal(JSON.stringify(checkChainStructure({ graph: reversed(graph), findings, chains })), a);
  }
});

test("checkChainStructure does not mutate its input", () => {
  const input = { graph: golden("node"), findings: [finding("OSWE-1", ["routes\\users.js", 6], ["./dao/userDao.js", 3])], chains: [chain("CHAIN-1", [transition("OSWE-1", "OSWE-1", { kind: "call-path" })])] };
  const before = JSON.stringify(input);
  checkChainStructure(input);
  assert.equal(JSON.stringify(input), before);
});

// ---- chain schema: typed transitions ----------------------------------------------------------------

test("chain schema: a call-path transition with anchors validates; a legacy transition without kind validates; kind magic fails", () => {
  const typed = chain("CHAIN-1", [transition("OSWE-1", "OSWE-2", { kind: "call-path", from_anchor: { file: "a.js", line: 2 }, to_anchor: { file: "b.js", line: 3 } })]);
  assert.deepEqual(validate("chain", typed), { valid: true, errors: [] });
  for (const kind of ["shared-state", "auth-gain"]) assert.equal(validate("chain", chain("CHAIN-1", [transition("OSWE-1", "OSWE-2", { kind })])).valid, true, kind);
  assert.deepEqual(validate("chain", chain("CHAIN-1", [transition("OSWE-1", "OSWE-2")])), { valid: true, errors: [] });
  assert.equal(validate("chain", chain("CHAIN-1", [transition("OSWE-1", "OSWE-2", { kind: "magic" })])).valid, false);
  assert.equal(validate("chain", chain("CHAIN-1", [transition("OSWE-1", "OSWE-2", { kind: "call-path", from_anchor: { file: "a.js" } })])).valid, false, "anchor without line");
  assert.equal(validate("chain", chain("CHAIN-1", [transition("OSWE-1", "OSWE-2", { kind: "call-path", to_anchor: { file: "a.js", line: 1, extra: 1 } })])).valid, false, "anchor with an extra key");
});

// ---- input validation (API) -------------------------------------------------------------------------

test("malformed input throws InputError: graph, findings, chains, max_depth", () => {
  const graph = golden("node");
  const f = [finding("OSWE-1", ["a.js", 1], ["a.js", 2])];
  const c = [chain("CHAIN-1", [transition("OSWE-1", "OSWE-1")])];
  const bad = [
    [undefined, "missing input"],
    [null, "null input"],
    [[], "array input"],
    [{ findings: f, chains: c }, "graph absent"],
    [{ graph: "g", findings: f, chains: c }, "graph a string"],
    [{ graph: { nodes: [] }, findings: f, chains: c }, "graph without edges"],
    [{ graph: { ...graph, version: 2 }, findings: f, chains: c }, "graph fails the schema"],
    [{ graph, chains: c }, "findings absent"],
    [{ graph, findings: {}, chains: c }, "findings not an array"],
    [{ graph, findings: [null], chains: c }, "finding null"],
    [{ graph, findings: [{ ...f[0], finding_id: "G-F001" }], chains: c }, "finding id not OSWE-N"],
    [{ graph, findings: [f[0], f[0]], chains: c }, "duplicate finding id"],
    [{ graph, findings: [{ ...f[0], source: undefined }], chains: c }, "finding without source"],
    [{ graph, findings: [{ ...f[0], sink: { file: "a.js", line: -1 } }], chains: c }, "sink line negative"],
    [{ graph, findings: [{ ...f[0], sink: { file: 3, line: 1 } }], chains: c }, "sink file not a string"],
    [{ graph, findings: f }, "chains absent"],
    [{ graph, findings: f, chains: "c" }, "chains not an array"],
    [{ graph, findings: f, chains: [{ ...c[0], chain_id: "C1" }] }, "chain id not CHAIN-N"],
    [{ graph, findings: f, chains: [c[0], c[0]] }, "duplicate chain id"],
    [{ graph, findings: f, chains: [{ ...c[0], transitions: null }] }, "transitions not an array"],
    [{ graph, findings: f, chains: [chain("CHAIN-1", [null])] }, "transition null"],
    [{ graph, findings: f, chains: [chain("CHAIN-1", [{ ...transition("OSWE-1", "x"), from: 1 }])] }, "transition from not a string"],
    [{ graph, findings: f, chains: [chain("CHAIN-1", [transition("OSWE-1", "OSWE-1", { kind: 7 })])] }, "kind not a string"],
    [{ graph, findings: f, chains: [chain("CHAIN-1", [transition("OSWE-1", "OSWE-1", { from_anchor: { file: "a.js" } })])] }, "anchor without line"],
    ...[0, -1, 1.5, "6", null, true, [3]].map((v) => [{ graph, findings: f, chains: c, max_depth: v }, `max_depth ${JSON.stringify(v)}`])
  ];
  for (const [input, why] of bad) {
    assert.throws(() => checkChainStructure(input), (e) => e instanceof InputError && /^bad input: /.test(e.message), why);
  }
  // graph null is well-formed (no graph), but the rest of the input is still checked
  assert.throws(() => checkChainStructure({ graph: null, findings: f }), InputError);
  assert.throws(() => checkChainStructure({ graph: null, findings: f, chains: c, max_depth: 0 }), InputError);
});

// ---- CLI --------------------------------------------------------------------------------------------

function runCli(t, input, { raw = null, outName = "out.json", graphFile = null } = {}) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-check-chain-structure-")));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const inFile = join(dir, "in.json");
  const outFile = join(dir, outName);
  writeFileSync(inFile, raw ?? JSON.stringify(input));
  const r = spawnSync(process.execPath, [CLI, "--file", inFile, "--out", outFile, ...(graphFile ? ["--graph", graphFile] : [])], { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, out: existsSync(outFile) ? readFileSync(outFile, "utf8") : null };
}

test("CLI: exit 0 and the same JSON as the API, pretty-printed; max_depth honoured; graph null is exit 0", (t) => {
  const input = {
    graph: golden("node"),
    findings: [finding("OSWE-1", ["routes/users.js", 6], ["services/userService.js", 10]), finding("OSWE-2", ["routes/users.js", 7], ["services/userService.js", 6])],
    chains: [chain("CHAIN-1", [transition("OSWE-2", "OSWE-1", { kind: "call-path" })])]
  };
  for (const variant of [input, { ...input, max_depth: 1 }, { ...input, graph: null }]) {
    const r = runCli(t, variant);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stderr, "");
    assert.equal(r.stdout, "");
    assert.equal(r.out, JSON.stringify(checkChainStructure(variant), null, 2) + "\n");
  }
});

test("CLI: exit 1 (and no output file) for a schema-invalid graph, missing findings, max_depth 0, a non-object input", (t) => {
  const graph = golden("node");
  const cases = [
    [{ graph: { ...graph, version: 2 }, findings: [], chains: [] }, /schema/],
    [{ graph, chains: [] }, /findings/],
    [{ graph, findings: [], chains: [], max_depth: 0 }, /max_depth/]
  ];
  for (const [input, re] of cases) {
    const r = runCli(t, input);
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stderr, re);
    assert.equal(r.out, null, "no output written on malformed input");
  }
  assert.equal(runCli(t, null, { raw: "[]" }).status, 1);
});

test("CLI: exit 2 for an unreadable --file, invalid JSON, an unwritable --out, and usage errors", (t) => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-check-chain-structure-")));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const missing = spawnSync(process.execPath, [CLI, "--file", join(dir, "nope.json"), "--out", join(dir, "out.json")], { encoding: "utf8" });
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /cannot read --file/);
  assert.equal(runCli(t, null, { raw: "{not json" }).status, 2);
  const unwritable = runCli(t, { graph: null, findings: [], chains: [] }, { outName: join("no-such-dir", "out.json") });
  assert.equal(unwritable.status, 2, unwritable.stderr);
  assert.match(unwritable.stderr, /cannot write --out/);
  const noOut = spawnSync(process.execPath, [CLI, "--file", join(dir, "x.json")], { encoding: "utf8" });
  assert.equal(noOut.status, 2);
  assert.match(noOut.stderr, /usage/);
});

test("CLI --graph <path>: a golden file = the inline API call; envelopes; inline graph superseded; unreadable file exit 2", (t) => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-check-chain-structure-")));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const goldenFile = join(FIXTURES_DIR, "node", "graph.expected.json");
  const nullEnvelope = join(dir, "graph-null.json");
  writeFileSync(nullEnvelope, JSON.stringify({ graph: null, reason: "parser unavailable" }));
  const objEnvelope = join(dir, "graph-obj.json");
  writeFileSync(objEnvelope, JSON.stringify({ graph: golden("node") }));
  const withGraph = (graphFile, input) => runCli(t, null, { raw: JSON.stringify(input), graphFile });
  const rest = {
    findings: [finding("OSWE-1", ["routes/users.js", 6], ["services/userService.js", 10]), finding("OSWE-2", ["routes/users.js", 7], ["services/userService.js", 6])],
    chains: [chain("CHAIN-1", [transition("OSWE-2", "OSWE-1", { kind: "call-path" })])]
  };
  const expected = JSON.stringify(checkChainStructure({ graph: golden("node"), ...rest }), null, 2) + "\n";
  for (const input of [rest, { graph: "junk", ...rest }]) {
    for (const file of [goldenFile, objEnvelope]) {
      const r = withGraph(file, input);
      assert.equal(r.status, 0, r.stderr);
      assert.equal(r.stderr, "");
      assert.equal(r.out, expected);
    }
  }
  // The { graph: null } envelope is graph null => every finding and transition n/a, even over an inline graph.
  const nul = withGraph(nullEnvelope, { graph: golden("node"), ...rest });
  assert.equal(nul.status, 0, nul.stderr);
  assert.equal(nul.out, JSON.stringify(checkChainStructure({ graph: null, ...rest }), null, 2) + "\n");
  const out = JSON.parse(nul.out);
  for (const v of Object.values(out.findings)) assert.equal(v.structural_path, "n/a");
  for (const list of Object.values(out.transitions)) for (const v of list) assert.equal(v.structural_path, "n/a");
  const missing = withGraph(join(dir, "nope.json"), rest);
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /cannot read --graph/);
  assert.equal(missing.out, null);
  const notJson = join(dir, "bad.json");
  writeFileSync(notJson, "{not json");
  assert.equal(withGraph(notJson, rest).status, 2);
  const invalid = join(dir, "invalid.json");
  writeFileSync(invalid, JSON.stringify({ ...golden("node"), version: 2 }));
  const inv = withGraph(invalid, rest);
  assert.equal(inv.status, 1, "validate(graph) still applies to the loaded graph");
  assert.match(inv.stderr, /schema/);
});
