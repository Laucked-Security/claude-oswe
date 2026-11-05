import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { partitionGraph, InputError } from "../partition-graph.mjs";
import { validate } from "../validate-output.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPTS_DIR = join(HERE, "..");
const REPO_ROOT = join(SCRIPTS_DIR, "..", "..", "..");
const FIXTURES_DIR = join(REPO_ROOT, "test-fixtures", "graph");
const CLI = join(SCRIPTS_DIR, "partition-graph.mjs");
const STACKS = ["node", "python", "java", "php", "dotnet"];

const golden = (stack) => JSON.parse(readFileSync(join(FIXTURES_DIR, stack, "graph.expected.json"), "utf8"));
const fileNodes = (graph) => graph.nodes.filter((n) => n.type === "file");
const routeNodes = (graph) => graph.nodes.filter((n) => n.type === "route");
const partitionById = (out, id) => out.partitions.find((p) => p.partition_id === id);
const allFiles = (out) => out.partitions.flatMap((p) => p.files);

// The node tree's directory partitioning as the orchestrator would hand it over: the route and
// service code in one partition, the DAO in another.
const NODE_FALLBACK = [
  { partition_id: "node-app", stack: "node", files: ["routes/users.js", "server.js", "services/userService.js"] },
  { partition_id: "node-data", stack: "node", files: ["dao/userDao.js"] }
];

let nextId = 0;
const hex12 = () => (++nextId).toString(16).padStart(12, "0");
const ZERO_STATS = {
  files_total: 0, files_parsed: 0, files_error: 0, files_skipped: 0, functions: 0, calls_total: 0, calls_exact: 0,
  calls_name_only: 0, calls_unresolved: 0, routes_by_auth: { unauthenticated: 0, authenticated: 0, unknown: 0 },
  coverage_matrix: {}, config_errors: []
};

// Schema-valid synthetic graph from a compact description:
//   files:  [path | [path, stack]]          (stack defaults to "node")
//   fns:    { name: file }                  (function ids are derived from the name)
//   routes: [{ file, auth, handler?, middlewares? }]   (handler / middlewares name functions)
//   calls:  [[fromName, toName | null, confidence]]
function synth({ files = [], fns = {}, routes = [], calls = [] }) {
  const fnId = Object.fromEntries(Object.keys(fns).map((name) => [name, hex12()]));
  const nodes = [];
  const edges = [];
  for (const f of files) {
    const [path, stack = "node"] = Array.isArray(f) ? f : [f];
    nodes.push({ type: "file", id: hex12(), path, stack, lang: "javascript", parse_status: "ok" });
  }
  for (const [name, file] of Object.entries(fns)) {
    nodes.push({ type: "function", id: fnId[name], file, name, qualified_name: name, line_start: 1, line_end: 2, kind: "function", exported: false });
  }
  for (const r of routes) {
    const id = hex12();
    nodes.push({
      type: "route", id, file: r.file, line: 1, http_method: "GET", path_pattern: "/x", handler: r.handler ? fnId[r.handler] : null,
      middlewares: (r.middlewares ?? []).map((m) => fnId[m]), framework: "express", auth: r.auth
    });
    if (r.handler) edges.push({ type: "handles", from: id, to: fnId[r.handler] });
    (r.middlewares ?? []).forEach((m, order) => edges.push({ type: "uses_middleware", from: id, to: fnId[m], order }));
  }
  for (const [from, to, confidence] of calls) {
    edges.push({ type: "calls", from: fnId[from], to: to ? fnId[to] : null, line: 1, callee_text: to ?? "unknown", confidence });
  }
  const graph = { version: 1, generated_by: "test", stats: ZERO_STATS, nodes, edges };
  assert.deepEqual(validate("graph", graph), { valid: true, errors: [] }, "the synthetic graph must itself be schema-valid");
  return graph;
}

const fallbackOf = (...partitions) => partitions.map(([partition_id, stack, files]) => ({ partition_id, stack, files }));

// ---- fallback: byte-identical to the orchestrator's own partitions ----------------------------------

test("graph: null -> fallback; partitions are the input objects, in order, byte-identical; no orphans", () => {
  const fallback_partitions = [
    { partition_id: "z-last", stack: "php", files: ["b.php", "a.php"] },
    { partition_id: "a-first", stack: "node", files: ["x/y.js"] }
  ];
  const out = partitionGraph({ graph: null, fallback_partitions });
  assert.equal(out.mode, "fallback");
  assert.deepEqual(out.partitions, fallback_partitions);
  assert.equal(JSON.stringify(out.partitions), JSON.stringify(fallback_partitions));
  out.partitions.forEach((p, i) => assert.equal(p, fallback_partitions[i], "same objects, not copies"));
  assert.deepEqual(out.orphan_partition_ids, []);
});

test("a real graph with no route nodes -> fallback, byte-identical (every golden stack)", () => {
  for (const stack of STACKS) {
    const g = golden(stack);
    const noRoutes = {
      ...g,
      nodes: g.nodes.filter((n) => n.type !== "route"),
      edges: g.edges.filter((e) => e.type !== "handles" && e.type !== "uses_middleware")
    };
    assert.equal(validate("graph", noRoutes).valid, true, stack);
    const fallback_partitions = [{ partition_id: `${stack}-all`, stack, files: fileNodes(g).map((f) => f.path).reverse() }];
    const out = partitionGraph({ graph: noRoutes, fallback_partitions });
    assert.equal(out.mode, "fallback", stack);
    assert.equal(JSON.stringify(out.partitions), JSON.stringify(fallback_partitions), stack);
    assert.deepEqual(out.orphan_partition_ids, [], stack);
  }
});

test("fallback mode accepts an empty fallback_partitions array", () => {
  const out = partitionGraph({ graph: null, fallback_partitions: [] });
  assert.deepEqual(out, { mode: "fallback", partitions: [], orphan_partition_ids: [] });
});

// ---- graph mode on the real node golden --------------------------------------------------------------

test("node golden: authenticated routes group + unauthenticated root group + a named orphan partition", () => {
  const out = partitionGraph({ graph: golden("node"), fallback_partitions: NODE_FALLBACK });
  assert.equal(out.mode, "graph");
  assert.deepEqual(out.partitions, [
    { partition_id: "g-node-authenticated-routes", stack: "node", files: ["routes/users.js", "services/userService.js"] },
    { partition_id: "g-node-unauthenticated-root", stack: "node", files: ["server.js"] },
    { partition_id: "node-data-orphan", stack: "node", files: ["dao/userDao.js"] }
  ]);
  assert.deepEqual(out.orphan_partition_ids, ["node-data-orphan"]);
});

test("node golden: server.js hosts the middleware the authenticated route uses AND the /health route; it stays with its own route group", () => {
  const out = partitionGraph({ graph: golden("node"), fallback_partitions: NODE_FALLBACK });
  assert.ok(partitionById(out, "g-node-unauthenticated-root").files.includes("server.js"));
  assert.equal(allFiles(out).filter((f) => f === "server.js").length, 1);
});

test("every golden: graph mode, every file at most once, route files claimed, files sorted, ids unique", () => {
  for (const stack of STACKS) {
    const g = golden(stack);
    const paths = fileNodes(g).map((f) => f.path);
    const out = partitionGraph({ graph: g, fallback_partitions: [{ partition_id: `${stack}-all`, stack, files: paths }] });
    assert.equal(out.mode, "graph", stack);
    const files = allFiles(out);
    assert.equal(new Set(files).size, files.length, `${stack}: no file in two partitions`);
    assert.deepEqual([...files].sort(), [...paths].sort(), `${stack}: every file ends up in exactly one partition`);
    for (const r of routeNodes(g)) assert.ok(files.includes(r.file), `${stack}: route file ${r.file} claimed`);
    const ids = out.partitions.map((p) => p.partition_id);
    assert.equal(new Set(ids).size, ids.length, `${stack}: partition ids unique`);
    for (const p of out.partitions) {
      assert.deepEqual(p.files, [...p.files].sort(), `${stack}/${p.partition_id}: files sorted`);
      assert.ok(p.files.length > 0, `${stack}/${p.partition_id}: no empty partition`);
      assert.deepEqual(Object.keys(p), ["partition_id", "stack", "files"]);
    }
    const groups = out.partitions.filter((p) => p.partition_id.startsWith("g-"));
    assert.deepEqual(groups.map((p) => p.partition_id), groups.map((p) => p.partition_id).sort(), `${stack}: groups in sorted id order`);
    for (const p of groups) assert.match(p.partition_id, new RegExp(`^g-${stack}-(authenticated|unauthenticated|unknown)-[A-Za-z0-9_.-]+$`));
  }
});

// ---- reachability -------------------------------------------------------------------------------------

test("reachability: handler + middleware files, transitive exact and name-only calls, cycles terminate", () => {
  const graph = synth({
    files: ["routes/a.js", "mw/auth.js", "svc/one.js", "svc/two.js", "svc/three.js", "svc/four.js", "lonely.js"],
    fns: { handler: "routes/a.js", guard: "mw/auth.js", one: "svc/one.js", two: "svc/two.js", three: "svc/three.js", four: "svc/four.js", lonely: "lonely.js" },
    routes: [{ file: "routes/a.js", auth: "authenticated", handler: "handler", middlewares: ["guard"] }],
    calls: [
      ["handler", "one", "exact"], ["one", "two", "name-only"], ["two", "three", "exact"], ["three", "two", "exact"], // cycle
      ["guard", "four", "name-only"], ["four", "four", "exact"]
    ]
  });
  const out = partitionGraph({ graph, fallback_partitions: fallbackOf(["all", "node", ["routes/a.js", "mw/auth.js", "svc/one.js", "svc/two.js", "svc/three.js", "svc/four.js", "lonely.js"]]) });
  assert.deepEqual(partitionById(out, "g-node-authenticated-routes").files, [
    "mw/auth.js", "routes/a.js", "svc/four.js", "svc/one.js", "svc/three.js", "svc/two.js"
  ]);
  assert.deepEqual(partitionById(out, "all-orphan").files, ["lonely.js"]);
});

test("unresolved calls edges are never followed", () => {
  const graph = synth({
    files: ["routes/a.js", "svc/unreached.js", "svc/reached.js"],
    fns: { handler: "routes/a.js", ghost: "svc/unreached.js", real: "svc/reached.js" },
    routes: [{ file: "routes/a.js", auth: "unknown", handler: "handler" }],
    // an `unresolved` edge that nevertheless carries a `to` must still be ignored
    calls: [["handler", "ghost", "unresolved"], ["handler", null, "unresolved"], ["handler", "real", "name-only"]]
  });
  const out = partitionGraph({ graph, fallback_partitions: fallbackOf(["all", "node", ["routes/a.js", "svc/unreached.js", "svc/reached.js"]]) });
  assert.deepEqual(partitionById(out, "g-node-unknown-routes").files, ["routes/a.js", "svc/reached.js"]);
  assert.deepEqual(partitionById(out, "all-orphan").files, ["svc/unreached.js"]);
});

test("a handler-less route still anchors its own file", () => {
  const graph = synth({ files: ["app.js"], routes: [{ file: "app.js", auth: "unauthenticated" }] });
  const out = partitionGraph({ graph, fallback_partitions: fallbackOf(["all", "node", ["app.js"]]) });
  assert.deepEqual(out.partitions, [{ partition_id: "g-node-unauthenticated-root", stack: "node", files: ["app.js"] }]);
  assert.deepEqual(out.orphan_partition_ids, []);
});

// ---- grouping -----------------------------------------------------------------------------------------

test("groups by (stack, auth, first path segment); a top-level file is `root`; ids sanitised; sorted", () => {
  const graph = synth({
    files: [["routes/a.js", "node"], ["routes/b.js", "node"], ["api/v1/c.js", "node"], ["top.js", "node"], ["my app/d.js", "node"], ["views/e.py", "python"]],
    routes: [
      { file: "routes/b.js", auth: "authenticated" },
      { file: "routes/a.js", auth: "authenticated" },
      { file: "routes/a.js", auth: "unauthenticated" },
      { file: "api/v1/c.js", auth: "unknown" },
      { file: "top.js", auth: "unauthenticated" },
      { file: "my app/d.js", auth: "authenticated" },
      { file: "views/e.py", auth: "authenticated" }
    ]
  });
  const out = partitionGraph({ graph, fallback_partitions: [] });
  // routes/a.js hosts an unauthenticated route too (group g-node-unauthenticated-routes), but the
  // sorted-earlier authenticated group claims the file first, which leaves that group with nothing:
  // it is omitted rather than emitted empty.
  assert.deepEqual(out.partitions, [
    { partition_id: "g-node-authenticated-my_app", stack: "node", files: ["my app/d.js"] },
    { partition_id: "g-node-authenticated-routes", stack: "node", files: ["routes/a.js", "routes/b.js"] },
    { partition_id: "g-node-unauthenticated-root", stack: "node", files: ["top.js"] },
    { partition_id: "g-node-unknown-api", stack: "node", files: ["api/v1/c.js"] },
    { partition_id: "g-python-authenticated-views", stack: "python", files: ["views/e.py"] }
  ]);
  assert.deepEqual(out.orphan_partition_ids, []);
});

test("directories that sanitise to the same id merge into one partition (ids stay unique)", () => {
  const graph = synth({
    files: ["my app/a.js", "my_app/b.js"],
    routes: [{ file: "my app/a.js", auth: "unknown" }, { file: "my_app/b.js", auth: "unknown" }]
  });
  const out = partitionGraph({ graph, fallback_partitions: [] });
  assert.deepEqual(out.partitions, [{ partition_id: "g-node-unknown-my_app", stack: "node", files: ["my app/a.js", "my_app/b.js"] }]);
});

test("a file reachable from two groups appears once, in the first group in sorted id order", () => {
  const graph = synth({
    files: ["routes/a.js", "server.js", "shared/util.js", "only/auth.js", "only/open.js"],
    fns: { a: "routes/a.js", s: "server.js", util: "shared/util.js", onlyAuth: "only/auth.js", onlyOpen: "only/open.js" },
    routes: [
      { file: "server.js", auth: "unauthenticated", handler: "s" },
      { file: "routes/a.js", auth: "authenticated", handler: "a" }
    ],
    calls: [["a", "util", "exact"], ["s", "util", "exact"], ["a", "onlyAuth", "exact"], ["s", "onlyOpen", "name-only"]]
  });
  const out = partitionGraph({ graph, fallback_partitions: fallbackOf(["all", "node", ["routes/a.js", "server.js", "shared/util.js", "only/auth.js", "only/open.js"]]) });
  assert.deepEqual(out.partitions, [
    { partition_id: "g-node-authenticated-routes", stack: "node", files: ["only/auth.js", "routes/a.js", "shared/util.js"] },
    { partition_id: "g-node-unauthenticated-root", stack: "node", files: ["only/open.js", "server.js"] }
  ]);
  assert.equal(allFiles(out).filter((f) => f === "shared/util.js").length, 1);
});

test("a route file belongs to its own group even when an earlier group reaches it", () => {
  const graph = synth({
    files: ["routes/a.js", "z/late.js"],
    fns: { a: "routes/a.js", late: "z/late.js" },
    routes: [{ file: "routes/a.js", auth: "authenticated", handler: "a" }, { file: "z/late.js", auth: "unauthenticated", handler: "late" }],
    calls: [["a", "late", "exact"]]
  });
  const out = partitionGraph({ graph, fallback_partitions: [] });
  assert.deepEqual(out.partitions, [
    { partition_id: "g-node-authenticated-routes", stack: "node", files: ["routes/a.js"] },
    { partition_id: "g-node-unauthenticated-z", stack: "node", files: ["z/late.js"] }
  ]);
});

// ---- orphans ------------------------------------------------------------------------------------------

test("orphans are cut by fallback membership, in fallback order, named <id>-orphan, files sorted", () => {
  const graph = synth({
    files: ["routes/a.js", "dao/b.js", "dao/a.js", "lib/c.js", "stray/d.js"],
    routes: [{ file: "routes/a.js", auth: "authenticated" }]
  });
  const out = partitionGraph({
    graph,
    fallback_partitions: fallbackOf(
      ["zz-lib", "node", ["lib/c.js"]],
      ["routes-only", "node", ["routes/a.js"]], // fully claimed by a group -> no orphan partition
      ["aa-dao", "node", ["dao/b.js", "dao/a.js"]]
    )
  });
  assert.deepEqual(out.partitions, [
    { partition_id: "g-node-authenticated-routes", stack: "node", files: ["routes/a.js"] },
    { partition_id: "zz-lib-orphan", stack: "node", files: ["lib/c.js"] },
    { partition_id: "aa-dao-orphan", stack: "node", files: ["dao/a.js", "dao/b.js"] }
  ]);
  assert.deepEqual(out.orphan_partition_ids, ["zz-lib-orphan", "aa-dao-orphan"]);
  // stray/d.js is a graph file in no fallback partition: the orchestrator chose not to analyse it
  assert.ok(!allFiles(out).includes("stray/d.js"));
});

test("orphan partitions take the fallback partition's stack", () => {
  const graph = synth({ files: ["routes/a.js", "x.py"], routes: [{ file: "routes/a.js", auth: "unknown" }] });
  const out = partitionGraph({ graph, fallback_partitions: fallbackOf(["py", "python", ["x.py"]]) });
  assert.deepEqual(partitionById(out, "py-orphan"), { partition_id: "py-orphan", stack: "python", files: ["x.py"] });
});

test("a file present in two fallback partitions lands in exactly one orphan partition (the first)", () => {
  const graph = synth({ files: ["routes/a.js", "dup.js", "only2.js"], routes: [{ file: "routes/a.js", auth: "unknown" }] });
  const out = partitionGraph({
    graph,
    fallback_partitions: fallbackOf(["first", "node", ["dup.js"]], ["second", "node", ["only2.js", "dup.js"]])
  });
  assert.equal(allFiles(out).filter((f) => f === "dup.js").length, 1);
  assert.deepEqual(partitionById(out, "first-orphan").files, ["dup.js"]);
  assert.deepEqual(partitionById(out, "second-orphan").files, ["only2.js"]);
  assert.deepEqual(out.orphan_partition_ids, ["first-orphan", "second-orphan"]);
});

test("fallback files the graph never parsed (templates, configs) are not dropped: they stay in their orphan partition", () => {
  const graph = synth({ files: ["routes/a.js"], routes: [{ file: "routes/a.js", auth: "authenticated" }] });
  const out = partitionGraph({
    graph,
    fallback_partitions: fallbackOf(["app", "node", ["routes/a.js", "views/index.ejs", "config/app.yml"]])
  });
  assert.deepEqual(out.partitions, [
    { partition_id: "g-node-authenticated-routes", stack: "node", files: ["routes/a.js"] },
    { partition_id: "app-orphan", stack: "node", files: ["config/app.yml", "views/index.ejs"] }
  ]);
});

test("a fallback file claimed by a group is not repeated in the orphans", () => {
  const graph = synth({
    files: ["routes/a.js", "svc/s.js"],
    fns: { a: "routes/a.js", s: "svc/s.js" },
    routes: [{ file: "routes/a.js", auth: "authenticated", handler: "a" }],
    calls: [["a", "s", "exact"]]
  });
  const out = partitionGraph({ graph, fallback_partitions: fallbackOf(["dir-svc", "node", ["svc/s.js"]]) });
  assert.deepEqual(out.orphan_partition_ids, []);
  assert.equal(allFiles(out).filter((f) => f === "svc/s.js").length, 1);
});

// ---- determinism / platform ---------------------------------------------------------------------------

test("the result does not depend on the order of the graph's nodes and edges", () => {
  const g = golden("python");
  const paths = fileNodes(g).map((f) => f.path);
  const fallback_partitions = [{ partition_id: "py", stack: "python", files: paths }];
  const forward = partitionGraph({ graph: g, fallback_partitions });
  const reversed = partitionGraph({ graph: { ...g, nodes: [...g.nodes].reverse(), edges: [...g.edges].reverse() }, fallback_partitions });
  assert.deepEqual(reversed, forward);
});

test("partitionGraph does not mutate its input", () => {
  const graph = golden("node");
  const fallback_partitions = JSON.parse(JSON.stringify(NODE_FALLBACK));
  const before = JSON.stringify({ graph, fallback_partitions });
  partitionGraph({ graph, fallback_partitions });
  assert.equal(JSON.stringify({ graph, fallback_partitions }), before);
});

test("windows: path comparison is case-insensitive (Routes/Users.js == routes/users.js); other platforms are case-sensitive", (t) => {
  if (process.platform !== "win32") return t.skip("case-insensitive path comparison applies to win32 only");
  const graph = synth({
    files: ["routes/users.js", "Routes/Users.js", "svc/s.js", "SVC/S.js"],
    fns: { h: "Routes/Users.js", s: "SVC/S.js" },
    routes: [{ file: "routes/users.js", auth: "authenticated", handler: "h" }],
    calls: [["h", "s", "exact"]]
  });
  const out = partitionGraph({
    graph,
    fallback_partitions: fallbackOf(["dirs", "node", ["ROUTES/USERS.JS", "Svc/s.js", "other.js"]])
  });
  // one entry per file, in the spelling first seen (the route's own file; the function's file for svc)
  assert.deepEqual(partitionById(out, "g-node-authenticated-routes").files, ["SVC/S.js", "routes/users.js"]);
  assert.deepEqual(partitionById(out, "dirs-orphan").files, ["other.js"]);
  assert.equal(allFiles(out).length, 3);
});

// ---- input validation (API) ---------------------------------------------------------------------------

test("malformed input throws: fallback_partitions, graph shape, schema-invalid graph", () => {
  const ok = [{ partition_id: "p", stack: "node", files: ["a.js"] }];
  const bad = [
    [undefined, "missing input"],
    [{ graph: null }, "fallback_partitions missing"],
    [{ graph: null, fallback_partitions: {} }, "fallback_partitions not an array"],
    [{ graph: null, fallback_partitions: [null] }, "partition not an object"],
    [{ graph: null, fallback_partitions: [{ partition_id: "p", stack: "node" }] }, "files missing"],
    [{ graph: null, fallback_partitions: [{ partition_id: "p", stack: "node", files: [1] }] }, "file not a string"],
    [{ graph: null, fallback_partitions: [{ partition_id: 7, stack: "node", files: [] }] }, "partition_id not a string"],
    [{ graph: null, fallback_partitions: [{ partition_id: "p", stack: null, files: [] }] }, "stack not a string"],
    [{ fallback_partitions: ok }, "graph undefined (must be null, not absent)"],
    [{ graph: "g", fallback_partitions: ok }, "graph a string"],
    [{ graph: [], fallback_partitions: ok }, "graph an array"],
    [{ graph: { edges: [] }, fallback_partitions: ok }, "graph without nodes"],
    [{ graph: { nodes: [] }, fallback_partitions: ok }, "graph without edges"],
    [{ graph: { ...golden("node"), version: 2 }, fallback_partitions: ok }, "graph fails the schema"]
  ];
  for (const [input, why] of bad) {
    assert.throws(() => partitionGraph(input), (e) => e instanceof InputError && /^bad input: /.test(e.message), why);
  }
});

// ---- CLI ----------------------------------------------------------------------------------------------

function runCli(t, input, { raw = null, outName = "out.json", args = null, graphFile = null } = {}) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-partition-graph-")));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const inFile = join(dir, "in.json");
  const outFile = join(dir, outName);
  writeFileSync(inFile, raw ?? JSON.stringify(input));
  const r = spawnSync(process.execPath, args ?? [CLI, "--file", inFile, "--out", outFile, ...(graphFile ? ["--graph", graphFile] : [])], { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, out: existsSync(outFile) ? readFileSync(outFile, "utf8") : null };
}

test("CLI: exit 0 and the same JSON as the API (graph mode)", (t) => {
  const input = { graph: golden("node"), fallback_partitions: NODE_FALLBACK };
  const r = runCli(t, input);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stderr, "");
  assert.equal(r.stdout, "");
  assert.deepEqual(JSON.parse(r.out), partitionGraph(input));
});

test("CLI: graph null -> exit 0, fallback, partitions byte-identical to the input's", (t) => {
  const input = { graph: null, fallback_partitions: [{ partition_id: "b", stack: "php", files: ["z.php", "a.php"] }, { partition_id: "a", stack: "node", files: ["m.js"] }] };
  const r = runCli(t, input);
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.out);
  assert.equal(out.mode, "fallback");
  assert.equal(JSON.stringify(out.partitions), JSON.stringify(input.fallback_partitions));
  assert.deepEqual(out.orphan_partition_ids, []);
  assert.deepEqual(out, partitionGraph(input));
});

test("CLI: exit 1 for a missing fallback_partitions", (t) => {
  const r = runCli(t, { graph: null });
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stderr, /fallback_partitions/);
  assert.equal(r.out, null, "no output written on malformed input");
});

test("CLI: exit 1 for a graph missing nodes", (t) => {
  const noNodes = golden("node");
  delete noNodes.nodes;
  const r = runCli(t, { graph: noNodes, fallback_partitions: NODE_FALLBACK });
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stderr, /nodes/);
  assert.equal(r.out, null);
});

test("CLI: exit 1 for a graph that fails the schema, and for a non-object input", (t) => {
  const invalid = runCli(t, { graph: { ...golden("node"), version: 2 }, fallback_partitions: NODE_FALLBACK });
  assert.equal(invalid.status, 1, invalid.stderr);
  assert.match(invalid.stderr, /schema/);
  const array = runCli(t, null, { raw: "[]" });
  assert.equal(array.status, 1, array.stderr);
});

test("CLI: exit 2 for an unreadable --file, an unwritable --out, and usage errors", (t) => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-partition-graph-")));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const missing = spawnSync(process.execPath, [CLI, "--file", join(dir, "nope.json"), "--out", join(dir, "out.json")], { encoding: "utf8" });
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /cannot read --file/);
  const notJson = runCli(t, null, { raw: "{not json" });
  assert.equal(notJson.status, 2, notJson.stderr);
  const unwritable = runCli(t, { graph: null, fallback_partitions: [] }, { outName: join("no-such-dir", "out.json") });
  assert.equal(unwritable.status, 2, unwritable.stderr);
  assert.match(unwritable.stderr, /cannot write --out/);
  const noOut = spawnSync(process.execPath, [CLI, "--file", join(dir, "x.json")], { encoding: "utf8" });
  assert.equal(noOut.status, 2);
  assert.match(noOut.stderr, /usage/);
  const none = spawnSync(process.execPath, [CLI], { encoding: "utf8" });
  assert.equal(none.status, 2);
});

test("CLI --graph <path>: a golden file = the inline API call; envelopes; inline graph superseded; unreadable file exit 2", (t) => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-partition-graph-")));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const goldenFile = join(FIXTURES_DIR, "node", "graph.expected.json");
  const nullEnvelope = join(dir, "graph-null.json");
  writeFileSync(nullEnvelope, JSON.stringify({ graph: null, reason: "parser unavailable" }));
  const objEnvelope = join(dir, "graph-obj.json");
  writeFileSync(objEnvelope, JSON.stringify({ graph: golden("node") }));
  const withGraph = (graphFile, input) => runCli(t, null, { raw: JSON.stringify(input), args: null, graphFile });
  // The inline graph key is omitted (first) or junk that must be ignored (second): --graph supersedes it.
  for (const input of [{ fallback_partitions: NODE_FALLBACK }, { graph: "junk", fallback_partitions: NODE_FALLBACK }]) {
    for (const file of [goldenFile, objEnvelope]) {
      const r = withGraph(file, input);
      assert.equal(r.status, 0, r.stderr);
      assert.equal(r.stderr, "");
      assert.equal(r.out, JSON.stringify(partitionGraph({ graph: golden("node"), fallback_partitions: NODE_FALLBACK }), null, 2) + "\n");
    }
  }
  const fb = withGraph(nullEnvelope, { graph: golden("node"), fallback_partitions: NODE_FALLBACK });
  assert.equal(fb.status, 0, fb.stderr);
  const out = JSON.parse(fb.out);
  assert.equal(out.mode, "fallback", "the { graph: null } envelope is graph null");
  assert.equal(JSON.stringify(out.partitions), JSON.stringify(NODE_FALLBACK));
  const missing = withGraph(join(dir, "nope.json"), { fallback_partitions: NODE_FALLBACK });
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /cannot read --graph/);
  assert.equal(missing.out, null);
  const notJson = join(dir, "bad.json");
  writeFileSync(notJson, "{not json");
  assert.equal(withGraph(notJson, { fallback_partitions: NODE_FALLBACK }).status, 2);
  const invalid = join(dir, "invalid.json");
  writeFileSync(invalid, JSON.stringify({ ...golden("node"), version: 2 }));
  const inv = withGraph(invalid, { fallback_partitions: NODE_FALLBACK });
  assert.equal(inv.status, 1, "validate(graph) still applies to the loaded graph");
  assert.match(inv.stderr, /schema/);
});

test("CLI --graph value guards: --graph with no value, or followed by the next flag, is a usage error (exit 2)", (t) => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-partition-graph-")));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const inFile = join(dir, "in.json");
  const outFile = join(dir, "out.json");
  writeFileSync(inFile, JSON.stringify({ graph: null, fallback_partitions: [] }));
  const noValue = spawnSync(process.execPath, [CLI, "--file", inFile, "--out", outFile, "--graph"], { encoding: "utf8" });
  assert.equal(noValue.status, 2, noValue.stderr);
  assert.match(noValue.stderr, /usage/);
  assert.equal(existsSync(outFile), false, "no output on a usage error");
  const nextFlag = spawnSync(process.execPath, [CLI, "--file", inFile, "--graph", "--out", outFile], { encoding: "utf8" });
  assert.equal(nextFlag.status, 2, nextFlag.stderr);
  assert.match(nextFlag.stderr, /usage/);
  assert.equal(existsSync(outFile), false, "no output on a usage error");
});
