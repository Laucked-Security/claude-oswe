import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { performance } from "node:perf_hooks";
import { enumeratePaths, InputError } from "../enumerate-paths.mjs";
import { validate } from "../validate-output.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPTS_DIR = join(HERE, "..");
const REPO_ROOT = join(SCRIPTS_DIR, "..", "..", "..");
const FIXTURES_DIR = join(REPO_ROOT, "test-fixtures", "graph");
const CLI = join(SCRIPTS_DIR, "enumerate-paths.mjs");

const golden = (stack) => JSON.parse(readFileSync(join(FIXTURES_DIR, stack, "graph.expected.json"), "utf8"));

// The partitions partition-graph.mjs produces for the node golden.
const AUTH_ROUTES = { partition_id: "g-node-authenticated-routes", stack: "node", files: ["routes/users.js", "services/userService.js"] };
const ROOT = { partition_id: "g-node-unauthenticated-root", stack: "node", files: ["server.js"] };

let nextId = 0;
const hex12 = () => (++nextId).toString(16).padStart(12, "0");
const ZERO_STATS = {
  files_total: 0, files_parsed: 0, files_error: 0, files_skipped: 0, functions: 0, calls_total: 0, calls_exact: 0,
  calls_name_only: 0, calls_unresolved: 0, routes_by_auth: { unauthenticated: 0, authenticated: 0, unknown: 0 },
  coverage_matrix: {}, config_errors: []
};

// Schema-valid synthetic graph from a compact description:
//   fns:    { name: file }                                 (function ids derive from the name, in declaration order;
//                                                            qualified_name is the name, line_start is 1)
//   routes: [{ file, auth, handler?, method?, path? }]     (handler names a function)
//   calls:  [[fromName, toName | null, confidence]]
//   sinks:  [{ fn: name | null, class, callee?, file? }]   (fn null = module level)
// Files are derived from `fns`, `routes` and `sinks`.
function synth({ fns = {}, routes = [], calls = [], sinks = [] }) {
  const fnId = Object.fromEntries(Object.keys(fns).map((name) => [name, hex12()]));
  const files = [...new Set([...Object.values(fns), ...routes.map((r) => r.file), ...sinks.map((s) => s.file).filter(Boolean)])];
  const nodes = files.map((path) => ({ type: "file", id: hex12(), path, stack: "node", lang: "javascript", parse_status: "ok" }));
  const edges = [];
  for (const [name, file] of Object.entries(fns)) {
    nodes.push({ type: "function", id: fnId[name], file, name, qualified_name: name, line_start: 1, line_end: 2, kind: "function", exported: false });
  }
  for (const r of routes) {
    const id = hex12();
    nodes.push({
      type: "route", id, file: r.file, line: 3, http_method: r.method ?? "GET", path_pattern: r.path ?? "/x", handler: r.handler ? fnId[r.handler] : null,
      middlewares: [], framework: "express", auth: r.auth
    });
    if (r.handler) edges.push({ type: "handles", from: id, to: fnId[r.handler] });
  }
  for (const [from, to, confidence] of calls) {
    edges.push({ type: "calls", from: fnId[from], to: to ? fnId[to] : null, line: 1, callee_text: to ?? "unknown", confidence });
  }
  for (const s of sinks) {
    const file = s.file ?? (s.fn ? fns[s.fn] : "module.js");
    nodes.push({ type: "sink", id: hex12(), file, line: 9, enclosing_fn: s.fn ? fnId[s.fn] : null, class: s.class, callee: s.callee ?? `${s.class}.call`, pattern: s.class });
  }
  const graph = { version: 1, generated_by: "test", stats: ZERO_STATS, nodes, edges };
  assert.deepEqual(validate("graph", graph), { valid: true, errors: [] }, "the synthetic graph must itself be schema-valid");
  return graph;
}

const part = (files, partition_id = "p") => ({ partition_id, stack: "node", files });
const names = (candidate) => candidate.hops.map((h) => h.function);
const classes = (out) => out.candidate_paths.map((c) => c.sink.class);

// Levelled diamond: h -> {a1,b1} -> {a2,b2} -> ... -> {aN,bN} -> end, every node linked to both nodes of
// the next level (2^N paths). The b edges are listed first so "first edge seen wins" would pick b.
function diamond(levels, sinkClass = "cmd-exec", confidence = "exact") {
  const fns = { h: "a.js" };
  for (let i = 1; i <= levels; i++) {
    fns[`a${i}`] = "a.js";
    fns[`b${i}`] = "a.js";
  }
  fns.end = "a.js";
  const calls = [];
  const link = (from, level) => {
    const next = level > levels ? ["end"] : [`b${level}`, `a${level}`];
    for (const to of next) calls.push([from, to, confidence]);
  };
  link("h", 1);
  for (let i = 1; i <= levels; i++) for (const from of [`b${i}`, `a${i}`]) link(from, i + 1);
  return synth({ fns, routes: [{ file: "a.js", auth: "authenticated", handler: "h" }], calls, sinks: [{ fn: "end", class: sinkClass }] });
}

// ---- the real node golden -----------------------------------------------------------------------------

test("node golden: the authenticated-routes partition yields exactly the route -> run -> UserService.run -> UserService.exec cmd-exec path", () => {
  const out = enumeratePaths({ graph: golden("node"), partition: AUTH_ROUTES });
  assert.deepEqual(out, {
    partition_id: "g-node-authenticated-routes",
    candidate_paths: [
      {
        id: "CP-g-node-authenticated-routes-1",
        route: { file: "routes/users.js", line: 10, http_method: "POST", path_pattern: "/users/:id/run", auth: "authenticated" },
        hops: [
          { file: "routes/users.js", line: 6, function: "run", edge_confidence: "exact" },
          { file: "services/userService.js", line: 5, function: "UserService.run", edge_confidence: "exact" },
          { file: "services/userService.js", line: 9, function: "UserService.exec", edge_confidence: "name-only" }
        ],
        sink: { file: "services/userService.js", line: 10, class: "cmd-exec", callee: "child_process.exec" },
        min_confidence: "name-only"
      }
    ]
  });
  const [c] = out.candidate_paths;
  assert.equal(c.hops.length, 3);
  assert.deepEqual(Object.keys(c), ["id", "route", "hops", "sink", "min_confidence"]);
});

test("node golden: the root partition (health handler reaches no sink) and the DAO partition (no route) yield no candidates", () => {
  assert.deepEqual(enumeratePaths({ graph: golden("node"), partition: ROOT }), { partition_id: "g-node-unauthenticated-root", candidate_paths: [] });
  assert.deepEqual(enumeratePaths({ graph: golden("node"), partition: part(["dao/userDao.js"], "node-data-orphan") }), {
    partition_id: "node-data-orphan",
    candidate_paths: []
  });
});

test("node golden: the DAO nosql sink is unreachable from any route, even with every file in the partition", () => {
  const all = part(["dao/userDao.js", "routes/users.js", "server.js", "services/userService.js"], "all");
  const out = enumeratePaths({ graph: golden("node"), partition: all });
  assert.deepEqual(classes(out), ["cmd-exec"]);
  assert.deepEqual(out.candidate_paths.map((c) => c.id), ["CP-all-1"]);
});

test("node golden: functions outside the partition's files are not traversed", () => {
  const out = enumeratePaths({ graph: golden("node"), partition: part(["routes/users.js"]) });
  assert.deepEqual(out.candidate_paths, []);
});

test("max_depth bounds hops.length: 2 prunes the golden's 3-hop path, 3 (and the default 6) keep it, 1 keeps only handler-level sinks", () => {
  const graph = golden("node");
  assert.deepEqual(enumeratePaths({ graph, partition: AUTH_ROUTES, max_depth: 2 }).candidate_paths, []);
  assert.equal(enumeratePaths({ graph, partition: AUTH_ROUTES, max_depth: 3 }).candidate_paths.length, 1);
  assert.equal(enumeratePaths({ graph, partition: AUTH_ROUTES, max_depth: 6 }).candidate_paths.length, 1);
  assert.deepEqual(enumeratePaths({ graph, partition: AUTH_ROUTES, max_depth: 1 }).candidate_paths, []);
  const direct = synth({ fns: { h: "a.js", g: "a.js" }, routes: [{ file: "a.js", auth: "unknown", handler: "h" }], calls: [["h", "g", "exact"]], sinks: [{ fn: "h", class: "sql" }, { fn: "g", class: "sql" }] });
  assert.deepEqual(enumeratePaths({ graph: direct, partition: part(["a.js"]), max_depth: 1 }).candidate_paths.map((c) => c.hops.length), [1]);
  assert.deepEqual(enumeratePaths({ graph: direct, partition: part(["a.js"]), max_depth: 2 }).candidate_paths.map((c) => c.hops.length), [1, 2]);
});

// ---- scale: diamond, max_paths ------------------------------------------------------------------------

test("diamond of depth 20 with 2 branches per level (2^20 paths): exactly one candidate, the shortest path, in < 2 s", () => {
  const graph = diamond(20);
  const partition = part(["a.js"]);
  const t0 = performance.now();
  const out = enumeratePaths({ graph, partition, max_depth: 25 });
  const elapsed = performance.now() - t0;
  assert.ok(elapsed < 2000, `took ${elapsed} ms`);
  assert.equal(out.candidate_paths.length, 1);
  const [c] = out.candidate_paths;
  assert.equal(c.hops.length, 22);
  // every branch is equally good: the smaller function id (the `a` node, declared first) wins at each level
  assert.deepEqual(names(c), ["h", ...Array.from({ length: 20 }, (_, i) => `a${i + 1}`), "end"]);
  assert.equal(c.min_confidence, "exact");
  // the default depth (6) cannot reach the end of a 22-hop path
  assert.deepEqual(enumeratePaths({ graph, partition }).candidate_paths, []);
});

test("max_paths caps the list (default 50), keeps the first in ranking order, and ids are 1-based in that order", () => {
  const fns = { h: "a.js" };
  const calls = [];
  const sinks = [];
  for (let i = 0; i < 60; i++) {
    fns[`f${i}`] = "a.js";
    calls.push(["h", `f${i}`, "exact"]);
    sinks.push({ fn: `f${i}`, class: "sql", callee: `q${i}` });
  }
  const graph = synth({ fns, routes: [{ file: "a.js", auth: "unauthenticated", handler: "h" }], calls, sinks });
  const partition = part(["a.js"], "big");
  const all = enumeratePaths({ graph, partition, max_paths: 1000 });
  assert.equal(all.candidate_paths.length, 60);
  const dflt = enumeratePaths({ graph, partition });
  assert.equal(dflt.candidate_paths.length, 50);
  assert.deepEqual(dflt.candidate_paths, all.candidate_paths.slice(0, 50));
  assert.deepEqual(dflt.candidate_paths.map((c) => c.id), Array.from({ length: 50 }, (_, i) => `CP-big-${i + 1}`));
  const three = enumeratePaths({ graph, partition, max_paths: 3 });
  assert.deepEqual(three.candidate_paths.map((c) => c.sink.callee), ["q0", "q1", "q2"]);
  assert.deepEqual(three.candidate_paths.map((c) => c.id), ["CP-big-1", "CP-big-2", "CP-big-3"]);
});

// ---- ordering -----------------------------------------------------------------------------------------

test("ordering: sink class rank first (cmd-exec/eval/deser, then sql/nosql/template/include, then file-*/ssrf/xxe, then the rest), sink id last", () => {
  const order = ["redirect", "ssrf", "sql", "eval", "trust-boundary", "xxe", "include", "cmd-exec", "template", "file-write", "deser", "file-read", "nosql", "other"];
  const graph = synth({
    fns: { h: "a.js" },
    routes: [{ file: "a.js", auth: "authenticated", handler: "h" }],
    sinks: order.map((c) => ({ fn: "h", class: c }))
  });
  const out = enumeratePaths({ graph, partition: part(["a.js"]) });
  assert.deepEqual(classes(out), [
    "eval", "cmd-exec", "deser",
    "sql", "include", "template", "nosql",
    "ssrf", "xxe", "file-write", "file-read",
    "redirect", "trust-boundary", "other"
  ]);
  assert.deepEqual(out.candidate_paths.map((c) => c.id), order.map((_, i) => `CP-p-${i + 1}`));
});

test("ordering: a cmd-exec path sorts first even when it is longer and a sql path is shorter", () => {
  const graph = synth({
    fns: { h: "a.js", deep: "a.js" },
    routes: [{ file: "a.js", auth: "authenticated", handler: "h" }],
    calls: [["h", "deep", "exact"]],
    sinks: [{ fn: "h", class: "sql" }, { fn: "deep", class: "cmd-exec" }]
  });
  const out = enumeratePaths({ graph, partition: part(["a.js"]) });
  assert.deepEqual(classes(out), ["cmd-exec", "sql"]);
  assert.equal(out.candidate_paths[0].id, "CP-p-1");
  assert.equal(out.candidate_paths[0].hops.length, 2);
});

test("ordering: within a sink rank an unauthenticated route sorts before an authenticated one, whatever the declaration order", () => {
  const graph = synth({
    fns: { authed: "a.js", open: "a.js", unk: "a.js" },
    routes: [
      { file: "a.js", auth: "authenticated", handler: "authed", path: "/authed" },
      { file: "a.js", auth: "unknown", handler: "unk", path: "/unk" },
      { file: "a.js", auth: "unauthenticated", handler: "open", path: "/open" }
    ],
    sinks: [{ fn: "authed", class: "sql" }, { fn: "unk", class: "sql" }, { fn: "open", class: "sql" }]
  });
  const out = enumeratePaths({ graph, partition: part(["a.js"]) });
  // `unknown` ranks with `authenticated`; their relative order falls through to route id
  assert.deepEqual(out.candidate_paths.map((c) => c.route.path_pattern), ["/open", "/authed", "/unk"]);
});

test("ordering: the sink rank outranks the route's auth (authenticated cmd-exec before unauthenticated sql)", () => {
  const graph = synth({
    fns: { open: "a.js", authed: "a.js" },
    routes: [{ file: "a.js", auth: "unauthenticated", handler: "open", path: "/open" }, { file: "a.js", auth: "authenticated", handler: "authed", path: "/authed" }],
    sinks: [{ fn: "open", class: "sql" }, { fn: "authed", class: "cmd-exec" }]
  });
  const out = enumeratePaths({ graph, partition: part(["a.js"]) });
  assert.deepEqual(out.candidate_paths.map((c) => c.route.path_pattern), ["/authed", "/open"]);
});

test("ordering: fewer hops first, then route id, then sink id (with equal rank and auth)", () => {
  const graph = synth({
    fns: { h1: "a.js", h2: "a.js", mid: "a.js", far: "a.js" },
    routes: [
      { file: "a.js", auth: "authenticated", handler: "h1", path: "/one" },
      { file: "a.js", auth: "authenticated", handler: "h2", path: "/two" }
    ],
    calls: [["h1", "mid", "exact"], ["mid", "far", "exact"]],
    sinks: [
      { fn: "far", class: "sql", callee: "far-sink" }, // 3 hops from /one
      { fn: "h2", class: "sql", callee: "h2-second" }, // 1 hop, /two ...
      { fn: "h2", class: "sql", callee: "h2-third" },
      { fn: "h1", class: "sql", callee: "h1-direct" } // ... 1 hop, /one: route id /one < /two
    ]
  });
  const out = enumeratePaths({ graph, partition: part(["a.js"]) });
  assert.deepEqual(
    out.candidate_paths.map((c) => [c.route.path_pattern, c.sink.callee, c.hops.length]),
    [["/one", "h1-direct", 1], ["/two", "h2-second", 1], ["/two", "h2-third", 1], ["/one", "far-sink", 3]]
  );
});

// ---- shortest path and its tie-breaks -----------------------------------------------------------------

test("tie-break: of two equally short branches the one without a name-only edge wins, whichever has the smaller id", () => {
  // `weak` is declared (and so id-ordered) before `strong`: only the name-only count can pick `strong`
  const graph = synth({
    fns: { h: "a.js", weak: "a.js", strong: "a.js", t: "a.js" },
    routes: [{ file: "a.js", auth: "authenticated", handler: "h" }],
    calls: [["h", "weak", "name-only"], ["weak", "t", "exact"], ["h", "strong", "exact"], ["strong", "t", "exact"]],
    sinks: [{ fn: "t", class: "cmd-exec" }]
  });
  const [c] = enumeratePaths({ graph, partition: part(["a.js"]) }).candidate_paths;
  assert.deepEqual(names(c), ["h", "strong", "t"]);
  assert.deepEqual(c.hops.map((h) => h.edge_confidence), ["exact", "exact", "exact"]);
  assert.equal(c.min_confidence, "exact");
});

test("tie-break: equal hops and equal name-only count -> the smaller function id", () => {
  const mk = (first, second) =>
    synth({
      fns: { h: "a.js", lo: "a.js", hi: "a.js", t: "a.js" },
      routes: [{ file: "a.js", auth: "authenticated", handler: "h" }],
      calls: [["h", first, "name-only"], ["h", second, "name-only"], [first, "t", "exact"], [second, "t", "exact"]],
      sinks: [{ fn: "t", class: "cmd-exec" }]
    });
  for (const graph of [mk("lo", "hi"), mk("hi", "lo")]) {
    const [c] = enumeratePaths({ graph, partition: part(["a.js"]) }).candidate_paths;
    assert.deepEqual(names(c), ["h", "lo", "t"]);
    assert.equal(c.min_confidence, "name-only");
  }
});

test("fewer hops beat fewer name-only edges: a 2-hop name-only path wins over a 3-hop exact one", () => {
  const graph = synth({
    fns: { h: "a.js", x: "a.js", y: "a.js", t: "a.js" },
    routes: [{ file: "a.js", auth: "authenticated", handler: "h" }],
    calls: [["h", "x", "exact"], ["x", "y", "exact"], ["y", "t", "exact"], ["h", "t", "name-only"]],
    sinks: [{ fn: "t", class: "cmd-exec" }]
  });
  const [c] = enumeratePaths({ graph, partition: part(["a.js"]) }).candidate_paths;
  assert.deepEqual(names(c), ["h", "t"]);
  assert.deepEqual(c.hops.map((h) => h.edge_confidence), ["exact", "name-only"]);
  assert.equal(c.min_confidence, "name-only");
});

test("parallel edges: the exact one is the hop's edge_confidence, whichever is listed first", () => {
  for (const confidences of [["exact", "name-only"], ["name-only", "exact"]]) {
    const graph = synth({
      fns: { h: "a.js", t: "a.js" },
      routes: [{ file: "a.js", auth: "authenticated", handler: "h" }],
      calls: confidences.map((c) => ["h", "t", c]),
      sinks: [{ fn: "t", class: "eval" }]
    });
    const [c] = enumeratePaths({ graph, partition: part(["a.js"]) }).candidate_paths;
    assert.deepEqual(c.hops.map((h) => h.edge_confidence), ["exact", "exact"], confidences.join());
    assert.equal(c.min_confidence, "exact");
  }
});

test("a sink on an intermediate function of the shortest path is its own candidate, with a shorter hop list", () => {
  const graph = synth({
    fns: { h: "a.js", m: "a.js", t: "a.js" },
    routes: [{ file: "a.js", auth: "authenticated", handler: "h" }],
    calls: [["h", "m", "exact"], ["m", "t", "exact"]],
    sinks: [{ fn: "m", class: "sql", callee: "mid" }, { fn: "t", class: "sql", callee: "end" }]
  });
  const out = enumeratePaths({ graph, partition: part(["a.js"]) });
  assert.deepEqual(out.candidate_paths.map((c) => [c.sink.callee, names(c)]), [["mid", ["h", "m"]], ["end", ["h", "m", "t"]]]);
});

// ---- traversal rules ----------------------------------------------------------------------------------

test("a sink in the handler itself is a one-hop candidate: edge_confidence exact, min_confidence exact", () => {
  const graph = synth({
    fns: { h: "a.js" },
    routes: [{ file: "a.js", auth: "unauthenticated", handler: "h", method: "DELETE", path: "/d" }],
    sinks: [{ fn: "h", class: "file-write", callee: "fs.writeFile" }]
  });
  const out = enumeratePaths({ graph, partition: part(["a.js"], "solo") });
  assert.deepEqual(out.candidate_paths, [
    {
      id: "CP-solo-1",
      route: { file: "a.js", line: 3, http_method: "DELETE", path_pattern: "/d", auth: "unauthenticated" },
      hops: [{ file: "a.js", line: 1, function: "h", edge_confidence: "exact" }],
      sink: { file: "a.js", line: 9, class: "file-write", callee: "fs.writeFile" },
      min_confidence: "exact"
    }
  ]);
});

test("unresolved calls edges are never followed, even one that carries a `to`; null targets are skipped", () => {
  const graph = synth({
    fns: { h: "a.js", ghost: "a.js", real: "a.js" },
    routes: [{ file: "a.js", auth: "authenticated", handler: "h" }],
    calls: [["h", "ghost", "unresolved"], ["h", null, "unresolved"], ["h", "real", "name-only"]],
    sinks: [{ fn: "ghost", class: "cmd-exec" }, { fn: "real", class: "sql" }]
  });
  const out = enumeratePaths({ graph, partition: part(["a.js"]) });
  assert.deepEqual(classes(out), ["sql"]);
  assert.deepEqual(names(out.candidate_paths[0]), ["h", "real"]);
});

test("cycles terminate and module-level sinks (enclosing_fn null) are never candidates", () => {
  const graph = synth({
    fns: { h: "a.js", x: "a.js", y: "a.js" },
    routes: [{ file: "a.js", auth: "authenticated", handler: "h" }],
    calls: [["h", "x", "exact"], ["x", "y", "exact"], ["y", "x", "exact"], ["y", "h", "exact"], ["h", "h", "exact"]],
    sinks: [{ fn: null, class: "cmd-exec" }, { fn: "y", class: "eval" }]
  });
  const out = enumeratePaths({ graph, partition: part(["a.js"]) });
  assert.deepEqual(classes(out), ["eval"]);
  assert.deepEqual(names(out.candidate_paths[0]), ["h", "x", "y"]);
});

test("routes without a handler yield nothing; routes in files outside the partition are not enumerated", () => {
  const graph = synth({
    fns: { h: "a.js", other: "b.js" },
    routes: [
      { file: "a.js", auth: "authenticated" }, // no handler
      { file: "b.js", auth: "authenticated", handler: "other" } // another partition's route
    ],
    sinks: [{ fn: "h", class: "sql" }, { fn: "other", class: "sql" }]
  });
  assert.deepEqual(enumeratePaths({ graph, partition: part(["a.js"]) }).candidate_paths, []);
  assert.equal(enumeratePaths({ graph, partition: part(["b.js"]) }).candidate_paths.length, 1);
});

test("a route whose handler lives outside the partition's files yields nothing", () => {
  const graph = synth({
    fns: { h: "ctl/c.js" },
    routes: [{ file: "a.js", auth: "authenticated", handler: "h" }],
    sinks: [{ fn: "h", class: "sql" }]
  });
  assert.deepEqual(enumeratePaths({ graph, partition: part(["a.js"]) }).candidate_paths, []);
  assert.equal(enumeratePaths({ graph, partition: part(["a.js", "ctl/c.js"]) }).candidate_paths.length, 1);
});

test("a function outside the partition is a wall: no path goes through it, even if a later hop is back inside", () => {
  const graph = synth({
    fns: { h: "a.js", mid: "z.js", back: "a.js", direct: "a.js" },
    routes: [{ file: "a.js", auth: "authenticated", handler: "h" }],
    calls: [["h", "mid", "exact"], ["mid", "back", "exact"], ["h", "direct", "exact"]],
    sinks: [{ fn: "back", class: "cmd-exec" }, { fn: "direct", class: "sql" }]
  });
  const out = enumeratePaths({ graph, partition: part(["a.js"]) });
  assert.deepEqual(classes(out), ["sql"]);
  assert.deepEqual(classes(enumeratePaths({ graph, partition: part(["a.js", "z.js"]) })), ["cmd-exec", "sql"]);
});

test("one candidate per (route, sink): two routes sharing a handler give two candidates for the same sink", () => {
  const graph = synth({
    fns: { h: "a.js", t: "a.js" },
    routes: [
      { file: "a.js", auth: "authenticated", handler: "h", method: "GET", path: "/g" },
      { file: "a.js", auth: "authenticated", handler: "h", method: "POST", path: "/p" }
    ],
    calls: [["h", "t", "exact"]],
    sinks: [{ fn: "t", class: "cmd-exec" }]
  });
  const out = enumeratePaths({ graph, partition: part(["a.js"]) });
  assert.deepEqual(out.candidate_paths.map((c) => [c.route.http_method, c.route.path_pattern, c.sink.class]), [["GET", "/g", "cmd-exec"], ["POST", "/p", "cmd-exec"]]);
  assert.deepEqual(out.candidate_paths.map((c) => c.id), ["CP-p-1", "CP-p-2"]);
});

test("windows: partition files compare case-insensitively against the graph's spelling; other platforms are case-sensitive", () => {
  const graph = synth({
    fns: { h: "Routes/Users.js", s: "SVC/S.js" },
    routes: [{ file: "Routes/Users.js", auth: "authenticated", handler: "h" }],
    calls: [["h", "s", "exact"]],
    sinks: [{ fn: "s", class: "sql" }]
  });
  const lower = enumeratePaths({ graph, partition: part(["routes/users.js", "svc/s.js"]) });
  if (process.platform !== "win32") {
    assert.deepEqual(lower.candidate_paths, []);
    return;
  }
  assert.equal(lower.candidate_paths.length, 1);
  assert.deepEqual(names(lower.candidate_paths[0]), ["h", "s"]);
  assert.equal(lower.candidate_paths[0].hops[0].file, "Routes/Users.js", "the graph's spelling is what is reported");
});

// ---- determinism --------------------------------------------------------------------------------------

test("determinism: two runs are byte-identical, and reversing graph.nodes / graph.edges changes nothing", () => {
  const reversed = (g) => ({ ...g, nodes: [...g.nodes].reverse(), edges: [...g.edges].reverse() });
  const cases = [
    [golden("node"), AUTH_ROUTES],
    [golden("node"), part(["dao/userDao.js", "routes/users.js", "server.js", "services/userService.js"], "all")],
    [diamond(6, "sql"), part(["a.js"])]
  ];
  for (const [graph, partition] of cases) {
    const opts = { partition, max_depth: 12 };
    const a = JSON.stringify(enumeratePaths({ graph, ...opts }));
    assert.equal(JSON.stringify(enumeratePaths({ graph, ...opts })), a);
    assert.equal(JSON.stringify(enumeratePaths({ graph: reversed(graph), ...opts })), a);
  }
});

test("determinism: ties between equal parallel branches resolve identically for every edge order", () => {
  const base = synth({
    fns: { h: "a.js", a: "a.js", b: "a.js", c: "a.js", t: "a.js" },
    routes: [{ file: "a.js", auth: "authenticated", handler: "h" }],
    calls: [["h", "c", "exact"], ["h", "b", "exact"], ["h", "a", "exact"], ["c", "t", "exact"], ["b", "t", "exact"], ["a", "t", "exact"]],
    sinks: [{ fn: "t", class: "cmd-exec" }]
  });
  const expected = names(enumeratePaths({ graph: base, partition: part(["a.js"]) }).candidate_paths[0]);
  assert.deepEqual(expected, ["h", "a", "t"]);
  const edges = base.edges;
  for (let shift = 0; shift < edges.length; shift++) {
    const rotated = { ...base, edges: [...edges.slice(shift), ...edges.slice(0, shift)] };
    assert.deepEqual(names(enumeratePaths({ graph: rotated, partition: part(["a.js"]) }).candidate_paths[0]), expected, `rotation ${shift}`);
  }
});

test("enumeratePaths does not mutate its input", () => {
  const graph = golden("node");
  const partition = JSON.parse(JSON.stringify(AUTH_ROUTES));
  const before = JSON.stringify({ graph, partition });
  enumeratePaths({ graph, partition });
  assert.equal(JSON.stringify({ graph, partition }), before);
});

// ---- input validation (API) ---------------------------------------------------------------------------

test("malformed input throws InputError: graph, partition, max_depth, max_paths", () => {
  const graph = golden("node");
  const p = AUTH_ROUTES;
  const bad = [
    [undefined, "missing input"],
    [null, "null input"],
    [[], "array input"],
    [{ partition: p }, "graph absent"],
    [{ graph: null, partition: p }, "graph null (the orchestrator skips this helper when there is no graph)"],
    [{ graph: "g", partition: p }, "graph a string"],
    [{ graph: [], partition: p }, "graph an array"],
    [{ graph: { edges: [] }, partition: p }, "graph without nodes"],
    [{ graph: { nodes: [] }, partition: p }, "graph without edges"],
    [{ graph: { ...graph, version: 2 }, partition: p }, "graph fails the schema"],
    [{ graph }, "partition absent"],
    [{ graph, partition: null }, "partition null"],
    [{ graph, partition: [] }, "partition an array"],
    [{ graph, partition: { stack: "node", files: [] } }, "partition_id missing"],
    [{ graph, partition: { partition_id: 7, stack: "node", files: [] } }, "partition_id not a string"],
    [{ graph, partition: { partition_id: "", stack: "node", files: [] } }, "partition_id empty"],
    [{ graph, partition: { partition_id: "p", stack: "node" } }, "files missing"],
    [{ graph, partition: { partition_id: "p", stack: "node", files: "a.js" } }, "files a string"],
    [{ graph, partition: { partition_id: "p", stack: "node", files: [1] } }, "file not a string"],
    ...[0, -1, 1.5, "6", null, true, [3]].map((v) => [{ graph, partition: p, max_depth: v }, `max_depth ${JSON.stringify(v)}`]),
    ...[0, -1, 1.5, "50", null, true, [3]].map((v) => [{ graph, partition: p, max_paths: v }, `max_paths ${JSON.stringify(v)}`])
  ];
  for (const [input, why] of bad) {
    assert.throws(() => enumeratePaths(input), (e) => e instanceof InputError && /^bad input: /.test(e.message), why);
  }
  // an empty files list is well-formed (just empty), and so are explicit valid limits
  assert.deepEqual(enumeratePaths({ graph, partition: part([]) }).candidate_paths, []);
  assert.equal(enumeratePaths({ graph, partition: p, max_depth: 3, max_paths: 1 }).candidate_paths.length, 1);
});

// ---- CLI ----------------------------------------------------------------------------------------------

function runCli(t, input, { raw = null, outName = "out.json", args = null, graphFile = null } = {}) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-enumerate-paths-")));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const inFile = join(dir, "in.json");
  const outFile = join(dir, outName);
  writeFileSync(inFile, raw ?? JSON.stringify(input));
  const r = spawnSync(process.execPath, args ?? [CLI, "--file", inFile, "--out", outFile, ...(graphFile ? ["--graph", graphFile] : [])], { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, out: existsSync(outFile) ? readFileSync(outFile, "utf8") : null };
}

test("CLI: exit 0 and the same JSON as the API, pretty-printed; max_depth / max_paths are honoured", (t) => {
  const input = { graph: golden("node"), partition: AUTH_ROUTES };
  const r = runCli(t, input);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stderr, "");
  assert.equal(r.stdout, "");
  assert.deepEqual(JSON.parse(r.out), enumeratePaths(input));
  assert.equal(r.out, JSON.stringify(enumeratePaths(input), null, 2) + "\n");
  const pruned = runCli(t, { ...input, max_depth: 2 });
  assert.equal(pruned.status, 0, pruned.stderr);
  assert.deepEqual(JSON.parse(pruned.out), { partition_id: "g-node-authenticated-routes", candidate_paths: [] });
  const synthetic = { graph: diamond(4, "sql"), partition: part(["a.js"]), max_depth: 12, max_paths: 1 };
  const capped = runCli(t, synthetic);
  assert.equal(capped.status, 0, capped.stderr);
  assert.deepEqual(JSON.parse(capped.out), enumeratePaths(synthetic));
});

test("CLI: exit 1 (and no output file) for graph null, a missing partition.files, max_depth 0, a bad max_paths, a schema-invalid graph, a non-object input", (t) => {
  const graph = golden("node");
  const cases = [
    [{ graph: null, partition: AUTH_ROUTES }, /graph/],
    [{ graph, partition: { partition_id: "p", stack: "node" } }, /files/],
    [{ graph, partition: AUTH_ROUTES, max_depth: 0 }, /max_depth/],
    [{ graph, partition: AUTH_ROUTES, max_paths: 2.5 }, /max_paths/],
    [{ graph: { ...graph, version: 2 }, partition: AUTH_ROUTES }, /schema/]
  ];
  for (const [input, re] of cases) {
    const r = runCli(t, input);
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stderr, re);
    assert.equal(r.out, null, "no output written on malformed input");
  }
  const array = runCli(t, null, { raw: "[]" });
  assert.equal(array.status, 1, array.stderr);
});

test("CLI: exit 2 for an unreadable --file, invalid JSON, an unwritable --out, and usage errors", (t) => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-enumerate-paths-")));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const missing = spawnSync(process.execPath, [CLI, "--file", join(dir, "nope.json"), "--out", join(dir, "out.json")], { encoding: "utf8" });
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /cannot read --file/);
  const notJson = runCli(t, null, { raw: "{not json" });
  assert.equal(notJson.status, 2, notJson.stderr);
  const unwritable = runCli(t, { graph: golden("node"), partition: ROOT }, { outName: join("no-such-dir", "out.json") });
  assert.equal(unwritable.status, 2, unwritable.stderr);
  assert.match(unwritable.stderr, /cannot write --out/);
  const noOut = spawnSync(process.execPath, [CLI, "--file", join(dir, "x.json")], { encoding: "utf8" });
  assert.equal(noOut.status, 2);
  assert.match(noOut.stderr, /usage/);
  const none = spawnSync(process.execPath, [CLI], { encoding: "utf8" });
  assert.equal(none.status, 2);
});

test("CLI --graph <path>: a golden file = the inline API call; envelopes; inline graph superseded; unreadable file exit 2", (t) => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-enumerate-paths-")));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const goldenFile = join(FIXTURES_DIR, "node", "graph.expected.json");
  const nullEnvelope = join(dir, "graph-null.json");
  writeFileSync(nullEnvelope, JSON.stringify({ graph: null, reason: "parser unavailable" }));
  const objEnvelope = join(dir, "graph-obj.json");
  writeFileSync(objEnvelope, JSON.stringify({ graph: golden("node") }));
  const withGraph = (graphFile, input) => runCli(t, null, { raw: JSON.stringify(input), graphFile });
  const expected = JSON.stringify(enumeratePaths({ graph: golden("node"), partition: AUTH_ROUTES }), null, 2) + "\n";
  for (const input of [{ partition: AUTH_ROUTES }, { graph: "junk", partition: AUTH_ROUTES }]) {
    for (const file of [goldenFile, objEnvelope]) {
      const r = withGraph(file, input);
      assert.equal(r.status, 0, r.stderr);
      assert.equal(r.stderr, "");
      assert.equal(r.out, expected);
    }
  }
  // The { graph: null } envelope is graph null, which this helper rejects (exit 1), even over an inline graph.
  const nul = withGraph(nullEnvelope, { graph: golden("node"), partition: AUTH_ROUTES });
  assert.equal(nul.status, 1, nul.stderr);
  assert.match(nul.stderr, /graph/);
  assert.equal(nul.out, null);
  const missing = withGraph(join(dir, "nope.json"), { partition: AUTH_ROUTES });
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /cannot read --graph/);
  assert.equal(missing.out, null);
  const notJson = join(dir, "bad.json");
  writeFileSync(notJson, "{not json");
  assert.equal(withGraph(notJson, { partition: AUTH_ROUTES }).status, 2);
  const invalid = join(dir, "invalid.json");
  writeFileSync(invalid, JSON.stringify({ ...golden("node"), version: 2 }));
  const inv = withGraph(invalid, { partition: AUTH_ROUTES });
  assert.equal(inv.status, 1, "validate(graph) still applies to the loaded graph");
  assert.match(inv.stderr, /schema/);
});

test("CLI --graph value guards: --graph with no value, or followed by the next flag, is a usage error (exit 2)", (t) => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-enumerate-paths-")));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const inFile = join(dir, "in.json");
  const outFile = join(dir, "out.json");
  writeFileSync(inFile, JSON.stringify({ graph: golden("node"), partition: ROOT }));
  const noValue = spawnSync(process.execPath, [CLI, "--file", inFile, "--out", outFile, "--graph"], { encoding: "utf8" });
  assert.equal(noValue.status, 2, noValue.stderr);
  assert.match(noValue.stderr, /usage/);
  assert.equal(existsSync(outFile), false, "no output on a usage error");
  const nextFlag = spawnSync(process.execPath, [CLI, "--file", inFile, "--graph", "--out", outFile], { encoding: "utf8" });
  assert.equal(nextFlag.status, 2, nextFlag.stderr);
  assert.match(nextFlag.stderr, /usage/);
  assert.equal(existsSync(outFile), false, "no output on a usage error");
});
