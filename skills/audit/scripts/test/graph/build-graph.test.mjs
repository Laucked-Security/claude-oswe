import { test } from "node:test";
import assert from "node:assert/strict";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import { buildGraph, FRAMEWORK_STACK, versionDigest, versionFiles, antPathRegex } from "../../graph/build-graph.mjs";
import { nodeId, edgeKey } from "../../graph/ids.mjs";
import { parserAvailable } from "../../graph/parser.mjs";
import { validate } from "../../validate-output.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPTS_DIR = join(HERE, "..", "..");
const REPO_ROOT = join(SCRIPTS_DIR, "..", "..", "..");
const FIXTURES_DIR = join(REPO_ROOT, "test-fixtures", "graph");
const REFERENCES_DIR = join(REPO_ROOT, "skills", "audit", "references");
const CLI = join(SCRIPTS_DIR, "graph", "build-graph.mjs");
const NODE_FIXTURE = realpathSync(join(FIXTURES_DIR, "node"));

// The frameworks each golden fixture is built with (spec: "the fixture's frameworks"); a stack not
// listed here is built with every framework of that stack.
const GOLDEN_FRAMEWORKS = { node: ["express"], python: ["flask", "django", "fastapi"], java: ["spring"], php: ["laravel", "symfony"], dotnet: ["aspnet"] };
const goldenFrameworks = (stack) => GOLDEN_FRAMEWORKS[stack] ?? Object.keys(FRAMEWORK_STACK).filter((f) => FRAMEWORK_STACK[f] === stack);

function tempDir(t, prefix = "oswe-build-graph-") {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function put(root, rel, content) {
  const abs = join(root, ...rel.split("/"));
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, content);
  return abs;
}

function build(projectDir, extra = {}) {
  return buildGraph({ projectDir, scopeRealpath: projectDir, stacks: ["node"], frameworks: ["express"], referencesDir: REFERENCES_DIR, ...extra });
}

const nodesOf = (graph, type) => graph.nodes.filter((n) => n.type === type);
const fnNamed = (graph, file, qualifiedName) => nodesOf(graph, "function").find((n) => n.file === file && n.qualified_name === qualifiedName);

function runCli(t, input, { checkpointDir = null } = {}) {
  const dir = tempDir(t, "oswe-build-graph-cli-");
  const inFile = join(dir, "in.json");
  const outFile = join(dir, "out.json");
  writeFileSync(inFile, JSON.stringify(input));
  const args = [CLI, "--file", inFile, "--out", outFile, ...(checkpointDir ? ["--checkpoint-dir", checkpointDir] : [])];
  const r = spawnSync(process.execPath, args, { encoding: "utf8" });
  return { status: r.status, stderr: r.stderr, out: existsSync(outFile) ? readFileSync(outFile, "utf8") : null };
}

// ---- ids ------------------------------------------------------------------------------------------

test("nodeId is the first 12 hex of SHA-1 over the spec §1.3 identity string", () => {
  const sha1 = (s) => createHash("sha1").update(s).digest("hex").slice(0, 12);
  assert.equal(nodeId("function", "a/b.js", "C.m", 42), sha1("fn:a/b.js:C.m:42"));
  assert.equal(nodeId("source", "a.js", 7), sha1("source:a.js:7"));
  assert.equal(nodeId("sink", "a.js", 7), sha1("sink:a.js:7"));
  assert.equal(nodeId("route", "a.js", 7), sha1("route:a.js:7"));
  assert.equal(nodeId("file", "a.js"), sha1("file:a.js"));
  assert.notEqual(nodeId("sink", "a.js", 7), nodeId("source", "a.js", 7));
  assert.throws(() => nodeId("nope", "a.js"), /unknown node type/);
});

test("edgeKey distinguishes every identity component", () => {
  const base = edgeKey("calls", "aaaaaaaaaaaa", "bbbbbbbbbbbb", 3, 10);
  assert.equal(edgeKey("calls", "aaaaaaaaaaaa", "bbbbbbbbbbbb", 3, 10), base);
  assert.notEqual(edgeKey("calls", "aaaaaaaaaaaa", null, 3, 10), base);
  assert.notEqual(edgeKey("calls", "aaaaaaaaaaaa", "bbbbbbbbbbbb", 3, 11), base);
  assert.notEqual(edgeKey("calls", "aaaaaaaaaaaa", "bbbbbbbbbbbb", 4, 10), base);
  assert.notEqual(edgeKey("handles", "aaaaaaaaaaaa", "bbbbbbbbbbbb", 3, 10), base);
});

// ---- (1) determinism, (2) schema --------------------------------------------------------------------

test("(1) two builds of the node fixture are byte-identical", async () => {
  const a = await build(NODE_FIXTURE);
  const b = await build(NODE_FIXTURE);
  assert.ok(a.graph);
  assert.equal(JSON.stringify(a.graph), JSON.stringify(b.graph));
});

test("(2) the node fixture graph validates against the graph schema, with sorted nodes and edges", async () => {
  const { graph } = await build(NODE_FIXTURE);
  const v = validate("graph", graph);
  assert.equal(v.valid, true, JSON.stringify(v.errors));
  assert.equal(graph.generated_by, "oswe-build-graph/1");
  const keys = graph.nodes.map((n) => `${n.type}\u0000${n.id}`);
  assert.deepEqual(keys, [...keys].sort());
  assert.equal(new Set(graph.nodes.map((n) => n.id)).size, graph.nodes.length);
  for (const n of nodesOf(graph, "file")) assert.ok(!n.path.includes("\\") && !/^[A-Za-z]:|^\//.test(n.path), n.path);
});

// ---- the fixture's structure ------------------------------------------------------------------------

test("node fixture: calls are graded, the cmd-exec and nosql sinks sit in their functions", async () => {
  const { graph } = await build(NODE_FIXTURE);
  const calls = graph.edges.filter((e) => e.type === "calls");
  const run = fnNamed(graph, "routes/users.js", "run");
  const svcRun = fnNamed(graph, "services/userService.js", "UserService.run");
  const exec = fnNamed(graph, "services/userService.js", "UserService.exec");
  assert.deepEqual(calls.find((e) => e.callee_text === "svc.run"), { type: "calls", from: run.id, to: svcRun.id, line: 7, callee_text: "svc.run", confidence: "exact" });
  assert.deepEqual(calls.find((e) => e.callee_text === "this.exec"), { type: "calls", from: svcRun.id, to: exec.id, line: 6, callee_text: "this.exec", confidence: "name-only" });
  assert.equal(calls.find((e) => e.callee_text === "cb").to, null); // shadowed by the parameter
  assert.ok(!calls.some((e) => e.callee_text === "require" || e.callee_text === "app.use")); // module level: no edge
  const sinks = nodesOf(graph, "sink");
  const cmd = sinks.find((s) => s.class === "cmd-exec");
  assert.equal(cmd.file, "services/userService.js");
  assert.equal(cmd.enclosing_fn, exec.id);
  const nosql = sinks.find((s) => s.class === "nosql");
  assert.equal(nosql.file, "dao/userDao.js");
  assert.equal(nosql.callee, "$ne");
  assert.equal(nosql.enclosing_fn, fnNamed(graph, "dao/userDao.js", "find").id);
  const sources = nodesOf(graph, "source");
  assert.deepEqual(sources.map((s) => s.kind).sort(), ["body", "params"]);
  for (const s of sources) assert.equal(s.enclosing_fn, run.id);
  const imports = graph.edges.filter((e) => e.type === "imports");
  const fileId = (p) => nodeId("file", p);
  assert.ok(imports.some((e) => e.from === fileId("server.js") && e.to === fileId("routes/users.js") && e.specifier === "./routes/users" && e.confidence === "exact"));
  assert.equal(graph.stats.files_total, 4);
  assert.equal(graph.stats.files_parsed, 4);
  assert.equal(graph.stats.calls_total, calls.length);
  assert.equal(graph.stats.calls_exact + graph.stats.calls_name_only + graph.stats.calls_unresolved, calls.length);
  assert.deepEqual(graph.stats.coverage_matrix.node.extractors_applied, ["express", "nest"]);
  assert.deepEqual(graph.stats.coverage_matrix.node.frameworks_detected, ["express"]);
});

// ---- (3) two sinks on one line ----------------------------------------------------------------------

test("(3) two sinks on one line are two sink nodes with distinct ids", async (t) => {
  const dir = tempDir(t);
  put(dir, "a.js", "function f(a, b) { eval(a); execSync(b); }\n");
  const { graph } = await build(dir);
  const sinks = nodesOf(graph, "sink");
  assert.equal(sinks.length, 2);
  assert.equal(sinks[0].line, sinks[1].line);
  assert.notEqual(sinks[0].id, sinks[1].id);
  assert.deepEqual(sinks.map((s) => s.class).sort(), ["cmd-exec", "eval"]);
});

test("enclosing_fn: end_byte is exclusive; a sink in an arrow inside a method belongs to the arrow", async (t) => {
  const dir = tempDir(t);
  put(dir, "a.js", "function f(){}eval(x);\n");
  put(dir, "b.js", "class K {\n  m() {\n    const g = () => { eval(y); };\n    execSync(z);\n  }\n}\n");
  const { graph } = await build(dir);
  const sinks = nodesOf(graph, "sink");
  assert.equal(sinks.find((s) => s.file === "a.js").enclosing_fn, null);
  const arrow = nodesOf(graph, "function").find((n) => n.file === "b.js" && n.kind === "arrow");
  assert.ok(arrow);
  assert.equal(sinks.find((s) => s.file === "b.js" && s.class === "eval").enclosing_fn, arrow.id);
  assert.equal(sinks.find((s) => s.file === "b.js" && s.class === "cmd-exec").enclosing_fn, fnNamed(graph, "b.js", "K.m").id);
});

// ---- (4) invalid UTF-8 ----------------------------------------------------------------------------

test("(4) invalid UTF-8 is decoded leniently (M2): garbage bytes are a syntax error, the partial tree is still extracted, the rest is built", async (t) => {
  const dir = tempDir(t);
  put(dir, "bad.js", Buffer.concat([Buffer.from([0xff, 0xfe, 0x00]), Buffer.from("function x() {}\n")]));
  put(dir, "good.js", "function y() {}\n");
  const { graph } = await build(dir);
  assert.ok(graph);
  assert.equal(validate("graph", graph).valid, true);
  const files = Object.fromEntries(nodesOf(graph, "file").map((n) => [n.path, n.parse_status]));
  assert.deepEqual(files, { "bad.js": "error", "good.js": "ok" });
  assert.equal(graph.stats.files_error, 1);
  assert.ok(fnNamed(graph, "good.js", "y"));
  assert.ok(fnNamed(graph, "bad.js", "x")); // decoded to U+FFFD, not dropped: like any syntax-error file
});

test("a syntax error still extracts the partial tree; CRLF and LF checkouts give the same ids", async (t) => {
  const dir = tempDir(t);
  put(dir, "broken.js", "function ok() { eval(x); }\nfunction bad( {\n");
  const lf = tempDir(t);
  const crlf = tempDir(t);
  put(lf, "a.js", "function f() {\n  eval(x);\n}\n");
  put(crlf, "a.js", "function f() {\r\n  eval(x);\r\n}\r\n");
  const broken = (await build(dir)).graph;
  assert.equal(nodesOf(broken, "file")[0].parse_status, "error");
  assert.ok(fnNamed(broken, "broken.js", "ok"));
  assert.equal(JSON.stringify((await build(lf)).graph), JSON.stringify((await build(crlf)).graph));
});

test("files without an extractor are skipped 'no extractor'; zero supported files is a valid empty graph", async (t) => {
  const dir = tempDir(t);
  put(dir, "a.py", "def f():\n    pass\n");
  put(dir, "b.js", "function g() {}\n");
  put(dir, "README.md", "# x\n");
  const noModules = tempDir(t, "oswe-build-graph-nolang-"); // no language has an extractor here
  const { graph } = await build(dir, { stacks: ["python"], frameworks: ["flask"], langModulesDir: noModules });
  assert.equal(validate("graph", graph).valid, true);
  const skipped = (path, stack, lang) => ({ type: "file", id: nodeId("file", path), path, stack, lang, parse_status: "skipped", skip_reason: "no extractor" });
  assert.deepEqual(nodesOf(graph, "file"), [skipped("a.py", "python", "python"), skipped("b.js", "node", "javascript")].sort((a, b) => (a.id < b.id ? -1 : 1)));
  assert.equal(graph.stats.files_skipped, 2);
  assert.deepEqual(graph.stats.coverage_matrix.python, { frameworks_detected: ["flask"], extractors_applied: [], not_extracted: [], patterns_unmatched: [] });
  assert.deepEqual(graph.stats.coverage_matrix.node, { frameworks_detected: [], extractors_applied: [], not_extracted: [], patterns_unmatched: [] });
  const empty = tempDir(t);
  put(empty, "notes.txt", "x");
  const r = await build(empty);
  assert.equal(validate("graph", r.graph).valid, true);
  assert.deepEqual(r.graph.nodes, []);
  assert.equal(r.graph.stats.files_total, 0);
  assert.deepEqual(Object.keys(r.graph.stats.coverage_matrix), ["node"]);
});

// ---- (5) parser unavailable -----------------------------------------------------------------------

test("(5) an empty vendorDir yields { graph: null, reason } and the CLI exits 0 with that envelope", async (t) => {
  const empty = tempDir(t);
  const r = await build(NODE_FIXTURE, { vendorDir: empty });
  assert.equal(r.graph, null);
  assert.equal(r.reason, "vendored parser files missing");
  assert.equal(/[\/]/.test(r.reason), false); // never the vendorDir path
  const cli = runCli(t, { projectDir: NODE_FIXTURE, scope_realpath: NODE_FIXTURE, stacks: ["node"], frameworks: ["express"], referencesDir: REFERENCES_DIR, vendorDir: empty });
  assert.equal(cli.status, 0, cli.stderr);
  const out = JSON.parse(cli.out);
  assert.equal(out.graph, null);
  assert.equal(out.reason, "vendored parser files missing");
});

// ---- (6) mounts and auth --------------------------------------------------------------------------

test("(6) mount + auth: POST /users/:id/run is authenticated via the mount middleware; /health is not", async () => {
  const { graph } = await build(NODE_FIXTURE);
  const routes = nodesOf(graph, "route");
  assert.equal(routes.length, 2); // the app.use mount itself is never a route node
  const ensure = fnNamed(graph, "server.js", "ensureAuthenticated");
  const run = fnNamed(graph, "routes/users.js", "run");
  const post = routes.find((r) => r.http_method === "POST");
  assert.deepEqual(post, {
    type: "route", id: nodeId("route", "routes/users.js", 259), file: "routes/users.js", line: 10, http_method: "POST",
    path_pattern: "/users/:id/run", handler: run.id, middlewares: [ensure.id], framework: "express", auth: "authenticated"
  });
  const health = routes.find((r) => r.path_pattern === "/health");
  assert.equal(health.auth, "unauthenticated");
  assert.equal(health.handler, fnNamed(graph, "server.js", "<anon>@9:20").id);
  assert.deepEqual(health.middlewares, []);
  const edges = graph.edges.filter((e) => e.from === post.id);
  assert.deepEqual(edges, [{ type: "handles", from: post.id, to: run.id }, { type: "uses_middleware", from: post.id, to: ensure.id, order: 0 }]);
  assert.deepEqual(graph.stats.routes_by_auth, { unauthenticated: 1, authenticated: 1, unknown: 0 });
});

test("(6) auth: an unresolved non-marker middleware is unknown; an unresolved marker is authenticated", async (t) => {
  const dir = tempDir(t);
  put(dir, "app.js", [
    "const passport = require('passport');",
    "function handler(req, res) {}",
    "app.get('/a', checkThing, handler);",
    "app.get('/b', passport.authenticate('local'), handler);",
    "app.get('/c', handler);",
    ""
  ].join("\n"));
  const { graph } = await build(dir);
  const auth = Object.fromEntries(nodesOf(graph, "route").map((r) => [r.path_pattern, [r.auth, r.middlewares]]));
  assert.deepEqual(auth, {
    "/a": ["unknown", ["checkThing"]],
    "/b": ["authenticated", ["passport.authenticate"]],
    "/c": ["unauthenticated", []]
  });
});

test("(6) a global app.use(fn) guards only later routes under its path; an unresolvable mount is not_extracted", async (t) => {
  const dir = tempDir(t);
  put(dir, "app.js", [
    "const admin = require('./admin');",
    "function ensureAuthenticated(req, res, next) { next(); }",
    "function h(req, res) {}",
    "app.get('/early', h);",
    "app.use(ensureAuthenticated);",
    "app.get('/late', h);",
    "app.use('/admin', admin);",
    "app.use('/x', express.static('pub'));",
    ""
  ].join("\n"));
  put(dir, "admin.js", [
    "const router = express.Router();",
    "const sub = require('./sub');",
    "router.get('/panel', (req, res) => {});",
    "router.use('/sub', sub);",
    "module.exports = router;",
    ""
  ].join("\n"));
  put(dir, "sub.js", "router.delete('/', (req, res) => {});\nmodule.exports = router;\n");
  const { graph } = await build(dir);
  const ensure = fnNamed(graph, "app.js", "ensureAuthenticated").id;
  const routes = Object.fromEntries(nodesOf(graph, "route").map((r) => [`${r.http_method} ${r.path_pattern}`, [r.auth, r.middlewares]]));
  assert.deepEqual(routes, {
    "GET /early": ["unauthenticated", []],
    "GET /late": ["authenticated", [ensure]],
    "GET /admin/panel": ["authenticated", [ensure]],
    "DELETE /admin/sub": ["authenticated", [ensure]]
  });
  // I3: express.static is BENIGN_MIDDLEWARE — ignored entirely (no note, no unresolved middleware)
  assert.deepEqual(graph.stats.coverage_matrix.node.not_extracted, []);
});

test("I3: an unresolved global app.use(...) is a middleware text for later routes: marker => authenticated, else unknown; benign ones are ignored", async (t) => {
  const dir = tempDir(t);
  put(dir, "app.js", [
    "const passport = require('passport');",
    "function h(req, res) {}",
    "app.use(express.json());",
    "app.use(bodyParser.urlencoded({ extended: false }));",
    "app.use(cors());",
    "app.use(helmet.contentSecurityPolicy());",
    "app.get('/open', h);",
    "app.use('/api', passport.authenticate('jwt'));",
    "app.get('/api/secret', h);",
    "app.get('/other', h);",
    "app.use('/v', vendorRouter);",
    "app.get('/v/x', h);",
    "app.get('/w', h);",
    "app.use(customThing());",
    "app.get('/later', h);",
    ""
  ].join("\n"));
  const { graph } = await build(dir);
  const routes = Object.fromEntries(nodesOf(graph, "route").map((r) => [r.path_pattern, [r.auth, r.middlewares]]));
  assert.deepEqual(routes, {
    "/open": ["unauthenticated", []],
    "/api/secret": ["authenticated", ["passport.authenticate"]],
    "/other": ["unauthenticated", []],
    "/v/x": ["unknown", ["vendorRouter"]],
    "/w": ["unauthenticated", []],
    "/later": ["unknown", ["customThing"]]
  });
  // a non-benign unresolved USE target may also be an unparsed router: still noted
  assert.deepEqual(graph.stats.coverage_matrix.node.not_extracted, ["mount:customThing", "mount:passport.authenticate", "mount:vendorRouter"]);
});

test("I3: the three ruled cases (passport global => authenticated; customThing() => unknown; express.json() => unauthenticated)", async (t) => {
  const cases = [["app.use(passport.authenticate('jwt'));\napp.get('/secret', h);\n", "authenticated"], ["app.use(customThing());\napp.get('/x', h);\n", "unknown"], ["app.use(express.json());\napp.get('/x', h);\n", "unauthenticated"]];
  for (const [src, auth] of cases) {
    const dir = tempDir(t);
    put(dir, "app.js", "function h(req, res) {}\n" + src);
    const { graph } = await build(dir);
    assert.deepEqual(nodesOf(graph, "route").map((r) => r.auth), [auth], src);
  }
});

test("I3: a benign per-route middleware never makes a route unknown", async (t) => {
  const dir = tempDir(t);
  put(dir, "app.js", "function h(req, res) {}\napp.post('/x', bodyParser.json(), h);\napp.post('/y', cookieParser(), checkThing, h);\n");
  const { graph } = await build(dir);
  const routes = Object.fromEntries(nodesOf(graph, "route").map((r) => [r.path_pattern, [r.auth, r.middlewares]]));
  assert.deepEqual(routes, { "/x": ["unauthenticated", ["bodyParser.json"]], "/y": ["unknown", ["cookieParser", "checkThing"]] });
});

test("(6) auth: a Nest @UseGuards guard is authenticated; an unguarded controller is unauthenticated", async (t) => {
  const dir = tempDir(t);
  put(dir, "c.controller.ts", "@Controller('/a')\n@UseGuards(AuthGuard)\nclass C {\n  @Get('/b')\n  m() {}\n}\n");
  put(dir, "d.controller.ts", "@Controller('/d')\nclass D {\n  @Get('/e')\n  m() {}\n}\n");
  const { graph } = await buildGraph({ projectDir: dir, scopeRealpath: dir, stacks: ["node"], frameworks: ["nest"], referencesDir: REFERENCES_DIR });
  const routes = Object.fromEntries(nodesOf(graph, "route").map((r) => [`${r.http_method} ${r.path_pattern}`, r]));
  assert.deepEqual(Object.keys(routes).sort(), ["GET /a/b", "GET /d/e"]);
  assert.equal(routes["GET /a/b"].auth, "authenticated");
  assert.deepEqual(routes["GET /a/b"].middlewares, ["UseGuards.AuthGuard"]);
  assert.equal(routes["GET /a/b"].handler, fnNamed(graph, "c.controller.ts", "C.m").id);
  assert.equal(routes["GET /a/b"].framework, "nest");
  assert.equal(routes["GET /d/e"].auth, "unauthenticated");
  assert.deepEqual(routes["GET /d/e"].middlewares, []);
});

test("(6) auth: a marker with an argument prefix (php ->middleware('auth) matches middleware names starting with it", async (t) => {
  const dir = tempDir(t);
  put(dir, "routes.php", [
    "<?php",
    "Route::get('/a', fn () => 1)->middleware('auth:api');",
    "Route::get('/b', fn () => 1)->middleware('auth.basic');",
    "Route::get('/c', fn () => 1)->middleware('throttle');",
    "Route::get('/d', fn () => 1);",
    "Route::get('/e', fn () => 1)->middleware('auth');",
    "Route::get('/f', fn () => 1)->middleware('author-logging');",
    "Route::get('/g', fn () => 1)->middleware('author');",
    "Route::get('/h', fn () => 1)->middleware('authorized_ip');",
    ""
  ].join("\n"));
  const { graph } = await buildGraph({ projectDir: dir, scopeRealpath: dir, stacks: ["php"], frameworks: ["laravel"], referencesDir: REFERENCES_DIR });
  const routes = Object.fromEntries(nodesOf(graph, "route").map((r) => [r.path_pattern, [r.auth, r.middlewares]]));
  assert.deepEqual(routes, {
    "/a": ["authenticated", ["auth:api"]],
    "/b": ["authenticated", ["auth.basic"]],
    "/c": ["unknown", ["throttle"]],
    "/d": ["unauthenticated", []],
    // I7: the prefix must be followed by end of string, `:` or `.` — `author…` is not `auth`
    "/e": ["authenticated", ["auth"]],
    "/f": ["unknown", ["author-logging"]],
    "/g": ["unknown", ["author"]],
    "/h": ["unknown", ["authorized_ip"]]
  });
});

test("(6) overloaded handlers: each route handles the overload containing it (C# GET/POST pair)", async (t) => {
  const dir = tempDir(t);
  put(dir, "EditController.cs", [
    "[Route(\"[controller]\")]",
    "public class EditController : Controller {",
    "  [HttpGet(\"edit\")] public IActionResult Edit(int id) => View();",
    "  [HttpPost(\"edit\")] public IActionResult Edit(Model m) => View();",
    "}",
    ""
  ].join("\n"));
  const { graph } = await buildGraph({ projectDir: dir, scopeRealpath: dir, stacks: ["dotnet"], frameworks: ["aspnet"], referencesDir: REFERENCES_DIR });
  const edits = nodesOf(graph, "function").filter((f) => f.qualified_name === "EditController.Edit");
  const byLine = new Map(edits.map((f) => [f.line_start, f.id]));
  assert.equal(byLine.size, 2);
  const routes = nodesOf(graph, "route").map((r) => [r.http_method, r.path_pattern, r.handler]).sort();
  assert.deepEqual(routes, [["GET", "/Edit/edit", byLine.get(3)], ["POST", "/Edit/edit", byLine.get(4)]].sort());
  const handles = graph.edges.filter((e) => e.type === "handles").map((e) => e.to).sort();
  assert.deepEqual(handles, [byLine.get(3), byLine.get(4)].sort());
  assert.deepEqual(graph.stats.coverage_matrix.dotnet.not_extracted, []);
});

test("(6) overloaded handlers: a route inside none of them falls back to the text, then notes route(overloaded handler)", async (t) => {
  const dir = tempDir(t);
  put(dir, "a.js", "// placeholder source, extracted by the stub module\n");
  const modules = tempDir(t, "oswe-build-graph-stub-");
  put(modules, "javascript.mjs", [
    "export const lang = { id: 'javascript', stack: 'node', langIds: ['javascript'], frameworks: ['express'], implicitThisCalls: false, submoduleImports: false, callableLocals: true, overloads: false };",
    "const fn = (start, end) => ({ name: 'm', qualified_name: 'K.m', line_start: 1, line_end: 1, start_byte: start, end_byte: end, param_count: 0, kind: 'method', exported: false, class: 'K' });",
    "export function extractFile() {",
    "  return { functions: [fn(0, 10), fn(10, 20)], calls: [], imports: [], exports: [], classes: [{ name: 'K', extends: null, methods: ['m'], start_byte: 0 }], namespace: null,",
    "    routes: [{ line: 1, start_byte: 30, http_method: 'GET', path_pattern: '/x', handler_text: 'K.m', middleware_texts: [], framework: 'express' }], sources: [], sinks: [], not_extracted: [] };",
    "}",
    "export const resolveImportSpecifier = () => null;",
    ""
  ].join("\n"));
  const { graph } = await build(dir, { langModulesDir: modules });
  assert.deepEqual(nodesOf(graph, "route").map((r) => [r.path_pattern, r.handler]), [["/x", null]]);
  assert.deepEqual(graph.stats.coverage_matrix.node.not_extracted, ["route(overloaded handler)"]);
});

test("nests edges: a closure or local helper is linked from its innermost enclosing function, and a nested helper call resolves exact", async (t) => {
  const dir = tempDir(t);
  put(dir, "a.js", "function h(req, res) {\n  const helper = () => { eval(req.body.x); };\n  db.get(1, (e, d) => { helper(); });\n}\napp.post('/x', h);\nmodule.exports = h;\n");
  const { graph } = await build(dir);
  const h = fnNamed(graph, "a.js", "h");
  const helper = fnNamed(graph, "a.js", "h.helper");
  const cb = nodesOf(graph, "function").find((n) => n.qualified_name.startsWith("h.<anon>@"));
  const nests = graph.edges.filter((e) => e.type === "nests").map((e) => `${e.from}>${e.to}`).sort();
  assert.deepEqual(nests, [`${h.id}>${helper.id}`, `${h.id}>${cb.id}`].sort());
  assert.deepEqual(graph.edges.filter((e) => e.type === "calls" && e.callee_text === "helper").map((e) => [e.from, e.to, e.confidence]), [[cb.id, helper.id, "exact"]]);
  assert.equal(nodesOf(graph, "sink").find((n) => n.callee === "eval").enclosing_fn, helper.id);
  assert.equal(graph.stats.calls_exact, 1);
  assert.deepEqual(validate("graph", graph), { valid: true, errors: [] });
});

test("(6) a mount cycle drops the cycle-closing mount: the root's routes stay unprefixed", async (t) => {
  const dir = tempDir(t);
  put(dir, "a.js", "const b = require('./b');\napp.use('/b', b);\napp.get('/x', (req, res) => {});\nmodule.exports = app;\n");
  put(dir, "b.js", "const a = require('./a');\nrouter.use('/a', a);\nrouter.get('/y', (req, res) => {});\nmodule.exports = router;\n");
  const { graph } = await build(dir);
  const routes = nodesOf(graph, "route").map((r) => r.file + " " + r.path_pattern).sort();
  assert.deepEqual(routes, ["a.js /x", "b.js /b/y"]);
  assert.deepEqual(graph.stats.coverage_matrix.node.not_extracted, ["mount:a(cycle)"]);
});

test("(6) a router mounted twice keeps the first mount; AllowAnonymous forces unauthenticated", async (t) => {
  const dir = tempDir(t);
  put(dir, "app.js", [
    "const r = require('./r');",
    "function ensureAuthenticated(req, res, next) { next(); }",
    "function h(req, res) {}",
    "app.use('/one', r);",
    "app.use('/two', r);",
    "app.get('/open', ensureAuthenticated, AllowAnonymous, h);",
    ""
  ].join("\n"));
  put(dir, "r.js", "router.get('/z', (req, res) => {});\nmodule.exports = router;\n");
  const { graph } = await build(dir);
  const routes = Object.fromEntries(nodesOf(graph, "route").map((r) => [r.path_pattern, r.auth]));
  assert.deepEqual(routes, { "/one/z": "unauthenticated", "/open": "unauthenticated" });
  assert.deepEqual(graph.stats.coverage_matrix.node.not_extracted, ["mount:r(mounted twice)"]);
});

test("(6) mounted paths keep the child's trailing slash, add none, and a bare / child is the mount path", async (t) => {
  const dir = tempDir(t);
  put(dir, "app.js", "const r = require('./r');\napp.use('/api', r);\n");
  put(dir, "r.js", "router.get('/ping/', (req, res) => {});\nrouter.get('/', (req, res) => {});\nrouter.get('/:id/run', (req, res) => {});\nmodule.exports = router;\n");
  const { graph } = await build(dir);
  assert.deepEqual(nodesOf(graph, "route").map((r) => r.path_pattern).sort(), ["/api", "/api/:id/run", "/api/ping/"]);
});

test("(6) a bare child under a slash-ending mount keeps the mount path as is: Django api/ + '' -> /api/", async (t) => {
  const dir = tempDir(t);
  put(dir, "urls.py", "from django.urls import include, path\n\nurlpatterns = [path('api/', include('api.urls'))]\n");
  put(dir, "api/urls.py", "from django.urls import path\n\n\ndef home(request):\n    pass\n\n\nurlpatterns = [path('', home), path('x/', home)]\n");
  const { graph } = await build(dir, { stacks: ["python"], frameworks: ["django"] });
  assert.deepEqual(nodesOf(graph, "route").map((r) => r.path_pattern).sort(), ["/api/", "/api/x/"]);
});

// ---- (7) cache ------------------------------------------------------------------------------------

test("(7) cache: a second CLI run hits; editing the reference page or tsconfig.json misses", async (t) => {
  const project = join(tempDir(t), "project");
  cpSync(NODE_FIXTURE, project, { recursive: true });
  rmSync(join(project, "graph.expected.json"), { force: true });
  writeFileSync(join(project, "tsconfig.json"), JSON.stringify({ compilerOptions: { baseUrl: "." } }));
  const refs = join(tempDir(t), "references");
  cpSync(REFERENCES_DIR, refs, { recursive: true });
  const checkpointDir = tempDir(t, "oswe-build-graph-ckpt-");
  const input = { projectDir: project, scope_realpath: project, stacks: ["node"], frameworks: ["express"], referencesDir: refs };
  const cacheFiles = () => readdirSync(join(checkpointDir, "build-graph")).filter((f) => f.endsWith(".json")).sort();

  const first = runCli(t, input, { checkpointDir });
  assert.equal(first.status, 0, first.stderr);
  assert.equal(validate("graph", JSON.parse(first.out)).valid, true);
  const [wrapperName] = cacheFiles();
  const wrapperPath = join(checkpointDir, "build-graph", wrapperName);
  const generatedAt = JSON.parse(readFileSync(wrapperPath, "utf8")).generated_at;

  const second = runCli(t, input, { checkpointDir });
  assert.equal(second.status, 0, second.stderr);
  assert.match(second.stderr, /cache hit/);
  assert.equal(second.out, first.out);
  assert.equal(JSON.parse(readFileSync(wrapperPath, "utf8")).generated_at, generatedAt);
  assert.equal(cacheFiles().length, 1);

  writeFileSync(join(refs, "node.md"), readFileSync(join(refs, "node.md"), "utf8") + "\n<!-- edited -->\n");
  const third = runCli(t, input, { checkpointDir });
  assert.equal(third.status, 0, third.stderr);
  assert.doesNotMatch(third.stderr, /cache hit/);
  assert.equal(cacheFiles().length, 2);

  writeFileSync(join(project, "tsconfig.json"), JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@s/*": ["services/*"] } } }));
  const fourth = runCli(t, input, { checkpointDir });
  assert.equal(fourth.status, 0, fourth.stderr);
  assert.doesNotMatch(fourth.stderr, /cache hit/);
  assert.equal(cacheFiles().length, 3);
});

test("(7) cache: adding a walk-skipped file (.min.js) misses and the rebuilt graph lists it", async (t) => {
  const project = join(tempDir(t), "project");
  cpSync(NODE_FIXTURE, project, { recursive: true });
  const checkpointDir = tempDir(t, "oswe-build-graph-ckpt-");
  const input = { projectDir: project, scope_realpath: project, stacks: ["node"], frameworks: ["express"], referencesDir: REFERENCES_DIR };
  const first = runCli(t, input, { checkpointDir });
  assert.equal(first.status, 0, first.stderr);
  writeFileSync(join(project, "lib.min.js"), "var a=1;\n");
  const second = runCli(t, input, { checkpointDir });
  assert.equal(second.status, 0, second.stderr);
  assert.doesNotMatch(second.stderr, /cache hit/);
  const before = JSON.parse(first.out);
  const after = JSON.parse(second.out);
  assert.equal(after.stats.files_total, before.stats.files_total + 1);
  assert.deepEqual(nodesOf(after, "file").find((n) => n.path === "lib.min.js"), { type: "file", id: nodeId("file", "lib.min.js"), path: "lib.min.js", stack: "node", lang: "javascript", parse_status: "skipped", skip_reason: "minified" });
});

test("(7) a { graph: null } envelope is never cached", (t) => {
  const checkpointDir = tempDir(t, "oswe-build-graph-ckpt-");
  const input = { projectDir: NODE_FIXTURE, scope_realpath: NODE_FIXTURE, stacks: ["node"], frameworks: ["express"], referencesDir: REFERENCES_DIR, vendorDir: tempDir(t) };
  const r = runCli(t, input, { checkpointDir });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.out).graph, null);
  const dir = join(checkpointDir, "build-graph");
  assert.deepEqual(existsSync(dir) ? readdirSync(dir) : [], []);
});

test("version digest covers the out-of-tree helpers and the graph schema; a schema byte change moves it", (t) => {
  const slash = (f) => f.split("\\").join("/");
  const files = versionFiles(join(REPO_ROOT, "skills", "audit", "vendor", "tree-sitter"));
  for (const rel of ["vendor/tree-sitter/web-tree-sitter.mjs", "scripts/validate-output.mjs", "scripts/confine-path.mjs", "scripts/cache-wrap.mjs", "schemas/graph.schema.json"]) {
    assert.ok(files.some((f) => slash(f).endsWith(rel)), rel);
  }
  const copy = join(tempDir(t), "graph.schema.json");
  cpSync(join(REPO_ROOT, "skills", "audit", "schemas", "graph.schema.json"), copy);
  const list = files.map((f) => (slash(f).endsWith("schemas/graph.schema.json") ? copy : f));
  const d1 = versionDigest(list);
  assert.match(d1, /^[0-9a-f]{64}$/);
  assert.equal(versionDigest(list), d1);
  writeFileSync(copy, readFileSync(copy, "utf8") + " ");
  assert.notEqual(versionDigest(list), d1);
});

// ---- CLI input contract ---------------------------------------------------------------------------

test("CLI: malformed input and an escaping scope exit 1; a missing --out exits 2", (t) => {
  const base = { projectDir: NODE_FIXTURE, scope_realpath: NODE_FIXTURE, stacks: ["node"], frameworks: [], referencesDir: REFERENCES_DIR };
  for (const key of ["projectDir", "stacks", "referencesDir"]) {
    const input = { ...base };
    delete input[key];
    const r = runCli(t, input);
    assert.equal(r.status, 1, `${key}: ${r.stderr}`);
    assert.match(r.stderr, new RegExp(key));
  }
  const escape = runCli(t, { ...base, scope_realpath: join(NODE_FIXTURE, "..") });
  assert.equal(escape.status, 1, escape.stderr);
  assert.match(escape.stderr, /scope_realpath escapes projectDir/);
  const usage = spawnSync(process.execPath, [CLI, "--file", "x.json"], { encoding: "utf8" });
  assert.equal(usage.status, 2);
});

// ---- (9) performance -------------------------------------------------------------------------------

test("(9) building every test-fixtures/graph/* tree takes < 2 s once the parser is initialised", async () => {
  assert.equal((await parserAvailable()).ok, true);
  const stacks = readdirSync(FIXTURES_DIR, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name);
  const start = performance.now();
  for (const stack of stacks) {
    const dir = realpathSync(join(FIXTURES_DIR, stack));
    const r = await build(dir, { stacks: [stack], frameworks: goldenFrameworks(stack) });
    assert.ok(r.graph, r.reason);
  }
  const elapsed = performance.now() - start;
  assert.ok(elapsed < 2000, `took ${elapsed.toFixed(0)} ms`);
});

// ---- (10) goldens ----------------------------------------------------------------------------------

test("(10) every test-fixtures/graph/<stack>/graph.expected.json equals the rebuilt graph byte-for-byte", async () => {
  // OSWE_UPDATE_GOLDEN=1 (re)writes the golden of every fixture directory, creating missing ones.
  const update = process.env.OSWE_UPDATE_GOLDEN === "1";
  const stacks = readdirSync(FIXTURES_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory() && (update || existsSync(join(FIXTURES_DIR, d.name, "graph.expected.json"))))
    .map((d) => d.name)
    .sort();
  if (!update) assert.ok(stacks.includes("node"), "the node golden is missing");
  for (const stack of stacks) {
    const dir = realpathSync(join(FIXTURES_DIR, stack));
    const { graph, reason } = await buildGraph({ projectDir: dir, scopeRealpath: dir, stacks: [stack], frameworks: goldenFrameworks(stack), referencesDir: REFERENCES_DIR });
    assert.ok(graph, reason);
    const text = JSON.stringify(graph, null, 2) + "\n";
    const golden = join(dir, "graph.expected.json");
    if (update) writeFileSync(golden, text);
    else assert.equal(text, readFileSync(golden, "utf8"), `${stack} golden drifted (rebuild with OSWE_UPDATE_GOLDEN=1 and review)`);
  }
});

// ---- I6: no repo content in stats / reasons ---------------------------------------------------------

test("I6: a mount text is reduced to an identifier-only label (no quotes, spaces or literals); a secret in a config never reaches stats", async (t) => {
  const dir = tempDir(t);
  const secret = "sk_live_51HxSECRETtoken";
  put(dir, "package.json", `{ "name": "x", "k": ${secret} }`);
  put(dir, "app.js", [
    "app.use('/x', handlers['weird key; rm -rf /']);",
    "app.use('/y', " + "a".repeat(80) + ");",
    "app.get('/z', (req, res) => {});",
    ""
  ].join("\n"));
  const { graph } = await build(dir);
  const notes = graph.stats.coverage_matrix.node.not_extracted;
  assert.deepEqual(notes, ["mount:" + "a".repeat(64), "mount:handlers.weirdkeyrmrf"]);
  for (const n of notes) assert.match(n, /^mount:[A-Za-z0-9_.$]{0,64}(\((cycle|mounted twice)\))?$/);
  assert.deepEqual(graph.stats.config_errors, [{ file: "package.json", message: "invalid JSON" }]);
  assert.equal(JSON.stringify(graph).includes(secret), false);
  assert.equal(JSON.stringify(graph).includes(dir), false);
});

// ---- I4: a Spring SecurityFilterChain makes unmarked Spring routes unknown ---------------------------

test("I4: with a SecurityFilterChain config, unauthenticated Spring routes are unknown; marker routes stay authenticated", async (t) => {
  const api = [
    "package com.ex;",
    "@RestController",
    "public class Api {",
    "    @GetMapping(\"/open\") public String open() { return \"ok\"; }",
    "    @PostMapping(\"/admin\") @PreAuthorize(\"hasRole('A')\") public String admin() { return \"ok\"; }",
    "}",
    ""
  ].join("\n");
  const config = "package com.ex;\npublic class Sec {\n    public SecurityFilterChain chain(HttpSecurity http) { return http.build(); }\n}\n";
  const run = async (files) => {
    const dir = tempDir(t);
    for (const [path, src] of Object.entries(files)) put(dir, path, src);
    const { graph } = await buildGraph({ projectDir: dir, scopeRealpath: dir, stacks: ["java"], frameworks: ["spring"], referencesDir: REFERENCES_DIR });
    return graph;
  };
  const without = await run({ "Api.java": api });
  assert.deepEqual(nodesOf(without, "route").map((r) => [r.path_pattern, r.auth]).sort(), [["/admin", "authenticated"], ["/open", "unauthenticated"]]);
  const secured = await run({ "Api.java": api, "Sec.java": config });
  assert.deepEqual(nodesOf(secured, "route").map((r) => [r.path_pattern, r.auth]).sort(), [["/admin", "authenticated"], ["/open", "unknown"]]);
  assert.deepEqual(secured.stats.routes_by_auth, { unauthenticated: 0, authenticated: 1, unknown: 1 });
  assert.ok(secured.stats.coverage_matrix.java.not_extracted.includes("security(unread chain)"));
});

// ---- I10: Spring Security request rules decide the unmarked java routes ---------------------------

const SEC_API = [
  "package com.ex;",
  "@RestController",
  "public class Api {",
  "    @GetMapping(\"/open\") public String open() { return \"ok\"; }",
  "    @GetMapping(\"/css/app.css\") public String css() { return \"ok\"; }",
  "    @PostMapping(\"/mail\") public String mail() { return \"ok\"; }",
  "    @RequestMapping(\"/any\") public String any() { return \"ok\"; }",
  "    @GetMapping(\"/service/admin/users/{name}\") public String admin() { return \"ok\"; }",
  "    @PostMapping(\"/secret\") @PreAuthorize(\"hasRole('A')\") public String secret() { return \"ok\"; }",
  "}",
  ""
].join("\n");
const chain = (body) => `package com.ex;\npublic class Sec {\n    public SecurityFilterChain chain(HttpSecurity http) {\n        http.authorizeHttpRequests(a -> a${body});\n        return http.build();\n    }\n}\n`;
async function javaRoutes(t, files) {
  const dir = tempDir(t);
  for (const [path, src] of Object.entries(files)) put(dir, path, src);
  const { graph } = await buildGraph({ projectDir: dir, scopeRealpath: dir, stacks: ["java"], frameworks: ["spring"], referencesDir: REFERENCES_DIR });
  return { graph, auth: Object.fromEntries(nodesOf(graph, "route").map((r) => [`${r.http_method} ${r.path_pattern}`, r.auth])) };
}

test("I10: one chain — first match over path and verb: permitAll ⇒ unauthenticated, hasAuthority / anyRequest ⇒ authenticated, a route's {var} is one segment, markers stand", async (t) => {
  const { graph, auth } = await javaRoutes(t, {
    "Api.java": SEC_API,
    "Sec.java": chain('.requestMatchers("/css/**", "/open").permitAll().requestMatchers(HttpMethod.POST, "/mail").permitAll().requestMatchers("/service/admin/**").hasAuthority("ADMIN").anyRequest().authenticated()')
  });
  assert.deepEqual(auth, {
    "GET /open": "unauthenticated", "GET /css/app.css": "unauthenticated", "POST /mail": "unauthenticated",
    "ANY /any": "authenticated", "GET /service/admin/users/{name}": "authenticated", "POST /secret": "authenticated"
  });
  assert.deepEqual(graph.stats.coverage_matrix.java.not_extracted, []);
  assert.deepEqual(graph.stats.routes_by_auth, { unauthenticated: 3, authenticated: 3, unknown: 0 });
});

test("I10: verb-specific rules — a route serving ANY is unknown unless every verb agrees; a verb follows its own first match; a path no rule matches is unknown", async (t) => {
  const api = SEC_API.replace('@RequestMapping("/any")', '@RequestMapping("/mail")');
  const only = await javaRoutes(t, { "Api.java": api, "Sec.java": chain('.requestMatchers(HttpMethod.POST, "/mail").permitAll().requestMatchers(HttpMethod.GET, "/open").authenticated()') });
  assert.equal(only.auth["ANY /mail"], "unknown"); // POST permitAll, the other verbs meet no rule
  assert.equal(only.auth["POST /mail"], "unauthenticated");
  assert.equal(only.auth["GET /open"], "authenticated");
  assert.equal(only.auth["GET /css/app.css"], "unknown"); // no rule, no anyRequest
  const agree = await javaRoutes(t, { "Api.java": api, "Sec.java": chain('.requestMatchers(HttpMethod.POST, "/mail").permitAll().anyRequest().permitAll()') });
  assert.equal(agree.auth["ANY /mail"], "unauthenticated");
  const disagree = await javaRoutes(t, { "Api.java": api, "Sec.java": chain('.requestMatchers(HttpMethod.POST, "/mail").permitAll().anyRequest().authenticated()') });
  assert.equal(disagree.auth["ANY /mail"], "unknown");
});

test("I10: access(...) and a non-literal matcher are unknown for every route they may cover; earlier literal rules still decide", async (t) => {
  const { graph, auth } = await javaRoutes(t, {
    "Api.java": SEC_API,
    "Sec.java": chain('.requestMatchers("/css/**").access("x").requestMatchers("/open").permitAll().requestMatchers(PUBLIC).permitAll().anyRequest().authenticated()')
  });
  assert.equal(auth["GET /css/app.css"], "unknown");
  assert.equal(auth["GET /open"], "unauthenticated");
  assert.equal(auth["ANY /any"], "unknown");
  assert.equal(auth["POST /mail"], "unknown");
  assert.equal(auth["POST /secret"], "authenticated");
  assert.ok(graph.stats.coverage_matrix.java.not_extracted.includes("security(non-literal matcher)"));
});

test("I10: several chains vote — agreement decides, disagreement is unknown; a securityMatcher scope restricts a chain's vote to the routes it covers; markers stand", async (t) => {
  const sec2 = (body) => chain(body).replace("class Sec", "class Sec2");
  const agree = await javaRoutes(t, { "Api.java": SEC_API, "Sec.java": chain('.requestMatchers("/open").permitAll().anyRequest().authenticated()'), "Sec2.java": sec2('.requestMatchers("/open", "/css/**").permitAll().anyRequest().authenticated()') });
  assert.deepEqual(agree.auth, { "GET /open": "unauthenticated", "GET /css/app.css": "unknown", "POST /mail": "authenticated", "ANY /any": "authenticated", "GET /service/admin/users/{name}": "authenticated", "POST /secret": "authenticated" });
  assert.ok(agree.graph.stats.coverage_matrix.java.not_extracted.includes("security(multiple chains)"));
  // a scoped chain alone decides the routes in its scope; the unscoped chain decides the rest
  const scoped = await javaRoutes(t, {
    "Api.java": SEC_API,
    "Sec.java": chain(".anyRequest().permitAll()").replace("http.authorizeHttpRequests", 'http.securityMatcher("/service/**").authorizeHttpRequests'),
    "Sec2.java": sec2(".anyRequest().authenticated()")
  });
  assert.equal(scoped.auth["GET /service/admin/users/{name}"], "unauthenticated");
  assert.equal(scoped.auth["GET /open"], "authenticated");
  assert.deepEqual(scoped.graph.stats.coverage_matrix.java.not_extracted, ["security(multiple chains)"]);
  // only scoped chains, none covering the route: no vote ⇒ unknown
  const uncovered = await javaRoutes(t, { "Api.java": SEC_API, "Sec.java": chain(".anyRequest().permitAll()").replace("http.authorizeHttpRequests", 'http.securityMatcher("/service/**").authorizeHttpRequests') });
  assert.equal(uncovered.auth["GET /open"], "unknown");
  assert.equal(uncovered.auth["GET /service/admin/users/{name}"], "unauthenticated");
});

test("I10: @WebServlet routes through build-graph — handler resolves, framework servlet, no security ⇒ unauthenticated, a chain hint ⇒ unknown, rules apply", async (t) => {
  const servlet = [
    "package com.ex;",
    "@WebServlet(value = \"/cmdi-00/BenchmarkTest00001\")",
    "public class BenchmarkTest00001 extends HttpServlet {",
    "  public void doGet(HttpServletRequest request, HttpServletResponse response) { doPost(request, response); }",
    "  public void doPost(HttpServletRequest request, HttpServletResponse response) { Runtime.getRuntime().exec(request.getParameter(\"cmd\")); }",
    "}",
    ""
  ].join("\n");
  const { graph } = await javaRoutes(t, { "BenchmarkTest00001.java": servlet });
  assert.deepEqual(
    nodesOf(graph, "route").map((r) => [r.http_method, r.path_pattern, r.framework, r.auth, r.handler !== null]).sort(),
    [["GET", "/cmdi-00/BenchmarkTest00001", "servlet", "unauthenticated", true], ["POST", "/cmdi-00/BenchmarkTest00001", "servlet", "unauthenticated", true]]
  );
  const fn = (qn) => graph.nodes.find((n) => n.type === "function" && n.qualified_name === qn);
  assert.ok(graph.edges.some((e) => e.type === "calls" && e.from === fn("BenchmarkTest00001.doGet").id && e.to === fn("BenchmarkTest00001.doPost").id && e.confidence === "exact"));
  assert.ok(graph.nodes.some((n) => n.type === "sink" && n.class === "cmd-exec" && n.enclosing_fn === fn("BenchmarkTest00001.doPost").id));
  assert.ok(graph.nodes.some((n) => n.type === "source" && n.kind === "query" && n.enclosing_fn === fn("BenchmarkTest00001.doPost").id));
  const hinted = await javaRoutes(t, { "BenchmarkTest00001.java": servlet, "Sec.java": "package com.ex;\npublic class Sec {\n    public SecurityFilterChain chain(HttpSecurity http) { return http.build(); }\n}\n" });
  assert.equal(hinted.auth["POST /cmdi-00/BenchmarkTest00001"], "unknown");
  const ruled = await javaRoutes(t, { "BenchmarkTest00001.java": servlet, "Sec.java": chain('.requestMatchers("/cmdi-00/**").authenticated()') });
  assert.equal(ruled.auth["GET /cmdi-00/BenchmarkTest00001"], "authenticated");
});

test("antPathRegex: Spring's AntPathMatcher subset (?, *, whole-segment **, {var} with nested braces, {*rest}); a pattern without a leading slash is unreadable (null)", () => {
  const hit = (pattern, path) => antPathRegex(pattern).test(path);
  assert.ok(hit("/css/**", "/css") && hit("/css/**", "/css/a/b.css") && !hit("/css/**", "/cssx"));
  assert.ok(hit("/a/**/b", "/a/b") && hit("/a/**/b", "/a/x/y/b") && !hit("/a/**/b", "/a/x"));
  assert.ok(hit("/**", "/anything/at/all") && hit("/**", "/"));
  assert.ok(hit("/*.mvc", "/register.mvc") && !hit("/*.mvc", "/a/register.mvc") && !hit("/*.mvc", "/registermvc"));
  assert.ok(hit("/u/?", "/u/a") && !hit("/u/?", "/u/ab"));
  assert.ok(hit("/users/{id}", "/users/42") && !hit("/users/{id}", "/users/42/x") && hit("/a/{b}/{c}", "/a/1/2"));
  // a `{var:regex}` constraint is not reproduced: unreadable (a permitAll on `/users/{id:\d+}` must not reach /users/me)
  assert.equal(antPathRegex("/users/{id:[0-9]+}/x"), null);
  assert.equal(antPathRegex("/users/{id:\\d{3}}"), null);
  assert.ok(hit("/files/{*rest}", "/files/a/b") && hit("/files/{*rest}", "/files/") && hit("/files/{*rest}", "/files") && !hit("/files/{*rest}", "/filesx"));
  // an empty trailing token is dropped, as AntPathMatcher does
  assert.ok(hit("/x/**/", "/x/a") && hit("/x/**/", "/x") && !hit("/x/**/", "/y"));
  assert.ok(hit("/a/**/**/b", "/a/b") && hit("/a/**/**/b", "/a/x/b") && hit("/**/x", "/x") && hit("/**/x", "/a/b/x"));
  // a `**` that is not a whole segment is a plain `*`
  assert.ok(hit("/publicx**", "/publicxfoo") && !hit("/publicx**", "/publicx/admin"));
  assert.ok(hit("/a+b(c).d", "/a+b(c).d") && !hit("/a+b(c).d", "/a+b(c)xd"));
  assert.equal(antPathRegex("admin/**"), null);
  assert.equal(antPathRegex("**"), null);
});

test("I10: a chain the extractor cannot read votes unknown (its scope only, when scoped); the §2.4 hint and a servlet filter turn an unauthenticated verdict into unknown", async (t) => {
  // B1: an admin chain whose rules live in a method reference, next to a permissive web chain
  const admin = "package com.ex;\npublic class Sec {\n    @Order(1) public SecurityFilterChain admin(HttpSecurity http) { http.securityMatcher(\"/service/admin/**\").authorizeHttpRequests(this::adminRules); return http.build(); }\n    @Order(2) public SecurityFilterChain web(HttpSecurity http) { http.authorizeHttpRequests(a -> a.anyRequest().permitAll()); return http.build(); }\n}\n";
  const b1 = await javaRoutes(t, { "Api.java": SEC_API, "Sec.java": admin });
  assert.equal(b1.auth["GET /service/admin/users/{name}"], "unknown");
  assert.equal(b1.auth["GET /open"], "unauthenticated");
  assert.ok(b1.graph.stats.coverage_matrix.java.not_extracted.includes("security(multiple chains)"));
  // the same admin chain with nothing at all inside: an unread chain, noted
  const empty = await javaRoutes(t, { "Api.java": SEC_API, "Sec.java": admin.replace("http.securityMatcher(\"/service/admin/**\").authorizeHttpRequests(this::adminRules); ", "") });
  assert.equal(empty.auth["GET /service/admin/users/{name}"], "unknown");
  assert.ok(empty.graph.stats.coverage_matrix.java.not_extracted.includes("security(unread chain)"));
  // the unread chain is unscoped: everything unknown
  const b1u = await javaRoutes(t, { "Api.java": SEC_API, "Sec.java": admin.replace('http.securityMatcher("/service/admin/**").', "http.") });
  assert.deepEqual(b1u.graph.stats.routes_by_auth, { unauthenticated: 0, authenticated: 1, unknown: 5 });
  // B2: a readable chain plus a file that only names a security type ⇒ the hint downgrades unauthenticated
  const b2 = await javaRoutes(t, { "Api.java": SEC_API, "Sec.java": chain(".anyRequest().permitAll()"), "Flux.java": "package com.ex;\n@EnableWebSecurity\npublic class Flux { }\n" });
  assert.equal(b2.auth["GET /open"], "unknown");
  // web.ignoring(): no security on those paths, the chain decides the rest
  const ignoring = await javaRoutes(t, { "Api.java": SEC_API, "Sec.java": chain(".anyRequest().authenticated()"), "Ign.java": "package com.ex;\npublic class Ign {\n    @Bean public WebSecurityCustomizer ignore() { return web -> web.ignoring().requestMatchers(\"/css/**\"); }\n}\n" });
  assert.equal(ignoring.auth["GET /css/app.css"], "unauthenticated");
  assert.equal(ignoring.auth["GET /open"], "authenticated");
  // servlets: a guard annotation authenticates; a filter class makes the unmarked servlet route unknown
  const servlet = "package com.ex;\n@WebServlet(\"/s\")\n@ServletSecurity(@HttpConstraint(rolesAllowed = \"admin\"))\npublic class S extends HttpServlet {\n  public void doGet(HttpServletRequest q, HttpServletResponse r) { }\n}\n@WebServlet(\"/plain\")\nclass P extends HttpServlet {\n  public void doGet(HttpServletRequest q, HttpServletResponse r) { }\n}\n";
  const guarded = await javaRoutes(t, { "S.java": servlet });
  assert.deepEqual(guarded.auth, { "GET /s": "authenticated", "GET /plain": "unauthenticated" });
  const filtered = await javaRoutes(t, { "S.java": servlet, "F.java": "package com.ex;\n@WebFilter(\"/*\")\npublic class F implements Filter {\n  public void doFilter(ServletRequest q, ServletResponse r, FilterChain c) { }\n}\n" });
  assert.deepEqual(filtered.auth, { "GET /s": "authenticated", "GET /plain": "unknown" });
});

test("I10: rules the extractor cannot see, unread scopes and verb-specific ignores never yield unauthenticated where Spring would authenticate", async (t) => {
  const admin = (body) => `package com.ex;\npublic class Sec {\n${body}\n}\n`;
  // the H2-console idiom: an unread scope next to an app chain using antMatcher(...) arguments
  const h2 = await javaRoutes(t, { "Api.java": SEC_API, "Sec.java": admin('    @Order(1) public SecurityFilterChain h2(HttpSecurity http) { http.securityMatcher(PathRequest.toH2Console()).authorizeHttpRequests(a -> a.anyRequest().permitAll()); return http.build(); }\n    @Order(2) public SecurityFilterChain app(HttpSecurity http) { http.authorizeHttpRequests(a -> a.requestMatchers(antMatcher("/open")).permitAll().anyRequest().authenticated()); return http.build(); }') });
  assert.equal(h2.auth["GET /service/admin/users/{name}"], "unknown"); // the unread-scope chain votes everywhere and disagrees
  assert.equal(h2.auth["GET /open"], "unauthenticated"); // both chains permit it
  // the chain's HttpSecurity handed to a helper that holds the restrictive rules
  const helper = await javaRoutes(t, { "Api.java": SEC_API, "Sec.java": admin('    public SecurityFilterChain a(HttpSecurity http) { common(http); http.authorizeHttpRequests(z -> z.anyRequest().permitAll()); return http.build(); }\n    private void common(HttpSecurity http) { http.authorizeHttpRequests(a -> a.requestMatchers("/service/admin/**").authenticated()); }') });
  assert.equal(helper.auth["GET /service/admin/users/{name}"], "unknown");
  assert.equal(helper.auth["GET /open"], "unknown");
  // a method reference, then a permissive authorize
  const ref = await javaRoutes(t, { "Api.java": SEC_API, "Sec.java": admin('    public SecurityFilterChain a(HttpSecurity http) { http.authorizeHttpRequests(this::rules).authorizeHttpRequests(a -> a.anyRequest().permitAll()); return http.build(); }') });
  assert.equal(ref.auth["GET /service/admin/users/{name}"], "unknown");
  // the zero-argument opener: scope unread, the chain votes everywhere
  const opener = await javaRoutes(t, { "Api.java": SEC_API, "Sec.java": admin('    @Order(1) public SecurityFilterChain api(HttpSecurity http) { http.securityMatchers().requestMatchers("/api/**"); http.authorizeHttpRequests(a -> a.anyRequest().permitAll()); return http.build(); }\n    @Order(2) public SecurityFilterChain web(HttpSecurity http) { http.authorizeHttpRequests(a -> a.anyRequest().authenticated()); return http.build(); }') });
  assert.equal(opener.auth["GET /service/admin/users/{name}"], "unknown");
  // a fully-qualified return type is a chain
  const qualified = await javaRoutes(t, { "Api.java": SEC_API, "Sec.java": admin('    public org.springframework.security.web.SecurityFilterChain b(HttpSecurity http) { http.authorizeHttpRequests(a -> a.requestMatchers("/service/admin/**").authenticated().anyRequest().permitAll()); return http.build(); }') });
  assert.equal(qualified.auth["GET /service/admin/users/{name}"], "authenticated");
  assert.equal(qualified.auth["GET /open"], "unauthenticated");
  // web.ignoring() keeps its verb: only GET /open bypasses security; POST /open is the main chain's
  const api = SEC_API.replace('@RequestMapping("/any")', '@PostMapping("/open")');
  const verb = await javaRoutes(t, { "Api.java": api, "Sec.java": chain(".anyRequest().authenticated()"), "Ign.java": "package com.ex;\npublic class Ign {\n    @Bean public WebSecurityCustomizer ignore() { return web -> web.ignoring().requestMatchers(HttpMethod.GET, \"/open\"); }\n}\n" });
  assert.equal(verb.auth["GET /open"], "unauthenticated");
  assert.equal(verb.auth["POST /open"], "authenticated");
  // ...and a route serving ANY verb under a verb-specific ignore is covered by it but not settled: unknown
  const any = await javaRoutes(t, { "Api.java": SEC_API.replace('@RequestMapping("/any")', '@RequestMapping("/open")'), "Sec.java": chain(".anyRequest().authenticated()"), "Ign.java": "package com.ex;\npublic class Ign {\n    @Bean public WebSecurityCustomizer ignore() { return web -> web.ignoring().requestMatchers(HttpMethod.GET, \"/open\"); }\n}\n" });
  assert.equal(any.auth["ANY /open"], "unknown");
  // a filter subclass makes the unmarked servlet route unknown
  const servlet = "package com.ex;\n@WebServlet(\"/plain\")\npublic class P extends HttpServlet {\n  public void doGet(HttpServletRequest q, HttpServletResponse r) { }\n}\n";
  const sub = await javaRoutes(t, { "P.java": servlet, "F.java": "package com.ex;\npublic class F extends HttpFilter {\n  protected void doFilter(HttpServletRequest q, HttpServletResponse r, FilterChain c) { }\n}\n" });
  assert.equal(sub.auth["GET /plain"], "unknown");
});

test("I10: regex scopes, {var:regex} rules, a filter guarding Spring routes, a web.xml constraint, Spring Security on the build path, an unread-scope chain alone, a verb-only scope: never unauthenticated where Spring would authenticate", async (t) => {
  const sec = (body) => `package com.ex;\npublic class Sec {\n${body}\n}\n`;
  const api = SEC_API.replace('@RequestMapping("/any")', '@GetMapping("/api/public/x") public String pub() { return "ok"; }\n    @GetMapping("/users/me") public String me() { return "ok"; }\n    @RequestMapping("/any")');
  // P18 / R1: a Spring 5 regex scope is not an Ant pattern — unread, so the chain votes everywhere
  const regex = await javaRoutes(t, { "Api.java": api, "Sec.java": sec('    @Order(1) public SecurityFilterChain api(HttpSecurity http) { http.regexMatcher("/api/.*").authorizeHttpRequests(a -> a.anyRequest().authenticated()); return http.build(); }\n    @Order(2) public SecurityFilterChain pub(HttpSecurity http) { http.antMatcher("/api/public/**").authorizeHttpRequests(a -> a.anyRequest().permitAll()); return http.build(); }') });
  assert.equal(regex.auth["GET /api/public/x"], "unknown");
  // R2: a {var:regex} rule is unreadable, so a permitAll on it never reaches /users/me; being unreadable it
  // may match any later route too (first match), so those are unknown rather than authenticated
  const constrained = await javaRoutes(t, { "Api.java": api, "Sec.java": chain('.requestMatchers("/users/{id:\\\\d+}").permitAll().anyRequest().authenticated()') });
  assert.equal(constrained.auth["GET /users/me"], "unknown");
  assert.equal(constrained.auth["GET /open"], "unknown");
  const literalFirst = await javaRoutes(t, { "Api.java": api, "Sec.java": chain('.requestMatchers("/open").authenticated().requestMatchers("/users/{id:\\\\d+}").permitAll().anyRequest().authenticated()') });
  assert.equal(literalFirst.auth["GET /open"], "authenticated");
  // R5: web.ignoring().regexMatchers is only noted
  const ignoreRegex = await javaRoutes(t, { "Api.java": api, "Sec.java": chain(".anyRequest().authenticated()"), "Ign.java": "package com.ex;\npublic class Ign {\n    @Bean public WebSecurityCustomizer ignore() { return web -> web.ignoring().regexMatchers(\"/api/.*\"); }\n}\n" });
  assert.equal(ignoreRegex.auth["GET /api/public/x"], "authenticated");
  assert.ok(ignoreRegex.graph.stats.coverage_matrix.java.not_extracted.includes("security(non-literal matcher)"));
  // R6: a filter bean and no chain: Boot registers it on every request, so the Spring routes are unknown
  const filterOnly = await javaRoutes(t, { "Api.java": api, "Jwt.java": "package com.ex;\n@Component\npublic class Jwt extends OncePerRequestFilter {\n  protected void doFilterInternal(HttpServletRequest q, HttpServletResponse r, FilterChain c) { }\n}\n" });
  assert.equal(filterOnly.auth["GET /open"], "unknown");
  assert.equal(filterOnly.auth["POST /secret"], "authenticated");
  // ...but with a chain, the chain decides the Spring routes
  const filterAndChain = await javaRoutes(t, { "Api.java": api, "Sec.java": chain('.requestMatchers("/open").permitAll().anyRequest().authenticated()'), "Jwt.java": "package com.ex;\n@Component\npublic class Jwt extends OncePerRequestFilter {\n  protected void doFilterInternal(HttpServletRequest q, HttpServletResponse r, FilterChain c) { }\n}\n" });
  assert.equal(filterAndChain.auth["GET /open"], "unauthenticated");
  // R7: a web.xml auth constraint at a conventional location makes every unmarked route unknown; without <auth-constraint> it is nothing
  const webXml = (body) => `<?xml version="1.0"?>\n<web-app>\n  <security-constraint>\n    <web-resource-collection><url-pattern>/*</url-pattern></web-resource-collection>\n${body}  </security-constraint>\n</web-app>\n`;
  const constraint = await javaRoutes(t, { "Api.java": api, "src/main/webapp/WEB-INF/web.xml": webXml("    <auth-constraint><role-name>admin</role-name></auth-constraint>\n") });
  assert.equal(constraint.auth["GET /open"], "unknown");
  assert.ok(constraint.graph.stats.coverage_matrix.java.not_extracted.includes("servlet(security-constraint)"));
  const noAuth = await javaRoutes(t, { "Api.java": api, "src/main/webapp/WEB-INF/web.xml": webXml("    <user-data-constraint><transport-guarantee>CONFIDENTIAL</transport-guarantee></user-data-constraint>\n") });
  assert.equal(noAuth.auth["GET /open"], "unauthenticated");
  // R4: Spring Security on the build path with no chain read: Boot's default chain, unknown; a readable chain still decides
  const pom = "<project><dependencies><dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-security</artifactId></dependency></dependencies></project>\n";
  const starter = await javaRoutes(t, { "Api.java": api, "pom.xml": pom });
  assert.equal(starter.auth["GET /open"], "unknown");
  assert.ok(starter.graph.stats.coverage_matrix.java.not_extracted.includes("security(dependency)"));
  const starterChain = await javaRoutes(t, { "Api.java": api, "pom.xml": pom, "Sec.java": chain('.requestMatchers("/open").permitAll().anyRequest().authenticated()') });
  assert.equal(starterChain.auth["GET /open"], "unauthenticated");
  assert.ok(!starterChain.graph.stats.coverage_matrix.java.not_extracted.includes("security(dependency)"));
  const gradle = await javaRoutes(t, { "Api.java": api, "build.gradle.kts": 'dependencies { implementation("org.springframework.boot:spring-boot-starter-security") }\n' });
  assert.equal(gradle.auth["GET /open"], "unknown");
  // P5 / R8: only an unread-scope chain: a route it may not cover meets no chain for sure — unknown, never authenticated
  const unreadOnly = await javaRoutes(t, { "Api.java": api, "Sec.java": sec('    public SecurityFilterChain api(HttpSecurity http) { http.securityMatcher(new AntPathRequestMatcher("/api/**")).authorizeHttpRequests(a -> a.anyRequest().authenticated()); return http.build(); }') });
  assert.equal(unreadOnly.auth["GET /open"], "unknown");
  assert.equal(unreadOnly.auth["GET /api/public/x"], "unknown");
  // R3: a GET-only scope permits GET /open; POST /open is the unscoped chain's; a route serving ANY verb is unknown
  const anyApi = SEC_API.replace('@RequestMapping("/any")', '@RequestMapping("/open")').replace('@GetMapping("/open") public String open()', '@PostMapping("/open2") public String open2()');
  const verbScope = await javaRoutes(t, { "Api.java": anyApi, "Sec.java": sec('    @Order(1) public SecurityFilterChain open(HttpSecurity http) { http.securityMatchers(m -> m.requestMatchers(HttpMethod.GET, "/open")).authorizeHttpRequests(a -> a.anyRequest().permitAll()); return http.build(); }\n    @Order(2) public SecurityFilterChain web(HttpSecurity http) { http.authorizeHttpRequests(a -> a.anyRequest().authenticated()); return http.build(); }') });
  assert.equal(verbScope.auth["ANY /open"], "unknown");
  assert.equal(verbScope.auth["POST /open2"], "authenticated");
});

// ---- I9: NodeGoat-shaped JavaScript ---------------------------------------------------------------

test("I9: NodeGoat-shaped app — the route handler resolves to SessionHandler.handleSignup and a /signup -> eval candidate path exists", async (t) => {
  const dir = tempDir(t);
  put(dir, "app/routes/session.js", [
    "function SessionHandler(db) {",
    "  \"use strict\";",
    "  const userDAO = new UserDAO(db);",
    "  this.handleSignup = (req, res, next) => {",
    "    const payload = req.body.x;",
    "    eval(req.body.x);",
    "    return userDAO.addUser(payload);",
    "  };",
    "}",
    "module.exports = SessionHandler;",
    ""
  ].join("\n"));
  put(dir, "app/routes/index.js", [
    "const SessionHandler = require('./session');",
    "const index = (app, db) => {",
    "  const sessionHandler = new SessionHandler(db);",
    "  app.post('/signup', sessionHandler.handleSignup);",
    "};",
    "module.exports = index;",
    ""
  ].join("\n"));
  const { graph } = await build(dir);
  const handler = fnNamed(graph, "app/routes/session.js", "SessionHandler.handleSignup");
  assert.ok(handler, "SessionHandler.handleSignup is a function node");
  assert.equal(handler.kind, "method");
  const [route] = nodesOf(graph, "route");
  assert.deepEqual([route.http_method, route.path_pattern, route.handler], ["POST", "/signup", handler.id]);
  const { enumeratePaths } = await import("../../enumerate-paths.mjs");
  const { partitionGraph } = await import("../../partition-graph.mjs");
  const [partition] = partitionGraph({ graph, fallback_partitions: [] }).partitions;
  const paths = enumeratePaths({ graph, partition }).candidate_paths;
  assert.deepEqual(paths.map((c) => [c.route.path_pattern, c.hops.map((h) => h.function), c.sink.class, c.sink.callee]), [
    ["/signup", ["SessionHandler.handleSignup"], "eval", "eval"]
  ]);
});

// ---- M2: non-fatal UTF-8 decoding ---------------------------------------------------------------------

test("M2: a Latin-1 file (invalid UTF-8 bytes) still parses: parse_status ok, its functions extracted", async (t) => {
  const dir = tempDir(t);
  const latin1 = Buffer.concat([Buffer.from("// caf"), Buffer.from([0xe9]), Buffer.from(" cr\xe8me\nfunction handler(req, res) { return 1; }\n", "latin1")]);
  writeFileSync(join(dir, "legacy.js"), latin1);
  const { graph } = await build(dir);
  assert.deepEqual(nodesOf(graph, "file").map((f) => [f.path, f.parse_status]), [["legacy.js", "ok"]]);
  assert.ok(fnNamed(graph, "legacy.js", "handler"));
  assert.equal(graph.stats.files_error, 0);
});

test("Task 10 minor: a route removing a marker-matching middleware (withoutMiddleware('auth')) is unknown, never authenticated", async (t) => {
  const dir = tempDir(t);
  put(dir, "routes.php", [
    "<?php",
    "Route::middleware('auth')->group(function () {",
    "    Route::get('/a', fn () => 1);",
    "    Route::get('/b', fn () => 1)->withoutMiddleware('auth');",
    "    Route::get('/c', fn () => 1)->withoutMiddleware('throttle');",
    "});",
    "Route::get('/d', fn () => 1)->withoutMiddleware('auth');",
    ""
  ].join("\n"));
  const { graph } = await buildGraph({ projectDir: dir, scopeRealpath: dir, stacks: ["php"], frameworks: ["laravel"], referencesDir: REFERENCES_DIR });
  const routes = Object.fromEntries(nodesOf(graph, "route").map((r) => [r.path_pattern, r.auth]));
  assert.deepEqual(routes, { "/a": "authenticated", "/b": "unknown", "/c": "authenticated", "/d": "unknown" });
  assert.ok(graph.stats.coverage_matrix.php.not_extracted.includes("withoutMiddleware"));
});
