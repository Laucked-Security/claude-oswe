import { test } from "node:test";
import assert from "node:assert/strict";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import { buildGraph, FRAMEWORK_STACK, versionDigest, versionFiles } from "../../graph/build-graph.mjs";
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
const GOLDEN_FRAMEWORKS = { node: ["express"], python: ["flask", "django", "fastapi"] };
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

test("(4) a file with invalid UTF-8 is parse_status error; the rest of the graph is built", async (t) => {
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
  assert.ok(!nodesOf(graph, "function").some((n) => n.file === "bad.js"));
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
  assert.match(r.reason, /not found/);
  const cli = runCli(t, { projectDir: NODE_FIXTURE, scope_realpath: NODE_FIXTURE, stacks: ["node"], frameworks: ["express"], referencesDir: REFERENCES_DIR, vendorDir: empty });
  assert.equal(cli.status, 0, cli.stderr);
  const out = JSON.parse(cli.out);
  assert.equal(out.graph, null);
  assert.match(out.reason, /not found/);
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
  assert.deepEqual(graph.stats.coverage_matrix.node.not_extracted, ["mount:express.static"]);
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
