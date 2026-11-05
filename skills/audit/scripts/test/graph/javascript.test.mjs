import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseSource } from "../../graph/parser.mjs";
import { loadSurface } from "../../graph/surface.mjs";
import { lang, extractFile, resolveImportSpecifier } from "../../graph/lang/javascript.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..", "..", "..");
const FIXTURE_DIR = join(REPO_ROOT, "test-fixtures", "graph", "node");
const SURFACE = loadSurface("node", join(REPO_ROOT, "skills", "audit", "references"));

async function extract(sourceText, { langId = "javascript", path = "src/a.js" } = {}) {
  const tree = await parseSource(langId, sourceText);
  try {
    return extractFile({ tree, path, sourceText, frameworks: lang.frameworks, surface: SURFACE });
  } finally {
    tree.delete();
  }
}

// CRLF checkouts are read as LF so offsets match the committed (eol=lf) fixture on every platform.
const extractFixture = (path) => extract(readFileSync(join(FIXTURE_DIR, path), "utf8").replace(/\r\n/g, "\n"), { path });
const names = (list) => list.map((x) => x.name);

test("lang descriptor", () => {
  assert.deepEqual(lang, { id: "javascript", stack: "node", langIds: ["javascript", "typescript", "tsx"], frameworks: ["express", "nest"] });
});

// ---- exports ------------------------------------------------------------------------------------

test("module.exports = { run } exports run", async () => {
  const x = await extract("function run() {}\nmodule.exports = { run };\n");
  assert.deepEqual(names(x.exports), ["run"]);
  assert.equal(x.functions[0].exported, true);
});

test("export default exports \"default\"", async () => {
  const x = await extract("export default function () { return 1; }\n");
  assert.deepEqual(names(x.exports), ["default"]);
});

test("export forms: declarations, clause with alias, exports.a, module.exports = ident", async () => {
  const x = await extract(
    "export function f() {}\nexport const k = 1, j = 2;\nexport class C {}\nconst a = 1, b = 2;\nexport { a, b as c };\n" +
      "exports.q = 1;\nmodule.exports.r = 2;\nfunction main() {}\nmodule.exports = main;\nmodule.exports = { s: 1, 't': 2, m() {} };\n"
  );
  assert.deepEqual(names(x.exports), ["f", "k", "j", "C", "a", "c", "q", "r", "default", "main", "s", "t", "m"]);
  const main = x.functions.find((f) => f.name === "main");
  assert.equal(main.exported, true);
});

// ---- imports ------------------------------------------------------------------------------------

test("import forms: named with alias, default, namespace, side effect, CommonJS", async () => {
  const x = await extract(
    "import { a as b, c } from './m';\nimport d from './d';\nimport * as ns from './ns';\nimport './side';\n" +
      "const { e, f: g } = require('./cjs');\nconst h = require('./h');\nrequire('./bare');\nrequire(name);\nimport(dyn);\n"
  );
  assert.deepEqual(x.imports, [
    { line: 1, specifier: "./m", bindings: [{ imported: "a", local: "b" }, { imported: "c", local: "c" }], local: null },
    { line: 2, specifier: "./d", bindings: "default", local: "d" },
    { line: 3, specifier: "./ns", bindings: "namespace", local: "ns" },
    { line: 4, specifier: "./side", bindings: [], local: null },
    { line: 5, specifier: "./cjs", bindings: [{ imported: "e", local: "e" }, { imported: "f", local: "g" }], local: null },
    { line: 6, specifier: "./h", bindings: "namespace", local: "h" },
    { line: 7, specifier: "./bare", bindings: [], local: null }
  ]);
  assert.deepEqual(x.not_extracted, ["dynamic import", "dynamic require"]);
});

// ---- routes -------------------------------------------------------------------------------------

test("@Controller('/a') + @Get('/b') yields route GET /a/b with class and method guards", async () => {
  const x = await extract(
    "@Controller('/a')\n@UseGuards(AuthGuard)\nexport class A {\n  @Get('/b')\n  m() {}\n" +
      "  @Post(':id')\n  @UseGuards(RolesGuard, new OwnerGuard())\n  n(@Param('id') id: string, @Body() body: any) {}\n}\n",
    { langId: "typescript", path: "src/a.controller.ts" }
  );
  assert.deepEqual(
    x.routes.map(({ http_method, path_pattern, handler_text, middleware_texts, framework }) => ({ http_method, path_pattern, handler_text, middleware_texts, framework })),
    [
      { http_method: "GET", path_pattern: "/a/b", handler_text: "A.m", middleware_texts: ["AuthGuard"], framework: "nest" },
      { http_method: "POST", path_pattern: "/a/:id", handler_text: "A.n", middleware_texts: ["AuthGuard", "RolesGuard", "OwnerGuard"], framework: "nest" }
    ]
  );
  assert.deepEqual(x.sources.map((s) => [s.kind, s.pattern]), [["params", "@Param("], ["body", "@Body("]]);
  assert.equal(x.calls.length, 0, "decorator calls are not runtime calls");
});

test("Nest path join: missing path, missing prefix, unprefixed segments", async () => {
  const x = await extract("@Controller('users')\nclass U {\n  @Get()\n  a() {}\n  @Delete('/:id/')\n  b() {}\n}\n@Controller()\nclass R {\n  @All()\n  c() {}\n}\n", {
    langId: "typescript",
    path: "u.ts"
  });
  assert.deepEqual(x.routes.map((r) => `${r.http_method} ${r.path_pattern}`), ["GET /users", "DELETE /users/:id", "ANY /"]);
});

test("Express routes: verbs, USE mounts, inline handlers become functions, router.route chains", async () => {
  const x = await extract(
    "app.use('/api', auth, [rate, log], api);\napp.use(express.json());\nrouter.get('/x', passport.authenticate('jwt'), (req, res) => {});\n" +
      "router.all('/y', h);\nrouter.route('/z').get(h);\napp.use(/re/, h);\napp.get('env');\naxios.get('/remote', { params: 1 });\n"
  );
  assert.deepEqual(
    x.routes.map(({ line, http_method, path_pattern, handler_text, middleware_texts }) => ({ line, http_method, path_pattern, handler_text, middleware_texts })),
    [
      { line: 1, http_method: "USE", path_pattern: "/api", handler_text: "api", middleware_texts: ["auth", "rate", "log"] },
      { line: 2, http_method: "USE", path_pattern: "/", handler_text: "express.json", middleware_texts: [] },
      { line: 3, http_method: "GET", path_pattern: "/x", handler_text: "<anon>@3:48", middleware_texts: ["passport.authenticate"] },
      { line: 4, http_method: "ANY", path_pattern: "/y", handler_text: "h", middleware_texts: [] }
    ]
  );
  assert.ok(x.routes.every((r) => r.framework === "express"));
  const anon = x.functions.find((f) => f.qualified_name === "<anon>@3:48");
  assert.deepEqual([anon.name, anon.kind], ["<anon>", "arrow"]);
  assert.deepEqual(x.not_extracted, ["app.use(regex)", "router.route().chain"]);
});

// ---- sources and sinks --------------------------------------------------------------------------

test("eval inside a string literal or a comment is not a sink; a real eval call is", async () => {
  const x = await extract("const s = 'eval(x)';\n// eval(y)\n/* eval(z) */\neval(w);\n");
  assert.deepEqual(x.sinks.map((s) => [s.line, s.class, s.callee, s.pattern]), [[4, "eval", "eval", "eval("]]);
});

test("{ $ne: null } is a nosql sink; a free \"$ne\" string is not", async () => {
  const keyed = await extract("db.find({ name: { $ne: null } });\ndb.find({ 'age': { '$gt': 1 } });\n");
  assert.deepEqual(keyed.sinks.map((s) => [s.line, s.class, s.callee]), [[1, "nosql", "$ne"], [2, "nosql", "$gt"]]);
  const free = await extract("const op = \"$ne\";\nlog(op, '$gt');\n");
  assert.deepEqual(free.sinks, []);
});

test("one sink per call: the callee member is not a second sink; new Function and word sinks", async () => {
  const x = await extract("cp.exec(a);\nchild_process.exec(b);\nnew Function(c);\nexecSync(d);\nconst run = execFile;\n");
  assert.deepEqual(x.sinks.map((s) => [s.line, s.class, s.callee, s.pattern]), [
    [2, "cmd-exec", "child_process.exec", "child_process.exec"],
    [3, "eval", "Function", "new Function"],
    [4, "cmd-exec", "execSync", "execSync"],
    [5, "cmd-exec", "execFile", "execFile"]
  ]);
});

test("a literal require is an import, not a sink; a dynamic require is an include sink", async () => {
  const x = await extract("const a = require('./a');\nrequire(name);\n");
  assert.deepEqual(x.sinks.map((s) => [s.line, s.class, s.pattern]), [[2, "include", "require("]]);
  assert.deepEqual(x.imports.map((i) => i.specifier), ["./a"]);
  assert.deepEqual(x.not_extracted, ["dynamic require"]);
});

test("calls and their sinks are anchored at the callee's final identifier", async () => {
  const chained = "a.b().c();\n";
  const x = await extract(chained);
  assert.deepEqual(x.calls.map((c) => [c.callee_text, c.start_byte]), [["a.b", chained.indexOf("b")], ["a.b.c", chained.indexOf("c")]]);
  // `exec` alone is not a node surface sink; `execSync` is.
  const oneLine = "execSync(a); eval(b); new Function(c);\n";
  const y = await extract(oneLine);
  assert.deepEqual(y.sinks.map((s) => [s.pattern, s.start_byte]), [["execSync", 0], ["eval(", oneLine.indexOf("eval")], ["new Function", oneLine.indexOf("Function")]]);
  assert.equal(new Set(y.sinks.map((s) => s.start_byte)).size, 3);
});

test("source kinds and one source per member chain", async () => {
  const x = await extract(
    "function h(req) {\n  return [req.query.a, req.body.b.c, req.params.id, req.headers['x'], req.cookies.s, req.files.f, request.body, req.body.toString()];\n}\n"
  );
  assert.deepEqual(x.sources.map((s) => [s.kind, s.pattern]), [
    ["query", "req.query"],
    ["body", "req.body"],
    ["params", "req.params"],
    ["header", "req.headers"],
    ["cookie", "req.cookies"],
    ["file", "req.files"],
    ["body", "req.body"]
  ]);
});

// ---- functions, classes, calls ------------------------------------------------------------------

test("functions: kinds, names, qualified names, classes", async () => {
  const x = await extract(
    "function outer(a) {\n  function inner() {}\n  const f = () => 1;\n  return [1].map(function () {});\n}\n" +
      "class B extends A.Base {\n  m() {}\n  static s() {}\n}\nconst obj = { k() {} };\n"
  );
  assert.deepEqual(
    x.functions.map((f) => [f.name, f.qualified_name, f.kind, f.class, f.line_start, f.line_end]),
    [
      ["outer", "outer", "function", null, 1, 5],
      ["inner", "outer.inner", "function", null, 2, 2],
      ["f", "outer.f", "arrow", null, 3, 3],
      ["<anon>", "outer.<anon>@4:18", "function", null, 4, 4],
      ["m", "B.m", "method", "B", 7, 7],
      ["s", "B.s", "method", "B", 8, 8],
      ["k", "k", "method", null, 10, 10]
    ]
  );
  assert.deepEqual(x.classes.map(({ name, extends: ext, methods }) => ({ name, extends: ext, methods })), [{ name: "B", extends: "A.Base", methods: ["m", "s"] }]);
  const moduleAnon = await extract("[1].map(() => 2);\n", { path: "lib/util.js" });
  assert.equal(moduleAnon.functions[0].qualified_name, "util.<anon>@1:9");
});

test("calls: scope_names exclude imports and top-level definitions, include params/locals/catch/for", async () => {
  const x = await extract(
    "import { imp } from './i';\nconst req2 = require('./r');\nconst mod = 1;\nfunction top() {}\nconst topArrow = () => {};\n" +
      "function f(p, { q, r: s }, ...rest) {\n  let local;\n  try {} catch (err) {}\n  for (const it of []) {}\n  top();\n}\n"
  );
  const call = x.calls.find((c) => c.callee_text === "top");
  assert.deepEqual(call.scope_names, ["err", "it", "local", "mod", "p", "q", "rest", "s"]);
  assert.equal(call.enclosing_start_byte, x.functions.find((f) => f.name === "f").start_byte);
  const req = x.calls.find((c) => c.callee_text === "require");
  assert.equal(req.enclosing_start_byte, null);
});

test("calls: receiver this and receiver_class from new C() or a TypeScript parameter type", async () => {
  const x = await extract(
    "const svc = new UserService();\nclass K {\n  m(repo: Repo, other) {\n    this.a.b();\n    svc.run();\n    repo.save();\n    other.go();\n  }\n}\n",
    { langId: "typescript", path: "k.ts" }
  );
  assert.deepEqual(
    x.calls.map((c) => [c.callee_text, c.receiver, c.receiver_class]),
    [
      ["this.a.b", "this", null],
      ["svc.run", null, "UserService"],
      ["repo.save", null, "Repo"],
      ["other.go", null, null]
    ]
  );
});

test("the node fixture: rule 1b receiver, this-dispatch, shadowing, mount", async () => {
  const users = await extractFixture("routes/users.js");
  const svcRun = users.calls.find((c) => c.callee_text === "svc.run");
  assert.equal(svcRun.receiver_class, "UserService");
  assert.ok(users.calls.find((c) => c.callee_text === "cb").scope_names.includes("cb"));
  const service = await extractFixture("services/userService.js");
  assert.equal(service.calls.find((c) => c.callee_text === "this.exec").receiver, "this");
  assert.deepEqual(service.classes.map((c) => [c.name, c.extends, c.methods]), [["UserService", null, ["run", "exec"]], ["AdminService", "UserService", ["exec"]]]);
  const server = await extractFixture("server.js");
  assert.deepEqual(server.routes.map((r) => [r.http_method, r.path_pattern, r.handler_text, r.middleware_texts]), [
    ["USE", "/users", "users", ["ensureAuthenticated"]],
    ["GET", "/health", "<anon>@9:20", []]
  ]);
});

test("every emitted list is sorted by start_byte", async () => {
  const x = await extractFixture("services/userService.js");
  for (const key of ["functions", "calls", "exports", "classes", "routes", "sources", "sinks"]) {
    const bytes = x[key].map((e) => e.start_byte);
    assert.deepEqual(bytes, [...bytes].sort((a, b) => a - b), key);
  }
});

test("tsx parses with the same extractor", async () => {
  const x = await extract("export const App = () => <div onClick={() => eval(code)} />;\n", { langId: "tsx", path: "src/App.tsx" });
  assert.deepEqual(names(x.exports), ["App"]);
  assert.equal(x.sinks[0].class, "eval");
});

// ---- resolveImportSpecifier ---------------------------------------------------------------------

test("resolveImportSpecifier: ./x from a/b.js resolves to a/x/index.js", () => {
  assert.deepEqual(resolveImportSpecifier({ specifier: "./x", fromPath: "a/b.js", filePaths: new Set(["a/x/index.js"]), configs: {} }), {
    path: "a/x/index.js",
    confidence: "exact"
  });
});

test("resolveImportSpecifier: extension probing, parent dirs, bare specifiers, escapes", () => {
  const filePaths = new Set(["src/a.ts", "src/lib/b.mjs", "c.js"]);
  const r = (specifier, fromPath = "src/lib/x.js") => resolveImportSpecifier({ specifier, fromPath, filePaths, configs: {} });
  assert.equal(r("../a").path, "src/a.ts");
  assert.equal(r("./b").path, "src/lib/b.mjs");
  assert.equal(r("./b.mjs").path, "src/lib/b.mjs");
  assert.equal(r("../../c").path, "c.js");
  assert.equal(r("express"), null);
  assert.equal(r("../../../outside"), null);
  assert.equal(r("./missing"), null);
});

test("resolveImportSpecifier: tsconfig paths resolve @svc/user to src/services/user.ts", () => {
  const configs = { tsconfig: { compilerOptions: { paths: { "@svc/*": ["src/services/*"] } } } };
  const filePaths = new Set(["src/services/user.ts", "src/app.ts"]);
  assert.deepEqual(resolveImportSpecifier({ specifier: "@svc/user", fromPath: "src/app.ts", filePaths, configs }), {
    path: "src/services/user.ts",
    confidence: "exact"
  });
  const withBase = { tsconfig: { compilerOptions: { baseUrl: "./src", paths: { "@lib": ["services/user"] } } } };
  assert.equal(resolveImportSpecifier({ specifier: "@lib", fromPath: "src/app.ts", filePaths, configs: withBase }).path, "src/services/user.ts");
  assert.deepEqual(resolveImportSpecifier({ specifier: "services/user", fromPath: "src/app.ts", filePaths, configs: withBase }), {
    path: "src/services/user.ts",
    confidence: "heuristic"
  });
});
