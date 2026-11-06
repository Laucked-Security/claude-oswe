import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, realpathSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseSource } from "../../graph/parser.mjs";
import { loadSurface } from "../../graph/surface.mjs";
import { buildGraph } from "../../graph/build-graph.mjs";
import { resolveImports, buildClassIndex, resolveCalls } from "../../graph/resolve.mjs";
import * as phpModule from "../../graph/lang/php.mjs";
import { lang, extractFile, resolveImportSpecifier } from "../../graph/lang/php.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..", "..", "..");
const FIXTURE_DIR = join(REPO_ROOT, "test-fixtures", "graph", "php");
const REFERENCES_DIR = join(REPO_ROOT, "skills", "audit", "references");
const SURFACE = loadSurface("php", REFERENCES_DIR);
const FIXTURE_FILES = ["routes/web.php", "routes/extra.php", "app/Http/Controllers/RunController.php", "app/Services/Runner.php", "app/Services/AdminRunner.php", "src/Controller/SymfonyController.php"];

async function extract(sourceText, { path = "src/k.php" } = {}) {
  const tree = await parseSource("php", sourceText);
  try {
    assert.equal(tree.rootNode.hasError, false, "test source parses cleanly");
    return extractFile({ tree, path, sourceText, frameworks: lang.frameworks, surface: SURFACE });
  } finally {
    tree.delete();
  }
}

// CRLF checkouts are read as LF so offsets match the committed (eol=lf) fixture on every platform.
const fixtureText = (file) => readFileSync(join(FIXTURE_DIR, file), "utf8").replace(/\r\n/g, "\n");
const extractFixture = (file) => extract(fixtureText(file), { path: file });
const routeRows = (x) => x.routes.map((r) => [r.http_method, r.path_pattern, r.handler_text, r.middleware_texts, r.framework]);
const callRows = (x) => x.calls.map((c) => [c.callee_text, c.receiver, c.receiver_class]);
const fnRows = (x) => x.functions.map((f) => [f.kind, f.name, f.qualified_name, f.class, f.exported]);
const php = (body) => `<?php\n${body}`;

test("lang descriptor", () => {
  assert.deepEqual(lang, { id: "php", stack: "php", langIds: ["php"], frameworks: ["laravel", "symfony"], implicitThisCalls: false, submoduleImports: false, callableLocals: false, overloads: false });
});

// ---- Laravel routes -----------------------------------------------------------------------------

test("Laravel: group middleware propagates to the inner route; [X::class, 'm'] ⇒ X.m; a closure handler is its <anon> label", async () => {
  const x = await extractFixture("routes/web.php");
  const text = fixtureText("routes/web.php");
  assert.deepEqual(routeRows(x), [
    ["POST", "/run", "RunController.run", ["auth"], "laravel"],
    ["GET", "/health", "<anon>@10:23", [], "laravel"]
  ]);
  assert.equal(x.routes[0].start_byte, text.indexOf("Route::post"));
  assert.equal(x.routes[0].line, 7);
  const handler = x.functions.find((f) => f.qualified_name === "<anon>@10:23");
  assert.deepEqual([handler?.kind, handler?.name, handler?.start_byte], ["arrow", "<anon>", text.indexOf("fn () => 'ok'")]);
  assert.deepEqual(routeRows(await extractFixture("routes/extra.php")), [["GET", "/ping", "<anon>@3:21", [], "laravel"]]);
});

test("Laravel: handler forms, verbs, chained / group middleware, prefixes, controller groups, nesting; resource noted; view / redirect ignored", async () => {
  const x = await extract(php(
    "Route::get('/a', 'UserController@show')->middleware('auth:api')->name('a');\n" +
      "Route::put('b', Invokable::class);\n" +
      "Route::match(['GET', 'POST'], '/c', [\\App\\X::class, 'c']);\n" +
      "Route::any('/d', fn () => 1)->middleware(['auth', 'can:update,post']);\n" +
      "Route::options('/e', [Y::class, 'e']);\n" +
      "Route::resource('photos', PhotoController::class);\n" +
      "Route::view('/welcome', 'welcome');\n" +
      "Route::redirect('/here', '/there');\n" +
      "Route::prefix('/admin')->middleware('auth')->group(function () {\n" +
      "    Route::delete('/run', [Z::class, 'run']);\n" +
      "    Route::group(['middleware' => ['admin'], 'prefix' => 'deep'], function () {\n" +
      "        Route::patch('/x', [Z::class, 'x'])->middleware('throttle');\n" +
      "    });\n" +
      "});\n" +
      "Route::controller(OrderController::class)->group(function () {\n" +
      "    Route::get('/orders', 'index');\n" +
      "});\n" +
      "Route::post('/after', [Y::class, 'after']);\n"
  ));
  assert.deepEqual(routeRows(x), [
    ["GET", "/a", "UserController.show", ["auth:api"], "laravel"],
    ["PUT", "/b", "Invokable.__invoke", [], "laravel"],
    ["ANY", "/c", "X.c", [], "laravel"],
    ["ANY", "/d", "<anon>@5:18", ["auth", "can:update,post"], "laravel"],
    ["OPTIONS", "/e", "Y.e", [], "laravel"],
    ["DELETE", "/admin/run", "Z.run", ["auth"], "laravel"],
    ["PATCH", "/admin/deep/x", "Z.x", ["auth", "admin", "throttle"], "laravel"],
    ["GET", "/orders", "OrderController.index", [], "laravel"],
    ["POST", "/after", "Y.after", [], "laravel"]
  ]);
  assert.ok(x.not_extracted.includes("resource route"));
  assert.ok(x.functions.some((f) => f.qualified_name === "<anon>@5:18" && f.kind === "arrow"));
  // the group closures are ordinary anonymous functions
  assert.ok(x.functions.some((f) => f.qualified_name === "k.<anon>@10:52" && f.kind === "lambda"));
});

// ---- Symfony routes -----------------------------------------------------------------------------

test("Symfony: class #[Route] prefix + method #[Route(methods: ['POST'])] ⇒ POST /sym/run with middleware_texts [IsGranted]", async () => {
  const x = await extractFixture("src/Controller/SymfonyController.php");
  const text = fixtureText("src/Controller/SymfonyController.php");
  assert.deepEqual(routeRows(x), [["POST", "/sym/run", "SymfonyController.run", ["IsGranted"], "symfony"]]);
  assert.equal(x.routes[0].start_byte, text.indexOf("Route('/run'"));
  assert.equal(x.routes[0].line, 11);
});

test("Symfony: path: named argument, several / no methods ⇒ ANY, class-level auth attributes first, Security, no class prefix", async () => {
  const x = await extract(php(
    "#[Route(path: '/p/')]\n#[IsGranted('ROLE_USER')]\nclass K {\n" +
      "    #[Route(path: '/a', methods: ['GET', 'HEAD'])] #[Security('x')] public function a() {}\n" +
      "    #[Route('/b', name: 'b')] public function b() {}\n" +
      "    #[Route('/c', methods: 'DELETE')] #[Deprecated] public function c() {}\n" +
      "    public function notARoute() {}\n}\n" +
      "class N {\n    #[Route('/n', methods: ['PUT'])] public function n() {}\n}\n"
  ));
  assert.deepEqual(routeRows(x), [
    ["ANY", "/p/a", "K.a", ["IsGranted", "Security"], "symfony"],
    ["ANY", "/p/b", "K.b", ["IsGranted"], "symfony"],
    ["DELETE", "/p/c", "K.c", ["IsGranted"], "symfony"],
    ["PUT", "/n", "N.n", [], "symfony"]
  ]);
});

// ---- functions and classes ----------------------------------------------------------------------

test("functions: methods, promoted-constructor class, exported = top-level or public method; fixture rows", async () => {
  const x = await extractFixture("app/Services/Runner.php");
  assert.deepEqual(fnRows(x), [
    ["method", "run", "Runner.run", "Runner", true],
    ["method", "exec", "Runner.exec", "Runner", true],
    ["method", "load", "Runner.load", "Runner", true]
  ]);
  const text = fixtureText("app/Services/Runner.php");
  assert.equal(x.functions[0].start_byte, text.indexOf("public function run"));
  assert.equal(x.functions[0].line_start, 7);
  assert.equal(x.functions[0].line_end, 10);
  assert.deepEqual(x.exports, [{ name: "Runner", start_byte: text.indexOf("class Runner") }]);
});

test("functions: nested functions, closures (lambda) and arrows (arrow) with class_start_byte, visibility, param_count", async () => {
  const x = await extract(php(
    "function outer($a, $b = 1) {\n    function inner(...$xs) {}\n    $f = function ($y) use ($a) { return $y; };\n}\n" +
      "class K {\n    function d() { $g = fn($z) => $z; }\n    private function p(int $a, string $b) {}\n    protected static function s() {}\n    public function __construct(private Runner $r) {}\n}\n" +
      "interface I { public function i(); }\n"
  ));
  assert.deepEqual(fnRows(x), [
    ["function", "outer", "outer", null, true],
    ["function", "inner", "outer.inner", null, false],
    ["lambda", "<anon>", "outer.<anon>@4:10", null, false],
    ["method", "d", "K.d", "K", true],
    ["arrow", "<anon>", "K.d.<anon>@7:25", null, false],
    ["method", "p", "K.p", "K", false],
    ["method", "s", "K.s", "K", false],
    ["method", "__construct", "K.__construct", "K", true],
    ["method", "i", "I.i", "I", true]
  ]);
  assert.deepEqual(x.functions.map((f) => f.param_count), [null, null, 1, 0, 1, 2, 0, 1, 0]);
  const cls = x.classes.find((c) => c.name === "K");
  assert.equal(x.functions[4].class_start_byte, cls.start_byte);
  assert.equal(x.functions[2].class_start_byte, null);
  assert.deepEqual(x.exports.map((e) => e.name), ["outer", "K", "I"]);
});

test("classes: extends is the base name; implements extracted, trait use noted; interface / trait / enum listed", async () => {
  const x = await extract(php(
    "class K extends \\Base\\P implements I, J {\n    use SomeTrait;\n    public function m() {}\n    public function m2() {}\n}\n" +
      "interface I extends Base { public function i(); }\ntrait T { public function t() {} }\nenum E { case A; public function e() {} }\n"
  ));
  assert.deepEqual(x.classes.map((c) => [c.name, c.extends, c.methods]), [["K", "P", ["m", "m2"]], ["I", "Base", ["i"]], ["T", null, ["t"]], ["E", null, ["e"]]]);
  assert.deepEqual(x.classes.find((c) => c.name === "K").implements, ["I", "J"]); // C1b: extracted, no longer noted
  assert.ok(x.not_extracted.includes("trait use"));
  assert.deepEqual(x.exports.map((e) => e.name), ["K", "I", "T", "E"]);
  const y = await extractFixture("app/Services/AdminRunner.php");
  assert.deepEqual(y.classes.map((c) => [c.name, c.extends, c.methods]), [["AdminRunner", "Runner", ["exec"]]]);
});

// ---- calls --------------------------------------------------------------------------------------

test("calls: receiver hints from $this, self / static / parent, typed / promoted / assigned properties, typed params, new, static classes", async () => {
  const x = await extract(php(
    "class K {\n    private ?Runner $typed;\n    private $assigned;\n    private Svc|null $union;\n" +
      "    public function __construct(private \\App\\Promoted $promoted) { $this->assigned = new Made(); }\n" +
      "    public function m(Param $p, $untyped) {\n" +
      "        $this->a(); self::b(); static::c(); parent::d();\n" +
      "        $this->typed->e(); $this->promoted->f(); $this->assigned->g(); $this->union->h(); $this->nope->i();\n" +
      "        $p->j(); $untyped->k(); $v = new Local(); $v->l(); Util::n(); \\App\\Q::o(); (new C)->p(); $this->a->b->q();\n" +
      "        f(); \\shell_exec($p); $p?->r();\n" +
      "    }\n}\n"
  ));
  assert.deepEqual(callRows(x), [
    ["$this.a", "this", null],
    ["self.b", "this", null],
    ["static.c", "this", null],
    ["parent.d", null, null],
    ["$this.typed.e", null, "Runner"],
    ["$this.promoted.f", null, "Promoted"],
    ["$this.assigned.g", null, "Made"],
    ["$this.union.h", null, "Svc"],
    ["$this.nope.i", null, null],
    ["$p.j", null, "Param"],
    ["$untyped.k", null, null],
    ["$v.l", null, "Local"],
    ["Util.n", null, "Util"],
    ["Q.o", null, "Q"],
    ["C.p", null, "C"],
    ["$this.a.b.q", null, null],
    ["f", null, null],
    ["shell_exec", null, null],
    ["$p.r", null, "Param"]
  ]);
  for (const c of x.calls) assert.deepEqual(c.scope_names, []);
  // the fixture's promoted constructor parameter
  assert.deepEqual(callRows(await extractFixture("app/Http/Controllers/RunController.php")), [["$this.runner.run", null, "Runner"], ["$request.input", null, "Request"]]);
});

test("calls: a variable call ($cb(), call_user_func) is not a call but noted; anchored at the name, enclosed by the innermost function", async () => {
  const x = await extractFixture("routes/web.php");
  assert.ok(!x.calls.some((c) => c.callee_text.includes("$cb")));
  assert.ok(x.not_extracted.includes("variable call"));
  const y = await extract(php("function f($cb, $o, $m) { call_user_func($cb); call_user_func_array($cb, []); $o->$m(); g(); }\n"));
  assert.deepEqual(y.calls.map((c) => c.callee_text), ["g"]);
  assert.deepEqual(y.not_extracted, ["variable call"]);
  const r = await extractFixture("app/Services/Runner.php");
  const text = fixtureText("app/Services/Runner.php");
  const fnAt = (name) => r.functions.find((f) => f.qualified_name === name).start_byte;
  assert.deepEqual(r.calls.map((c) => [c.callee_text, c.start_byte, c.line, c.enclosing_start_byte]), [
    ["$this.exec", text.indexOf("exec($cmd)"), 9, fnAt("Runner.run")],
    ["shell_exec", text.indexOf("shell_exec"), 14, fnAt("Runner.exec")]
  ]);
});

test("arity: arg_count (null with spread), param_count", async () => {
  const x = await extract(php("function f($a, int ...$rest) { g(1, 2); h(...$a); k(); }\n"));
  assert.deepEqual(x.calls.map((c) => [c.callee_text, c.arg_count]), [["g", 2], ["h", null], ["k", 0]]);
  assert.equal(x.functions[0].param_count, null);
});

// ---- sources and sinks --------------------------------------------------------------------------

test("sinks: shell_exec is cmd-exec at its name; $this->exec() is not a sink; eval($_GET['x']) ⇒ eval sink + query source", async () => {
  const r = await extractFixture("app/Services/Runner.php");
  const text = fixtureText("app/Services/Runner.php");
  assert.deepEqual(r.sinks.map((s) => [s.class, s.callee, s.pattern, s.start_byte]), [
    ["cmd-exec", "shell_exec", "shell_exec", text.indexOf("shell_exec")],
    ["include", "require", "require(", text.indexOf("require $p")]
  ]);
  const s = await extractFixture("src/Controller/SymfonyController.php");
  const sText = fixtureText("src/Controller/SymfonyController.php");
  assert.deepEqual(s.sinks.map((k) => [k.class, k.callee, k.start_byte]), [["eval", "eval", sText.indexOf("eval(")]]);
  assert.deepEqual(s.sources, [{ line: 15, start_byte: sText.indexOf("$_GET"), kind: "query", pattern: "$_GET" }]);
});

test("include / require: a literal or __DIR__ . literal is an import, never a sink; a variable argument is an include sink", async () => {
  const x = await extract(php(
    "require 'fixed.php';\nrequire_once __DIR__ . '/lib/x.php';\ninclude('a/b.php');\n" +
      "function f($p) { require $p; include_once $p . '.php'; require_once dirname(__FILE__) . '/y.php'; }\n"
  ));
  assert.deepEqual(x.imports, [
    { line: 2, specifier: "fixed.php", bindings: [], local: null },
    { line: 3, specifier: "/lib/x.php", bindings: [], local: null },
    { line: 4, specifier: "a/b.php", bindings: [], local: null }
  ]);
  assert.deepEqual(x.sinks.map((s) => [s.class, s.callee, s.pattern]), [["include", "require", "require("], ["include", "include_once", "include_once"], ["include", "require_once", "require_once"]]);
  assert.ok(x.not_extracted.includes("dynamic include"));
  const web = await extractFixture("routes/web.php");
  assert.deepEqual(web.sinks, []);
  assert.ok(web.imports.some((i) => i.specifier === "/extra.php"));
});

test("sources: superglobals, php://input, getallheaders and the Request getters, each with its kind", async () => {
  const x = await extract(php(
    "function f($request) {\n" +
      "    $_GET['a']; $_POST['b']; $_REQUEST['c']; $_COOKIE['d']; $_FILES['e']; $_SERVER['f'];\n" +
      "    file_get_contents('php://input'); getallheaders();\n" +
      "    $request->input('g'); $request->all(); $request->query('h'); $request->request->get('i'); $request->query->get('j'); $request->headers->get('k');\n" +
      "}\n"
  ));
  assert.deepEqual(x.sources.map((s) => [s.kind, s.pattern]), [
    ["query", "$_GET"], ["body", "$_POST"], ["body", "$_REQUEST"], ["cookie", "$_COOKIE"], ["file", "$_FILES"], ["header", "$_SERVER"],
    ["body", "php://input"], ["header", "getallheaders("],
    ["body", "$request->input("], ["body", "$request->all("], ["query", "$request->query("], ["body", "$request->request->get("], ["query", "$request->query->get("], ["header", "$request->headers->get("]
  ]);
});

test("sinks: type-qualified candidates (DB $db ⇒ DB.select), member / word / call shapes, new, one sink per node", async () => {
  const x = await extract(php(
    "function f(DB $db, \\PDO $pdo, $q, $s) {\n" +
      "    $db->select($s); $pdo->query($s); DB::raw($s); $q->whereRaw($s); mysqli_query($c, $s); system($s); $pdo->exec($s);\n" +
      "    unserialize($s); preg_replace($a, $b, $s); file_put_contents($s, $s); move_uploaded_file($s, $s); passthru($s); proc_open($s); popen($s, 'r');\n" +
      "}\n"
  ));
  assert.deepEqual(x.sinks.map((s) => [s.class, s.callee, s.pattern]), [
    ["sql", "$db.select", "DB::select"],
    ["sql", "$pdo.query", "->query("],
    ["sql", "DB.raw", "DB::raw"],
    ["sql", "$q.whereRaw", "whereRaw"],
    ["sql", "mysqli_query", "mysqli_query"],
    ["cmd-exec", "system", "system("],
    ["cmd-exec", "$pdo.exec", "exec("],
    ["deser", "unserialize", "unserialize("],
    ["eval", "preg_replace", "preg_replace"],
    ["file-write", "file_put_contents", "file_put_contents"],
    ["file-write", "move_uploaded_file", "move_uploaded_file"],
    ["cmd-exec", "passthru", "passthru"],
    ["cmd-exec", "proc_open", "proc_open"],
    ["cmd-exec", "popen", "popen("]
  ]);
});

// ---- imports and resolution ---------------------------------------------------------------------

test("imports: use / alias / grouped forms; use function / const noted; namespace from the namespace declaration", async () => {
  const x = await extract(php("namespace App\\Http;\nuse App\\Services\\Runner;\nuse X\\Y as Z;\nuse \\G;\nuse X\\{A, B as C};\nuse function foo\\bar;\nuse const X\\Y;\n"));
  assert.equal(x.namespace, "App\\Http");
  assert.deepEqual(x.imports, [
    { line: 3, specifier: "App\\Services\\Runner", bindings: [{ imported: "Runner", local: "Runner" }], local: null },
    { line: 4, specifier: "X\\Y", bindings: [{ imported: "Y", local: "Z" }], local: null },
    { line: 5, specifier: "G", bindings: [{ imported: "G", local: "G" }], local: null },
    { line: 6, specifier: "X\\A", bindings: [{ imported: "A", local: "A" }], local: null },
    { line: 6, specifier: "X\\B", bindings: [{ imported: "B", local: "C" }], local: null }
  ]);
  assert.deepEqual(x.not_extracted, ["use function/const"]);
  assert.equal((await extract(php("f();\n"))).namespace, null);
});

test("resolveImportSpecifier: PSR-4 (longest prefix), namespace + basename fallback, relative require files, null otherwise", () => {
  const filePaths = new Set(["app/Services/Runner.php", "app/Http/K.php", "http-src/K.php", "lib/Pkg/Thing.php", "src/Other/Thing.php", "routes/web.php", "routes/extra.php", "common.php"]);
  const namespaces = new Map([["app/Services/Runner.php", "App\\Services"], ["lib/Pkg/Thing.php", "Vendor\\Pkg"], ["src/Other/Thing.php", "App\\Other"], ["routes/web.php", null]]);
  const configs = { composerJson: { autoload: { "psr-4": { "App\\": "app/", "App\\Http\\": ["./http-src"] } } } };
  const resolve = (specifier, { fromPath = "routes/web.php", cfg = configs } = {}) => resolveImportSpecifier({ specifier, fromPath, filePaths, configs: cfg, namespaces });
  assert.deepEqual(resolve("App\\Services\\Runner"), { path: "app/Services/Runner.php", confidence: "exact" });
  assert.deepEqual(resolve("App\\Http\\K"), { path: "http-src/K.php", confidence: "exact" }); // the longest prefix wins
  assert.deepEqual(resolve("Vendor\\Pkg\\Thing"), { path: "lib/Pkg/Thing.php", confidence: "exact" });
  assert.deepEqual(resolve("App\\Other\\Thing"), { path: "src/Other/Thing.php", confidence: "exact" }); // PSR-4 misses, namespace hits
  assert.deepEqual(resolve("App\\Services\\Runner", { cfg: {} }), { path: "app/Services/Runner.php", confidence: "exact" });
  assert.equal(resolve("App\\Services\\Missing"), null);
  assert.deepEqual(resolve("/extra.php"), { path: "routes/extra.php", confidence: "exact" });
  assert.deepEqual(resolve("extra.php"), { path: "routes/extra.php", confidence: "exact" });
  assert.deepEqual(resolve("../common.php"), { path: "common.php", confidence: "exact" });
  assert.equal(resolve("missing.php"), null);
  assert.equal(resolve("../../escape.php"), null);
});

test("every emitted list is sorted by start_byte", async () => {
  for (const file of FIXTURE_FILES) {
    const x = await extractFixture(file);
    for (const key of ["functions", "calls", "exports", "classes", "routes", "sources", "sinks"]) {
      const bytes = x[key].map((e) => e.start_byte);
      assert.deepEqual(bytes, [...bytes].sort((a, b) => a - b), `${file}: ${key}`);
    }
  }
});

// ---- through resolve / build-graph --------------------------------------------------------------

async function resolveSources(sources) {
  const files = [];
  for (const [path, text] of Object.entries(sources)) files.push({ path, langId: "php", stack: "php", extract: await extract(text, { path }) });
  const langModules = new Map([["php", phpModule]]);
  const importMap = resolveImports(files, { langModules, filePaths: new Set(Object.keys(sources)), configs: {} });
  return resolveCalls(files, importMap, { classIndex: buildClassIndex(files, importMap), langModules });
}

test("resolution: a closure in a method acts for its class ($this inside); a bare call never targets a method", async () => {
  const results = await resolveSources({
    "k.php": php("class K {\n    public function a() {}\n    public function m() {\n        $f = function () { $this->a(); };\n        a();\n    }\n}\n")
  });
  assert.deepEqual(results.map((r) => [r.callee_text, r.to?.qualified_name ?? null, r.confidence]), [["$this.a", "K.a", "exact"], ["a", null, "unresolved"]]);
});

test("the php fixture through build-graph: route auth, PSR-4 receiver resolution, override grading, sinks in their methods, require edge", async () => {
  const dir = realpathSync(FIXTURE_DIR);
  const { graph, reason } = await buildGraph({ projectDir: dir, scopeRealpath: dir, stacks: ["php"], frameworks: ["laravel", "symfony"], referencesDir: REFERENCES_DIR });
  assert.ok(graph, reason);
  const fn = (file, qn) => graph.nodes.find((n) => n.type === "function" && n.file === file && n.qualified_name === qn);
  const routes = Object.fromEntries(graph.nodes.filter((n) => n.type === "route").map((r) => [`${r.http_method} ${r.path_pattern}`, [r.auth, r.handler, r.framework]]));
  assert.deepEqual(routes, {
    "POST /run": ["authenticated", fn("app/Http/Controllers/RunController.php", "RunController.run").id, "laravel"],
    "GET /health": ["unauthenticated", fn("routes/web.php", "<anon>@10:23").id, "laravel"],
    "GET /ping": ["unauthenticated", fn("routes/extra.php", "<anon>@3:21").id, "laravel"],
    "POST /sym/run": ["authenticated", fn("src/Controller/SymfonyController.php", "SymfonyController.run").id, "symfony"]
  });
  const calls = graph.edges.filter((e) => e.type === "calls");
  const runnerRun = calls.find((e) => e.callee_text === "$this.runner.run");
  assert.deepEqual([runnerRun.to, runnerRun.confidence], [fn("app/Services/Runner.php", "Runner.run").id, "exact"]);
  const thisExec = calls.find((e) => e.callee_text === "$this.exec");
  assert.deepEqual([thisExec.to, thisExec.confidence], [fn("app/Services/Runner.php", "Runner.exec").id, "name-only"]); // AdminRunner overrides exec
  const sinks = graph.nodes.filter((n) => n.type === "sink").map((s) => [s.file, s.class, s.enclosing_fn]);
  assert.deepEqual(sinks.sort(), [
    ["app/Services/Runner.php", "cmd-exec", fn("app/Services/Runner.php", "Runner.exec").id],
    ["app/Services/Runner.php", "include", fn("app/Services/Runner.php", "Runner.load").id],
    ["src/Controller/SymfonyController.php", "eval", fn("src/Controller/SymfonyController.php", "SymfonyController.run").id]
  ].sort());
  const sources = graph.nodes.filter((n) => n.type === "source").map((s) => [s.file, s.kind, s.enclosing_fn]);
  assert.deepEqual(sources.sort(), [
    ["app/Http/Controllers/RunController.php", "body", fn("app/Http/Controllers/RunController.php", "RunController.run").id],
    ["src/Controller/SymfonyController.php", "query", fn("src/Controller/SymfonyController.php", "SymfonyController.run").id]
  ].sort());
  const imports = graph.edges.filter((e) => e.type === "imports").map((e) => [e.specifier, e.confidence]);
  assert.deepEqual(imports.sort(), [["/extra.php", "exact"], ["App\\Http\\Controllers\\RunController", "exact"], ["App\\Services\\Runner", "exact"]].sort());
  assert.ok(graph.stats.coverage_matrix.php.not_extracted.includes("variable call"));
  assert.deepEqual(graph.stats.coverage_matrix.php.extractors_applied, ["laravel", "symfony"]);
});

// ---- C1b: implements and bodiless ------------------------------------------------------------------

test("C1b: classes carry implements (class_interface_clause; an interface's extra parents); interface / abstract methods are bodiless", async () => {
  const x = await extract(php(
    "interface IR extends IB, IC { public function run($c); }\n" +
      "abstract class A extends B implements IR, \\X\\Y { abstract public function run($c); public function y() {} }\n" +
      "class C { public function z() {} }\n"
  ));
  assert.deepEqual(x.classes.map((c) => [c.name, c.extends, c.implements]), [["IR", "IB", ["IC"]], ["A", "B", ["IR", "Y"]], ["C", null, []]]);
  const bodiless = Object.fromEntries(x.functions.map((f) => [f.qualified_name, f.bodiless === true]));
  assert.deepEqual(bodiless, { "IR.run": true, "A.run": true, "A.y": false, "C.z": false });
  assert.equal(x.not_extracted.includes("implements clause"), false);
});

test("Task 10 minor: ->withoutMiddleware(...) is noted and carried as without_middleware_texts (route or group level)", async () => {
  const x = await extract(php(
    "Route::middleware('auth')->group(function () {\n" +
      "    Route::get('/a', fn () => 1);\n" +
      "    Route::get('/b', fn () => 1)->withoutMiddleware('auth');\n" +
      "    Route::get('/c', fn () => 1)->withoutMiddleware(['throttle', 'csrf']);\n" +
      "});\n" +
      "Route::withoutMiddleware('auth:api')->group(function () { Route::get('/d', fn () => 1); });\n"
  ));
  assert.deepEqual(x.routes.map((r) => [r.path_pattern, r.middleware_texts, r.without_middleware_texts ?? []]), [
    ["/a", ["auth"], []], ["/b", ["auth"], ["auth"]], ["/c", ["auth"], ["throttle", "csrf"]], ["/d", [], ["auth:api"]]
  ]);
  assert.ok(x.not_extracted.includes("withoutMiddleware"));
});
