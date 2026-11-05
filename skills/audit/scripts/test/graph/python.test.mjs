import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, realpathSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseSource } from "../../graph/parser.mjs";
import { loadSurface } from "../../graph/surface.mjs";
import { buildGraph } from "../../graph/build-graph.mjs";
import { lang, extractFile, resolveImportSpecifier } from "../../graph/lang/python.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..", "..", "..");
const FIXTURE_DIR = join(REPO_ROOT, "test-fixtures", "graph", "python");
const REFERENCES_DIR = join(REPO_ROOT, "skills", "audit", "references");
const SURFACE = loadSurface("python", REFERENCES_DIR);

async function extract(sourceText, { path = "pkg/a.py" } = {}) {
  const tree = await parseSource("python", sourceText);
  try {
    return extractFile({ tree, path, sourceText, frameworks: lang.frameworks, surface: SURFACE });
  } finally {
    tree.delete();
  }
}

// CRLF checkouts are read as LF so offsets match the committed (eol=lf) fixture on every platform.
const extractFixture = (path) => extract(readFileSync(join(FIXTURE_DIR, path), "utf8").replace(/\r\n/g, "\n"), { path });
const names = (list) => list.map((x) => x.name);
const routeRows = (x) => x.routes.map((r) => [r.http_method, r.path_pattern, r.handler_text, r.middleware_texts, r.framework]);

test("lang descriptor", () => {
  assert.deepEqual(lang, { id: "python", stack: "python", langIds: ["python"], frameworks: ["flask", "django", "fastapi"], implicitThisCalls: false, submoduleImports: true, callableLocals: true });
});

// ---- routes -------------------------------------------------------------------------------------

test("Flask: @app.route('/run', methods=['POST']) + @login_required ⇒ POST /run with middleware login_required", async () => {
  const x = await extractFixture("app.py");
  assert.deepEqual(routeRows(x), [
    ["POST", "/run", "run_cmd", ["login_required"], "flask"],
    ["GET", "/health", "health", [], "flask"]
  ]);
  const route = x.routes[0];
  const decorator = "@app.route('/run', methods=['POST'])";
  const text = readFileSync(join(FIXTURE_DIR, "app.py"), "utf8").replace(/\r\n/g, "\n");
  assert.equal(route.start_byte, text.indexOf(decorator));
  assert.equal(route.line, text.slice(0, route.start_byte).split("\n").length);
});

test("Flask: methods / verb decorators, decorator calls reduced to names, other route decorators are not middleware", async () => {
  const x = await extract(
    "@bp.route('/a', methods=['GET', 'POST'])\n@bp.route('/b')\n@permission_required('x.y')\n@jwt_required()\ndef a():\n    pass\n\n" +
      "@app.post('/c')\ndef c():\n    pass\n\n" +
      "class V:\n    @app.delete('/d')\n    def d(self):\n        pass\n"
  );
  assert.deepEqual(routeRows(x), [
    ["ANY", "/a", "a", ["permission_required", "jwt_required"], "flask"],
    ["GET", "/b", "a", ["permission_required", "jwt_required"], "flask"],
    ["POST", "/c", "c", [], "flask"],
    ["DELETE", "/d", "V.d", [], "flask"]
  ]);
});

test("FastAPI: @router.get ⇒ route; Depends in dependencies and parameter defaults become Depends.<name>", async () => {
  const x = await extractFixture("views/users.py");
  assert.deepEqual(routeRows(x), [["GET", "/users/{id}", "get_user", ["Depends.get_current_user"], "fastapi"]]);
  const y = await extract(
    "from fastapi import FastAPI, Depends\napp = FastAPI()\n\n@app.post('/items', dependencies=[Depends(auth.verify)])\n@cache\n" +
      "async def create(item: Item, user: User = Depends(current_user), db=Depends(get_db)):\n    pass\n"
  );
  assert.deepEqual(routeRows(y), [["POST", "/items", "create", ["cache", "Depends.auth.verify", "Depends.current_user", "Depends.get_db"], "fastapi"]]);
});

test("Django: urlpatterns path / re_path routes, include ⇒ USE mount + import, class-based views", async () => {
  const x = await extractFixture("urls.py");
  assert.deepEqual(routeRows(x), [
    ["ANY", "/run/", "views.run", [], "django"],
    ["USE", "/api/", "api.urls", [], "django"]
  ]);
  assert.deepEqual(x.imports.at(-1), { line: 7, specifier: "api.urls", bindings: "namespace", local: "api.urls" });
  const y = await extract(
    "from django.contrib.auth.mixins import PermissionRequiredMixin\nfrom django.views import View\n\n" +
      "class RunView(PermissionRequiredMixin, View):\n    pass\n\n" +
      "urlpatterns = [path('/x', RunView.as_view()), re_path(r'^y/$', other.y)]\nurlpatterns += [path('', home)]\n"
  );
  assert.deepEqual(routeRows(y), [
    ["ANY", "/x", "RunView.as_view", ["PermissionRequiredMixin", "View"], "django"],
    ["ANY", "/^y/$", "other.y", [], "django"],
    ["ANY", "/", "home", [], "django"]
  ]);
  assert.ok(y.not_extracted.includes("class-based view dispatch"));
  assert.ok(y.not_extracted.includes("multiple inheritance"));
});

test("Django include through build-graph: the included file's routes are prefixed (trailing slash kept), the submodule view resolves; Flask auth from login_required", async () => {
  const dir = realpathSync(FIXTURE_DIR);
  const { graph, reason } = await buildGraph({ projectDir: dir, scopeRealpath: dir, stacks: ["python"], frameworks: ["flask", "django", "fastapi"], referencesDir: REFERENCES_DIR });
  assert.ok(graph, reason);
  const routes = graph.nodes.filter((n) => n.type === "route").map((r) => [r.file, r.http_method, r.path_pattern, r.auth]);
  assert.deepEqual(routes.sort(), [
    ["api/urls.py", "ANY", "/api/ping/", "unauthenticated"],
    ["app.py", "GET", "/health", "unauthenticated"],
    ["app.py", "POST", "/run", "authenticated"],
    ["urls.py", "ANY", "/run/", "unauthenticated"],
    ["views/users.py", "GET", "/users/{id}", "unknown"]
  ]);
  // `from views import users as views` names the submodule views/users.py, so views.run resolves
  const djangoRun = graph.nodes.find((n) => n.type === "route" && n.file === "urls.py" && n.path_pattern === "/run/");
  const run = graph.nodes.find((n) => n.type === "function" && n.file === "views/users.py" && n.qualified_name === "run");
  assert.equal(djangoRun.handler, run.id);
});

// ---- sources and sinks --------------------------------------------------------------------------

test("eval in a docstring or a comment is not a sink; a real eval call is", async () => {
  const x = await extract('def f(x):\n    """Never eval(x) here."""\n    # eval(x)\n    return eval(x)\n');
  assert.equal(x.sinks.length, 1);
  assert.equal(x.sinks[0].line, 4);
  assert.equal(x.sinks[0].class, "eval");
});

test("sinks: subprocess.run is cmd-exec anchored at the callee's last identifier; exec( is eval", async () => {
  const x = await extractFixture("services/runner.py");
  const run = x.sinks.find((s) => s.callee === "subprocess.run");
  assert.equal(run.class, "cmd-exec");
  const text = readFileSync(join(FIXTURE_DIR, "services/runner.py"), "utf8").replace(/\r\n/g, "\n");
  assert.equal(run.start_byte, text.indexOf("run(c, shell=True)"));
  assert.ok(!x.sinks.some((s) => s.callee === "self.exec"), "the method self.exec is not the builtin exec(");
  const z = await extract("import jinja2\n\nclass K:\n    def m(self, c, t):\n        self.exec(c)\n        exec(c)\n        jinja2.Template(t)\n");
  assert.deepEqual(z.sinks.map((s) => [s.callee, s.class, s.line]), [["exec", "eval", 6], ["jinja2.Template", "template", 7]]);
  const y = await extract("exec(code)\nos.system(cmd)\nrender_template_string(t)\n");
  assert.deepEqual(y.sinks.map((s) => [s.callee, s.class]), [["exec", "eval"], ["os.system", "cmd-exec"], ["render_template_string", "template"]]);
});

test("source kinds; a subscript's attribute is the candidate; one source per access chain", async () => {
  const x = await extract(
    "def v(request):\n    a = request.args['q']\n    b = request.form.get('f')\n    c = request.get_json()\n    d = request.headers['h']\n" +
      "    e = request.COOKIES['c']\n    f = request.FILES['f']\n    g = request.GET['g']\n    h = request.META['m']\n    i = request.body\n"
  );
  assert.deepEqual(x.sources.map((s) => [s.pattern, s.kind]), [
    ["request.args", "query"], ["request.form", "body"], ["request.get_json", "body"], ["request.headers", "header"],
    ["request.COOKIES", "cookie"], ["request.FILES", "file"], ["request.GET", "query"], ["request.META", "header"], ["request.body", "body"]
  ]);
  const text = "def v(request):\n    a = request.args['q']\n";
  assert.equal(x.sources[0].start_byte, text.indexOf("request.args"));
});

// ---- functions, classes, exports ----------------------------------------------------------------

test("functions: kinds, names, qualified names, lambdas", async () => {
  const x = await extract(
    "def top(a):\n    def inner():\n        return lambda: a\n    return inner\n\nclass K(Base):\n    def m(self):\n        pass\n" +
      "    async def n(self):\n        f = lambda y: y\n\nsquare = lambda v: v * v\n"
  );
  assert.deepEqual(x.functions.map((f) => [f.name, f.qualified_name, f.kind, f.class]), [
    ["top", "top", "function", null],
    ["inner", "top.inner", "function", null],
    ["<anon>", "top.inner.<anon>@3:16", "lambda", null],
    ["m", "K.m", "method", "K"],
    ["n", "K.n", "method", "K"],
    ["f", "K.n.f", "lambda", null],
    ["square", "square", "lambda", null]
  ]);
  const fn = x.functions[0];
  assert.equal(fn.start_byte, 0);
  assert.deepEqual([fn.line_start, fn.line_end], [1, 4]);
});

test("exports: top-level def/class not starting with _, or __all__ when present; methods follow their class", async () => {
  const x = await extract("def a():\n    pass\n\ndef _b():\n    pass\n\nclass C:\n    def m(self):\n        pass\n\nv = 1\n");
  assert.deepEqual(names(x.exports), ["a", "C"]);
  assert.deepEqual(x.exports.map((e) => e.start_byte), [0, x.classes[0].start_byte]);
  assert.deepEqual(x.functions.map((f) => [f.qualified_name, f.exported]), [["a", true], ["_b", false], ["C.m", true]]);
  const y = await extract("__all__ = ['b']\n\ndef a():\n    pass\n\ndef b():\n    pass\n");
  assert.deepEqual(names(y.exports), ["b"]);
});

test("classes: extends is the first base's last segment; object and keyword bases ignored", async () => {
  const x = await extract("class A:\n    pass\n\nclass B(object):\n    pass\n\nclass C(mixins.Base, metaclass=M):\n    def m(self):\n        pass\n");
  assert.deepEqual(x.classes.map((c) => [c.name, c.extends, c.methods]), [["A", null, []], ["B", null, []], ["C", "Base", ["m"]]]);
  assert.deepEqual(x.not_extracted, []);
  const fixture = await extractFixture("services/runner.py");
  assert.deepEqual(fixture.classes.map((c) => [c.name, c.extends, c.methods]), [["Base", null, ["exec"]], ["Runner", "Base", ["run"]], ["Child", "Runner", ["exec"]]]);
});

// ---- calls --------------------------------------------------------------------------------------

test("calls: scope_names hold parameters, locals, loop / with / except / walrus / comprehension targets and module assignments", async () => {
  const x = await extract(
    "import os\nfrom m import n\nG = 1\n\ndef top():\n    pass\n\nclass K:\n    pass\n\n" +
      "def f(a, b: int, *c, **d):\n    e, (g, h) = 1, (2, 3)\n    i += 1\n    for j in []:\n        pass\n    with open(a) as k:\n        pass\n" +
      "    try:\n        pass\n    except E as l:\n        pass\n    if (w := 1):\n        pass\n    [q for q in a]\n    def nested():\n        pass\n    class Local:\n        pass\n    run()\n"
  );
  const run = x.calls.find((c) => c.callee_text === "run");
  assert.deepEqual(run.scope_names, ["G", "Local", "a", "b", "c", "d", "e", "g", "h", "i", "j", "k", "l", "nested", "q", "w"]);
  assert.equal(run.enclosing_start_byte, x.functions.find((fn) => fn.name === "f").start_byte);
});

test("calls: the fixture's shadowing case, decorators are not calls, anchors at the callee's last identifier", async () => {
  const x = await extractFixture("app.py");
  const cb = x.calls.find((c) => c.callee_text === "cb");
  assert.ok(cb.scope_names.includes("cb"), "the parameter cb shadows the module-level def");
  assert.deepEqual(x.calls.find((c) => c.callee_text === "helper").scope_names, ["app", "check", "runner"]);
  assert.ok(!x.calls.some((c) => c.callee_text === "app.route" || c.callee_text === "login_required"));
  const text = readFileSync(join(FIXTURE_DIR, "app.py"), "utf8").replace(/\r\n/g, "\n");
  const run = x.calls.find((c) => c.callee_text === "runner.run");
  assert.equal(run.start_byte, text.indexOf("run(request"));
  assert.equal(run.receiver_class, "Runner");
  assert.equal(run.receiver, null);
});

test("calls: receiver this for the method's first parameter, receiver_class from construction, annotations and self attributes", async () => {
  const x = await extract(
    "svc = Service()\nmod_typed: Repo = make()\n\nclass K:\n    db: Database\n\n    def __init__(self):\n        self.cache: Cache = make()\n        self.client = http.Client()\n\n" +
      "    def m(self, p: Parser, q):\n        self.go()\n        cls.make()\n        self.db.query()\n        self.cache.get()\n        self.client.send()\n        self.other.x()\n" +
      "        p.parse()\n        q.parse()\n        svc.run()\n        mod_typed.find()\n        local = pkg.Thing(1)\n        local.do()\n        a.b.c()\n\n" +
      "    @classmethod\n    def build(cls):\n        cls.make()\n        cls.db.query()\n\n" +
      "def shadow(svc):\n    svc.run()\n"
  );
  const rows = x.calls.filter((c) => c.callee_text.split(".").length > 1).map((c) => [c.callee_text, c.receiver, c.receiver_class]);
  assert.deepEqual(rows, [
    ["http.Client", null, null],
    ["self.go", "this", null],
    ["cls.make", null, null], // cls is not m's first parameter
    ["self.db.query", null, "Database"],
    ["self.cache.get", null, "Cache"],
    ["self.client.send", null, "Client"],
    ["self.other.x", null, null],
    ["p.parse", null, "Parser"],
    ["q.parse", null, null],
    ["svc.run", null, "Service"],
    ["mod_typed.find", null, "Repo"],
    ["pkg.Thing", null, null],
    ["local.do", null, "Thing"],
    ["a.b.c", null, null],
    ["cls.make", "this", null], // classmethod shape: cls is build's first parameter
    ["cls.db.query", null, "Database"],
    ["svc.run", null, null]
  ]);
});

test("calls: self / cls are receivers only as a method's unrebound first parameter", async () => {
  const x = await extract(
    "class Registry:\n    def run(self):\n        pass\n\n    def run_all(self, handlers):\n        for cls in handlers:\n            cls.run()\n\n" +
      "    def named(me):\n        me.run()\n\n    def rebound(self):\n        self = other()\n        self.run()\n\n" +
      "    def nested(self):\n        def inner(self):\n            self.run()\n        return lambda: self.run()\n\n" +
      "def g(self):\n    self.x()\n    self.attr.y()\n"
  );
  const rows = x.calls.filter((c) => c.callee_text.includes(".")).map((c) => [c.line, c.callee_text, c.receiver, c.receiver_class]);
  assert.deepEqual(rows, [
    [7, "cls.run", null, null], // a loop variable named cls
    [10, "me.run", "this", null], // the first parameter, whatever its name
    [14, "self.run", null, null], // rebound in the method
    [18, "self.run", null, null], // a nested plain function's parameter
    [19, "self.run", "this", null], // a lambda closing over the method's self
    [22, "self.x", null, null], // a module-level function is not a method
    [23, "self.attr.y", null, null]
  ]);
  assert.ok(x.calls.find((c) => c.line === 7).scope_names.includes("cls"), "the loop variable shadows, so the call stays unresolved");
});

test("calls: a @staticmethod's first parameter is no receiver and contributes no attribute types", async () => {
  const x = await extract(
    "class K:\n    def go(self):\n        pass\n\n    @staticmethod\n    def f(x):\n        x.go()\n        x.attr = C()\n\n" +
      "    @staticmethod()\n    def g(y):\n        y.go()\n\n    def m(self):\n        self.attr.run()\n"
  );
  const rows = x.calls.filter((c) => c.callee_text.includes(".")).map((c) => [c.callee_text, c.receiver, c.receiver_class]);
  assert.deepEqual(rows, [["x.go", null, null], ["y.go", null, null], ["self.attr.run", null, null]]);
  assert.ok(x.calls.find((c) => c.callee_text === "x.go").scope_names.includes("x"), "x is an ordinary parameter");
});

// ---- imports ------------------------------------------------------------------------------------

test("import forms: dotted, aliased, from-import with alias, relative, star", async () => {
  const x = await extract("import a.b\nimport c.d as m, e\nfrom f.g import h, i as j\nfrom . import k\nfrom ..x import y\nfrom z import *\n");
  assert.deepEqual(x.imports, [
    { line: 1, specifier: "a.b", bindings: "namespace", local: "a.b" },
    { line: 2, specifier: "c.d", bindings: "namespace", local: "m" },
    { line: 2, specifier: "e", bindings: "namespace", local: "e" },
    { line: 3, specifier: "f.g", bindings: [{ imported: "h", local: "h" }, { imported: "i", local: "j" }], local: null },
    { line: 4, specifier: ".", bindings: [{ imported: "k", local: "k" }], local: null },
    { line: 5, specifier: "..x", bindings: [{ imported: "y", local: "y" }], local: null },
    { line: 6, specifier: "z", bindings: [], local: null }
  ]);
  assert.deepEqual(x.not_extracted, ["star import"]);
});

test("resolveImportSpecifier: from .x import y resolves next to the importing file; extra dots climb", () => {
  const filePaths = new Set(["pkg/__init__.py", "pkg/x.py", "pkg/sub/__init__.py", "pkg/sub/mod.py", "pkg/other/__init__.py"]);
  const r = (specifier, fromPath = "pkg/sub/mod.py") => resolveImportSpecifier({ specifier, fromPath, filePaths, configs: {}, namespaces: new Map() });
  assert.deepEqual(r(".x", "pkg/a.py"), { path: "pkg/x.py", confidence: "exact" });
  assert.deepEqual(r("..x"), { path: "pkg/x.py", confidence: "exact" });
  assert.deepEqual(r("."), { path: "pkg/sub/__init__.py", confidence: "exact" });
  assert.deepEqual(r("..other"), { path: "pkg/other/__init__.py", confidence: "exact" });
  assert.equal(r(".missing"), null);
  assert.equal(r("....too.far"), null);
});

test("resolveImportSpecifier: dotted specifiers from the scope root, then from ancestor package directories", () => {
  const filePaths = new Set(["a/b.py", "lib/__init__.py", "lib/c/__init__.py", "lib/util.py", "lib/inner/__init__.py", "lib/inner/mod.py"]);
  const r = (specifier, fromPath = "lib/inner/mod.py") => resolveImportSpecifier({ specifier, fromPath, filePaths, configs: {}, namespaces: new Map() });
  assert.deepEqual(r("a.b"), { path: "a/b.py", confidence: "exact" });
  assert.deepEqual(r("lib.c"), { path: "lib/c/__init__.py", confidence: "exact" });
  assert.deepEqual(r("util"), { path: "lib/util.py", confidence: "exact" });
  assert.equal(r("util", "a/b.py"), null, "a/ has no __init__.py");
  assert.equal(r("flask"), null);
  assert.equal(r(""), null);
});

test("resolveImportSpecifier: src/ is a root after the scope root, before package ancestors", () => {
  const filePaths = new Set(["src/app/__init__.py", "src/app/models.py", "src/app/views.py", "src/app/app/models.py"]);
  const r = (specifier, paths = filePaths) => resolveImportSpecifier({ specifier, fromPath: "src/app/views.py", filePaths: paths, configs: {}, namespaces: new Map() });
  assert.deepEqual(r("app.models"), { path: "src/app/models.py", confidence: "exact" }, "src/ wins over the package ancestor src/app");
  assert.equal(r("app.models", new Set([...filePaths, "app/models.py"])).path, "app/models.py", "the scope root wins over src/");
});

test("the python fixture: an import resolves to another fixture file", async () => {
  const x = await extractFixture("app.py");
  const filePaths = new Set(["app.py", "services/runner.py", "views/users.py", "urls.py", "api/urls.py"]);
  const runner = x.imports.find((i) => i.specifier === "services.runner");
  assert.deepEqual(runner.bindings, [{ imported: "Runner", local: "Runner" }]);
  assert.deepEqual(resolveImportSpecifier({ specifier: "services.runner", fromPath: "app.py", filePaths, configs: {}, namespaces: new Map() }), {
    path: "services/runner.py",
    confidence: "exact"
  });
});

test("every emitted list is sorted by start_byte", async () => {
  for (const path of ["app.py", "services/runner.py", "views/users.py", "urls.py"]) {
    const x = await extractFixture(path);
    for (const key of ["functions", "calls", "exports", "classes", "routes", "sources", "sinks"]) {
      const bytes = x[key].map((e) => e.start_byte);
      assert.deepEqual(bytes, [...bytes].sort((a, b) => a - b), `${path}: ${key}`);
    }
  }
});

test("arity: param_count without the receiver (splat / default / keyword-only ⇒ null), arg_count (splat ⇒ null)", async () => {
  const x = await extract(
    "def f(a, b):\n    pass\n\nclass C:\n    def m(self, x):\n        pass\n\n    @staticmethod\n    def s(x):\n        pass\n\n" +
      "def g(a, *r):\n    pass\n\ndef h(a=1):\n    pass\n\ndef k(a, *, b):\n    pass\n\nq = lambda u, v: u\nf(1, b=2)\nf(*xs)\nf(**kw)\n"
  );
  assert.deepEqual(x.functions.map((f) => [f.qualified_name, f.param_count]), [["f", 2], ["C.m", 1], ["C.s", 1], ["g", null], ["h", null], ["k", null], ["q", 2]]);
  assert.deepEqual(x.calls.map((c) => [c.callee_text, c.arg_count]), [["f", 2], ["f", null], ["f", null]]);
});
