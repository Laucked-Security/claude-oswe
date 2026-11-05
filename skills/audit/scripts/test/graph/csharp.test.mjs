import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, realpathSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseSource } from "../../graph/parser.mjs";
import { loadSurface } from "../../graph/surface.mjs";
import { buildGraph } from "../../graph/build-graph.mjs";
import { resolveImports, buildClassIndex, resolveCalls } from "../../graph/resolve.mjs";
import * as csharpModule from "../../graph/lang/csharp.mjs";
import { lang, extractFile, resolveImportSpecifier } from "../../graph/lang/csharp.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..", "..", "..");
const FIXTURE_DIR = join(REPO_ROOT, "test-fixtures", "graph", "dotnet");
const REFERENCES_DIR = join(REPO_ROOT, "skills", "audit", "references");
const SURFACE = loadSurface("dotnet", REFERENCES_DIR);
const FIXTURE_FILES = ["Program.cs", "Controllers/RunController.cs", "Services/Runner.cs", "Services/AdminRunner.cs", "Data/Dao.cs"];

async function extract(sourceText, { path = "K.cs" } = {}) {
  const tree = await parseSource("c_sharp", sourceText);
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

test("lang descriptor", () => {
  assert.deepEqual(lang, { id: "csharp", stack: "dotnet", langIds: ["c_sharp"], frameworks: ["aspnet"], implicitThisCalls: true, submoduleImports: false, callableLocals: false, overloads: true });
});

// ---- routes -------------------------------------------------------------------------------------

test("attribute routing: [Route(\"api/[controller]\")] + [HttpPost(\"run\")] ⇒ POST /api/Run/run; [Authorize] / [AllowAnonymous] ⇒ middleware texts", async () => {
  const x = await extractFixture("Controllers/RunController.cs");
  assert.deepEqual(routeRows(x), [
    ["POST", "/api/Run/run", "RunController.Run", ["Authorize"], "aspnet"],
    ["GET", "/api/Run/ping", "RunController.Ping", ["AllowAnonymous"], "aspnet"],
    ["GET", "/api/Run/find", "RunController.Find", [], "aspnet"]
  ]);
  const text = fixtureText("Controllers/RunController.cs");
  assert.equal(x.routes[0].start_byte, text.indexOf('HttpPost("run")'));
  assert.equal(x.routes[0].line, 18);
  assert.deepEqual(x.not_extracted, []);
});

test("attribute routing: verbs, [action] / [controller] tokens, method [Route] ⇒ ANY, absolute templates, class-then-method auth attributes", async () => {
  const x = await extract(
    "[Authorize(Roles = \"admin\")]\n[Microsoft.AspNetCore.Mvc.RouteAttribute(\"v1/[controller]/\")]\npublic class UsersController : Controller {\n" +
      "  [HttpGet] public void A() {}\n" +
      "  [HttpPut(\"[action]/{id}\")] [AllowAnonymous] public void B(int id) {}\n" +
      "  [HttpDelete(\"x\"), HttpPatch(\"y\")] public void C() {}\n" +
      "  [HttpHead(\"h\")] [HttpOptions(\"o\")] public void D() {}\n" +
      "  [Route(\"any\")] public void E() {}\n" +
      "  [HttpGet] [Route(\"both\")] public void F() {}\n" +
      "  [HttpPost(\"/abs\")] public void G() {}\n" +
      "  [HttpGet(\"~/root\")] public void H() {}\n" +
      "  [HttpGet(Path)] public void I() {}\n" +
      "  [NonAction] public void J() {}\n" +
      "  private void K() {}\n}\n"
  );
  assert.deepEqual(routeRows(x), [
    ["GET", "/v1/Users/", "UsersController.A", ["Authorize"], "aspnet"],
    ["PUT", "/v1/Users/B/{id}", "UsersController.B", ["Authorize", "AllowAnonymous"], "aspnet"],
    ["DELETE", "/v1/Users/x", "UsersController.C", ["Authorize"], "aspnet"],
    ["PATCH", "/v1/Users/y", "UsersController.C", ["Authorize"], "aspnet"],
    ["HEAD", "/v1/Users/h", "UsersController.D", ["Authorize"], "aspnet"],
    ["OPTIONS", "/v1/Users/o", "UsersController.D", ["Authorize"], "aspnet"],
    ["ANY", "/v1/Users/any", "UsersController.E", ["Authorize"], "aspnet"],
    ["GET", "/v1/Users/both", "UsersController.F", ["Authorize"], "aspnet"],
    ["POST", "/abs", "UsersController.G", ["Authorize"], "aspnet"],
    ["GET", "/root", "UsersController.H", ["Authorize"], "aspnet"]
  ]);
  assert.deepEqual(x.not_extracted, ["route(non-literal path)"]);
});

test("attribute routing: no class prefix; several class prefixes ⇒ the first, noted; a controller with an unattributed public method ⇒ conventional routing", async () => {
  const x = await extract(
    "class Plain { [HttpGet(\"p\")] public void P() {} public void Q() {} }\n" +
      "[Route(\"a\")] [Route(\"b\")] class TwoController { [HttpGet(\"x\")] public void X() {} }\n" +
      "public class HomeController : Controller { public IActionResult Index() => View(); }\n"
  );
  assert.deepEqual(routeRows(x), [
    ["GET", "/p", "Plain.P", [], "aspnet"],
    ["GET", "/a/x", "TwoController.X", [], "aspnet"]
  ]);
  assert.deepEqual(x.not_extracted, ["conventional routing", "route(multiple class prefixes)"]);
});

test("minimal APIs: MapGet / MapPost with lambda handlers named by their <anon> label, .RequireAuthorization() ⇒ middleware text", async () => {
  const x = await extractFixture("Program.cs");
  assert.deepEqual(routeRows(x), [
    ["GET", "/health", "<anon>@6:23", [], "aspnet"],
    ["POST", "/exec", "<anon>@7:22", ["RequireAuthorization"], "aspnet"]
  ]);
  const text = fixtureText("Program.cs");
  assert.equal(x.routes[0].start_byte, text.indexOf('app.MapGet'));
  assert.equal(x.routes[1].line, 7);
  // the handler lambdas are functions whose qualified name is the route's handler text
  assert.deepEqual(fnRows(x), [
    ["lambda", "<anon>", "<anon>@6:23", null, false],
    ["lambda", "<anon>", "<anon>@7:22", null, false]
  ]);
  assert.deepEqual(x.functions.map((f) => [f.param_count, f.class_start_byte]), [[0, null], [2, null]]);
});

test("minimal APIs: Map / MapMethods ⇒ ANY, method-group handlers, chained AllowAnonymous / RequireAuthorization, groups noted, non-routes ignored", async () => {
  const x = await extract(
    "app.Map(\"/any\", Handlers.Any);\n" +
      "app.MapMethods(\"/m\", new[] { \"GET\" }, delegate (HttpContext c) { return 1; });\n" +
      "app.MapPut(\"/p\", Put).WithName(\"p\").RequireAuthorization(\"policy\");\n" +
      "app.MapDelete(\"/d\", () => 1).AllowAnonymous();\n" +
      "app.MapPatch(@\"/v\", Svc.Patch);\n" +
      "var api = app.MapGroup(\"/api\");\napi.MapGet(\"/in\", () => 2);\napp.MapControllers();\n" +
      "app.MapGet(route, () => 3);\nvar d = mapper.Map<Dto>(src);\nvar e = mapper.Map(src, dst);\napp.MapGet(\"/h\", handlers[0]);\n"
  );
  assert.deepEqual(routeRows(x), [
    ["ANY", "/any", "Handlers.Any", [], "aspnet"],
    ["ANY", "/m", "<anon>@2:39", [], "aspnet"],
    ["PUT", "/p", "Put", ["RequireAuthorization"], "aspnet"],
    ["DELETE", "/d", "<anon>@4:21", ["AllowAnonymous"], "aspnet"],
    ["PATCH", "/v", "Svc.Patch", [], "aspnet"],
    ["GET", "/in", "<anon>@7:19", [], "aspnet"]
  ]);
  assert.deepEqual(x.not_extracted, ["route group", "route(non-literal handler)", "route(non-literal path)"]);
  assert.deepEqual(x.functions.map((f) => f.qualified_name), ["<anon>@2:39", "<anon>@4:21", "<anon>@7:19", "K.<anon>@9:19"]);
});

// ---- functions and classes ----------------------------------------------------------------------

test("functions: overloads are two methods with distinct start_byte; a lambda is named by its local", async () => {
  const x = await extractFixture("Services/Runner.cs");
  assert.deepEqual(fnRows(x), [
    ["method", "Run", "Runner.Run", "Runner", true],
    ["method", "Exec", "Runner.Exec", "Runner", true],
    ["method", "Run", "Runner.Run", "Runner", true],
    ["lambda", "a", "Runner.Run.a", null, false]
  ]);
  const text = fixtureText("Services/Runner.cs");
  assert.equal(x.functions[0].start_byte, text.indexOf("public void Run(string cmd)"));
  assert.deepEqual([x.functions[0].line_start, x.functions[0].line_end], [7, 10]);
  assert.equal(x.functions[3].start_byte, text.indexOf("() => Exec(cmd)"));
  assert.equal(x.functions[3].class_start_byte, text.indexOf("public class Runner"));
  assert.deepEqual(x.functions.map((f) => f.param_count), [1, 1, 2, 0]);
});

test("functions: constructors, expression bodies, local functions, anonymous methods, interface / struct / record / nested members, exported", async () => {
  const x = await extract(
    "namespace N;\npublic class K {\n  public K() { Func<int> f = delegate { return 1; }; Go(x => x); }\n" +
      "  internal int Pkg() => 1;\n  public static class In { public void M() { int Local(int a) => a; } }\n" +
      "  private class Priv { public void P() {} }\n" +
      "  public int Prop { get { return 1; } }\n  public int this[int i] => i;\n}\n" +
      "public interface IThing { void T(); }\npublic struct S { public void U() {} }\npublic record R(int A) { public void V() {} }\nclass Internal { public void W() {} }\n"
  );
  assert.deepEqual(fnRows(x), [
    ["method", "K", "K.K", "K", true],
    ["lambda", "f", "K.K.f", null, false],
    ["lambda", "<anon>", "K.K.<anon>@3:57", null, false],
    ["method", "Pkg", "K.Pkg", "K", false],
    ["method", "M", "In.M", "In", true],
    ["function", "Local", "In.M.Local", null, false],
    ["method", "P", "Priv.P", "Priv", false],
    ["method", "T", "IThing.T", "IThing", true],
    ["method", "U", "S.U", "S", true],
    ["method", "V", "R.V", "R", true],
    ["method", "W", "Internal.W", "Internal", false]
  ]);
  assert.ok(x.not_extracted.includes("property body"));
  assert.equal(x.functions.find((f) => f.name === "Local").class_start_byte, undefined);
});

test("classes: extends is the first base unless it looks like an interface; other bases noted; nested types by simple name", async () => {
  const x = await extract(
    "public class K<T> : Base.Generic<T>, IDisposable where T : class {\n  void M() {}\n  void M(int a) {}\n  class Nested : K<string> { void N() {} }\n}\n" +
      "class Only : IOnly { }\ninterface IA : IB { void A(); }\nstruct S : IS { }\nrecord R(int A) : RBase(A) { void Q() {} }\nenum E { X }\n"
  );
  assert.deepEqual(
    x.classes.map((c) => [c.name, c.extends, c.methods]),
    [["K", "Generic", ["M"]], ["Nested", "K", ["N"]], ["Only", null, []], ["IA", null, ["A"]], ["S", null, []], ["R", "RBase", ["Q"]], ["E", null, []]]
  );
  assert.equal(x.classes[0].start_byte, 0);
  assert.ok(x.not_extracted.includes("implements clause"));
  const y = await extractFixture("Services/AdminRunner.cs");
  assert.deepEqual(y.classes.map((c) => [c.name, c.extends, c.methods]), [["AdminRunner", "Runner", ["Exec"]]]);
  assert.deepEqual(y.not_extracted, []);
});

// ---- calls --------------------------------------------------------------------------------------

test("calls: receiver hints from locals, parameters, fields, properties, record parameters, loop / catch / lambda variables, static classes, this, base, new", async () => {
  const x = await extract(
    "record Rec(Engine Engine) { void E() { Engine.Start(); } }\n" +
      "class K {\n  private readonly Repo<User> _repo;\n  public Runner Runner { get; }\n  Foo foo;\n  Item[] items;\n" +
      "  void Q(Svc svc, Opt? opt, int n) {\n" +
      "    svc.A(); opt.B(); _repo.C(); Runner.D(); foo.E(); this.foo.F(); this.G(); H(); Util.I<int>(); new C<T>().J(); base.K(); a.b.L(); x.M(); items.N();\n" +
      "    var v = new Made(); v.O(); System.IO.Stream s = null; s.P(); Foo w = new(); w?.R();\n" +
      "    foreach (Item it in items) { it.S(); }\n" +
      "    try { } catch (IOException e) { e.T(); }\n" +
      "    Fn g = (Arg z) => z.U();\n" +
      "    int foo = 1; foo.V();\n" +
      "  }\n}\n"
  );
  assert.deepEqual(callRows(x), [
    ["Engine.Start", null, "Engine"],
    ["svc.A", null, "Svc"],
    ["opt.B", null, "Opt"],
    ["_repo.C", null, "Repo"],
    ["Runner.D", null, "Runner"],
    ["foo.E", null, "Foo"],
    ["this.foo.F", null, "Foo"],
    ["this.G", "this", null],
    ["H", null, null],
    ["Util.I", null, "Util"],
    ["C.J", null, "C"],
    ["base.K", null, null],
    ["a.b.L", null, null],
    ["x.M", null, null],
    ["items.N", null, null],
    ["v.O", null, "Made"],
    ["s.P", null, "Stream"],
    ["w.R", null, "Foo"],
    ["it.S", null, "Item"],
    ["e.T", null, "IOException"],
    ["z.U", null, "Arg"],
    ["foo.V", null, null]
  ]);
  // the fixture's field `private readonly Runner _runner;` and the minimal-API lambda parameter `Runner r`
  assert.deepEqual(callRows(await extractFixture("Controllers/RunController.cs")), [["_runner.Run", null, "Runner"], ["Ok", null, null]]);
  assert.deepEqual(callRows(await extractFixture("Program.cs")), [
    ["WebApplication.CreateBuilder", null, "WebApplication"],
    ["builder.Build", null, null],
    ["app.MapGet", null, null],
    ["app.MapPost", null, null],
    ["r.Run", null, "Runner"],
    ["app.MapPost.RequireAuthorization", null, null],
    ["app.Run", null, null]
  ]);
});

test("calls: top-level statement locals bind receivers; class bodies do not see them", async () => {
  const x = await extract("var r = new Runner();\nr.Go();\nclass K { void M() { r.Go(); } }\n");
  assert.deepEqual(callRows(x), [["r.Go", null, "Runner"], ["r.Go", null, null]]);
  // a switch block is one scope across its sections
  const y = await extract("class K { void M(int n) { switch (n) { case 1: var a = new A(); break; default: a.Go(); break; } a.Up(); } }\n");
  assert.deepEqual(callRows(y), [["a.Go", null, "A"], ["a.Up", null, null]]);
});

test("calls: scope_names always [] (callableLocals: false); anchored at the method name, enclosed by the innermost function; attribute arguments and nameof are not calls", async () => {
  const x = await extractFixture("Services/Runner.cs");
  const text = fixtureText("Services/Runner.cs");
  const fnAt = (qn, i = 0) => x.functions.filter((f) => f.qualified_name === qn)[i];
  assert.deepEqual(
    x.calls.map((c) => [c.callee_text, c.enclosing_start_byte, c.scope_names]),
    [
      ["Exec", fnAt("Runner.Run").start_byte, []],
      ["Process.Start", fnAt("Runner.Exec").start_byte, []],
      ["Exec", fnAt("Runner.Run.a").start_byte, []],
      ["a", fnAt("Runner.Run", 1).start_byte, []]
    ]
  );
  assert.equal(x.calls[0].start_byte, text.indexOf("Exec(cmd)"));
  assert.equal(x.calls[1].start_byte, text.indexOf("Start("));
  assert.equal(x.calls[0].line, 9);
  const y = await extract("class K {\n  [Obsolete(nameof(M))] [Custom(Compute(\"x\"))] string s;\n  void M() { var n = nameof(M); N(); F()(); (g)(); }\n}\n");
  assert.deepEqual(y.calls.map((c) => c.callee_text), ["N", "F"]);
  assert.deepEqual(y.not_extracted, ["computed callee"]);
});

test("a nested class body is a barrier: code in a nested type's field initializer has no enclosing method", async () => {
  const x = await extract("class Outer {\n  void Exec() {}\n  void M() { Exec(); }\n  class Inner { int f = Exec(); Action r = () => Exec(); }\n}\n");
  const lambda = x.functions.find((f) => f.kind === "lambda");
  const inner = x.classes.find((c) => c.name === "Inner");
  assert.deepEqual([lambda.qualified_name, lambda.class, lambda.class_start_byte], ["Inner.<anon>@4:44", null, inner.start_byte]);
  assert.deepEqual(x.calls.map((c) => [c.callee_text, c.enclosing_start_byte]), [["Exec", x.functions[1].start_byte], ["Exec", null], ["Exec", lambda.start_byte]]);
});

test("arity: param_count (null with params or an optional parameter), arg_count (named arguments count)", async () => {
  const x = await extract("class K {\n  void A(params string[] xs) {}\n  void B(int a, int b = 2) {}\n  void C(this string s, int t) { A(1, b: 2); C(); }\n  Fn f = (a, b) => a;\n  Fn g = x => x;\n}\n");
  assert.deepEqual(x.functions.map((f) => [f.qualified_name, f.param_count]), [["K.A", null], ["K.B", null], ["K.C", 2], ["K.<anon>@5:10", 2], ["K.<anon>@6:10", 1]]);
  assert.deepEqual(x.calls.map((c) => c.arg_count), [2, 0]);
});

// ---- sources and sinks --------------------------------------------------------------------------

test("sinks: Process.Start is cmd-exec at Start; new SqlCommand and cmd.ExecuteReader are sql", async () => {
  const x = await extractFixture("Services/Runner.cs");
  const text = fixtureText("Services/Runner.cs");
  assert.deepEqual(x.sinks, [{ line: 14, start_byte: text.indexOf("Start("), class: "cmd-exec", callee: "Process.Start", pattern: "Process.Start" }]);
  const dao = await extractFixture("Data/Dao.cs");
  const daoText = fixtureText("Data/Dao.cs");
  assert.deepEqual(dao.sinks, [
    { line: 9, start_byte: daoText.indexOf("SqlCommand(q"), class: "sql", callee: "SqlCommand", pattern: "SqlCommand" },
    { line: 10, start_byte: daoText.indexOf("ExecuteReader"), class: "sql", callee: "cmd.ExecuteReader", pattern: "ExecuteReader" }
  ]);
  assert.deepEqual(callRows(dao), [["cmd.ExecuteReader", null, "SqlCommand"]]);
});

test("sinks: type-qualified candidates, declared types, object creation, initializer identifiers, static members, one sink per node", async () => {
  const x = await extract(
    "class K {\n  BinaryFormatter bf;\n  void M(Process p, string root, string input) {\n" +
      "    p.Start();\n    var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };\n" +
      "    var i = new ProcessStartInfo(\"sh\") { UseShellExecute = true };\n    var doc = new System.Xml.XmlDocument();\n" +
      "    db.Users.FromSqlRaw(input); Path.Combine(root, input); this.Start();\n  }\n}\n"
  );
  assert.deepEqual(
    x.sinks.map((s) => [s.class, s.callee, s.pattern]),
    [
      ["deser", "BinaryFormatter", "BinaryFormatter"],
      ["cmd-exec", "p.Start", "Process.Start"],
      ["deser", "TypeNameHandling", "TypeNameHandling"],
      ["deser", "TypeNameHandling", "TypeNameHandling"],
      ["cmd-exec", "ProcessStartInfo", "ProcessStartInfo"],
      ["cmd-exec", "UseShellExecute", "UseShellExecute"],
      ["xxe", "System.Xml.XmlDocument", "XmlDocument"],
      ["sql", "db.Users.FromSqlRaw", "FromSqlRaw"],
      ["file-read", "Path.Combine", "Path.Combine"]
    ]
  );
});

test("sources: [FromBody] / [FromQuery] parameters in the fixture, Request.* members and attribute sources with their kinds", async () => {
  const ctl = await extractFixture("Controllers/RunController.cs");
  const text = fixtureText("Controllers/RunController.cs");
  assert.deepEqual(ctl.sources, [
    { line: 20, start_byte: text.indexOf("FromBody"), kind: "body", pattern: "[FromBody]" },
    { line: 31, start_byte: text.indexOf("FromQuery"), kind: "query", pattern: "[FromQuery]" }
  ]);
  const x = await extract(
    "class K : Controller {\n  void M([FromRoute] int id, [FromForm] F f) {\n" +
      "    var a = Request.Query[\"a\"]; var b = Request.Form[\"b\"]; var c = Request.Cookies[\"c\"]; var d = Request.Headers[\"d\"];\n" +
      "    var e = Request.RouteValues[\"e\"]; var g = Request.QueryString; var h = Request.Params[\"h\"]; Request.Body.ReadAsync(buf);\n" +
      "    var i = Request.Query[\"i\"].ToString();\n  }\n}\n"
  );
  assert.deepEqual(
    x.sources.map((s) => [s.kind, s.pattern]),
    [
      ["params", "[FromRoute]"],
      ["body", "[FromForm]"],
      ["query", "Request.Query"],
      ["body", "Request.Form"],
      ["cookie", "Request.Cookies"],
      ["header", "Request.Headers"],
      ["params", "Request.RouteValues"],
      ["query", "Request.QueryString"],
      ["query", "Request.Params"],
      ["body", "Request.Body"],
      ["query", "Request.Query"]
    ]
  );
});

// ---- imports and resolution ---------------------------------------------------------------------

test("imports: using / global using / using static / alias forms; namespace from the file-scoped or block declaration", async () => {
  const x = await extract("global using System.Text;\nusing static A.B.C;\nusing Al = P.Q.R;\nnamespace Demo.Web;\nusing Demo.Services;\nclass K {}\n");
  assert.equal(x.namespace, "Demo.Web");
  assert.deepEqual(x.imports, [
    { line: 1, specifier: "System.Text", bindings: [], local: null },
    { line: 2, specifier: "A.B.C", bindings: [], local: null },
    { line: 3, specifier: "P.Q.R", bindings: [{ imported: "R", local: "Al" }], local: null },
    { line: 5, specifier: "Demo.Services", bindings: [], local: null }
  ]);
  assert.deepEqual(x.not_extracted, ["using static"]);
  const y = await extract("namespace A.B {\n  using C;\n  class K {}\n}\nnamespace D { }\n");
  assert.equal(y.namespace, "A.B");
  assert.deepEqual(y.imports, [{ line: 2, specifier: "C", bindings: [], local: null }]);
  assert.deepEqual(y.not_extracted, ["multiple namespaces"]);
  assert.equal((await extractFixture("Program.cs")).namespace, null);
});

test("exports: every public top-level type", async () => {
  const x = await extract("namespace N {\n  public class A { public class Inner {} }\n  class B {}\n  public interface IC {}\n  public record R(int X);\n}\npublic enum E { X }\n");
  assert.deepEqual(x.exports.map((e) => e.name), ["A", "IC", "R", "E"]);
  assert.equal(x.exports[1].start_byte, x.classes.find((c) => c.name === "IC").start_byte);
});

test("resolveImportSpecifier: a namespace ⇒ the first file declaring it (heuristic); an alias / static target ⇒ namespace + basename (exact); null otherwise", () => {
  const filePaths = new Set(["Services/Runner.cs", "Services/AdminRunner.cs", "Controllers/RunController.cs", "Program.cs", "Other/Runner.cs"]);
  const namespaces = new Map([
    ["Services/Runner.cs", "Demo.Services"],
    ["Services/AdminRunner.cs", "Demo.Services"],
    ["Controllers/RunController.cs", "Demo.Controllers"],
    ["Program.cs", null],
    ["Other/Runner.cs", "Other"]
  ]);
  const resolve = (specifier) => resolveImportSpecifier({ specifier, fromPath: "Program.cs", filePaths, configs: {}, namespaces });
  assert.deepEqual(resolve("Demo.Services"), { path: "Services/AdminRunner.cs", confidence: "heuristic" });
  assert.deepEqual(resolve("Demo.Services.Runner"), { path: "Services/Runner.cs", confidence: "exact" });
  assert.deepEqual(resolve("Demo.Services.Missing"), null);
  assert.equal(resolve("System.Text"), null);
  assert.equal(resolve(""), null);
  assert.equal(resolve(undefined), null);
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

// ---- through resolve.mjs / build-graph ----------------------------------------------------------

// Resolve the calls of in-memory C# sources ({ path: text }) with the C# module.
async function resolveSources(sources) {
  const files = [];
  for (const [path, text] of Object.entries(sources)) files.push({ path, langId: "c_sharp", stack: "dotnet", extract: await extract(text, { path }) });
  const langModules = new Map([["c_sharp", csharpModule]]);
  const importMap = resolveImports(files, { langModules, filePaths: new Set(Object.keys(sources)), configs: {} });
  return { files, results: resolveCalls(files, importMap, { classIndex: buildClassIndex(files, importMap), langModules }) };
}

test("resolution: overloads by arity, this.M, a lambda's bare call acts for its method's class", async () => {
  const { results } = await resolveSources({
    "K.cs": "class K {\n  void Run(string c) { }\n  void Run(string c, int n) { }\n  void Go(string cmd) {\n    Run(cmd, 3);\n    this.Run(cmd);\n    Action r = () => Run(cmd);\n  }\n}\n"
  });
  assert.deepEqual(
    results.map((r) => [r.line, r.callee_text, r.to?.start_byte ?? null, r.confidence]),
    [[5, "Run", 37, "exact"], [6, "this.Run", 12, "exact"], [7, "Run", 12, "exact"]]
  );
});

test("the dotnet fixture through build-graph: route auth, field-typed receiver, override grading, sinks in their methods, namespace import edges", async () => {
  const dir = realpathSync(FIXTURE_DIR);
  const { graph, reason } = await buildGraph({ projectDir: dir, scopeRealpath: dir, stacks: ["dotnet"], frameworks: ["aspnet"], referencesDir: REFERENCES_DIR });
  assert.ok(graph, reason);
  const routes = graph.nodes.filter((n) => n.type === "route").map((r) => [r.http_method, r.path_pattern, r.auth]);
  assert.deepEqual(routes.sort(), [
    ["GET", "/api/Run/find", "unauthenticated"],
    ["GET", "/api/Run/ping", "unauthenticated"],
    ["GET", "/health", "unauthenticated"],
    ["POST", "/api/Run/run", "authenticated"],
    ["POST", "/exec", "authenticated"]
  ]);
  const fn = (file, qn) => graph.nodes.filter((n) => n.type === "function" && n.file === file && n.qualified_name === qn);
  const [run1, run2] = fn("Services/Runner.cs", "Runner.Run").sort((a, b) => a.line_start - b.line_start);
  assert.ok(run1 && run2 && run1.id !== run2.id, "two Runner.Run overloads with distinct ids");
  const exec = fn("Services/Runner.cs", "Runner.Exec")[0];
  const lambda = fn("Services/Runner.cs", "Runner.Run.a")[0];
  const calls = graph.edges.filter((e) => e.type === "calls");
  const fieldRun = calls.find((e) => e.callee_text === "_runner.Run");
  assert.deepEqual([fieldRun.to, fieldRun.confidence], [run1.id, "exact"]); // the 1-parameter overload, via the field's type
  const bareExec = calls.find((e) => e.from === run1.id && e.callee_text === "Exec");
  assert.deepEqual([bareExec.to, bareExec.confidence], [exec.id, "name-only"]); // AdminRunner overrides Exec
  const lambdaExec = calls.find((e) => e.from === lambda.id && e.callee_text === "Exec");
  assert.deepEqual([lambdaExec.to, lambdaExec.confidence], [exec.id, "name-only"]); // the lambda acts for Runner
  const cmd = graph.nodes.find((n) => n.type === "sink" && n.class === "cmd-exec");
  assert.equal(cmd.enclosing_fn, exec.id);
  const find = fn("Data/Dao.cs", "Dao.Find")[0];
  assert.deepEqual(graph.nodes.filter((n) => n.type === "sink" && n.class === "sql").map((s) => [s.callee, s.enclosing_fn]).sort(), [["SqlCommand", find.id], ["cmd.ExecuteReader", find.id]].sort());
  const body = graph.nodes.find((n) => n.type === "source" && n.kind === "body");
  assert.equal(body.enclosing_fn, fn("Controllers/RunController.cs", "RunController.Run")[0].id);
  const fileId = (path) => graph.nodes.find((n) => n.type === "file" && n.path === path).id;
  const imports = graph.edges.filter((e) => e.type === "imports" && e.specifier === "Demo.Services");
  assert.deepEqual(
    imports.map((e) => [e.from, e.to, e.confidence]).sort(),
    [[fileId("Controllers/RunController.cs"), fileId("Services/AdminRunner.cs"), "heuristic"], [fileId("Program.cs"), fileId("Services/AdminRunner.cs"), "heuristic"]].sort()
  );
  assert.deepEqual(graph.stats.coverage_matrix.dotnet.extractors_applied, ["aspnet"]);
});
