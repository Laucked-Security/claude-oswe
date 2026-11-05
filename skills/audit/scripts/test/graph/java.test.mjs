import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, realpathSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseSource } from "../../graph/parser.mjs";
import { loadSurface } from "../../graph/surface.mjs";
import { buildGraph } from "../../graph/build-graph.mjs";
import { lang, extractFile, resolveImportSpecifier } from "../../graph/lang/java.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..", "..", "..");
const FIXTURE_DIR = join(REPO_ROOT, "test-fixtures", "graph", "java");
const SRC = "src/main/java/com/ex";
const REFERENCES_DIR = join(REPO_ROOT, "skills", "audit", "references");
const SURFACE = loadSurface("java", REFERENCES_DIR);

async function extract(sourceText, { path = "src/K.java" } = {}) {
  const tree = await parseSource("java", sourceText);
  try {
    assert.equal(tree.rootNode.hasError, false, "test source parses cleanly");
    return extractFile({ tree, path, sourceText, frameworks: lang.frameworks, surface: SURFACE });
  } finally {
    tree.delete();
  }
}

// CRLF checkouts are read as LF so offsets match the committed (eol=lf) fixture on every platform.
const fixtureText = (file) => readFileSync(join(FIXTURE_DIR, SRC, file), "utf8").replace(/\r\n/g, "\n");
const extractFixture = (file) => extract(fixtureText(file), { path: `${SRC}/${file}` });
const routeRows = (x) => x.routes.map((r) => [r.http_method, r.path_pattern, r.handler_text, r.middleware_texts, r.framework]);
const callRows = (x) => x.calls.map((c) => [c.callee_text, c.receiver, c.receiver_class]);
const fnRows = (x) => x.functions.map((f) => [f.kind, f.name, f.qualified_name, f.class, f.exported]);

test("lang descriptor", () => {
  assert.deepEqual(lang, { id: "java", stack: "java", langIds: ["java"], frameworks: ["spring"], implicitThisCalls: true, submoduleImports: false, callableLocals: false });
});

// ---- routes -------------------------------------------------------------------------------------

test("Spring: class @RequestMapping prefix + @PostMapping ⇒ POST /api/run, @PreAuthorize ⇒ middleware text", async () => {
  const x = await extractFixture("Api.java");
  assert.deepEqual(routeRows(x), [
    ["POST", "/api/run", "Api.run", ["PreAuthorize"], "spring"],
    ["GET", "/api/health", "Api.health", [], "spring"]
  ]);
  const text = fixtureText("Api.java");
  assert.equal(x.routes[0].start_byte, text.indexOf('@PostMapping("/run")'));
  assert.equal(x.routes[0].line, text.slice(0, x.routes[0].start_byte).split("\n").length);
});

test("Spring: @RequestMapping method / value / path forms, prefix joining, class-then-method auth annotations", async () => {
  const x = await extract(
    "@RestController\n@RequestMapping(path = \"/p/\")\n@Secured(\"ROLE_USER\")\npublic class K {\n" +
      "  @RequestMapping(value = \"/a\", method = RequestMethod.POST) @RolesAllowed(\"X\") @Deprecated public void a() {}\n" +
      "  @RequestMapping(\"b\") public void b() {}\n" +
      "  @RequestMapping(value = \"/c\", method = {RequestMethod.GET, RequestMethod.PUT}) public void c() {}\n" +
      "  @RequestMapping(method = {RequestMethod.DELETE}) public void d() {}\n" +
      "  @PutMapping(path = \"/e\") public void e() {}\n" +
      "  @PatchMapping public void f() {}\n" +
      "  @DeleteMapping(value = \"/g\") @org.springframework.security.access.prepost.PreAuthorize(\"x\") public void g() {}\n" +
      "  @GetMapping(PATH) public void h() {}\n" +
      "  public void notARoute() {}\n}\n" +
      "class N {\n  @GetMapping public void i() {}\n}\n"
  );
  assert.deepEqual(routeRows(x), [
    ["POST", "/p/a", "K.a", ["Secured", "RolesAllowed"], "spring"],
    ["ANY", "/p/b", "K.b", ["Secured"], "spring"],
    ["ANY", "/p/c", "K.c", ["Secured"], "spring"],
    ["DELETE", "/p/", "K.d", ["Secured"], "spring"],
    ["PUT", "/p/e", "K.e", ["Secured"], "spring"],
    ["PATCH", "/p/", "K.f", ["Secured"], "spring"],
    ["DELETE", "/p/g", "K.g", ["Secured", "PreAuthorize"], "spring"],
    ["GET", "/", "N.i", [], "spring"]
  ]);
  assert.ok(x.not_extracted.includes("route(non-literal path)"));
});

test("SecurityFilterChain in a file ⇒ not_extracted \"SecurityFilterChain matchers\"; routes elsewhere are unaffected", async () => {
  const config = await extractFixture("SecurityConfig.java");
  assert.ok(config.not_extracted.includes("SecurityFilterChain matchers"));
  const api = await extractFixture("Api.java");
  assert.ok(!api.not_extracted.includes("SecurityFilterChain matchers"));
});

// ---- functions and classes ----------------------------------------------------------------------

test("functions: overloads are two methods with distinct start_byte; lambdas named by their local or anonymous", async () => {
  const x = await extractFixture("service/UserService.java");
  assert.deepEqual(fnRows(x), [
    ["method", "run", "UserService.run", "UserService", true],
    ["method", "exec", "UserService.exec", "UserService", true],
    ["method", "run", "UserService.run", "UserService", true],
    ["lambda", "r", "UserService.run.r", null, false]
  ]);
  const runs = x.functions.filter((f) => f.qualified_name === "UserService.run");
  assert.notEqual(runs[0].start_byte, runs[1].start_byte);
  const text = fixtureText("service/UserService.java");
  assert.equal(x.functions[0].start_byte, text.indexOf("public void run(String cmd)"));
  assert.equal(x.functions[0].line_start, 4);
  assert.equal(x.functions[0].line_end, 6);
  assert.equal(x.functions[3].start_byte, text.indexOf("() -> exec(cmd)"));
});

test("functions: constructors, nested / interface / enum / record methods, anonymous lambdas, exported = public type + public member", async () => {
  const x = await extract(
    "public class K {\n  public K() { Runnable a = null; run(() -> go()); }\n  void pkg() {}\n  public static class In { public void m() {} }\n}\n" +
      "interface I { void m(); }\nenum E { A; public void e() {} }\nrecord R(int x) { R { } }\n"
  );
  assert.deepEqual(fnRows(x), [
    ["method", "K", "K.K", "K", true],
    ["lambda", "<anon>", "K.K.<anon>@2:39", null, false],
    ["method", "pkg", "K.pkg", "K", false],
    ["method", "m", "In.m", "In", true],
    ["method", "m", "I.m", "I", false],
    ["method", "e", "E.e", "E", false],
    ["method", "R", "R.R", "R", false]
  ]);
  assert.deepEqual(x.exports, [{ name: "K", start_byte: 0 }]);
});

test("classes: extends is the superclass base name; implements is only noted; nested types listed by simple name", async () => {
  const x = await extract(
    "public class K<T> extends base.Base<T> implements I, J {\n  void m() {}\n  void m(int a) {}\n  static class Nested extends K<String> { void n() {} }\n}\n" +
      "interface I { void i(); }\nenum E { A; void e() {} }\nrecord R(int x) { void r() {} }\n"
  );
  assert.deepEqual(
    x.classes.map((c) => [c.name, c.extends, c.methods]),
    [["K", "Base", ["m"]], ["Nested", "K", ["n"]], ["I", null, ["i"]], ["E", null, ["e"]], ["R", null, ["r"]]]
  );
  assert.equal(x.classes[0].start_byte, 0);
  assert.ok(x.not_extracted.includes("implements clause"));
  const y = await extractFixture("service/AdminService.java");
  assert.deepEqual(y.classes.map((c) => [c.name, c.extends, c.methods]), [["AdminService", "UserService", ["exec"]]]);
});

// ---- calls --------------------------------------------------------------------------------------

test("calls: receiver hints from locals, parameters, loop / catch / lambda variables, fields, static classes, this, new, super", async () => {
  const x = await extract(
    "class K {\n  @Autowired private Repo<User> repo;\n  Foo foo;\n" +
      "  void q(Svc svc, int n) throws Exception {\n" +
      "    svc.a(); repo.b(); foo.c(); this.foo.d(); this.e(); f(); Util.g(); new C<T>().h(); super.i(); a.b.j(); x.k();\n" +
      "    java.util.List<Item> items = null; items.l();\n" +
      "    for (Item it : items) { it.m(); }\n" +
      "    try { } catch (IOException e) { e.n(); }\n" +
      "    Fn g = (Arg z) -> z.o();\n" +
      "    var v = new Made(); v.p();\n" +
      "    int foo = 1; foo.q();\n" +
      "  }\n}\n"
  );
  assert.deepEqual(callRows(x), [
    ["svc.a", null, "Svc"],
    ["repo.b", null, "Repo"],
    ["foo.c", null, "Foo"],
    ["this.foo.d", null, "Foo"],
    ["this.e", "this", null],
    ["f", null, null],
    ["Util.g", null, "Util"],
    ["C.h", null, "C"],
    ["super.i", null, null],
    ["a.b.j", null, null],
    ["x.k", null, null],
    ["items.l", null, "List"],
    ["it.m", null, "Item"],
    ["e.n", null, "IOException"],
    ["z.o", null, "Arg"],
    ["v.p", null, "Made"],
    ["foo.q", null, null]
  ]);
  // the fixture's @Autowired field, typed through `import com.ex.service.UserService;`
  assert.deepEqual(callRows(await extractFixture("Api.java")), [["userService.run", null, "UserService"]]);
});

test("calls: a parameter named like a method never shadows it (callableLocals: false ⇒ scope_names always [])", async () => {
  const x = await extract("class K {\n  void exec(String c) {}\n  void run(String exec) { exec(exec); }\n}\n");
  assert.deepEqual(x.calls.map((c) => [c.callee_text, c.scope_names]), [["exec", []]]);
  const y = await extractFixture("service/UserService.java");
  for (const c of y.calls) assert.deepEqual(c.scope_names, []);
});

test("calls: anchored at the method name, enclosed by the innermost method / lambda; annotation arguments are not calls", async () => {
  const x = await extractFixture("service/UserService.java");
  const text = fixtureText("service/UserService.java");
  const fnAt = (name) => x.functions.find((f) => f.qualified_name === name);
  assert.deepEqual(
    x.calls.map((c) => [c.callee_text, c.enclosing_start_byte]),
    [
      ["exec", fnAt("UserService.run").start_byte],
      ["Runtime.getRuntime", fnAt("UserService.exec").start_byte],
      ["Runtime.getRuntime.exec", fnAt("UserService.exec").start_byte],
      ["exec", fnAt("UserService.run.r").start_byte],
      ["r.run", x.functions[2].start_byte]
    ]
  );
  assert.equal(x.calls[0].start_byte, text.indexOf("exec(cmd)"));
  assert.equal(x.calls[2].start_byte, text.indexOf("exec(c)"));
  assert.equal(x.calls[0].line, 5);
  const y = await extract("class K {\n  @Value(compute(\"x\")) String s;\n  void m() { n(); }\n}\n");
  assert.deepEqual(y.calls.map((c) => c.callee_text), ["n"]);
});

// ---- sources and sinks --------------------------------------------------------------------------

test("sinks: Runtime.getRuntime().exec is cmd-exec at the exec name; st.execute is sql via the type-qualified candidate", async () => {
  const x = await extractFixture("service/UserService.java");
  const text = fixtureText("service/UserService.java");
  assert.deepEqual(x.sinks, [
    { line: 9, start_byte: text.indexOf("exec(c)"), class: "cmd-exec", callee: "Runtime.getRuntime.exec", pattern: "Runtime.getRuntime().exec" }
  ]);
  const dao = await extractFixture("Dao.java");
  const daoText = fixtureText("Dao.java");
  assert.deepEqual(dao.sinks, [{ line: 6, start_byte: daoText.indexOf("execute(q)"), class: "sql", callee: "st.execute", pattern: "Statement.execute" }]);
});

test("sinks: object creation, declared types, annotations, annotation keys, method names, one sink per node", async () => {
  const x = await extract(
    "@JsonTypeInfo(use = Id.CLASS)\nclass K {\n" +
      "  @Query(value = \"select\", nativeQuery = true) void q() {}\n" +
      "  void m(java.io.InputStream in, HttpSession session) throws Exception {\n" +
      "    ObjectInputStream o = new java.io.ObjectInputStream(in); o.readObject();\n" +
      "    session.setAttribute(\"k\", in); new ProcessBuilder(\"sh\").start();\n" +
      "  }\n}\n"
  );
  assert.deepEqual(
    x.sinks.map((s) => [s.class, s.callee, s.pattern]),
    [
      ["deser", "JsonTypeInfo", "@JsonTypeInfo"],
      ["sql", "nativeQuery", "nativeQuery"],
      ["deser", "ObjectInputStream", "ObjectInputStream"],
      ["deser", "java.io.ObjectInputStream", "ObjectInputStream"],
      ["deser", "o.readObject", ".readObject("],
      ["trust-boundary", "session.setAttribute", "setAttribute"],
      ["cmd-exec", "ProcessBuilder", "ProcessBuilder"]
    ]
  );
});

test("sources: parameter / method annotations, request getters, identity header literals", async () => {
  const api = await extractFixture("Api.java");
  const text = fixtureText("Api.java");
  assert.deepEqual(api.sources, [{ line: 20, start_byte: text.indexOf("@RequestParam String"), kind: "query", pattern: "@RequestParam" }]);
  const x = await extract(
    "class K {\n  @ModelAttribute void pre() {}\n" +
      "  void m(@RequestBody B b, @PathVariable String id, @RequestHeader String h, @CookieValue String c, HttpServletRequest req) throws Exception {\n" +
      "    req.getParameter(\"a\"); req.getQueryString(); req.getHeader(\"X-User-Role\"); req.getCookies(); req.getInputStream(); req.getReader();\n" +
      "  }\n}\n"
  );
  assert.deepEqual(
    x.sources.map((s) => [s.kind, s.pattern]),
    [
      ["body", "@ModelAttribute"],
      ["body", "@RequestBody"],
      ["params", "@PathVariable"],
      ["header", "@RequestHeader"],
      ["cookie", "@CookieValue"],
      ["query", "getParameter"],
      ["query", "getQueryString"],
      ["header", "getHeader"],
      ["header", "X-User-Role"],
      ["cookie", "getCookies"],
      ["body", "getInputStream"],
      ["body", "getReader"]
    ]
  );
});

// ---- imports and resolution ---------------------------------------------------------------------

test("imports: single-type, wildcard and static forms; namespace from the package declaration", async () => {
  const x = await extract("package a.b;\n\nimport c.d.Z;\nimport c.d.*;\nimport static c.d.Z.m;\nimport static c.d.Z.*;\nclass K {}\n");
  assert.equal(x.namespace, "a.b");
  assert.deepEqual(x.imports, [
    { line: 3, specifier: "c.d.Z", bindings: [{ imported: "Z", local: "Z" }], local: null },
    { line: 4, specifier: "c.d", bindings: "namespace", local: "c.d" },
    { line: 5, specifier: "c.d.Z", bindings: [{ imported: "m", local: "m" }], local: null },
    { line: 6, specifier: "c.d.Z", bindings: "namespace", local: "c.d.Z" }
  ]);
  assert.deepEqual(x.not_extracted, ["static import", "wildcard import"]);
  const y = await extract("class K {}\n");
  assert.equal(y.namespace, null);
});

test("exports: every public top-level type", async () => {
  const x = await extract("public class A { public class Inner {} }\nclass B {}\npublic interface C {}\n");
  assert.deepEqual(x.exports.map((e) => e.name), ["A", "C"]);
  assert.equal(x.exports[1].start_byte, x.classes.find((c) => c.name === "C").start_byte);
});

test("resolveImportSpecifier: package + simple name through namespaces (exact), path suffix without a namespace entry (heuristic), wildcards null", () => {
  const filePaths = new Set(["src/com/ex/service/UserService.java", "other/UserService.java", "lib/a/b/Z.java", "src/com/ex/Api.java"]);
  const namespaces = new Map([
    ["src/com/ex/service/UserService.java", "com.ex.service"],
    ["other/UserService.java", "other"],
    ["src/com/ex/Api.java", "com.ex"]
  ]);
  const resolve = (specifier) => resolveImportSpecifier({ specifier, fromPath: "src/com/ex/Api.java", filePaths, configs: {}, namespaces });
  assert.deepEqual(resolve("com.ex.service.UserService"), { path: "src/com/ex/service/UserService.java", confidence: "exact" });
  assert.deepEqual(resolve("a.b.Z"), { path: "lib/a/b/Z.java", confidence: "heuristic" });
  assert.equal(resolve("com.ex.service"), null);
  assert.equal(resolve("com.ex.other.UserService"), null);
  assert.equal(resolve("com.ex.service.Missing"), null);
});

test("every emitted list is sorted by start_byte", async () => {
  for (const file of ["Api.java", "Dao.java", "SecurityConfig.java", "service/UserService.java", "service/AdminService.java"]) {
    const x = await extractFixture(file);
    for (const key of ["functions", "calls", "exports", "classes", "routes", "sources", "sinks"]) {
      const bytes = x[key].map((e) => e.start_byte);
      assert.deepEqual(bytes, [...bytes].sort((a, b) => a - b), `${file}: ${key}`);
    }
  }
});

// ---- through build-graph ------------------------------------------------------------------------

test("the java fixture through build-graph: route auth, implicit-this override grading, sinks in their methods", async () => {
  const dir = realpathSync(FIXTURE_DIR);
  const { graph, reason } = await buildGraph({ projectDir: dir, scopeRealpath: dir, stacks: ["java"], frameworks: ["spring"], referencesDir: REFERENCES_DIR });
  assert.ok(graph, reason);
  const routes = graph.nodes.filter((n) => n.type === "route").map((r) => [r.http_method, r.path_pattern, r.auth]);
  assert.deepEqual(routes.sort(), [["GET", "/api/health", "unauthenticated"], ["POST", "/api/run", "authenticated"]]);
  const fn = (file, qn) => graph.nodes.filter((n) => n.type === "function" && n.file === `${SRC}/${file}` && n.qualified_name === qn);
  const [run1, run2] = fn("service/UserService.java", "UserService.run");
  assert.ok(run1 && run2 && run1.id !== run2.id, "two UserService.run overloads with distinct ids");
  const exec = fn("service/UserService.java", "UserService.exec")[0];
  const calls = graph.edges.filter((e) => e.type === "calls");
  const bareExec = calls.find((e) => e.from === run1.id && e.callee_text === "exec");
  assert.deepEqual([bareExec.to, bareExec.confidence], [exec.id, "name-only"]); // AdminService overrides exec
  const cmd = graph.nodes.find((n) => n.type === "sink" && n.class === "cmd-exec");
  assert.equal(cmd.enclosing_fn, exec.id);
  const sql = graph.nodes.find((n) => n.type === "sink" && n.class === "sql");
  assert.deepEqual([sql.callee, sql.enclosing_fn], ["st.execute", fn("Dao.java", "Dao.find")[0].id]);
  assert.ok(graph.stats.coverage_matrix.java.not_extracted.includes("SecurityFilterChain matchers"));
  const imports = graph.edges.filter((e) => e.type === "imports" && e.specifier === "com.ex.service.UserService");
  assert.deepEqual(imports.map((e) => e.confidence), ["exact"]);
});
