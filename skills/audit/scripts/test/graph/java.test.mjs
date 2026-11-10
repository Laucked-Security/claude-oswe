import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, realpathSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseSource } from "../../graph/parser.mjs";
import { loadSurface } from "../../graph/surface.mjs";
import { buildGraph } from "../../graph/build-graph.mjs";
import { resolveImports, buildClassIndex, resolveCalls } from "../../graph/resolve.mjs";
import * as javaModule from "../../graph/lang/java.mjs";
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
  assert.deepEqual(lang, { id: "java", stack: "java", langIds: ["java"], frameworks: ["spring", "servlet"], implicitThisCalls: true, submoduleImports: false, callableLocals: false, overloads: true });
});

test("functions: a lambda named by the local it initialises carries binds_name (resolve.mjs's nested definitions); an argument lambda and a method do not", async () => {
  const x = await extract("class K {\n  void m(java.util.List<String> list) {\n    Runnable r = () -> {};\n    list.forEach(x -> {});\n  }\n}\n");
  assert.deepEqual(x.functions.map((f) => [f.qualified_name, f.kind, f.binds_name ?? false]), [["K.m", "method", false], ["K.m.r", "lambda", true], ["K.m.<anon>@4:18", "lambda", false]]);
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

const ruleRows = (chain) => chain.rules.map((r) => [r.line, r.http_method, r.patterns, r.auth]);

test("security chains: the fixture's SecurityFilterChain yields one unscoped chain at the method with its matchers in source order, at their matcher; formLogin's permitAll is not a rule; no note", async () => {
  const config = await extractFixture("SecurityConfig.java");
  const text = fixtureText("SecurityConfig.java");
  assert.equal(config.security_chains.length, 1);
  const [chain] = config.security_chains;
  assert.deepEqual([chain.line, chain.start_byte, chain.scope, chain.scope_unknown], [11, text.indexOf("@Bean"), null, false]);
  assert.deepEqual(ruleRows(chain), [
    [14, null, ["/api/health", "/public/**"], "unauthenticated"],
    [15, "POST", ["/di/**"], "authenticated"],
    [16, null, ["/**"], "authenticated"]
  ]);
  assert.deepEqual(chain.rules.map((r) => r.start_byte), [text.indexOf("requestMatchers(\"/api/health\""), text.indexOf("requestMatchers(HttpMethod.POST"), text.indexOf("anyRequest()")]);
  assert.deepEqual(config.not_extracted, []);
  const api = await extractFixture("Api.java");
  assert.deepEqual(api.security_chains, []);
  assert.ok(!api.not_extracted.includes("SecurityFilterChain matchers"));
});

test("security chains: a SecurityFilterChain that yields no rule is still a chain (rules []) and noted \"SecurityFilterChain matchers\"; a configure(HttpSecurity) override (legacy antMatchers / mvcMatchers) is a chain; a helper taking an HttpSecurity is not", async () => {
  const bare = await extract("class Sec {\n  public SecurityFilterChain chain(HttpSecurity http) { return http.build(); }\n}\n");
  assert.deepEqual(bare.security_chains, [{ line: 2, start_byte: bare.functions[0].start_byte, scope: null, scope_unknown: false, rules: [] }]);
  assert.deepEqual(bare.not_extracted, ["security(unread chain)"]);
  const legacy = await extract(
    "class Sec extends WebSecurityConfigurerAdapter {\n  protected void configure(HttpSecurity http) throws Exception {\n" +
      "    http.authorizeRequests().antMatchers(\"/open/**\").permitAll().mvcMatchers(HttpMethod.GET, \"/r\").hasAnyRole(\"A\", \"B\").anyRequest().denyAll();\n  }\n" +
      "  private void common(HttpSecurity http) { http.authorizeRequests().anyRequest().permitAll(); }\n" +
      "  protected abstract void configure(HttpSecurity http, int x);\n}\n" +
      "interface I { SecurityFilterChain chain(HttpSecurity http); }\n"
  );
  assert.equal(legacy.security_chains.length, 1);
  assert.deepEqual(ruleRows(legacy.security_chains[0]), [[3, null, ["/open/**"], "unauthenticated"], [3, "GET", ["/r"], "authenticated"], [3, null, ["/**"], "authenticated"]]);
  assert.deepEqual(legacy.not_extracted, []);
  // a fully-qualified return type is a chain too
  const qualified = await extract("class Sec {\n  public org.springframework.security.web.SecurityFilterChain b(HttpSecurity http) { http.authorizeHttpRequests(a -> a.anyRequest().authenticated()); return http.build(); }\n}\n");
  assert.deepEqual(ruleRows(qualified.security_chains[0]), [[2, null, ["/**"], "authenticated"]]);
  // only an import / annotation names a security type: the hint, no chain
  const imported = await extract("import org.springframework.security.web.SecurityFilterChain;\n@EnableWebSecurity\nclass Sec {\n  void m() {}\n}\n");
  assert.deepEqual([imported.security_chains, imported.not_extracted], [[], ["SecurityFilterChain matchers"]]);
  const flux = await extract("class Sec {\n  public SecurityWebFilterChain chain(ServerHttpSecurity http) { return http.build(); }\n}\n");
  assert.deepEqual([flux.security_chains, flux.not_extracted], [[], ["SecurityFilterChain matchers"]]);
});

test("security chains: a rule's auth is the call chained directly on its matcher; hasIpAddress / not() ⇒ unknown; matchers outside an authorize call and rule-named calls elsewhere are nothing", async () => {
  const x = await extract(
    "class Sec extends WebSecurityConfigurerAdapter {\n  protected void configure(HttpSecurity http) throws Exception {\n" +
      "    http.authorizeRequests().antMatchers(\"/admin/**\").hasIpAddress(\"127.0.0.1\").antMatchers(\"/deny/**\").not().permitAll()\n" +
      "        .and().formLogin().loginPage(\"/login\").permitAll().and().anonymous().disable();\n" +
      "    http.requiresChannel(c -> c.anyRequest().requiresSecure()).csrf(c -> c.ignoringRequestMatchers(\"/csrf/**\"));\n" +
      "    http.authorizeHttpRequests(a -> a.requestMatchers(\"/open\").permitAll()).formLogin(f -> f.permitAll());\n  }\n}\n"
  );
  assert.equal(x.security_chains.length, 1);
  assert.deepEqual(ruleRows(x.security_chains[0]), [[3, null, ["/admin/**"], "unknown"], [3, null, ["/deny/**"], "unknown"], [6, null, ["/open"], "unauthenticated"]]);
  assert.deepEqual(x.not_extracted, []);
});

test("security chains: rules the extractor cannot see are an unreadable rule at their position — the HttpSecurity handed to a helper, http.with / apply, an authorize call given a method reference or a value", async () => {
  const x = await extract(
    "class Sec {\n  public SecurityFilterChain a(HttpSecurity http) {\n    common(http);\n    http.authorizeHttpRequests(z -> z.anyRequest().permitAll());\n    return http.build();\n  }\n" +
      "  public SecurityFilterChain b(HttpSecurity http) {\n    http.authorizeHttpRequests(this::rules).authorizeHttpRequests(a -> a.requestMatchers(\"/x\").permitAll());\n    return http.build();\n  }\n" +
      "  public SecurityFilterChain c(HttpSecurity http) {\n    http.with(new AdminDsl(), Customizer.withDefaults()).authorizeHttpRequests(customizer);\n    return http.build();\n  }\n" +
      "  public SecurityFilterChain d(HttpSecurity http) {\n    http.authorizeHttpRequests(a -> a.requestMatchers(antMatcher(\"/open\"), antMatcher(HttpMethod.GET, \"/g\")).permitAll().requestMatchers(antMatcher(HttpMethod.GET, \"/m\"), antMatcher(HttpMethod.POST, \"/m\")).denyAll().requestMatchers(new AntPathRequestMatcher(\"/o\")).permitAll().anyRequest().authenticated());\n    return http.build();\n  }\n}\n"
  );
  assert.deepEqual(x.security_chains.map(ruleRows), [
    [[3, null, null, "unknown"], [4, null, ["/**"], "unauthenticated"]],
    [[8, null, null, "unknown"], [8, null, ["/x"], "unauthenticated"]],
    [[12, null, null, "unknown"], [12, null, null, "unknown"]],
    // antMatcher(...) factories are the pattern (verb kept when they agree); a RequestMatcher object is unreadable
    [[16, "GET", ["/open", "/g"], "unauthenticated"], [16, null, null, "authenticated"], [16, null, null, "unauthenticated"], [16, null, ["/**"], "authenticated"]]
  ]);
  assert.deepEqual(x.not_extracted, ["security(non-literal matcher)"]);
});

test("security chains: securityMatcher / antMatcher / securityMatchers(m -> ...) patterns are the scope; a non-literal pattern or regexMatchers ⇒ patterns null + note; access(...) ⇒ unknown", async () => {
  const x = await extract(
    "class Sec {\n  static final String P = \"/p\";\n  public SecurityFilterChain chain(HttpSecurity http) {\n" +
      "    http.securityMatcher(\"/api/**\", \"/v2/**\").authorizeHttpRequests(a -> a.requestMatchers(P).permitAll().regexMatchers(\"/x.*\").authenticated()" +
      ".requestMatchers(HttpMethod.POST).access(\"x\").requestMatchers(\"/q\").anyRequest().authenticated());\n" +
      "    http.formLogin(l -> l.permitAll());\n    return http.build();\n  }\n" +
      "  public SecurityFilterChain other(HttpSecurity http) {\n    http.securityMatcher(SCOPE).authorizeHttpRequests(a -> a.anyRequest().permitAll());\n    return http.build();\n  }\n" +
      "  public SecurityFilterChain third(HttpSecurity http) {\n    http.securityMatchers(m -> m.requestMatchers(\"/m/**\").antMatchers(\"/n\")).authorizeHttpRequests(a -> a.anyRequest().denyAll());\n    return http.build();\n  }\n" +
      "  public SecurityFilterChain fourth(HttpSecurity http) {\n    http.antMatcher(\"/legacy/**\").authorizeRequests().anyRequest().authenticated();\n    return http.build();\n  }\n" +
      "  public SecurityFilterChain fifth(HttpSecurity http) {\n    http.securityMatchers().requestMatchers(\"/api/**\");\n    http.authorizeHttpRequests(a -> a.anyRequest().permitAll());\n    return http.build();\n  }\n" +
      "  public SecurityFilterChain sixth(HttpSecurity http) {\n    http.requestMatchers().antMatchers(\"/old/**\").and().authorizeRequests().anyRequest().permitAll();\n    return http.build();\n  }\n" +
      "  public SecurityFilterChain seventh(HttpSecurity http) {\n    http.securityMatcher(antMatcher(HttpMethod.GET, \"/g/**\")).authorizeHttpRequests(a -> a.anyRequest().permitAll());\n    return http.build();\n  }\n}\n"
  );
  assert.equal(x.security_chains.length, 7);
  const scopes = (c) => [c.scope, c.scope_unknown];
  assert.deepEqual(scopes(x.security_chains[0]), [[{ http_method: null, patterns: ["/api/**", "/v2/**"] }], false]);
  // the `/q` matcher is chained into anyRequest(), not a rule call: unknown
  assert.deepEqual(ruleRows(x.security_chains[0]), [[4, null, null, "unauthenticated"], [4, null, null, "authenticated"], [4, "POST", ["/**"], "unknown"], [4, null, ["/q"], "unknown"], [4, null, ["/**"], "authenticated"]]);
  // a non-literal scope: unread, not unscoped
  assert.deepEqual([scopes(x.security_chains[1]), ruleRows(x.security_chains[1])], [[null, true], [[9, null, ["/**"], "unauthenticated"]]]);
  assert.deepEqual([scopes(x.security_chains[2]), ruleRows(x.security_chains[2])], [[[{ http_method: null, patterns: ["/m/**"] }, { http_method: null, patterns: ["/n"] }], false], [[13, null, ["/**"], "authenticated"]]]);
  assert.deepEqual([scopes(x.security_chains[3]), ruleRows(x.security_chains[3])], [[[{ http_method: null, patterns: ["/legacy/**"] }], false], [[17, null, ["/**"], "authenticated"]]]);
  // the zero-argument openers (Spring 6 securityMatchers(), Spring 5 requestMatchers()) leave the scope unread
  assert.deepEqual([scopes(x.security_chains[4]), ruleRows(x.security_chains[4])], [[null, true], [[22, null, ["/**"], "unauthenticated"]]]);
  assert.deepEqual([scopes(x.security_chains[5]), ruleRows(x.security_chains[5])], [[null, true], [[26, null, ["/**"], "unauthenticated"]]]);
  // a factory with a verb scopes by verb too
  assert.deepEqual(scopes(x.security_chains[6]), [[{ http_method: "GET", patterns: ["/g/**"] }], false]);
  assert.deepEqual(x.not_extracted, ["security(non-literal matcher)"]);
  // a regex scope is not an Ant pattern: unread
  const regex = await extract("class Sec {\n  public SecurityFilterChain a(HttpSecurity http) {\n    http.regexMatcher(\"/api/.*\").authorizeHttpRequests(a -> a.anyRequest().authenticated());\n    return http.build();\n  }\n}\n");
  assert.deepEqual(scopes(regex.security_chains[0]), [null, true]);
});

test("security chains: web.ignoring() literal matchers (WebSecurityCustomizer or configure(WebSecurity)) are a scoped chain permitting exactly them, verb kept; a non-literal ignore is only noted", async () => {
  const x = await extract(
    "class Sec {\n  @Bean public WebSecurityCustomizer ignore() { return web -> web.ignoring().requestMatchers(\"/css/**\", \"/js/**\").requestMatchers(HttpMethod.GET, \"/open\"); }\n" +
      "  public void configure(WebSecurity web) { web.ignoring().antMatchers(\"/static/**\"); }\n" +
      "  public WebSecurityCustomizer dyn() { return web -> web.ignoring().requestMatchers(STATIC); }\n" +
      "  public WebSecurityCustomizer rx() { return web -> web.ignoring().regexMatchers(\"/api/.*\"); }\n}\n"
  );
  assert.deepEqual(x.security_chains.map((c) => [c.line, c.scope, c.scope_unknown, ruleRows(c)]), [
    [2, [{ http_method: null, patterns: ["/css/**", "/js/**"] }, { http_method: "GET", patterns: ["/open"] }], false, [[2, null, ["/css/**", "/js/**"], "unauthenticated"], [2, "GET", ["/open"], "unauthenticated"]]],
    [3, [{ http_method: null, patterns: ["/static/**"] }], false, [[3, null, ["/static/**"], "unauthenticated"]]]
  ]);
  assert.deepEqual(x.not_extracted, ["security(non-literal matcher)"]);
});

test("servlet routes: @WebServlet value / urlPatterns / plain literal ⇒ one route per handler method at the method, framework servlet", async () => {
  const x = await extract(
    "@WebServlet(value = \"/cmdi-00/BenchmarkTest00001\")\npublic class BenchmarkTest00001 extends HttpServlet {\n" +
      "  @Override public void doGet(HttpServletRequest request, HttpServletResponse response) { doPost(request, response); }\n" +
      "  @Override public void doPost(HttpServletRequest request, HttpServletResponse response) { }\n" +
      "  private void helper() { }\n}\n" +
      "@WebServlet(urlPatterns = {\"/a\", \"/b\"}, name = \"two\")\nclass Two extends HttpServlet {\n  protected void service(HttpServletRequest q, HttpServletResponse r) { }\n}\n" +
      "@WebServlet(\"/plain\")\nclass Plain extends HttpServlet {\n  protected void doDelete(HttpServletRequest q, HttpServletResponse r) { }\n}\n" +
      "@WebServlet(name = \"n\")\nclass NoPath extends HttpServlet {\n  protected void doGet(HttpServletRequest q, HttpServletResponse r) { }\n}\n" +
      "@WebServlet(PATTERN)\nclass Dyn extends HttpServlet {\n  protected void doGet(HttpServletRequest q, HttpServletResponse r) { }\n}\n"
  );
  assert.deepEqual(routeRows(x), [
    ["GET", "/cmdi-00/BenchmarkTest00001", "BenchmarkTest00001.doGet", [], "servlet"],
    ["POST", "/cmdi-00/BenchmarkTest00001", "BenchmarkTest00001.doPost", [], "servlet"],
    ["ANY", "/a", "Two.service", [], "servlet"],
    ["DELETE", "/plain", "Plain.doDelete", [], "servlet"]
  ]);
  assert.deepEqual(x.routes.map((r) => r.line), [3, 4, 9, 13]);
  assert.deepEqual(x.not_extracted, ["route(multiple servlet patterns)", "route(non-literal path)"]);
});

test("servlet routes: @ServletSecurity / @RolesAllowed on the class then the method are middleware texts; a @WebFilter or Filter class is noted servlet(filter)", async () => {
  const x = await extract(
    "@WebServlet(\"/admin\")\n@ServletSecurity(@HttpConstraint(rolesAllowed = \"admin\"))\nclass S extends HttpServlet {\n" +
      "  @RolesAllowed(\"admin\") protected void doGet(HttpServletRequest q, HttpServletResponse r) { }\n  protected void doPost(HttpServletRequest q, HttpServletResponse r) { }\n}\n"
  );
  assert.deepEqual(routeRows(x), [["GET", "/admin", "S.doGet", ["ServletSecurity", "RolesAllowed"], "servlet"], ["POST", "/admin", "S.doPost", ["ServletSecurity"], "servlet"]]);
  assert.deepEqual(x.not_extracted, []);
  const filtered = await extract("@WebFilter(\"/*\")\nclass AuthFilter implements Filter {\n  public void doFilter(ServletRequest q, ServletResponse r, FilterChain c) { }\n}\nclass Plain implements javax.servlet.Filter { }\n");
  assert.deepEqual(filtered.not_extracted, ["servlet(filter)"]);
  const subclassed = await extract("class Auth extends jakarta.servlet.http.HttpFilter {\n  protected void doFilter(HttpServletRequest q, HttpServletResponse r, FilterChain c) { }\n}\n");
  assert.deepEqual(subclassed.not_extracted, ["servlet(filter)"]);
  const none = await extract("class K { void m() { } }\n");
  assert.deepEqual(none.not_extracted, []);
});

test("calls: super.m() carries the enclosing class's superclass and resolves exact to its method", async () => {
  const { files, results } = await resolveSources({
    "A.java": "class A {\n  void m() { }\n}\n",
    "B.java": "class B extends A {\n  void n() { super.m(); }\n  Runnable r = new Runnable() { public void run() { super.toString(); } };\n}\n"
  });
  assert.deepEqual(files[1].extract.calls.map((c) => [c.callee_text, c.receiver, c.receiver_class]), [["super.m", null, "A"], ["super.toString", null, null]]);
  assert.deepEqual(results.filter((r) => r.callee_text === "super.m").map((r) => [r.to?.qualified_name ?? null, r.confidence]), [["A.m", "exact"]]);
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

test("classes: extends is the superclass base name; implements is extracted; nested types listed by simple name", async () => {
  const x = await extract(
    "public class K<T> extends base.Base<T> implements I, J {\n  void m() {}\n  void m(int a) {}\n  static class Nested extends K<String> { void n() {} }\n}\n" +
      "interface I { void i(); }\nenum E { A; void e() {} }\nrecord R(int x) { void r() {} }\n"
  );
  assert.deepEqual(
    x.classes.map((c) => [c.name, c.extends, c.methods]),
    [["K", "Base", ["m"]], ["Nested", "K", ["n"]], ["I", null, ["i"]], ["E", null, ["e"]], ["R", null, ["r"]]]
  );
  assert.equal(x.classes[0].start_byte, 0);
  assert.deepEqual(x.classes[0].implements, ["I", "J"]); // C1b: extracted, no longer noted
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

// ---- class-scope barriers, nested exports, multiple paths ---------------------------------------

test("a nested class body is a barrier: code in an anonymous / local class initializer has no enclosing method", async () => {
  const x = await extract(
    "class Outer {\n  void put(String a, String b) {}\n  void exec() {}\n" +
      "  void m() {\n    java.util.Map<String, String> h = new java.util.HashMap<>() {{ put(\"a\", \"b\"); }};\n" +
      "    class Local { Runnable r = () -> exec(); }\n  }\n}\nclass Other { void exec() {} }\n"
  );
  const lambda = x.functions.find((f) => f.kind === "lambda");
  const local = x.classes.find((c) => c.name === "Local");
  assert.deepEqual([lambda.qualified_name, lambda.class, lambda.class_start_byte], ["Local.<anon>@6:32", null, local.start_byte]);
  assert.deepEqual(x.calls.map((c) => [c.callee_text, c.enclosing_start_byte]), [["put", null], ["exec", lambda.start_byte]]);
  const { results } = await resolveSources({
    "Outer.java": "class Outer {\n  void exec() {}\n  void m() {\n    class Local { Runnable r = () -> exec(); }\n    Runnable s = () -> exec();\n  }\n}\nclass Other { void exec() {} }\n"
  });
  // the local class's lambda never climbs to Outer; the method's own lambda does
  assert.deepEqual(results.map((r) => [r.line, r.to?.qualified_name ?? null, r.confidence]), [[4, null, "unresolved"], [5, "Outer.exec", "exact"]]);
});

test("exported: a public member of a non-public nested type is not exported", async () => {
  const x = await extract("public class A {\n  private static class P { public void m() {} }\n  public static class Q { public void n() {} }\n  static class R { public void o() {} }\n}\n");
  assert.deepEqual(x.functions.map((f) => [f.qualified_name, f.exported]), [["P.m", false], ["Q.n", true], ["R.o", false]]);
});

test("Spring: several literal paths ⇒ one route per path, each at its literal; several class prefixes ⇒ the first, noted", async () => {
  const text = "@RequestMapping(\"/api\")\nclass K {\n  @GetMapping({\"/a\", \"/b\"}) @Secured(\"X\") public void a() {}\n  @RequestMapping(value = {\"/c\"}, method = RequestMethod.POST) public void c() {}\n}\n" +
    "@RequestMapping({\"/p\", \"/q\"})\nclass M {\n  @GetMapping(\"/x\") public void x() {}\n}\n";
  const x = await extract(text);
  assert.deepEqual(routeRows(x), [
    ["GET", "/api/a", "K.a", ["Secured"], "spring"],
    ["GET", "/api/b", "K.a", ["Secured"], "spring"],
    ["POST", "/api/c", "K.c", [], "spring"],
    ["GET", "/p/x", "M.x", [], "spring"]
  ]);
  assert.deepEqual(x.routes.slice(0, 3).map((r) => r.start_byte), [text.indexOf("\"/a\""), text.indexOf("\"/b\""), text.indexOf("@RequestMapping(value")]);
  assert.deepEqual(x.not_extracted, ["route(multiple class prefixes)"]);
});

// ---- through build-graph ------------------------------------------------------------------------

// Resolve the calls of in-memory Java sources ({ path: text }) with the Java module.
async function resolveSources(sources) {
  const files = [];
  for (const [path, text] of Object.entries(sources)) files.push({ path, langId: "java", stack: "java", extract: await extract(text, { path }) });
  const langModules = new Map([["java", javaModule]]);
  const importMap = resolveImports(files, { langModules, filePaths: new Set(Object.keys(sources)), configs: {} });
  return { files, results: resolveCalls(files, importMap, { classIndex: buildClassIndex(files, importMap), langModules }) };
}

test("arity: param_count / arg_count, varargs ⇒ null", async () => {
  const x = await extractFixture("service/UserService.java");
  assert.deepEqual(x.functions.map((f) => [f.qualified_name, f.param_count]), [["UserService.run", 1], ["UserService.exec", 1], ["UserService.run", 2], ["UserService.run.r", 0]]);
  assert.deepEqual(x.calls.map((c) => [c.callee_text, c.arg_count]), [["exec", 1], ["Runtime.getRuntime", 0], ["Runtime.getRuntime.exec", 1], ["exec", 1], ["r.run", 0]]);
  const y = await extract("record R(int a, int b) {\n  R { }\n  void v(String f, Object... rest) { m(a, /* c */ b); }\n  Fn g = (p, q) -> p;\n  Fn h = p -> p;\n}\n");
  assert.deepEqual(y.functions.map((f) => [f.qualified_name, f.param_count]), [["R.R", 2], ["R.v", null], ["R.<anon>@4:10", 2], ["R.<anon>@5:10", 1]]);
  assert.deepEqual(y.calls.map((c) => c.arg_count), [2]);
});

test("arity: run(cmd) and run(cmd, 3) resolve exact to their own overloads; a lambda's bare call acts for its method's class", async () => {
  const { results } = await resolveSources({
    "K.java": "class K {\n  void run(String c) { }\n  void run(String c, int n) { }\n  void go(String cmd) {\n    run(cmd, 3);\n    this.run(cmd);\n    Runnable r = () -> run(cmd);\n  }\n}\n"
  });
  assert.deepEqual(
    results.map((r) => [r.line, r.callee_text, r.to?.start_byte ?? null, r.confidence]),
    [[5, "run", 37, "exact"], [6, "this.run", 12, "exact"], [7, "run", 12, "exact"]]
  );
});

test("the java fixture through build-graph: route auth, implicit-this override grading, sinks in their methods", async () => {
  const dir = realpathSync(FIXTURE_DIR);
  const { graph, reason } = await buildGraph({ projectDir: dir, scopeRealpath: dir, stacks: ["java"], frameworks: ["spring"], referencesDir: REFERENCES_DIR });
  assert.ok(graph, reason);
  const routes = graph.nodes.filter((n) => n.type === "route").map((r) => [r.http_method, r.path_pattern, r.auth]);
  // SecurityConfig's rules: /api/health permitAll, POST /di/** hasRole, anyRequest authenticated; /api/run by its marker
  assert.deepEqual(routes.sort(), [["GET", "/api/health", "unauthenticated"], ["POST", "/api/run", "authenticated"], ["POST", "/di/run", "authenticated"]]);
  const fn = (file, qn) => graph.nodes.filter((n) => n.type === "function" && n.file === `${SRC}/${file}` && n.qualified_name === qn);
  const [run1, run2] = fn("service/UserService.java", "UserService.run").sort((a, b) => a.line_start - b.line_start);
  assert.ok(run1 && run2 && run1.id !== run2.id, "two UserService.run overloads with distinct ids");
  const exec = fn("service/UserService.java", "UserService.exec")[0];
  const lambda = fn("service/UserService.java", "UserService.run.r")[0];
  const calls = graph.edges.filter((e) => e.type === "calls");
  const bareExec = calls.find((e) => e.from === run1.id && e.callee_text === "exec");
  assert.deepEqual([bareExec.to, bareExec.confidence], [exec.id, "name-only"]); // AdminService overrides exec
  const lambdaExec = calls.find((e) => e.from === lambda.id && e.callee_text === "exec");
  assert.deepEqual([lambdaExec.to, lambdaExec.confidence], [exec.id, "name-only"]); // the lambda acts for UserService
  const svcRun = calls.find((e) => e.from === fn("Api.java", "Api.run")[0].id && e.callee_text === "userService.run");
  assert.deepEqual([svcRun.to, svcRun.confidence], [run1.id, "exact"]); // the 1-parameter overload of the concrete class
  // C1b: an @Autowired interface field resolves through the DI hint to its one implementation, name-only
  const diRun = calls.find((e) => e.from === fn("di/DiApi.java", "DiApi.run")[0].id && e.callee_text === "userService.run");
  assert.deepEqual([diRun.to, diRun.confidence], [fn("di/DiApi.java", "UserServiceImpl.run")[0].id, "name-only"]);
  const cmd = graph.nodes.find((n) => n.type === "sink" && n.class === "cmd-exec" && n.file === `${SRC}/service/UserService.java`);
  assert.equal(cmd.enclosing_fn, exec.id);
  const sql = graph.nodes.find((n) => n.type === "sink" && n.class === "sql");
  assert.deepEqual([sql.callee, sql.enclosing_fn], ["st.execute", fn("Dao.java", "Dao.find")[0].id]);
  // the chain's rules were read: no file-level hint is left
  assert.deepEqual(graph.stats.coverage_matrix.java.not_extracted, []);
  const imports = graph.edges.filter((e) => e.type === "imports" && e.specifier === "com.ex.service.UserService");
  assert.deepEqual(imports.map((e) => e.confidence), ["exact"]);
});

// ---- C1b: implements and bodiless ------------------------------------------------------------------

test("C1b: classes carry implements (class implements list, interface extends list); interface / abstract methods are bodiless", async () => {
  const x = await extract(
    "public class K extends Base implements I, pkg.J<String> {\n  void m() {}\n}\n" +
      "interface I extends L, M { void i(); default void d() {} }\n" +
      "abstract class A implements I { abstract void a(); void b() {} }\nenum E implements I { X; public void i() {} }\nrecord R(int x) implements I { public void i() {} }\n"
  );
  assert.deepEqual(x.classes.map((c) => [c.name, c.extends, c.implements]), [
    ["K", "Base", ["I", "J"]], ["I", null, ["L", "M"]], ["A", null, ["I"]], ["E", null, ["I"]], ["R", null, ["I"]]
  ]);
  const bodiless = Object.fromEntries(x.functions.map((f) => [f.qualified_name, f.bodiless === true]));
  assert.deepEqual(bodiless, { "K.m": false, "I.i": true, "I.d": false, "A.a": true, "A.b": false, "E.i": false, "R.i": false });
  assert.equal(x.not_extracted.includes("implements clause"), false);
});
