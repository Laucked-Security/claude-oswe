import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { normalizeToken, classifyPattern, loadSurface } from "../../graph/surface.mjs";
import { sinkClassFor, SINK_CLASS_RULES } from "../../graph/sink-classes.mjs";

const REFERENCES_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "references");
const STACKS = ["php", "node", "python", "java", "dotnet"];
const ROLES = ["sources", "sinks", "sanitizers", "auth_markers"];
const SHAPES = ["call", "member", "decorator", "chain", "key", "word", "literal"];

// ---- normalizeToken ----------------------------------------------------------------------------

test("normalizeToken removes whitespace and (), and maps :: and -> to a dot", () => {
  assert.equal(normalizeToken("Runtime.getRuntime().exec"), "Runtime.getRuntime.exec");
  assert.equal(normalizeToken("$this->authorize"), "$this.authorize");
  assert.equal(normalizeToken("Auth::check"), "Auth.check");
  assert.equal(normalizeToken("new Function"), "newFunction");
  assert.equal(normalizeToken("a . b\n.c ()"), "a.b.c");
});

// ---- classifyPattern: one assertion per shape ---------------------------------------------------

// [token, role, shape, normalized]
const CLASSIFY_CASES = [
  ["eval(", "sinks", "call", "eval"],
  [".query(", "sinks", "member", "query"],
  ["@RequestParam", "sources", "decorator", "RequestParam"],
  ["[FromBody]", "sources", "decorator", "FromBody"],
  ["#[IsGranted", "auth_markers", "decorator", "IsGranted"],
  ["$where", "sinks", "key", "$where"],
  ["$_GET", "sources", "chain", "$_GET"],
  ["req.body", "sources", "chain", "req.body"],
  ["os.system", "sinks", "call", "os.system"],
  ["Runtime.getRuntime().exec", "sinks", "call", "Runtime.getRuntime.exec"],
  ["Auth::check", "auth_markers", "chain", "Auth.check"],
  ["->middleware('auth", "auth_markers", "member", "middleware"],
  ["ProcessBuilder", "sinks", "word", "ProcessBuilder"],
  ["php://input", "sources", "literal", "php://input"],
  ["X-User-Role", "sources", "literal", "X-User-Role"]
];

for (const [token, role, shape, normalized] of CLASSIFY_CASES) {
  test(`classifyPattern(${JSON.stringify(token)}, ${role}) -> ${shape}/${normalized}`, () => {
    assert.deepEqual(classifyPattern(token, role), { raw: token, shape, normalized });
  });
}

test("classifyPattern: rule 6 splits on role (sinks/sanitizers -> call, sources/auth_markers -> chain)", () => {
  for (const role of ["sinks", "sanitizers"]) assert.equal(classifyPattern("shlex.quote", role).shape, "call");
  for (const role of ["sources", "auth_markers"]) assert.equal(classifyPattern("shlex.quote", role).shape, "chain");
  // `$`-prefixed non-key tokens and `::` / `->` chains follow the same role split.
  assert.equal(classifyPattern("DB::raw", "sinks").shape, "call");
  assert.equal(classifyPattern("DB::raw", "sinks").normalized, "DB.raw");
  assert.equal(classifyPattern("$_SERVER", "sources").shape, "chain");
  assert.equal(classifyPattern("$_SERVER", "sinks").shape, "call");
});

test("classifyPattern: a trailing ( makes a call and wins over the dotted-chain rule", () => {
  assert.deepEqual(classifyPattern("$this->authorize(", "auth_markers"),
    { raw: "$this->authorize(", shape: "call", normalized: "$this.authorize" });
  assert.deepEqual(classifyPattern("req.isAuthenticated(", "auth_markers"),
    { raw: "req.isAuthenticated(", shape: "call", normalized: "req.isAuthenticated" });
  assert.deepEqual(classifyPattern("$request->query->get(", "sources"),
    { raw: "$request->query->get(", shape: "call", normalized: "$request.query.get" });
});

test("classifyPattern: member prefixes (. and ->) are stripped; decorator prefixes and trailers too", () => {
  assert.deepEqual(classifyPattern("->query(", "sinks"), { raw: "->query(", shape: "member", normalized: "query" });
  assert.deepEqual(classifyPattern(".readObject(", "sinks"), { raw: ".readObject(", shape: "member", normalized: "readObject" });
  assert.equal(classifyPattern("@Query(", "sources").normalized, "Query");
  assert.equal(classifyPattern("[Authorize(", "auth_markers").normalized, "Authorize");
  assert.equal(classifyPattern("[Authorize]", "auth_markers").normalized, "Authorize");
});

test("classifyPattern: the literal rule only takes capitalised hyphenated headers and URL-ish tokens", () => {
  assert.equal(classifyPattern("X-Forwarded-User", "sources").shape, "literal");
  // lower-case hyphenated names are plain words, not literals
  assert.deepEqual(classifyPattern("mongo-sanitize", "sanitizers"),
    { raw: "mongo-sanitize", shape: "word", normalized: "mongo-sanitize" });
});

test("classifyPattern: normalizeToken is applied to the normalized value in every shape", () => {
  assert.equal(classifyPattern("new Function", "sinks").normalized, "newFunction");
  assert.equal(classifyPattern("Runtime.getRuntime().exec", "sources").normalized, "Runtime.getRuntime.exec");
});

test("classifyPattern rejects empty / non-string tokens and unknown roles with a TypeError", () => {
  for (const bad of ["", undefined, null, 42, {}, ["eval("]]) {
    assert.throws(() => classifyPattern(bad, "sinks"), TypeError, `token ${JSON.stringify(bad)}`);
  }
  assert.throws(() => classifyPattern("eval(", "nope"), TypeError);
  assert.throws(() => classifyPattern("eval(", undefined), TypeError);
  // a token that normalizes to nothing is as unusable as an empty one
  assert.throws(() => classifyPattern("@", "sinks"), TypeError);
  assert.throws(() => classifyPattern("   ", "sinks"), TypeError);
});

// ---- real references ---------------------------------------------------------------------------

test("every token of every real references/<stack>.md surface block classifies", () => {
  for (const stack of STACKS) {
    const surface = loadSurface(stack, REFERENCES_DIR);
    assert.ok(surface, `${stack}: reference page with a surface block`);
    for (const role of ROLES) {
      assert.ok(Array.isArray(surface[role]), `${stack}.${role} is an array`);
      for (const p of surface[role]) {
        assert.ok(SHAPES.includes(p.shape), `${stack}.${role} ${JSON.stringify(p.raw)}: shape ${p.shape}`);
        assert.equal(typeof p.normalized, "string");
        assert.ok(p.normalized.length > 0, `${stack}.${role} ${JSON.stringify(p.raw)}: normalized is non-empty`);
        assert.equal(typeof p.raw, "string");
      }
    }
    for (const role of ["sources", "sinks", "auth_markers"]) {
      assert.ok(surface[role].length > 0, `${stack}.${role} is non-empty`);
    }
  }
});

test("loadSurface classifies the real node page in block order with each token's role", () => {
  const s = loadSurface("node", REFERENCES_DIR);
  assert.deepEqual(Object.keys(s), ["sources", "sinks", "sanitizers", "auth_markers"]);
  assert.deepEqual(s.sources[0], { raw: "req.query", shape: "chain", normalized: "req.query" });
  assert.deepEqual(s.sources.find((p) => p.raw === "@Body("), { raw: "@Body(", shape: "decorator", normalized: "Body" });
  assert.deepEqual(s.sinks.find((p) => p.raw === "child_process.exec"),
    { raw: "child_process.exec", shape: "call", normalized: "child_process.exec" });
  assert.deepEqual(s.sinks.find((p) => p.raw === "$where"), { raw: "$where", shape: "key", normalized: "$where" });
  assert.deepEqual(s.sinks.find((p) => p.raw === "eval("), { raw: "eval(", shape: "call", normalized: "eval" });
  assert.deepEqual(s.sanitizers.find((p) => p.raw === "escape("), { raw: "escape(", shape: "call", normalized: "escape" });
  assert.deepEqual(s.auth_markers.find((p) => p.raw === "passport.authenticate"),
    { raw: "passport.authenticate", shape: "chain", normalized: "passport.authenticate" });
});

test("loadSurface keeps the block's original order and role split (php/java/dotnet spot checks)", () => {
  const php = loadSurface("php", REFERENCES_DIR);
  assert.deepEqual(php.sources.map((p) => p.raw).slice(0, 3), ["$_GET", "$_POST", "$_REQUEST"]);
  assert.deepEqual(php.auth_markers.find((p) => p.raw === "->middleware('auth"),
    { raw: "->middleware('auth", shape: "member", normalized: "middleware" });
  assert.deepEqual(php.auth_markers.find((p) => p.raw === "Auth::check"),
    { raw: "Auth::check", shape: "chain", normalized: "Auth.check" });
  const java = loadSurface("java", REFERENCES_DIR);
  assert.deepEqual(java.sinks.find((p) => p.raw === "Runtime.getRuntime().exec"),
    { raw: "Runtime.getRuntime().exec", shape: "call", normalized: "Runtime.getRuntime.exec" });
  assert.equal(java.sources.find((p) => p.raw === "X-User-Role").shape, "literal");
  const dotnet = loadSurface("dotnet", REFERENCES_DIR);
  assert.equal(dotnet.sources.find((p) => p.raw === "[FromBody]").normalized, "FromBody");
  assert.equal(dotnet.auth_markers.find((p) => p.raw === "[Authorize]").normalized, "Authorize");
});

test("loadSurface returns null for an invalid stack name or a missing reference page", () => {
  for (const bad of ["../../../etc/x", "a/b", "a.b", "", "PHP", "no-such-stack", undefined, null, 7]) {
    assert.equal(loadSurface(bad, REFERENCES_DIR), null, `stack ${JSON.stringify(bad)}`);
  }
});

test("loadSurface does not escape referencesDir: a traversal name never reads the planted sibling page", () => {
  const root = mkdtempSync(join(tmpdir(), "oswe-surface-graph-"));
  writeFileSync(join(root, "secret.md"), "```surface\n{ \"sources\": [\"planted\"], \"sinks\": [], \"auth_markers\": [] }\n```\n");
  const refs = join(root, "refs");
  assert.equal(loadSurface("../secret", refs), null);
});

test("loadSurface: a block without sanitizers yields [], a page without a block yields null", () => {
  const dir = mkdtempSync(join(tmpdir(), "oswe-surface-graph-"));
  writeFileSync(join(dir, "mini.md"), "# mini\n```surface\n{ \"sources\": [\"req.body\"], \"sinks\": [\"eval(\"], \"auth_markers\": [\"@Auth\"] }\n```\n");
  writeFileSync(join(dir, "bare.md"), "# no block here\n");
  const s = loadSurface("mini", dir);
  assert.deepEqual(s.sanitizers, []);
  assert.deepEqual(s.sources, [{ raw: "req.body", shape: "chain", normalized: "req.body" }]);
  assert.deepEqual(s.sinks, [{ raw: "eval(", shape: "call", normalized: "eval" }]);
  assert.deepEqual(s.auth_markers, [{ raw: "@Auth", shape: "decorator", normalized: "Auth" }]);
  assert.equal(loadSurface("bare", dir), null);
});

// ---- sink classes ------------------------------------------------------------------------------

test("sinkClassFor: the brief's anchor cases", () => {
  assert.equal(sinkClassFor("child_process.exec", "node"), "cmd-exec");
  assert.equal(sinkClassFor("pickle.loads", "python"), "deser");
  assert.equal(sinkClassFor("$ne", "node"), "nosql");
  assert.equal(sinkClassFor("exec", "python"), "eval");
  assert.equal(sinkClassFor("exec", "php"), "cmd-exec");
  assert.equal(sinkClassFor("Template", "python"), "template");
  assert.equal(sinkClassFor("raw", "python"), "sql");
  assert.equal(sinkClassFor("frobnicate", "node"), "other");
});

test("sinkClassFor: exec is the only stack-sensitive token; an unknown stack behaves like a non-python stack", () => {
  assert.equal(sinkClassFor("exec", "node"), "cmd-exec");
  assert.equal(sinkClassFor("exec", "java"), "cmd-exec");
  assert.equal(sinkClassFor("exec", "no-such-stack"), "cmd-exec");
  assert.equal(sinkClassFor("exec", undefined), "cmd-exec");
  assert.equal(sinkClassFor("eval", "python"), "eval");
  assert.equal(sinkClassFor("os.system", "python"), "cmd-exec");
  // exec is only the bare word: a longer name is not rerouted
  assert.equal(sinkClassFor("Runtime.getRuntime.exec", "java"), "cmd-exec");
});

test("sinkClassFor lower-cases its input; one case per class and a rule-order check", () => {
  const cases = [
    ["Runtime.getRuntime.exec", "java", "cmd-exec"],
    ["newFunction", "node", "eval"],
    ["MVEL.eval", "java", "eval"],
    ["ObjectInputStream", "java", "deser"],
    ["TypeNameHandling", "dotnet", "deser"],
    ["$where", "node", "nosql"],
    ["render_template_string", "python", "template"],
    ["DB.raw", "php", "sql"],
    ["Statement.execute", "java", "sql"],
    ["include", "php", "include"],
    ["require", "node", "include"],
    ["file_put_contents", "php", "file-write"],
    ["Path.Combine", "dotnet", "file-read"],
    ["res.sendFile", "node", "file-read"],
    ["axios", "node", "ssrf"],
    ["XmlDocument", "dotnet", "xxe"],
    ["setAttribute", "java", "trust-boundary"],
    ["redirect", "node", "redirect"],
    ["frobnicate", "node", "other"]
  ];
  for (const [token, stack, cls] of cases) assert.equal(sinkClassFor(token, stack), cls, `${stack} ${token}`);
  // first match wins: "nosql" ($-prefix) is evaluated before "sql"/"redirect" substrings
  assert.equal(sinkClassFor("$redirect", "node"), "nosql");
  // cmd-exec is evaluated before sql ("system" beats "query")
  assert.equal(sinkClassFor("system.query", "node"), "cmd-exec");
});

test("SINK_CLASS_RULES is a frozen ordered table ending before the 'other' default", () => {
  assert.ok(Object.isFrozen(SINK_CLASS_RULES));
  assert.deepEqual(SINK_CLASS_RULES.map((r) => r.class), [
    "cmd-exec", "eval", "deser", "nosql", "template", "sql", "include",
    "file-write", "file-read", "ssrf", "xxe", "trust-boundary", "redirect"
  ]);
  for (const r of SINK_CLASS_RULES) assert.equal(typeof r.test, "function");
});

test("every real sink token maps to a defined sink class", () => {
  const classes = new Set([...SINK_CLASS_RULES.map((r) => r.class), "other"]);
  for (const stack of STACKS) {
    for (const p of loadSurface(stack, REFERENCES_DIR).sinks) {
      const cls = sinkClassFor(p.normalized, stack);
      assert.ok(classes.has(cls), `${stack} ${p.raw} -> ${cls}`);
    }
  }
});
