import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadResolutionConfigs, resolveImports, buildClassIndex, resolveCalls } from "../../graph/resolve.mjs";

// Small in-memory Extracts (no parsing). A stub language module resolves a specifier through a
// plain lookup table, so each test states exactly which imports resolve and where.

function fn(name, start, cls = null) {
  return {
    name, qualified_name: cls ? `${cls}.${name}` : name, line_start: 1, line_end: 1,
    start_byte: start, end_byte: start + 10, kind: cls ? "method" : "function", exported: false, class: cls
  };
}

function call(callee, start, { enc = null, receiver = null, receiverClass = null, scope = [] } = {}) {
  return { line: 1, start_byte: start, callee_text: callee, enclosing_start_byte: enc, receiver, receiver_class: receiverClass, scope_names: scope };
}

function file(path, parts = {}) {
  return { path, langId: "stub", stack: "node", extract: { functions: [], calls: [], imports: [], exports: [], classes: [], namespace: null, ...parts } };
}

const named = (specifier, ...names) => ({ line: 1, specifier, bindings: names.map((n) => (Array.isArray(n) ? { imported: n[0], local: n[1] } : { imported: n, local: n })), local: null });
const whole = (specifier, form, local) => ({ line: 1, specifier, bindings: form, local });
const cls = (name, start, methods, ext = null) => ({ name, extends: ext, methods, start_byte: start });

function stubModule(table, seen = [], lang = { id: "stub", implicitThisCalls: false }) {
  return {
    lang,
    resolveImportSpecifier(args) {
      seen.push(args);
      const hit = table[args.specifier];
      return hit ? (typeof hit === "string" ? { path: hit, confidence: "exact" } : hit) : null;
    }
  };
}

function resolveAll(files, table = {}, lang = undefined) {
  const langModules = new Map([["stub", stubModule(table, [], lang)]]);
  const filePaths = new Set(files.map((f) => f.path));
  const importMap = resolveImports(files, { langModules, filePaths, configs: {} });
  const classIndex = buildClassIndex(files, importMap);
  return resolveCalls(files, importMap, { classIndex, langModules });
}

const only = (results, path, start) => {
  const hits = results.filter((r) => r.from_path === path && r.start_byte === start);
  assert.equal(hits.length, 1);
  return hits[0];
};

// ---- rule 1: same file ---------------------------------------------------------------------------

test("rule 1: a same-file top-level foo() is exact", () => {
  const a = file("a.js", { functions: [fn("foo", 0), fn("main", 20)], calls: [call("foo", 25, { enc: 20 })] });
  const r = only(resolveAll([a]), "a.js", 25);
  assert.deepEqual(r, {
    from_fn_start_byte: 20, from_path: "a.js", line: 1, start_byte: 25, callee_text: "foo",
    to: { path: "a.js", qualified_name: "foo", start_byte: 0 }, confidence: "exact"
  });
});

test("rule 1: the same name shadowed by a parameter is unresolved, callee_text kept", () => {
  const a = file("a.js", { functions: [fn("foo", 0), fn("main", 20)], calls: [call("foo", 25, { enc: 20, scope: ["foo"] })] });
  const r = only(resolveAll([a]), "a.js", 25);
  assert.equal(r.confidence, "unresolved");
  assert.equal(r.to, null);
  assert.equal(r.callee_text, "foo");
});

// A bare foo() inside a method of K, where K defines foo (and AdminK overrides it on request).
function implicitThisFile(path, { override = false, importFoo = false } = {}) {
  const classes = [cls("K", 0, ["run", "foo"])];
  const functions = [fn("run", 10, "K"), fn("foo", 40, "K")];
  if (override) {
    classes.push(cls("AdminK", 100, ["foo"], "K"));
    functions.push(fn("foo", 110, "AdminK"));
  }
  return file(path, { classes, functions, imports: importFoo ? [named("./b", "foo")] : [], calls: [call("foo", 15, { enc: 10 })] });
}
const IMPLICIT_THIS = { id: "stub", implicitThisCalls: true };
const bFoo = () => file("b.x", { functions: [fn("foo", 5)], exports: [{ name: "foo", start_byte: 5 }] });

test("implicit this: a bare foo() in a method of K is exact to K.foo when the language declares implicitThisCalls", () => {
  const r = only(resolveAll([implicitThisFile("a.java")], {}, IMPLICIT_THIS), "a.java", 15);
  assert.equal(r.confidence, "exact");
  assert.deepEqual(r.to, { path: "a.java", qualified_name: "K.foo", start_byte: 40 });
  const viaImport = only(resolveAll([implicitThisFile("a.java", { importFoo: true }), bFoo()], { "./b": "b.x" }, IMPLICIT_THIS), "a.java", 15);
  assert.equal(viaImport.to.qualified_name, "K.foo", "the same-class step runs before rule 2");
});

test("implicit this: a subclass overriding foo downgrades the bare call to name-only", () => {
  const r = only(resolveAll([implicitThisFile("a.java", { override: true })], {}, IMPLICIT_THIS), "a.java", 15);
  assert.equal(r.confidence, "name-only");
  assert.deepEqual(r.to, { path: "a.java", qualified_name: "K.foo", start_byte: 40 });
});

test("no implicit this (flag false, or no language module): a bare foo() never targets a method", () => {
  const flagged = only(resolveAll([implicitThisFile("a.js")]), "a.js", 15);
  assert.deepEqual([flagged.to, flagged.confidence], [null, "unresolved"]);
  const orphan = { ...implicitThisFile("a.js"), langId: "no-such-module" };
  const bare = only(resolveAll([orphan]), "a.js", 15);
  assert.deepEqual([bare.to, bare.confidence], [null, "unresolved"]);
  const viaImport = only(resolveAll([implicitThisFile("a.js", { importFoo: true }), bFoo()], { "./b": "b.x" }), "a.js", 15);
  assert.equal(viaImport.confidence, "exact", "falls through to rule 2");
  assert.deepEqual(viaImport.to, { path: "b.x", qualified_name: "foo", start_byte: 5 });
});

test("a call whose enclosing_start_byte matches no function is treated as module level", () => {
  const a = file("a.js", { functions: [fn("foo", 0)], calls: [call("foo", 50, { enc: 999 })] });
  const r = only(resolveAll([a]), "a.js", 50);
  assert.equal(r.from_fn_start_byte, null);
  assert.equal(r.confidence, "exact");
  assert.equal(r.to.qualified_name, "foo");
});

// ---- rule 2: imports -----------------------------------------------------------------------------

test("rule 2: import {x} from './b' + x() is exact to b's export x", () => {
  const a = file("a.js", { imports: [named("./b", "x")], calls: [call("x", 30)] });
  const b = file("b.js", { functions: [fn("x", 5)], exports: [{ name: "x", start_byte: 0 }] });
  const r = only(resolveAll([a, b], { "./b": "b.js" }), "a.js", 30);
  assert.equal(r.confidence, "exact");
  assert.deepEqual(r.to, { path: "b.js", qualified_name: "x", start_byte: 5 });
});

test("rule 2: an import that resolves to a file without that export is unresolved", () => {
  const a = file("a.js", { imports: [named("./b", "x")], calls: [call("x", 30)] });
  const b = file("b.js", { functions: [fn("x", 5)], exports: [{ name: "y", start_byte: 0 }] });
  const r = only(resolveAll([a, b], { "./b": "b.js" }), "a.js", 30);
  assert.equal(r.confidence, "unresolved");
  assert.equal(r.to, null);
});

test("rule 2: a renamed binding {x as y} + y() resolves the imported name", () => {
  const a = file("a.js", { imports: [named("./b", ["x", "y"])], calls: [call("y", 30)] });
  const b = file("b.js", { functions: [fn("x", 5)], exports: [{ name: "x", start_byte: 5 }] });
  assert.deepEqual(only(resolveAll([a, b], { "./b": "b.js" }), "a.js", 30).to, { path: "b.js", qualified_name: "x", start_byte: 5 });
});

test("rule 2: a default import binding resolves to the function anchored at the default export's offset", () => {
  const a = file("a.js", { imports: [whole("./b", "default", "run")], calls: [call("run", 30)] });
  const b = file("b.js", { functions: [fn("helper", 0), fn("main", 40)], exports: [{ name: "default", start_byte: 40 }] });
  const r = only(resolveAll([a, b], { "./b": "b.js" }), "a.js", 30);
  assert.equal(r.confidence, "exact");
  assert.deepEqual(r.to, { path: "b.js", qualified_name: "main", start_byte: 40 });
});

test("rule 2: a local shadowing an import is unresolved", () => {
  const a = file("a.js", { functions: [fn("main", 0)], imports: [named("./b", "x")], calls: [call("x", 30, { enc: 0, scope: ["x"] })] });
  const b = file("b.js", { functions: [fn("x", 5)], exports: [{ name: "x", start_byte: 5 }] });
  assert.equal(only(resolveAll([a, b], { "./b": "b.js" }), "a.js", 30).confidence, "unresolved");
});

test("rule 2: an import resolved only heuristically yields name-only, not exact", () => {
  const a = file("a.js", { imports: [named("lib/b", "x")], calls: [call("x", 30)] });
  const b = file("lib/b.js", { functions: [fn("x", 5)], exports: [{ name: "x", start_byte: 5 }] });
  const r = only(resolveAll([a, b], { "lib/b": { path: "lib/b.js", confidence: "heuristic" } }), "a.js", 30);
  assert.equal(r.confidence, "name-only");
  assert.equal(r.to.path, "lib/b.js");
});

test("rule 2: a binding from an unresolved (external) import never falls back to a unique homonym", () => {
  const a = file("a.js", { imports: [named("child_process", "exec")], calls: [call("exec", 30)] });
  const b = file("b.js", { functions: [fn("exec", 5)] });
  const r = only(resolveAll([a, b]), "a.js", 30);
  assert.equal(r.confidence, "unresolved");
  assert.equal(r.to, null);
});

test("rule 2: ns.foo through a namespace import is exact to the target's export foo", () => {
  const a = file("a.js", { imports: [whole("./b", "namespace", "ns")], calls: [call("ns.foo", 30), call("ns.bar", 40), call("ns.foo.x", 50)] });
  const b = file("b.js", { functions: [fn("foo", 5), fn("bar", 20)], exports: [{ name: "foo", start_byte: 5 }] });
  const results = resolveAll([a, b], { "./b": "b.js" });
  assert.deepEqual(only(results, "a.js", 30), {
    from_fn_start_byte: null, from_path: "a.js", line: 1, start_byte: 30, callee_text: "ns.foo",
    to: { path: "b.js", qualified_name: "foo", start_byte: 5 }, confidence: "exact"
  });
  assert.equal(only(results, "a.js", 40).confidence, "unresolved", "bar is not exported");
  assert.equal(only(results, "a.js", 50).confidence, "unresolved", "three segments");
});

test("rule 2: X.m through a named class import is exact to the class's method", () => {
  const a = file("a.js", { imports: [named("./b", "Util")], calls: [call("Util.make", 30)] });
  const b = file("b.js", { classes: [cls("Util", 0, ["make"])], functions: [fn("make", 10, "Util")], exports: [{ name: "Util", start_byte: 0 }] });
  const r = only(resolveAll([a, b], { "./b": "b.js" }), "a.js", 30);
  assert.equal(r.confidence, "exact");
  assert.deepEqual(r.to, { path: "b.js", qualified_name: "Util.make", start_byte: 10 });
});

test("any other dotted callee is unresolved with callee_text kept", () => {
  const a = file("a.js", { functions: [fn("query", 0)], calls: [call("db.query", 30)] });
  const r = only(resolveAll([a]), "a.js", 30);
  assert.deepEqual([r.to, r.confidence, r.callee_text], [null, "unresolved", "db.query"]);
});

// ---- rule 3: this.m ------------------------------------------------------------------------------

function userService(withAdminOverride) {
  const classes = [cls("UserService", 0, ["run", "exec"])];
  const functions = [fn("run", 10, "UserService"), fn("exec", 60, "UserService")];
  if (withAdminOverride) {
    classes.push(cls("AdminService", 100, ["exec"], "UserService"));
    functions.push(fn("exec", 140, "AdminService"));
  }
  return file("services/userService.js", {
    classes, functions,
    calls: [call("this.exec", 20, { enc: 10, receiver: "this" })],
    exports: [{ name: "UserService", start_byte: 0 }]
  });
}

test("rule 3: this.exec() with no subclass override is exact", () => {
  const r = only(resolveAll([userService(false)]), "services/userService.js", 20);
  assert.equal(r.confidence, "exact");
  assert.deepEqual(r.to, { path: "services/userService.js", qualified_name: "UserService.exec", start_byte: 60 });
});

test("rule 3: AdminService extends UserService overriding exec downgrades this.exec() to name-only", () => {
  const r = only(resolveAll([userService(true)]), "services/userService.js", 20);
  assert.equal(r.confidence, "name-only");
  assert.deepEqual(r.to, { path: "services/userService.js", qualified_name: "UserService.exec", start_byte: 60 });
});

test("rule 3: an override two levels down (grandchild class) also downgrades to name-only", () => {
  const a = file("a.js", {
    classes: [cls("A", 0, ["run", "m"]), cls("B", 100, [], "A"), cls("C", 200, ["m"], "B")],
    functions: [fn("run", 10, "A"), fn("m", 50, "A"), fn("m", 210, "C")],
    calls: [call("this.m", 20, { enc: 10, receiver: "this" })]
  });
  assert.equal(only(resolveAll([a]), "a.js", 20).confidence, "name-only");
});

test("rule 3: a method defined on the parent class (in another file) is exact to the parent's method", () => {
  const base = file("base.js", { classes: [cls("Base", 0, ["save"])], functions: [fn("save", 10, "Base")], exports: [{ name: "Base", start_byte: 0 }] });
  const child = file("child.js", {
    imports: [named("./base", "Base")],
    classes: [cls("Child", 0, ["run"], "Base")],
    functions: [fn("run", 10, "Child")],
    calls: [call("this.save", 20, { enc: 10, receiver: "this" }), call("this.missing", 30, { enc: 10, receiver: "this" })]
  });
  const results = resolveAll([base, child], { "./base": "base.js" });
  const r = only(results, "child.js", 20);
  assert.equal(r.confidence, "exact");
  assert.deepEqual(r.to, { path: "base.js", qualified_name: "Base.save", start_byte: 10 });
  assert.equal(only(results, "child.js", 30).confidence, "unresolved");
});

test("rule 3: this.m() outside any class is unresolved", () => {
  const a = file("a.js", { functions: [fn("m", 0), fn("f", 20)], calls: [call("this.m", 25, { enc: 20, receiver: "this" })] });
  assert.equal(only(resolveAll([a]), "a.js", 25).confidence, "unresolved");
});

// ---- rule 1b: receiver_class ---------------------------------------------------------------------

function routesFile() {
  return file("routes/users.js", {
    imports: [named("../services/userService", "UserService")],
    functions: [fn("handler", 0)],
    calls: [call("svc.run", 30, { enc: 0, receiverClass: "UserService", scope: ["svc"] })]
  });
}

function serviceWithRunOverride(override) {
  const classes = [cls("UserService", 0, ["run"])];
  const functions = [fn("run", 10, "UserService")];
  if (override) {
    classes.push(cls("AdminService", 100, ["run"], "UserService"));
    functions.push(fn("run", 110, "AdminService"));
  }
  return file("services/userService.js", { classes, functions, exports: [{ name: "UserService", start_byte: 0 }] });
}

test("rule 1b: receiver_class bound through an import resolves to that class's method (exact)", () => {
  const r = only(resolveAll([routesFile(), serviceWithRunOverride(false)], { "../services/userService": "services/userService.js" }), "routes/users.js", 30);
  assert.equal(r.confidence, "exact");
  assert.equal(r.from_fn_start_byte, 0);
  assert.deepEqual(r.to, { path: "services/userService.js", qualified_name: "UserService.run", start_byte: 10 });
});

test("rule 1b: a subclass overriding the method downgrades to name-only", () => {
  const r = only(resolveAll([routesFile(), serviceWithRunOverride(true)], { "../services/userService": "services/userService.js" }), "routes/users.js", 30);
  assert.equal(r.confidence, "name-only");
  assert.deepEqual(r.to, { path: "services/userService.js", qualified_name: "UserService.run", start_byte: 10 });
});

test("rule 1b: receiver_class naming a class defined in two files (no import) is unresolved", () => {
  const a = file("a.js", { calls: [call("svc.run", 30, { receiverClass: "Svc" })] });
  const b = file("b.js", { classes: [cls("Svc", 0, ["run"])], functions: [fn("run", 10, "Svc")] });
  const c = file("c.js", { classes: [cls("Svc", 0, ["run"])], functions: [fn("run", 10, "Svc")] });
  const r = only(resolveAll([a, b, c]), "a.js", 30);
  assert.deepEqual([r.to, r.confidence], [null, "unresolved"]);
});

test("rule 1b: a class unique across parsed files resolves by name; the method on its parent resolves too", () => {
  const a = file("a.js", { calls: [call("svc.run", 30, { receiverClass: "Svc" }), call("svc.nope", 40, { receiverClass: "Svc" })] });
  const b = file("b.js", {
    classes: [cls("Base", 0, ["run"]), cls("Svc", 50, [], "Base")],
    functions: [fn("run", 10, "Base")]
  });
  const results = resolveAll([a, b]);
  assert.deepEqual(only(results, "a.js", 30).to, { path: "b.js", qualified_name: "Base.run", start_byte: 10 });
  assert.equal(only(results, "a.js", 30).confidence, "exact");
  assert.equal(only(results, "a.js", 40).confidence, "unresolved");
});

test("rule 1b: a default-imported class resolves at the default export's offset", () => {
  const a = file("a.js", { imports: [whole("./b", "default", "Repo")], calls: [call("r.find", 30, { receiverClass: "Repo" })] });
  const b = file("b.js", { classes: [cls("Other", 0, ["find"]), cls("UserRepo", 60, ["find"])], functions: [fn("find", 10, "Other"), fn("find", 70, "UserRepo")], exports: [{ name: "default", start_byte: 60 }] });
  assert.deepEqual(only(resolveAll([a, b], { "./b": "b.js" }), "a.js", 30).to, { path: "b.js", qualified_name: "UserRepo.find", start_byte: 70 });
});

// ---- rules 4 and 5 -------------------------------------------------------------------------------

test("rule 4: a bare helper() defined once in another file, with no import, is name-only", () => {
  const a = file("a.js", { calls: [call("helper", 30)] });
  const b = file("b.js", { functions: [fn("helper", 5)] });
  const r = only(resolveAll([a, b]), "a.js", 30);
  assert.equal(r.confidence, "name-only");
  assert.deepEqual(r.to, { path: "b.js", qualified_name: "helper", start_byte: 5 });
});

test("rule 5: a bare helper() defined in two other files is unresolved", () => {
  const a = file("a.js", { calls: [call("helper", 30)] });
  const b = file("b.js", { functions: [fn("helper", 5)] });
  const c = file("c.js", { functions: [fn("helper", 5)] });
  const r = only(resolveAll([a, b, c]), "a.js", 30);
  assert.deepEqual([r.to, r.confidence], [null, "unresolved"]);
});

test("resolveCalls output is ordered by (from_path, start_byte) whatever the input order", () => {
  const z = file("z.js", { functions: [fn("f", 0)], calls: [call("f", 50), call("f", 20)] });
  const a = file("a.js", { calls: [call("g", 9)] });
  const order = resolveAll([z, a]).map((r) => `${r.from_path}@${r.start_byte}`);
  assert.deepEqual(order, ["a.js@9", "z.js@20", "z.js@50"]);
});

// ---- resolveImports ------------------------------------------------------------------------------

test("resolveImports keys by fromPath\\0specifier, passes namespaces through, drops unresolvable targets", () => {
  const seen = [];
  const a = file("a.php", { namespace: "App\\Http", imports: [named("App\\Models\\User", "User"), named("./gone", "x"), named("ext", "y")] });
  const b = file("b.php", { namespace: "App\\Models" });
  const langModules = new Map([["stub", stubModule({ "App\\Models\\User": "b.php", "./gone": "gone.php" }, seen)]]);
  const filePaths = new Set(["a.php", "b.php"]);
  const configs = { tsconfig: null };
  const map = resolveImports([a, b], { langModules, filePaths, configs });
  assert.deepEqual([...map.entries()], [["a.php\u0000App\\Models\\User", { path: "b.php", confidence: "exact" }]]);
  assert.equal(seen.length, 3);
  for (const args of seen) {
    assert.equal(args.fromPath, "a.php");
    assert.equal(args.filePaths, filePaths);
    assert.equal(args.configs, configs);
    assert.ok(args.namespaces instanceof Map);
    assert.deepEqual([...args.namespaces.entries()], [["a.php", "App\\Http"], ["b.php", "App\\Models"]]);
  }
});

// ---- loadResolutionConfigs -----------------------------------------------------------------------

function tempDir(t) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-resolve-")));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test("loadResolutionConfigs: a JSONC tsconfig (comment + trailing comma) is one error, still read, never thrown", (t) => {
  const dir = tempDir(t);
  writeFileSync(join(dir, "tsconfig.json"), '{\n  // comment\n  "compilerOptions": { "baseUrl": "." },\n}\n');
  const configs = loadResolutionConfigs(dir, dir);
  assert.equal(configs.errors.length, 1);
  assert.equal(configs.errors[0].file, "tsconfig.json");
  assert.equal(configs.read.length, 1);
  assert.equal(configs.tsconfig, null);
});

test("loadResolutionConfigs: a valid tsconfig + a JSONC package.json gives one error and two read entries", (t) => {
  const dir = tempDir(t);
  writeFileSync(join(dir, "tsconfig.json"), '{ "compilerOptions": { "baseUrl": "src" } }\n');
  writeFileSync(join(dir, "package.json"), '{ "name": "x", }\n');
  const configs = loadResolutionConfigs(dir, dir);
  assert.deepEqual(configs.tsconfig, { compilerOptions: { baseUrl: "src" } });
  assert.equal(configs.packageJson, null);
  assert.equal(configs.jsconfig, null);
  assert.equal(configs.composerJson, null);
  assert.equal(configs.pyproject, null);
  assert.deepEqual(configs.errors.map((e) => e.file), ["package.json"]);
  assert.deepEqual(configs.read.map((r) => r.path), ["tsconfig.json", "package.json"]);
  for (const r of configs.read) assert.match(r.sha256, /^[0-9a-f]{64}$/);
});

test("loadResolutionConfigs: scope files win over project files, both are read; toml/cfg stay raw text", (t) => {
  const dir = tempDir(t);
  mkdirSync(join(dir, "app"));
  writeFileSync(join(dir, "tsconfig.json"), '{ "compilerOptions": { "baseUrl": "." } }');
  writeFileSync(join(dir, "app", "tsconfig.json"), '{ "compilerOptions": { "baseUrl": "lib" } }');
  writeFileSync(join(dir, "app", "pyproject.toml"), "[tool.x]\nname = 'x'\n");
  writeFileSync(join(dir, "setup.cfg"), "[metadata]\nname = x\n");
  const configs = loadResolutionConfigs(dir, join(dir, "app"));
  assert.equal(configs.tsconfig.compilerOptions.baseUrl, "lib");
  assert.equal(configs.pyproject, "[tool.x]\nname = 'x'\n");
  assert.equal(configs.setupCfg, "[metadata]\nname = x\n");
  assert.deepEqual(configs.read.map((r) => r.path).sort(), ["app/pyproject.toml", "app/tsconfig.json", "setup.cfg", "tsconfig.json"]);
  assert.deepEqual(configs.errors, []);
});
