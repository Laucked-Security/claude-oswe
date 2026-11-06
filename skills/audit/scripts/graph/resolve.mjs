// Import and call resolution for the SP10 application graph (spec §1.4), language-independent.
// It consumes the per-file Extracts the language modules emit (see lang/javascript.mjs) and decides,
// with graded confidence, which parsed function each call targets:
//   exact      a demonstrated binding: a same-file definition (top-level, or nested in the call's
//              enclosing function or one enclosing it — a `const f = () => {}` / `function f() {}` /
//              `def f():` helper that the extractor marked `binds_name` (its name is bound in the
//              scope enclosing it: a nested declaration, or an anonymous function / arrow / lambda
//              named by the local or assignment initialising it — never an object-literal method or
//              a named function expression), the innermost such definition winning), an import
//              resolved (exactly) to a file whose export names the function, `this.m()` / a receiver
//              of a known class whose method no subclass overrides;
//   name-only  a candidate, not a proof: the method is overridden in a subclass, the import was
//              resolved heuristically, the bare name is defined exactly once across all files, or
//              (overloads, below) no definition is the only one matching the call's arity;
//   unresolved `to: null` — shadowed names, unresolved imports, homonyms across files or classes,
//              any other dotted callee.
// Interface / abstract dispatch (functions[] `bodiless: true`, classes[] `implements`): a target that
// is bodiless is never exact — it resolves name-only to the implementation hint (the first, by
// (path, start_byte), of the subclasses / implementors of its class defining the method with a body)
// or, without one, to the bodiless method; a class whose `implements` names the target class counts
// for the override check like a subclass.
// In a language declaring `lang.overloads`, same-named definitions in one file / class are overloads
// told apart by arity: the single definition whose `param_count` equals the call's `arg_count`
// (both non-null) is the target; elsewhere a second definition is a redefinition (unresolved). A call
// inside a lambda / arrow acts for the class of the innermost method containing it (lexical
// `this`), never across a class body.
//
// Input records are `{ path, langId, stack, extract }` with repo-relative forward-slash paths.
//   loadResolutionConfigs(projectDir, scopeRealpath) -> { tsconfig, jsconfig, packageJson,
//     composerJson, pyproject, setupCfg, pomXml, buildGradle, buildGradleKts, webXml (text, for
//     build-graph's Java auth hints), read: [{ path, sha256 }], errors: [{ file, message }] }
//     with message one of CONFIG_ERRORS: "invalid JSON" | "unreadable" | "escapes project" (never
//     repo content, never an absolute path).
//   resolveImports(files, { langModules, filePaths, configs })   (one resolveImportSpecifier call per
//     distinct module importCacheKey; Java / C# / PHP index filePaths once per Set, common.mjs)
//     -> Map<"<fromPath>\0<specifier>", { path, confidence }>   (unresolvable specifiers absent)
//     plus, for a language declaring `lang.submoduleImports: true` (Python: `from pkg import sub` may
//     name the module pkg.sub), "<fromPath>\0<specifier>\0<imported>" entries for each named binding
//     whose target does not export `imported` (or does not resolve) while the submodule specifier
//     resolves; such a binding then acts as a namespace binding to that module.
//   buildClassIndex(files, importMap) -> { byName: Map<name, [{ path, name, extends, implements, methods,
//     start_byte }]>, byKey: Map<"<path>\0<start_byte>", entry>, parentOf: Map<key, { entry,
//     confidence } | null>, childrenOf: Map<key, entry[]>, danglingByName: Map<name, entry[]> }
//   resolveCalls(files, importMap, { classIndex, langModules }) -> [{ from_fn_start_byte,
//     from_path, line, start_byte, callee_text, to: { path, qualified_name, start_byte } | null,
//     confidence }] ordered by (from_path, start_byte).
//     A bare call may target a method only in a file whose language module declares
//     `lang.implicitThisCalls: true` (Java, C#: a bare `foo()` in a method can mean `this.foo()`);
//     otherwise (JS, Python, PHP, or no module / flag) it only ever targets a top-level function.
//
// Config files are read through confinePath: a config symlink escaping the project is an error,
// never read. JSON configs use plain JSON.parse, so a JSONC file (comments, trailing commas) lands
// in `errors`; it is still listed in `read` so the cache key covers it.
import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { confinePath } from "../confine-path.mjs";
import { lastSegment } from "./text.mjs";

const MAX_EXTENDS_DEPTH = 10;

const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const byPath = (files) => [...files].sort((a, b) => compare(a.path, b.path));
const weaker = (a, b) => (a === "exact" && b === "exact" ? "exact" : "name-only");

// ---- configs --------------------------------------------------------------------------------------

const CONFIG_FILES = [
  ["tsconfig.json", "tsconfig", "json"],
  ["jsconfig.json", "jsconfig", "json"],
  ["package.json", "packageJson", "json"],
  ["composer.json", "composerJson", "json"],
  ["pyproject.toml", "pyproject", "text"],
  ["setup.cfg", "setupCfg", "text"],
  // Java auth hints (build-graph.mjs springSecurity): the build file names Spring Security, the
  // servlet deployment descriptor (its conventional locations) declares a security constraint
  ["pom.xml", "pomXml", "text"],
  ["build.gradle", "buildGradle", "text"],
  ["build.gradle.kts", "buildGradleKts", "text"],
  ["src/main/webapp/WEB-INF/web.xml", "webXml", "text"],
  ["WebContent/WEB-INF/web.xml", "webXml", "text"],
  ["web/WEB-INF/web.xml", "webXml", "text"],
  ["WEB-INF/web.xml", "webXml", "text"]
];

// Config error messages are a fixed vocabulary: never the parser's or the OS's message, which can quote
// a fragment of the file (JSON.parse) or an absolute path (readFileSync) into stats.config_errors.
export const CONFIG_ERRORS = Object.freeze({ invalidJson: "invalid JSON", unreadable: "unreadable", escapes: "escapes project" });

// null when the file does not exist; otherwise { sha256?, value? , error? }.
function readConfig(root, rel, format) {
  let real;
  try {
    real = confinePath(root, rel);
  } catch (e) {
    return e.code === "ENOENT" ? null : { error: CONFIG_ERRORS.escapes };
  }
  let bytes;
  try {
    bytes = readFileSync(real);
  } catch {
    return { error: CONFIG_ERRORS.unreadable };
  }
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const text = bytes.toString("utf8");
  if (format === "text") return { sha256, value: text };
  try {
    return { sha256, value: JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text) }; // drop a BOM
  } catch {
    return { sha256, error: CONFIG_ERRORS.invalidJson };
  }
}

export function loadResolutionConfigs(projectDir, scopeRealpath) {
  const root = realpathSync(resolve(projectDir));
  const scope = scopeRealpath ? resolve(scopeRealpath) : root;
  const dirs = scope === root ? [root] : [root, scope];
  const result = { tsconfig: null, jsconfig: null, packageJson: null, composerJson: null, pyproject: null, setupCfg: null, pomXml: null, buildGradle: null, buildGradleKts: null, webXml: null, read: [], errors: [] };
  for (const [name, key, format] of CONFIG_FILES) {
    // Project first, then scope: a scope copy that exists overrides the project's value, even when
    // it fails to parse (the value is then null, never the project copy's).
    for (const dir of dirs) {
      const rel = relative(root, join(dir, name)).split(sep).join("/");
      const loaded = readConfig(root, rel, format);
      if (!loaded) continue;
      if (loaded.sha256) result.read.push({ path: rel, sha256: loaded.sha256 });
      if (loaded.error !== undefined) result.errors.push({ file: rel, message: loaded.error });
      result[key] = loaded.error !== undefined ? null : loaded.value;
    }
  }
  return result;
}

// ---- import resolution ----------------------------------------------------------------------------

const importKey = (fromPath, specifier) => `${fromPath}\u0000${specifier}`;

// One resolver call per distinct memo key per language module and run: a module exporting
// importCacheKey({ specifier, fromPath }) names what its result depends on (Java / C#: the specifier
// alone; JS / PHP: the importing directory too for relative / file specifiers; Python: the importing
// directory); without one, the key is (fromPath, specifier), which never shares a result.
function memoisedResolver({ filePaths, configs, namespaces }) {
  const memo = new Map(); // module -> Map<key, hit | null>
  return (mod, specifier, fromPath) => {
    if (!memo.has(mod)) memo.set(mod, new Map());
    const cache = memo.get(mod);
    const key = typeof mod.importCacheKey === "function" ? mod.importCacheKey({ specifier, fromPath }) : `${fromPath}\u0000${specifier}`;
    if (!cache.has(key)) cache.set(key, mod.resolveImportSpecifier({ specifier, fromPath, filePaths, configs, namespaces }) ?? null);
    return cache.get(key);
  };
}

export function resolveImports(files, { langModules, filePaths, configs }) {
  const sorted = byPath(files);
  const namespaces = new Map(sorted.map((f) => [f.path, f.extract.namespace ?? null]));
  const importMap = new Map();
  const resolveSpecifier = memoisedResolver({ filePaths, configs, namespaces });
  for (const file of sorted) {
    const mod = langModules.get(file.langId);
    if (typeof mod?.resolveImportSpecifier !== "function") continue;
    const asked = new Set();
    for (const { specifier } of file.extract.imports) {
      if (asked.has(specifier)) continue;
      asked.add(specifier);
      const hit = resolveSpecifier(mod, specifier, file.path);
      if (hit && filePaths.has(hit.path)) importMap.set(importKey(file.path, specifier), { path: hit.path, confidence: hit.confidence });
    }
  }
  resolveSubmodules(sorted, { langModules, filePaths, resolveSpecifier, importMap });
  return importMap;
}

const submoduleKey = (fromPath, specifier, imported) => `${fromPath}\u0000${specifier}\u0000${imported}`;
// `from . import views` -> ".views"; `from .x import views` -> ".x.views"; `from a.b import c` -> "a.b.c".
const submoduleSpecifier = (specifier, imported) => (specifier.endsWith(".") ? `${specifier}${imported}` : `${specifier}.${imported}`);

function resolveSubmodules(sorted, { langModules, filePaths, resolveSpecifier, importMap }) {
  const exportsOf = new Map(sorted.map((f) => [f.path, new Set((f.extract.exports ?? []).map((e) => e.name))]));
  for (const file of sorted) {
    const mod = langModules.get(file.langId);
    if (mod?.lang?.submoduleImports !== true || typeof mod.resolveImportSpecifier !== "function") continue;
    for (const { specifier, bindings } of file.extract.imports) {
      if (!Array.isArray(bindings)) continue;
      const target = importMap.get(importKey(file.path, specifier));
      for (const { imported } of bindings) {
        const key = submoduleKey(file.path, specifier, imported);
        if (importMap.has(key) || (target && exportsOf.get(target.path)?.has(imported))) continue;
        const hit = resolveSpecifier(mod, submoduleSpecifier(specifier, imported), file.path);
        if (hit && filePaths.has(hit.path)) importMap.set(key, { path: hit.path, confidence: hit.confidence });
      }
    }
  }
}

// The import that binds `local` in a file, as { specifier, form: named|default|namespace, imported }.
// A named `{ default as x }` binding counts as the default form.
function importBinding(extract, local) {
  for (const imp of extract?.imports ?? []) {
    if (Array.isArray(imp.bindings)) {
      const b = imp.bindings.find((x) => x.local === local);
      if (b) return { specifier: imp.specifier, form: b.imported === "default" ? "default" : "named", imported: b.imported };
    } else if (imp.local === local) {
      return { specifier: imp.specifier, form: imp.bindings, imported: null };
    }
  }
  return null;
}

// ---- shared lookups -------------------------------------------------------------------------------

function context(files, importMap, classIndex) {
  return { extracts: new Map(files.map((f) => [f.path, f.extract])), importMap, classIndex, parents: new Map() };
}

// The import binding of `local` in a file with its resolved target: { binding, resolved | null }, or
// null when no import binds it. A named binding with a resolved submodule (see resolveImports) is
// read as a namespace binding to that module.
function boundImport(ctx, fromPath, local) {
  const binding = importBinding(ctx.extracts.get(fromPath), local);
  if (!binding) return null;
  const submodule = binding.form === "named" ? ctx.importMap.get(submoduleKey(fromPath, binding.specifier, binding.imported)) : null;
  if (submodule) return { binding: { specifier: binding.specifier, form: "namespace", imported: null }, resolved: submodule };
  return { binding, resolved: ctx.importMap.get(importKey(fromPath, binding.specifier)) ?? null };
}

const functionsIn = (ctx, path) => ctx.extracts.get(path)?.functions ?? [];
const isTopLevel = (f) => f.class == null && f.qualified_name === f.name;
const defaultExport = (ctx, path) => (ctx.extracts.get(path)?.exports ?? []).find((e) => e.name === "default") ?? null;
const unique = (list) => (list.length === 1 ? list[0] : null);

// One of the same-named definitions of one file or class -> { fn, confidence, arityMismatch } (null
// for none). Without overloads (a language not declaring `lang.overloads`: a second definition is a
// redefinition) only a single definition is a target, exact. With overloads, arity decides: the
// single definition whose `param_count` equals the call's `arg_count` (both known) is exact; a lone
// definition whose known count differs is name-only (`arityMismatch`: the right overload may be
// inherited); otherwise the first by start_byte is name-only.
function pickDefinition(definitions, argCount, overloads) {
  if (!definitions.length) return null;
  const known = argCount != null && overloads;
  if (definitions.length === 1) {
    const mismatch = known && definitions[0].param_count != null && definitions[0].param_count !== argCount;
    return { fn: definitions[0], confidence: mismatch ? "name-only" : "exact", arityMismatch: mismatch };
  }
  if (!overloads) return null;
  const byArity = known ? definitions.filter((f) => f.param_count != null && f.param_count === argCount) : [];
  if (byArity.length === 1) return { fn: byArity[0], confidence: "exact", arityMismatch: false };
  return { fn: definitions.reduce((a, b) => (b.start_byte < a.start_byte ? b : a)), confidence: "name-only", arityMismatch: known };
}

// The top-level function `name` of a file (see pickDefinition), provided the file exports that name.
function exportedFunction(ctx, path, name, argCount) {
  if (!(ctx.extracts.get(path)?.exports ?? []).some((e) => e.name === name)) return null;
  return pickDefinition(functionsIn(ctx, path).filter((f) => isTopLevel(f) && f.name === name), argCount, ctx.overloads.has(path));
}

function defaultExportFunction(ctx, path) {
  const entry = defaultExport(ctx, path);
  return entry ? functionsIn(ctx, path).find((f) => f.class == null && f.start_byte === entry.start_byte) ?? null : null;
}

const target = (path, fn, confidence) => ({ to: { path, qualified_name: fn.qualified_name, start_byte: fn.start_byte }, confidence });

// ---- class index ----------------------------------------------------------------------------------

const classKey = (entry) => `${entry.path}\u0000${entry.start_byte}`;
const classesIn = (ctx, path, name) => (ctx.classIndex.byName.get(name) ?? []).filter((e) => e.path === path);

const classAt = (ctx, path, startByte) => ctx.classIndex.byKey.get(`${path}\u0000${startByte}`) ?? null;

function defaultExportClass(ctx, path) {
  const entry = defaultExport(ctx, path);
  return entry ? classAt(ctx, path, entry.start_byte) : null;
}

// The class an import binding names in its resolved target file (rule 2's export check applies):
// a named `{ imported: X }` needs an export named X — the class that export's offset anchors, else
// the single class named X; a default / namespace (CommonJS) binding is the default-export class.
function importedClass(ctx, binding, targetPath) {
  if (binding.form !== "named") return defaultExportClass(ctx, targetPath);
  const exported = (ctx.extracts.get(targetPath)?.exports ?? []).filter((e) => e.name === binding.imported);
  if (!exported.length) return null;
  for (const e of exported) {
    const anchored = classAt(ctx, targetPath, e.start_byte);
    if (anchored) return anchored;
  }
  return unique(classesIn(ctx, targetPath, binding.imported));
}

// Class `name` as seen from `fromPath` (rule 1b): same file, else the file's import binding, else
// the unique class of that name across parsed files. -> { entry, confidence } | null.
function lookupClass(name, fromPath, ctx) {
  const local = classesIn(ctx, fromPath, name);
  if (local.length) return local.length === 1 ? { entry: local[0], confidence: "exact" } : null;
  const bound = boundImport(ctx, fromPath, name);
  if (bound) {
    const { binding, resolved } = bound;
    const entry = resolved ? importedClass(ctx, binding, resolved.path) : null;
    return entry ? { entry, confidence: weaker("exact", resolved.confidence) } : null;
  }
  const all = ctx.classIndex.byName.get(name) ?? [];
  return all.length === 1 ? { entry: all[0], confidence: "exact" } : null;
}

const pushTo = (map, key, value) => (map.has(key) ? map.get(key).push(value) : map.set(key, [value]));

// byName / byKey index the classes; parentOf holds each class's resolved parent link; childrenOf
// is its reverse, plus — for the override check and the implementation hint — every class whose
// `implements` names the class; danglingByName lists the classes whose `extends` or an `implements`
// entry did not resolve, under the last dotted segment of that text (conservative).
export function buildClassIndex(files, importMap) {
  const byName = new Map();
  const byKey = new Map();
  for (const file of byPath(files)) {
    const classes = [...file.extract.classes].sort((a, b) => a.start_byte - b.start_byte);
    for (const c of classes) {
      const entry = { path: file.path, name: c.name, extends: c.extends, implements: c.implements ?? [], methods: c.methods, start_byte: c.start_byte };
      pushTo(byName, c.name, entry);
      if (!byKey.has(classKey(entry))) byKey.set(classKey(entry), entry);
    }
  }
  const classIndex = { byName, byKey, parentOf: new Map(), childrenOf: new Map(), danglingByName: new Map() };
  const ctx = context(files, importMap, classIndex);
  for (const entries of byName.values()) {
    for (const entry of entries) {
      const found = entry.extends == null ? null : lookupClass(entry.extends, entry.path, ctx);
      const parent = found && found.entry !== entry ? found : null;
      classIndex.parentOf.set(classKey(entry), parent);
      if (parent) pushTo(classIndex.childrenOf, classKey(parent.entry), entry);
      else if (entry.extends != null) pushTo(classIndex.danglingByName, lastSegment(entry.extends), entry);
      for (const name of entry.implements) {
        const iface = lookupClass(name, entry.path, ctx);
        if (iface && iface.entry !== entry) pushTo(classIndex.childrenOf, classKey(iface.entry), entry);
        else pushTo(classIndex.danglingByName, lastSegment(name), entry);
      }
    }
  }
  return classIndex;
}

// Method `method` on the class, or (up to maxDepth hops) on its `extends` chain; overloads are
// picked by arity (pickDefinition). When no definition on a class matches the call's known arity,
// the walk goes on up the chain for one that does; failing that, the first such class's pick is the
// (name-only) target.
function findMethod(ref, method, ctx, maxDepth, argCount) {
  let current = ref;
  let fallback = null;
  for (let depth = 0; current && depth <= maxDepth; depth++) {
    const { entry } = current;
    const methods = functionsIn(ctx, entry.path).filter((f) => f.class === entry.name && f.name === method);
    const picked = pickDefinition(methods, argCount, ctx.overloads.has(entry.path));
    if (methods.length && !picked) return fallback; // redefinitions: no target
    if (picked) {
      const found = { entry, path: entry.path, fn: picked.fn, confidence: weaker(current.confidence, picked.confidence) };
      if (!picked.arityMismatch) return found;
      fallback ??= found;
    }
    const parent = ctx.classIndex.parentOf.get(classKey(entry));
    current = parent && { entry: parent.entry, confidence: weaker(current.confidence, parent.confidence) };
  }
  return fallback;
}

// The subclasses of `entry` (up to 10 levels down), breadth-first: through the resolved parent links
// and `implements` entries (childrenOf), so an aliased or dotted parent name counts and an unrelated
// same-named class does not, plus a class whose `extends` / `implements` text did not resolve when its
// last dotted segment names a class on the way (conservative). `visit(sub)` returning true stops the walk.
function walkSubclasses(entry, classIndex, visit) {
  const seen = new Set([classKey(entry)]);
  let frontier = [entry];
  for (let depth = 0; frontier.length && depth < MAX_EXTENDS_DEPTH; depth++) {
    const next = [];
    for (const node of frontier) {
      const subclasses = [...(classIndex.childrenOf.get(classKey(node)) ?? []), ...(classIndex.danglingByName.get(node.name) ?? [])];
      for (const sub of subclasses) {
        if (seen.has(classKey(sub))) continue;
        if (visit(sub)) return true;
        seen.add(classKey(sub));
        next.push(sub);
      }
    }
    frontier = next;
  }
  return false;
}

// Rule 3's override check: does any subclass or implementor of `entry` redefine `method`?
const isOverridden = (entry, method, classIndex) => walkSubclasses(entry, classIndex, (sub) => sub.methods.includes(method));

// The implementation hint for a bodiless (interface / abstract) target: among the subclasses and
// implementors of the class declaring it, those defining `method` with a body (overloads picked by
// arity); the first by (path, start_byte) — one or several, the edge is name-only either way.
function implementationOf(found, method, ctx, argCount) {
  const candidates = [];
  walkSubclasses(found.entry, ctx.classIndex, (sub) => {
    const bodies = functionsIn(ctx, sub.path).filter((f) => f.class === sub.name && f.name === method && f.bodiless !== true);
    const picked = pickDefinition(bodies, argCount, ctx.overloads.has(sub.path));
    if (picked) candidates.push({ path: sub.path, fn: picked.fn });
    return false;
  });
  candidates.sort((a, b) => compare(a.path, b.path) || a.fn.start_byte - b.fn.start_byte);
  return candidates[0] ?? null;
}

// A bodiless target (an interface method, an abstract method) is never exact: dispatch picks an
// implementation at run time. It resolves to the implementation hint when there is one, else to
// the bodiless method itself, name-only in both cases.
function methodTarget(ref, method, ctx, { maxDepth = MAX_EXTENDS_DEPTH, argCount = null } = {}) {
  if (!ref) return null;
  const found = findMethod(ref, method, ctx, maxDepth, argCount);
  if (!found) return null;
  if (found.fn.bodiless === true) {
    const impl = implementationOf(found, method, ctx, argCount);
    return impl ? target(impl.path, impl.fn, "name-only") : target(found.path, found.fn, "name-only");
  }
  return target(found.path, found.fn, isOverridden(ref.entry, method, ctx.classIndex) ? "name-only" : found.confidence);
}

// ---- call resolution ------------------------------------------------------------------------------

function sameFileClass(ctx, path, name) {
  const entry = unique(classesIn(ctx, path, name));
  return entry ? { entry, confidence: "exact" } : null;
}

// Rule 2 for a bare callee bound by an import.
function importedFunction({ binding, resolved }, ctx, argCount) {
  if (!resolved) return null;
  if (binding.form === "named") {
    const picked = exportedFunction(ctx, resolved.path, binding.imported, argCount);
    return picked ? target(resolved.path, picked.fn, weaker(picked.confidence, resolved.confidence)) : null;
  }
  const fn = defaultExportFunction(ctx, resolved.path);
  return fn ? target(resolved.path, fn, weaker("exact", resolved.confidence)) : null;
}

// Rule 1 for a definition nested in a function: a `const f = () => {}` / `function f() {}` / `def f():`
// declared in the call's enclosing function or in one enclosing it (lexical scoping: the innermost
// such definition wins; two at one level are a redefinition, null). Only a function the extractor
// marked `binds_name` counts — its name is bound in the scope enclosing it — so an object-literal
// method or a named function expression (`function index() {}` passed as an argument), which bind
// nothing there, never shadow or replace the real target. The extractors keep such definitions out of
// scope_names (only parameters and value locals shadow), so a nested helper resolves like a top-level
// one. Containment is by byte range (parentsOf), within the file.
// -> target | null (nested definitions exist but are ambiguous) | undefined (none in scope).
function nestedDefinition(site, name, ctx) {
  if (!site.enclosing) return undefined;
  const named = functionsIn(ctx, site.path).filter((f) => f.binds_name === true && f.name === name && f.class == null && !isTopLevel(f));
  if (!named.length) return undefined;
  const parents = parentsIn(ctx, site.path);
  for (let scope = site.enclosing; scope; scope = parents.get(scope) ?? null) {
    const here = named.filter((f) => parents.get(f) === scope);
    if (here.length) return here.length === 1 ? target(site.path, here[0], "exact") : null;
  }
  return undefined;
}

// Rules 1, 2, 4 for a bare identifier callee (already known not to be shadowed). The same-class
// method step and methods in rule 4's count apply only to implicit-this languages.
function resolveBare(site, name, ctx) {
  const argCount = site.call.arg_count ?? null;
  const nested = nestedDefinition(site, name, ctx);
  if (nested !== undefined) return nested;
  const local = pickDefinition(functionsIn(ctx, site.path).filter((f) => isTopLevel(f) && f.name === name), argCount, ctx.overloads.has(site.path));
  if (local) return target(site.path, local.fn, local.confidence);
  if (site.implicitThis && site.ownClass) {
    const member = methodTarget(sameFileClass(ctx, site.path, site.ownClass), name, ctx, { maxDepth: 0, argCount });
    if (member) return member;
  }
  const bound = boundImport(ctx, site.path, name);
  if (bound) return importedFunction(bound, ctx, argCount);
  const definitions = (ctx.definitionsByName.get(name) ?? []).filter((d) => site.implicitThis || d.fn.class == null);
  // several definitions count as one candidate only when they are overloads in one file and class
  const [first] = definitions;
  if (!first || definitions.some((d) => d.path !== first.path || d.fn.class !== first.fn.class)) return null;
  const picked = pickDefinition(definitions.map((d) => d.fn), argCount, ctx.overloads.has(first.path));
  return picked ? target(first.path, picked.fn, "name-only") : null;
}

// Rule 2 for `ns.foo` / `X.m` whose head is an import binding: a namespace binding names the
// target's export `foo`; a named or default binding names a class (importedClass), whose method
// `m` is the target.
function resolveImportMember(site, segments, ctx) {
  if (segments.length !== 2) return null;
  const [head, member] = segments;
  const bound = boundImport(ctx, site.path, head);
  if (!bound?.resolved) return null;
  const { binding, resolved } = bound;
  const confidence = weaker("exact", resolved.confidence);
  const argCount = site.call.arg_count ?? null;
  if (binding.form === "namespace") {
    const picked = exportedFunction(ctx, resolved.path, member, argCount);
    return picked ? target(resolved.path, picked.fn, weaker(confidence, picked.confidence)) : null;
  }
  const entry = importedClass(ctx, binding, resolved.path);
  return methodTarget(entry && { entry, confidence }, member, ctx, { argCount });
}

function resolveCall(site, ctx) {
  const { call } = site;
  const segments = call.callee_text.split(".");
  const last = segments[segments.length - 1];
  const argCount = call.arg_count ?? null;
  if (call.receiver === "this") {
    return site.ownClass ? methodTarget(sameFileClass(ctx, site.path, site.ownClass), last, ctx, { argCount }) : null;
  }
  if (call.receiver_class != null) return methodTarget(lookupClass(call.receiver_class, site.path, ctx), last, ctx, { argCount });
  if (call.scope_names.includes(segments[0])) return null;
  return segments.length === 1 ? resolveBare(site, last, ctx) : resolveImportMember(site, segments, ctx);
}

// Rule 4's universe: top-level functions and methods across all files, by bare name (resolveBare
// drops the methods for a call from a language without implicit `this`). A bodiless signature
// (interface / abstract method) is not a definition: declaring an interface never turns a bare call
// into a homonym.
function definitionsByName(files) {
  const index = new Map();
  for (const file of byPath(files)) {
    for (const fn of file.extract.functions) {
      if (fn.class == null && !isTopLevel(fn)) continue; // nested and anonymous functions
      if (fn.bodiless === true) continue;
      if (!index.has(fn.name)) index.set(fn.name, []);
      index.get(fn.name).push({ path: file.path, fn });
    }
  }
  return index;
}

const LEXICAL_THIS = new Set(["lambda", "arrow"]);

// The lexical container of every function of one file: Map<fn, the innermost function strictly
// containing it by byte range | null>, from one sweep over the functions sorted by (start_byte,
// -end_byte, qualified_name) — O(F log F) and independent of the input order (two functions with one
// byte range are twins: the later one takes the first one's container, neither contains the other).
// Shared with build-graph.mjs, whose `nests` edges are exactly this relation.
export function parentsOf(functions) {
  const order = [...functions].sort((a, b) => a.start_byte - b.start_byte || b.end_byte - a.end_byte || compare(a.qualified_name, b.qualified_name));
  const parents = new Map();
  const open = []; // the containers of the current position, outermost first
  for (const fn of order) {
    while (open.length && open.at(-1).end_byte <= fn.start_byte) open.pop();
    let parent = open.at(-1) ?? null;
    if (parent && parent.start_byte === fn.start_byte && parent.end_byte === fn.end_byte) parent = parents.get(parent) ?? null;
    parents.set(fn, parent);
    open.push(fn);
  }
  return parents;
}

const parentsIn = (ctx, path) => {
  if (!ctx.parents.has(path)) ctx.parents.set(path, parentsOf(functionsIn(ctx, path)));
  return ctx.parents.get(path);
};

// The class a call's enclosing function acts for (rule 3's `this`, the implicit-this step): its own
// class, or — for a lambda / arrow, whose `this` is lexical — the class of the innermost method
// strictly containing it (by byte range, same file), walking outward through nested lambdas /
// arrows. A `function` (dynamic `this`) never inherits, and the walk never crosses a class body:
// every lambda on the way must share the starting lambda's `class_start_byte` (the classes[] entry
// of the innermost class containing it), and the method reached must belong to that class (not so
// for a lambda in a local / anonymous class's initializer).
function ownClassOf(enclosing, ctx, path) {
  if (!enclosing || enclosing.class != null || !LEXICAL_THIS.has(enclosing.kind)) return enclosing?.class ?? null;
  const classStart = enclosing.class_start_byte ?? null;
  const parents = parentsIn(ctx, path);
  let fn = enclosing;
  while (fn && fn.class == null && LEXICAL_THIS.has(fn.kind)) {
    if ((fn.class_start_byte ?? null) !== classStart) return null;
    fn = parents.get(fn) ?? null;
  }
  if (fn?.class == null || classStart == null) return null;
  return classAt(ctx, path, classStart)?.name === fn.class ? fn.class : null;
}

export function resolveCalls(files, importMap, { classIndex, langModules }) {
  // files whose language declares `lang.overloads` (Java, C#): same-named definitions are overloads
  const overloads = new Set(files.filter((f) => langModules?.get(f.langId)?.lang?.overloads === true).map((f) => f.path));
  const ctx = { ...context(files, importMap, classIndex), definitionsByName: definitionsByName(files), overloads };
  const results = [];
  for (const file of byPath(files)) {
    const implicitThis = langModules?.get(file.langId)?.lang?.implicitThisCalls === true;
    const byStart = new Map();
    for (const fn of file.extract.functions) if (!byStart.has(fn.start_byte)) byStart.set(fn.start_byte, fn);
    const ownClasses = new Map(); // enclosing start_byte -> ownClassOf(enclosing)
    for (const call of file.extract.calls) {
      const enclosing = call.enclosing_start_byte == null ? null : byStart.get(call.enclosing_start_byte) ?? null;
      if (enclosing && !ownClasses.has(enclosing.start_byte)) ownClasses.set(enclosing.start_byte, ownClassOf(enclosing, ctx, file.path));
      const ownClass = enclosing ? ownClasses.get(enclosing.start_byte) : null;
      const hit = resolveCall({ path: file.path, call, enclosing, ownClass, implicitThis }, ctx);
      results.push({
        from_fn_start_byte: enclosing ? enclosing.start_byte : null,
        from_path: file.path,
        line: call.line,
        start_byte: call.start_byte,
        callee_text: call.callee_text,
        to: hit ? hit.to : null,
        confidence: hit ? hit.confidence : "unresolved"
      });
    }
  }
  return results.sort((a, b) => compare(a.from_path, b.from_path) || a.start_byte - b.start_byte || compare(a.callee_text, b.callee_text));
}
