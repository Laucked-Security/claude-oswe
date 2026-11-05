// Import and call resolution for the SP10 application graph (spec §1.4), language-independent.
// It consumes the per-file Extracts the language modules emit (see lang/javascript.mjs) and decides,
// with graded confidence, which parsed function each call targets:
//   exact      a demonstrated binding: a same-file definition, an import resolved (exactly) to a
//              file whose export names the function, `this.m()` / a receiver of a known class whose
//              method no subclass overrides;
//   name-only  a candidate, not a proof: the method is overridden in a subclass, the import was
//              resolved heuristically, or the bare name is defined exactly once across all files;
//   unresolved `to: null` — shadowed names, unresolved imports, homonyms, any other dotted callee.
//
// Input records are `{ path, langId, stack, extract }` with repo-relative forward-slash paths.
//   loadResolutionConfigs(projectDir, scopeRealpath) -> { tsconfig, jsconfig, packageJson,
//     composerJson, pyproject, setupCfg, read: [{ path, sha256 }], errors: [{ file, message }] }
//   resolveImports(files, { langModules, filePaths, configs })
//     -> Map<"<fromPath>\0<specifier>", { path, confidence }>   (unresolvable specifiers absent)
//   buildClassIndex(files, importMap) -> { byName: Map<name, [{ path, name, extends, methods,
//     start_byte }]>, parentOf: Map<"<path>\0<start_byte>", { entry, confidence } | null> }
//   resolveCalls(files, importMap, { classIndex }) -> [{ from_fn_start_byte, from_path, line,
//     start_byte, callee_text, to: { path, qualified_name, start_byte } | null, confidence }]
//     ordered by (from_path, start_byte).
//
// Config files are read through confinePath: a config symlink escaping the project is an error,
// never read. JSON configs use plain JSON.parse, so a JSONC file (comments, trailing commas) lands
// in `errors`; it is still listed in `read` so the cache key covers it.
import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { confinePath } from "../confine-path.mjs";

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
  ["setup.cfg", "setupCfg", "text"]
];

// null when the file does not exist; otherwise { sha256?, value? , error? }.
function readConfig(root, rel, format) {
  let real;
  try {
    real = confinePath(root, rel);
  } catch (e) {
    return e.code === "ENOENT" ? null : { error: e.message };
  }
  let bytes;
  try {
    bytes = readFileSync(real);
  } catch (e) {
    return { error: e.message };
  }
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const text = bytes.toString("utf8");
  if (format === "text") return { sha256, value: text };
  try {
    return { sha256, value: JSON.parse(text.replace(/^﻿/, "")) };
  } catch (e) {
    return { sha256, error: e.message };
  }
}

export function loadResolutionConfigs(projectDir, scopeRealpath) {
  const root = realpathSync(resolve(projectDir));
  const scope = scopeRealpath ? resolve(scopeRealpath) : root;
  const dirs = scope === root ? [root] : [root, scope];
  const result = { tsconfig: null, jsconfig: null, packageJson: null, composerJson: null, pyproject: null, setupCfg: null, read: [], errors: [] };
  for (const [name, key, format] of CONFIG_FILES) {
    // Project first, then scope: a scope file that parses overrides the project's value.
    for (const dir of dirs) {
      const rel = relative(root, join(dir, name)).split(sep).join("/");
      const loaded = readConfig(root, rel, format);
      if (!loaded) continue;
      if (loaded.sha256) result.read.push({ path: rel, sha256: loaded.sha256 });
      if (loaded.error !== undefined) result.errors.push({ file: rel, message: loaded.error });
      else result[key] = loaded.value;
    }
  }
  return result;
}

// ---- import resolution ----------------------------------------------------------------------------

const importKey = (fromPath, specifier) => `${fromPath}\u0000${specifier}`;

export function resolveImports(files, { langModules, filePaths, configs }) {
  const sorted = byPath(files);
  const namespaces = new Map(sorted.map((f) => [f.path, f.extract.namespace ?? null]));
  const importMap = new Map();
  for (const file of sorted) {
    const mod = langModules.get(file.langId);
    if (typeof mod?.resolveImportSpecifier !== "function") continue;
    const asked = new Set();
    for (const { specifier } of file.extract.imports) {
      if (asked.has(specifier)) continue;
      asked.add(specifier);
      const hit = mod.resolveImportSpecifier({ specifier, fromPath: file.path, filePaths, configs, namespaces });
      if (hit && filePaths.has(hit.path)) importMap.set(importKey(file.path, specifier), { path: hit.path, confidence: hit.confidence });
    }
  }
  return importMap;
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
  return { extracts: new Map(files.map((f) => [f.path, f.extract])), importMap, classIndex };
}

const functionsIn = (ctx, path) => ctx.extracts.get(path)?.functions ?? [];
const isTopLevel = (f) => f.class == null && f.qualified_name === f.name;
const defaultExport = (ctx, path) => (ctx.extracts.get(path)?.exports ?? []).find((e) => e.name === "default") ?? null;
const unique = (list) => (list.length === 1 ? list[0] : null);

// The single top-level function `name` of a file, provided the file exports that name.
function exportedFunction(ctx, path, name) {
  if (!(ctx.extracts.get(path)?.exports ?? []).some((e) => e.name === name)) return null;
  return unique(functionsIn(ctx, path).filter((f) => isTopLevel(f) && f.name === name));
}

function defaultExportFunction(ctx, path) {
  const entry = defaultExport(ctx, path);
  return entry ? functionsIn(ctx, path).find((f) => f.class == null && f.start_byte === entry.start_byte) ?? null : null;
}

const target = (path, fn, confidence) => ({ to: { path, qualified_name: fn.qualified_name, start_byte: fn.start_byte }, confidence });

// ---- class index ----------------------------------------------------------------------------------

const classKey = (entry) => `${entry.path}\u0000${entry.start_byte}`;
const classesIn = (ctx, path, name) => (ctx.classIndex.byName.get(name) ?? []).filter((e) => e.path === path);

function defaultExportClass(ctx, path) {
  const entry = defaultExport(ctx, path);
  if (!entry) return null;
  return [...ctx.classIndex.byName.values()].flat().find((e) => e.path === path && e.start_byte === entry.start_byte) ?? null;
}

// Class `name` as seen from `fromPath` (rule 1b): same file, else the file's import binding, else
// the unique class of that name across parsed files. -> { entry, confidence } | null.
function lookupClass(name, fromPath, ctx) {
  const local = classesIn(ctx, fromPath, name);
  if (local.length) return local.length === 1 ? { entry: local[0], confidence: "exact" } : null;
  const binding = importBinding(ctx.extracts.get(fromPath), name);
  if (binding) {
    const resolved = ctx.importMap.get(importKey(fromPath, binding.specifier));
    if (!resolved) return null;
    const entry = binding.form === "default"
      ? defaultExportClass(ctx, resolved.path)
      : unique(classesIn(ctx, resolved.path, binding.form === "namespace" ? name : binding.imported));
    return entry ? { entry, confidence: weaker("exact", resolved.confidence) } : null;
  }
  const all = ctx.classIndex.byName.get(name) ?? [];
  return all.length === 1 ? { entry: all[0], confidence: "exact" } : null;
}

export function buildClassIndex(files, importMap) {
  const byName = new Map();
  for (const file of byPath(files)) {
    const classes = [...file.extract.classes].sort((a, b) => a.start_byte - b.start_byte);
    for (const c of classes) {
      if (!byName.has(c.name)) byName.set(c.name, []);
      byName.get(c.name).push({ path: file.path, name: c.name, extends: c.extends, methods: c.methods, start_byte: c.start_byte });
    }
  }
  const classIndex = { byName, parentOf: new Map() };
  const ctx = context(files, importMap, classIndex);
  for (const entries of byName.values()) {
    for (const entry of entries) {
      const parent = entry.extends == null ? null : lookupClass(entry.extends, entry.path, ctx);
      classIndex.parentOf.set(classKey(entry), parent && parent.entry !== entry ? parent : null);
    }
  }
  return classIndex;
}

// Method `method` on the class, or (up to maxDepth hops) on its `extends` chain.
function findMethod(ref, method, ctx, maxDepth) {
  let current = ref;
  for (let depth = 0; current && depth <= maxDepth; depth++) {
    const { entry } = current;
    const methods = functionsIn(ctx, entry.path).filter((f) => f.class === entry.name && f.name === method);
    if (methods.length) return methods.length === 1 ? { path: entry.path, fn: methods[0], confidence: current.confidence } : null;
    const parent = ctx.classIndex.parentOf.get(classKey(entry));
    current = parent && { entry: parent.entry, confidence: weaker(current.confidence, parent.confidence) };
  }
  return null;
}

// Rule 3's override check: does any parsed class extending `className` (directly or through
// intermediate subclasses) redefine `method`? Matched by name, conservatively.
function isOverridden(className, method, byName) {
  const seen = new Set([className]);
  let frontier = new Set(seen);
  for (let depth = 0; frontier.size && depth < MAX_EXTENDS_DEPTH; depth++) {
    const next = new Set();
    for (const entries of byName.values()) {
      for (const e of entries) {
        if (!frontier.has(e.extends)) continue;
        if (e.methods.includes(method)) return true;
        if (!seen.has(e.name)) { seen.add(e.name); next.add(e.name); }
      }
    }
    frontier = next;
  }
  return false;
}

function methodTarget(ref, method, ctx, maxDepth = MAX_EXTENDS_DEPTH) {
  if (!ref) return null;
  const found = findMethod(ref, method, ctx, maxDepth);
  if (!found) return null;
  return target(found.path, found.fn, isOverridden(ref.entry.name, method, ctx.classIndex.byName) ? "name-only" : found.confidence);
}

// ---- call resolution ------------------------------------------------------------------------------

function sameFileClass(ctx, path, name) {
  const entry = unique(classesIn(ctx, path, name));
  return entry ? { entry, confidence: "exact" } : null;
}

// Rule 2 for a bare callee bound by an import.
function importedFunction(fromPath, binding, ctx) {
  const resolved = ctx.importMap.get(importKey(fromPath, binding.specifier));
  if (!resolved) return null;
  const fn = binding.form === "named" ? exportedFunction(ctx, resolved.path, binding.imported) : defaultExportFunction(ctx, resolved.path);
  return fn ? target(resolved.path, fn, weaker("exact", resolved.confidence)) : null;
}

// Rules 1, 2, 4 for a bare identifier callee (already known not to be shadowed).
function resolveBare(site, name, ctx) {
  const local = functionsIn(ctx, site.path).filter((f) => isTopLevel(f) && f.name === name);
  if (local.length) return local.length === 1 ? target(site.path, local[0], "exact") : null;
  const ownClass = site.enclosing?.class;
  if (ownClass) {
    const member = methodTarget(sameFileClass(ctx, site.path, ownClass), name, ctx, 0);
    if (member) return member;
  }
  const binding = importBinding(ctx.extracts.get(site.path), name);
  if (binding) return importedFunction(site.path, binding, ctx);
  const definitions = ctx.definitionsByName.get(name) ?? [];
  return definitions.length === 1 ? target(definitions[0].path, definitions[0].fn, "name-only") : null;
}

// Rule 2 for `ns.foo` / `X.m` whose head is an import binding.
function resolveImportMember(site, segments, ctx) {
  if (segments.length !== 2) return null;
  const [head, member] = segments;
  const binding = importBinding(ctx.extracts.get(site.path), head);
  if (!binding) return null;
  const resolved = ctx.importMap.get(importKey(site.path, binding.specifier));
  if (!resolved) return null;
  const confidence = weaker("exact", resolved.confidence);
  if (binding.form === "named") {
    const entry = unique(classesIn(ctx, resolved.path, binding.imported));
    return methodTarget(entry && { entry, confidence }, member, ctx);
  }
  const fn = exportedFunction(ctx, resolved.path, member);
  return fn ? target(resolved.path, fn, confidence) : null;
}

function resolveCall(site, ctx) {
  const { call } = site;
  const segments = call.callee_text.split(".");
  const last = segments[segments.length - 1];
  if (call.receiver === "this") {
    const ownClass = site.enclosing?.class;
    return ownClass ? methodTarget(sameFileClass(ctx, site.path, ownClass), last, ctx) : null;
  }
  if (call.receiver_class != null) return methodTarget(lookupClass(call.receiver_class, site.path, ctx), last, ctx);
  if (call.scope_names.includes(segments[0])) return null;
  return segments.length === 1 ? resolveBare(site, last, ctx) : resolveImportMember(site, segments, ctx);
}

// Rule 4's universe: top-level functions and methods across all files, by bare name.
function definitionsByName(files) {
  const index = new Map();
  for (const file of byPath(files)) {
    for (const fn of file.extract.functions) {
      if (fn.class == null && !isTopLevel(fn)) continue; // nested and anonymous functions
      if (!index.has(fn.name)) index.set(fn.name, []);
      index.get(fn.name).push({ path: file.path, fn });
    }
  }
  return index;
}

export function resolveCalls(files, importMap, { classIndex }) {
  const ctx = { ...context(files, importMap, classIndex), definitionsByName: definitionsByName(files) };
  const results = [];
  for (const file of byPath(files)) {
    const byStart = new Map();
    for (const fn of file.extract.functions) if (!byStart.has(fn.start_byte)) byStart.set(fn.start_byte, fn);
    for (const call of file.extract.calls) {
      const enclosing = call.enclosing_start_byte == null ? null : byStart.get(call.enclosing_start_byte) ?? null;
      const hit = resolveCall({ path: file.path, call, enclosing }, ctx);
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
