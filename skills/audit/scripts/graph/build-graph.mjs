// SP10 application graph builder (spec §1, §2.1, §3.1) — zero runtime dependencies, Node >= 20.
// Walks the confined scope, parses every supported file with the vendored tree-sitter, runs the
// file's language module (lang/<module>.mjs), resolves imports / calls / route handlers through
// resolve.mjs, propagates Express mounts and global middlewares, computes route auth from the
// surface `auth_markers`, and emits a graph that validates against schemas/graph.schema.json.
// Deterministic: ids are content-derived (ids.mjs), nodes are sorted by (type, id), edges by
// (type, from, to, line, start_byte); CRLF is normalised to LF before parsing, so two builds of the
// same input — on any checkout — are byte-identical. No Date, no randomness, no absolute paths.
//
// API: buildGraph({ projectDir, scopeRealpath, stacks, frameworks, excludes, referencesDir, vendorDir })
//        -> Promise<{ graph } | { graph: null, reason }>     (throws InputError on malformed input)
//
// CLI: node graph/build-graph.mjs --file <in.json> --out <out.json> [--checkpoint-dir <abs>]
//   input:  { projectDir, scope_realpath?, stacks[], frameworks[]?, excludes[]?, referencesDir, vendorDir? }
//   output: the graph JSON, or { "graph": null, "reason": "<msg>" } when the parser cannot load or
//           the assembled graph fails schema validation (building the graph never aborts an audit).
//   exit 0 ok (graph or null envelope) / 1 malformed input (missing projectDir / stacks /
//   referencesDir, scope_realpath escaping projectDir) / 2 IO | usage.
//   --checkpoint-dir wraps the run with cache-wrap (helperName "build-graph"): the input digest
//   covers every walked file (path, walk status / skip reason, bytes), the resolution configs read,
//   the reference pages loaded, the stacks / frameworks / excludes and vendor MANIFEST.json; the
//   version digest covers every graph/**/*.mjs plus versionFiles() (vendored loader, out-of-tree
//   helpers, graph schema). A hit rewrites the cached output byte-for-byte. Only graphs are
//   stored: a { graph: null } envelope is never cached.
//
// Language modules are discovered, not registered: a file whose module (LANG_MODULE_FILE) does not
// exist yet is a `file` node with parse_status "skipped", skip_reason "no extractor".
import { existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { canonicalize, sha256Hex, dirVersionDigest, cacheLookup, cacheStore } from "../cache-wrap.mjs";
import { confinePath } from "../confine-path.mjs";
import { validate } from "../validate-output.mjs";
import { parseSource, parserAvailable, VENDOR_DIR } from "./parser.mjs";
import { walkFiles, DEFAULT_EXCLUDES } from "./walk.mjs";
import { loadSurface, normalizeToken } from "./surface.mjs";
import { matchesPattern } from "./match.mjs";
import { loadResolutionConfigs, resolveImports, buildClassIndex, resolveCalls } from "./resolve.mjs";
import { nodeId, edgeKey } from "./ids.mjs";

export const GENERATED_BY = "oswe-build-graph/1";
const GRAPH_DIR = dirname(fileURLToPath(import.meta.url));

export const LANG_MODULE_FILE = { javascript: "javascript", typescript: "javascript", tsx: "javascript", python: "python", java: "java", php: "php", c_sharp: "csharp" };
export const LANG_STACK = { javascript: "node", typescript: "node", tsx: "node", python: "python", java: "java", php: "php", c_sharp: "dotnet" };
export const FRAMEWORK_STACK = { express: "node", nest: "node", flask: "python", django: "python", fastapi: "python", spring: "java", laravel: "php", symfony: "php", aspnet: "dotnet" };

export class InputError extends Error {}

const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const sortedUnique = (list) => [...new Set(list)].sort(compare);
const fileSha256 = (abs) => {
  try {
    return createHash("sha256").update(readFileSync(abs)).digest("hex");
  } catch {
    return null;
  }
};
const pushTo = (map, key, value) => (map.has(key) ? map.get(key).push(value) : map.set(key, [value]));

// ---- stage 1: input + confinement -----------------------------------------------------------------

const isStringArray = (v) => Array.isArray(v) && v.every((x) => typeof x === "string");

function normalizeOptions(opts) {
  const { projectDir, scopeRealpath, stacks, frameworks = [], excludes, referencesDir, vendorDir, langModulesDir } = opts ?? {};
  if (typeof projectDir !== "string" || projectDir === "") throw new InputError("projectDir must be a non-empty string");
  if (!isStringArray(stacks)) throw new InputError("stacks must be an array of strings");
  if (typeof referencesDir !== "string" || referencesDir === "") throw new InputError("referencesDir must be a non-empty string");
  if (!isStringArray(frameworks)) throw new InputError("frameworks must be an array of strings");
  if (excludes !== undefined && !isStringArray(excludes)) throw new InputError("excludes must be an array of strings");
  if (scopeRealpath !== undefined && scopeRealpath !== null && typeof scopeRealpath !== "string") throw new InputError("scope_realpath must be a string");
  if (vendorDir !== undefined && typeof vendorDir !== "string") throw new InputError("vendorDir must be a string");
  if (langModulesDir !== undefined && typeof langModulesDir !== "string") throw new InputError("langModulesDir must be a string");
  let root;
  try {
    root = realpathSync(resolve(projectDir));
  } catch {
    throw new InputError(`projectDir does not exist: ${projectDir}`);
  }
  // Re-confine the scope the orchestrator handed us: an escaping scope is an orchestrator bug.
  let scope;
  try {
    scope = confinePath(root, relative(root, resolve(scopeRealpath || root)));
  } catch (e) {
    throw new InputError(e.code === "ENOENT" ? `scope_realpath does not exist: ${scopeRealpath}` : "scope_realpath escapes projectDir");
  }
  return { root, scope, stacks, frameworks, excludes: excludes ?? DEFAULT_EXCLUDES, referencesDir, vendorDir: vendorDir ?? VENDOR_DIR, langModulesDir: langModulesDir ?? LANG_MODULES_DIR };
}

// ---- stage 2: walk + read + language modules ------------------------------------------------------

// `langModulesDir` is an internal option (tests point it at an empty dir); the CLI never sets it.
const LANG_MODULES_DIR = join(GRAPH_DIR, "lang");
const moduleCache = new Map(); // module absolute path -> Promise<module | null>

function loadLangModule(dir, name) {
  const abs = join(dir, `${name}.mjs`);
  if (!moduleCache.has(abs)) {
    const promise = existsSync(abs)
      ? import(pathToFileURL(abs).href).then((m) => (typeof m.extractFile === "function" && m.lang ? m : null))
      : Promise.resolve(null);
    moduleCache.set(abs, promise);
  }
  return moduleCache.get(abs);
}

async function loadLangModules(dir, langIds) {
  const modules = new Map();
  for (const langId of sortedUnique(langIds)) {
    const mod = await loadLangModule(dir, LANG_MODULE_FILE[langId]);
    if (mod) modules.set(langId, mod);
  }
  return modules;
}

// Everything the cache key covers, gathered before any parsing.
async function prepare(opts) {
  const o = normalizeOptions(opts);
  const walked = walkFiles({ projectDir: o.root, scopeRealpath: o.scope, excludes: o.excludes });
  const langModules = await loadLangModules(o.langModulesDir, walked.map((w) => w.langId));
  const files = walked.map((w) => {
    const file = { path: w.path, langId: w.langId, stack: LANG_STACK[w.langId], status: w.status, skip_reason: w.skip_reason };
    if (w.status !== "ok") return file;
    try {
      file.bytes = readFileSync(w.abs);
    } catch {
      return { ...file, status: "skipped", skip_reason: "unreadable" };
    }
    file.sha256 = createHash("sha256").update(file.bytes).digest("hex");
    return file;
  });
  // Every walked file is in the cache key — a newly added skipped file (too large, minified,
  // out of scope) changes the graph's file nodes and stats just like a parsed one.
  const walkDigest = files.map((f) => ({ path: f.path, status: f.status, skip_reason: f.skip_reason ?? null, sha256: f.sha256 ?? null }));
  const configs = loadResolutionConfigs(o.root, o.scope);
  const referenceStacks = sortedUnique(files.filter((f) => f.status === "ok" && langModules.has(f.langId)).map((f) => f.stack));
  const references = referenceStacks.map((stack) => ({ stack, sha256: fileSha256(join(o.referencesDir, `${stack}.md`)) }));
  return { o, files, walkDigest, langModules, configs, references };
}

function inputDigest({ o, walkDigest, configs, references }) {
  return sha256Hex(canonicalize({
    files: walkDigest,
    configs: configs.read,
    references,
    stacks: o.stacks,
    frameworks: o.frameworks,
    excludes: o.excludes,
    manifest_sha256: fileSha256(join(o.vendorDir, "MANIFEST.json"))
  }));
}

// Code outside graph/ that decides the output: the vendored loader, the out-of-tree helpers graph/
// imports (surface-scan, confine-path, cache-wrap, validate-output and its generated validators),
// and the graph schema.
export function versionFiles(vendorDir) {
  const scripts = join(GRAPH_DIR, "..");
  return [
    join(vendorDir, "web-tree-sitter.mjs"),
    ...["validate-output.mjs", "validators.mjs", "confine-path.mjs", "cache-wrap.mjs", "surface-scan.mjs"].map((f) => join(scripts, f)),
    join(scripts, "..", "schemas", "graph.schema.json")
  ];
}

// PURE over its inputs: dirVersionDigest(graphDir) plus the bytes of each listed file, in order
// (a missing file contributes "missing"). Paths themselves are not hashed.
export function versionDigest(files, { graphDir = GRAPH_DIR } = {}) {
  return sha256Hex([dirVersionDigest(graphDir), ...files.map((f) => fileSha256(f) ?? "missing")].join(":"));
}

// ---- stage 3: decode + parse + extract ------------------------------------------------------------

const UTF8 = new TextDecoder("utf-8", { fatal: true });

const frameworksOf = (o, stack) => sortedUnique(o.frameworks.filter((f) => FRAMEWORK_STACK[f] === stack));

async function extractAll({ o, files, langModules }, surfaceOf) {
  for (const file of files) {
    if (file.status !== "ok") continue;
    const mod = langModules.get(file.langId);
    if (!mod) {
      Object.assign(file, { status: "skipped", skip_reason: "no extractor" });
      continue;
    }
    let text;
    let tree;
    try {
      text = UTF8.decode(file.bytes).replace(/\r\n/g, "\n");
      tree = await parseSource(file.langId, text, { vendorDir: o.vendorDir });
    } catch {
      file.status = "error";
      continue;
    }
    try {
      file.status = tree.rootNode.hasError ? "error" : "ok";
      file.extract = mod.extractFile({ tree, path: file.path, sourceText: text, frameworks: frameworksOf(o, file.stack), surface: surfaceOf(file.stack) });
      file.module = mod;
    } catch {
      file.status = "error";
      file.extract = undefined;
    } finally {
      tree.delete();
    }
  }
}

// ---- stage 4: resolution --------------------------------------------------------------------------

const importKey = (fromPath, specifier) => `${fromPath}\u0000${specifier}`;
const siteKey = (path, x) => `${path}\u0000${x}`;
const routeSiteKey = (path, startByte) => `${path}\u0001${startByte}`;
const fnRef = (path, fn) => ({ path, qualified_name: fn.qualified_name, start_byte: fn.start_byte });

// The function a route handler / middleware text names in its file: `<anon>@l:c` and `Class.method`
// texts are same-file qualified names; anything else resolves exactly like a call from module level.
// A handler text naming several same-file functions (overloaded C# / Java actions) is the one whose
// [start_byte, end_byte) contains the route (its routing attribute / annotation lies inside the
// method), stored under routeSiteKey(path, route.start_byte); when none contains it that key holds
// null and the route falls back to the text's resolution (buildRoutes notes a miss).
function resolveRouteTexts(parsed, importMap, classIndex, langModules) {
  const resolved = new Map(); // siteKey(path, text) | routeSiteKey(path, start) -> { path, qualified_name, start_byte } | null
  const pseudo = new Map(); // path -> pseudo-calls
  const bySeq = new Map(); // siteKey(path, seq) -> siteKey(path, text)
  for (const file of parsed) {
    for (const route of file.extract.routes ?? []) {
      const overloads = /[.@]/.test(route.handler_text) ? file.extract.functions.filter((f) => f.qualified_name === route.handler_text) : [];
      if (overloads.length > 1) {
        const containing = overloads.filter((f) => f.start_byte <= route.start_byte && route.start_byte < f.end_byte);
        const innermost = containing.reduce((a, f) => (a && a.start_byte > f.start_byte ? a : f), null);
        resolved.set(routeSiteKey(file.path, route.start_byte), innermost && fnRef(file.path, innermost));
      }
      for (const text of [route.handler_text, ...route.middleware_texts]) {
        const key = siteKey(file.path, text);
        if (resolved.has(key)) continue;
        const direct = /[.@]/.test(text) ? file.extract.functions.filter((f) => f.qualified_name === text) : [];
        if (direct.length === 1) {
          resolved.set(key, fnRef(file.path, direct[0]));
          continue;
        }
        resolved.set(key, null);
        const calls = pseudo.get(file.path) ?? [];
        bySeq.set(siteKey(file.path, calls.length), key);
        calls.push({ line: route.line, start_byte: calls.length, callee_text: text, enclosing_start_byte: null, receiver: null, receiver_class: null, scope_names: [] });
        pseudo.set(file.path, calls);
      }
    }
  }
  const files = parsed.map((f) => ({ ...f, extract: { ...f.extract, calls: pseudo.get(f.path) ?? [] } }));
  for (const r of resolveCalls(files, importMap, { classIndex, langModules })) resolved.set(bySeq.get(siteKey(r.from_path, r.start_byte)), r.to);
  return resolved;
}

function resolveAll(parsed, langModules, configs, filePaths) {
  const files = parsed.map((f) => ({ path: f.path, langId: f.langId, stack: f.stack, extract: f.extract }));
  const importMap = resolveImports(files, { langModules, filePaths, configs });
  const classIndex = buildClassIndex(files, importMap);
  const calls = resolveCalls(files, importMap, { classIndex, langModules });
  const routeTexts = resolveRouteTexts(files, importMap, classIndex, langModules);
  return { importMap, calls, routeTexts };
}

// ---- stage 5: routes, mounts, auth ----------------------------------------------------------------

// Mounted path: collapse `//`; the child's own trailing `/` is kept (Django `api/` + `ping/` ->
// `/api/ping/`) and none is added (`/users` + `/:id/run`); a bare child (`/`, ``) is the mount path
// as is (Express `/api` + `/` -> `/api`, Django `api/` + `` -> `/api/`).
function joinPath(prefix, own) {
  const joined = `${prefix}/${own}`.replace(/\/{2,}/g, "/");
  if (joined.length === 1) return joined;
  const bare = own.replace(/^\/+/, "") === "";
  return (bare ? prefix.endsWith("/") : own.endsWith("/")) ? joined : joined.replace(/\/$/, "");
}

// Express prefix semantics: `/` matches everything; `/a` matches `/a` and `/a/...`, never `/ab`.
const underPrefix = (prefix, path) => prefix === "/" || path === prefix || path.startsWith(prefix.endsWith("/") ? prefix : `${prefix}/`);

// The parsed file a bare text names through its file's import bindings (an Express router module).
function importedFile(file, text, importMap, extractsByPath) {
  for (const imp of file.extract.imports ?? []) {
    const binds = Array.isArray(imp.bindings) ? imp.bindings.some((b) => b.local === text) : imp.local === text;
    if (!binds) continue;
    const hit = importMap.get(importKey(file.path, imp.specifier));
    return hit && extractsByPath.has(hit.path) ? hit.path : null;
  }
  return null;
}

// Classify every `USE` entry: a function (global middleware for later routes / mounts of its file),
// a mounted router file, or neither (recorded as not_extracted "mount:<text>").
function classifyUses(parsed, resolved, importMap, notExtracted) {
  const extractsByPath = new Map(parsed.map((f) => [f.path, f.extract]));
  const globals = new Map(); // path -> [{ path_pattern, start_byte, mws: [{ file, text }] }]
  const mountOf = new Map(); // mounted path -> { file, stack, text, path_pattern, start_byte, mws }
  for (const file of parsed) {
    for (const route of file.extract.routes ?? []) {
      if (route.http_method !== "USE") continue;
      const mws = route.middleware_texts.map((text) => ({ file: file.path, text }));
      if (resolved.get(siteKey(file.path, route.handler_text))) {
        pushTo(globals, file.path, { path_pattern: route.path_pattern, start_byte: route.start_byte, mws: [...mws, { file: file.path, text: route.handler_text }] });
        continue;
      }
      const target = importedFile(file, route.handler_text, importMap, extractsByPath);
      if (target && !mountOf.has(target)) mountOf.set(target, { file: file.path, stack: file.stack, text: route.handler_text, path_pattern: route.path_pattern, start_byte: route.start_byte, mws });
      else notExtracted(file.stack).add(target ? `mount:${route.handler_text}(mounted twice)` : `mount:${route.handler_text}`);
    }
  }
  breakMountCycles(mountOf, notExtracted);
  return { globals, mountOf };
}

// Each file has at most one parent mount, so a cycle is a simple loop. Its root is the cycle's
// smallest path: the mount that targets the root (the one closing the cycle) is dropped and
// recorded in the mounting file's not_extracted as "mount:<text>(cycle)"; the root stays unprefixed.
function breakMountCycles(mountOf, notExtracted) {
  for (const start of [...mountOf.keys()].sort(compare)) {
    const chain = [];
    let current = start;
    while (mountOf.has(current) && !chain.includes(current)) {
      chain.push(current);
      current = mountOf.get(current).file;
    }
    if (!chain.includes(current)) continue;
    const root = chain.slice(chain.indexOf(current)).sort(compare)[0];
    const closing = mountOf.get(root);
    mountOf.delete(root);
    notExtracted(closing.stack).add(`mount:${closing.text}(cycle)`);
  }
}

const globalsBefore = (globals, path, startByte, pathPattern) =>
  (globals.get(path) ?? []).filter((g) => g.start_byte < startByte && underPrefix(g.path_pattern, pathPattern)).flatMap((g) => g.mws);

// The path prefix and inherited middlewares of a file, composed along its (acyclic, see
// breakMountCycles) chain of mounts.
function mountContext(path, { globals, mountOf }, memo) {
  if (memo.has(path)) return memo.get(path);
  const mount = mountOf.get(path);
  let ctx = { prefix: null, mws: [] };
  if (mount) {
    const parent = mountContext(mount.file, { globals, mountOf }, memo);
    ctx = {
      prefix: parent.prefix === null ? joinPath("", mount.path_pattern) : joinPath(parent.prefix, mount.path_pattern),
      mws: [...parent.mws, ...globalsBefore(globals, mount.file, mount.start_byte, mount.path_pattern), ...mount.mws]
    };
  }
  memo.set(path, ctx);
  return ctx;
}

const SHAPE_CATEGORY = { decorator: "decorator", call: "call", chain: "call", member: "call", word: "identifier" };

// A marker with an argument prefix (php `->middleware('auth`, see surface.mjs) matches a middleware
// name starting with it (`auth`, `auth:api`); every other marker matches by its shape.
function isAuthMarker(text, surface) {
  const candidate = { text: normalizeToken(text) };
  return (surface?.auth_markers ?? []).some((p) =>
    p.arg_prefix !== undefined ? text.startsWith(p.arg_prefix) : SHAPE_CATEGORY[p.shape] && matchesPattern(p, { ...candidate, category: SHAPE_CATEGORY[p.shape] }));
}

function routeAuth(mws, surfaceOfPath) {
  if (mws.some((m) => normalizeToken(m.text) === "AllowAnonymous")) return "unauthenticated";
  if (mws.some((m) => isAuthMarker(m.text, surfaceOfPath(m.file)))) return "authenticated";
  return mws.some((m) => !m.ref) ? "unknown" : "unauthenticated";
}

// -> [{ node, handlerRef, mws: [{ file, text, ref }] }] for every non-USE route.
function buildRoutes(parsed, resolved, importMap, surfaceOfPath, notExtracted) {
  const uses = classifyUses(parsed, resolved, importMap, notExtracted);
  const memo = new Map();
  const routes = [];
  for (const file of parsed) {
    const ctx = mountContext(file.path, uses, memo);
    for (const route of file.extract.routes ?? []) {
      if (route.http_method === "USE") continue;
      const own = route.middleware_texts.map((text) => ({ file: file.path, text }));
      const mws = [...ctx.mws, ...globalsBefore(uses.globals, file.path, route.start_byte, route.path_pattern), ...own]
        .map((m) => ({ ...m, ref: resolved.get(siteKey(m.file, m.text)) ?? null }));
      const overloadKey = routeSiteKey(file.path, route.start_byte);
      const handlerRef = resolved.get(overloadKey) ?? resolved.get(siteKey(file.path, route.handler_text)) ?? null;
      if (!handlerRef && resolved.has(overloadKey)) notExtracted(file.stack).add("route(overloaded handler)");
      routes.push({
        handlerRef,
        mws,
        node: {
          type: "route",
          id: nodeId("route", file.path, route.start_byte),
          file: file.path,
          line: route.line,
          http_method: route.http_method,
          path_pattern: ctx.prefix === null ? route.path_pattern : joinPath(ctx.prefix, route.path_pattern),
          handler: handlerRef && fnRefId(handlerRef),
          middlewares: mws.map((m) => (m.ref ? fnRefId(m.ref) : m.text)),
          framework: route.framework,
          auth: routeAuth(mws, surfaceOfPath)
        }
      });
    }
  }
  return routes;
}

// ---- stage 6: nodes, edges, stats -----------------------------------------------------------------

const fnRefId = (ref) => nodeId("function", ref.path, ref.qualified_name, ref.start_byte);

// Innermost function of the file whose [start_byte, end_byte) contains the offset (tree-sitter end
// offsets are exclusive); null at module level.
function enclosingFn(file, startByte) {
  let best = null;
  for (const fn of file.extract.functions) {
    if (fn.start_byte <= startByte && startByte < fn.end_byte && (!best || fn.start_byte > best.start_byte)) best = fn;
  }
  return best && nodeId("function", file.path, best.qualified_name, best.start_byte);
}

function fileNode(f) {
  return { type: "file", id: nodeId("file", f.path), path: f.path, stack: f.stack, lang: f.langId, parse_status: f.status, ...(f.skip_reason ? { skip_reason: f.skip_reason } : {}) };
}

function extractNodes(file) {
  const nodes = [];
  for (const fn of file.extract.functions) {
    nodes.push({
      type: "function", id: nodeId("function", file.path, fn.qualified_name, fn.start_byte), file: file.path, name: fn.name, qualified_name: fn.qualified_name,
      line_start: fn.line_start, line_end: fn.line_end, kind: fn.kind, exported: fn.exported === true, ...(fn.class != null ? { class: fn.class } : {})
    });
  }
  for (const s of file.extract.sources) {
    nodes.push({ type: "source", id: nodeId("source", file.path, s.start_byte), file: file.path, line: s.line, enclosing_fn: enclosingFn(file, s.start_byte), kind: s.kind, pattern: s.pattern });
  }
  for (const s of file.extract.sinks) {
    nodes.push({ type: "sink", id: nodeId("sink", file.path, s.start_byte), file: file.path, line: s.line, enclosing_fn: enclosingFn(file, s.start_byte), class: s.class, callee: s.callee, pattern: s.pattern });
  }
  return nodes;
}

// One `imports` edge per (from file, specifier) that resolved to a file node.
function importEdges(parsed, importMap) {
  const edges = [];
  for (const file of parsed) {
    const seen = new Set();
    for (const imp of file.extract.imports ?? []) {
      if (seen.has(imp.specifier)) continue;
      seen.add(imp.specifier);
      const hit = importMap.get(importKey(file.path, imp.specifier));
      if (!hit) continue;
      edges.push({ line: imp.line, start: null, edge: { type: "imports", from: nodeId("file", file.path), to: nodeId("file", hit.path), confidence: hit.confidence, specifier: imp.specifier } });
    }
  }
  return edges;
}

// `calls` edges for calls inside a function; module-level calls have no `from` node.
function callEdges(calls, parsed) {
  const fnAt = new Map();
  for (const file of parsed) for (const fn of file.extract.functions) if (!fnAt.has(siteKey(file.path, fn.start_byte))) fnAt.set(siteKey(file.path, fn.start_byte), fn);
  const edges = [];
  for (const c of calls) {
    const from = c.from_fn_start_byte === null ? null : fnAt.get(siteKey(c.from_path, c.from_fn_start_byte));
    if (!from) continue;
    edges.push({
      line: c.line, start: c.start_byte,
      edge: { type: "calls", from: nodeId("function", c.from_path, from.qualified_name, from.start_byte), to: c.to && fnRefId(c.to), line: c.line, callee_text: c.callee_text, confidence: c.confidence }
    });
  }
  return edges;
}

// `handles` / `uses_middleware` (order = position in `middlewares`; it also fills the key's offset slot).
function routeEdges(routes) {
  const edges = [];
  for (const { node, handlerRef, mws } of routes) {
    if (handlerRef) edges.push({ line: null, start: null, edge: { type: "handles", from: node.id, to: fnRefId(handlerRef) } });
    mws.forEach((m, order) => {
      if (m.ref) edges.push({ line: null, start: order, edge: { type: "uses_middleware", from: node.id, to: fnRefId(m.ref), order } });
    });
  }
  return edges;
}

function sortEdges(entries) {
  const unique = new Map();
  for (const e of entries) {
    const key = edgeKey(e.edge.type, e.edge.from, e.edge.to, e.line, e.start) + (e.edge.type === "imports" ? `\u0000${e.edge.specifier}` : "");
    if (!unique.has(key)) unique.set(key, e);
  }
  const num = (x) => (x === null || x === undefined ? -1 : x);
  return [...unique.values()]
    .sort((a, b) =>
      compare(a.edge.type, b.edge.type) || compare(a.edge.from, b.edge.from) || compare(a.edge.to ?? "", b.edge.to ?? "") ||
      num(a.line) - num(b.line) || num(a.start) - num(b.start) || compare(canonicalize(a.edge), canonicalize(b.edge)))
    .map((e) => e.edge);
}

function sortNodes(nodes) {
  const unique = new Map();
  for (const n of nodes) if (!unique.has(n.id)) unique.set(n.id, n);
  return [...unique.values()].sort((a, b) => compare(a.type, b.type) || compare(a.id, b.id));
}

function buildStats({ o, files, configs }, nodes, edges, notExtracted) {
  const count = (pred, list) => list.filter(pred).length;
  const calls = edges.filter((e) => e.type === "calls");
  const routes = nodes.filter((n) => n.type === "route");
  const coverage = {};
  for (const stack of sortedUnique([...o.stacks, ...files.map((f) => f.stack)])) {
    const ran = files.filter((f) => f.stack === stack && f.module);
    coverage[stack] = {
      frameworks_detected: frameworksOf(o, stack),
      extractors_applied: ran.length ? sortedUnique(ran[0].module.lang.frameworks ?? []) : [],
      not_extracted: sortedUnique([...ran.flatMap((f) => f.extract.not_extracted ?? []), ...(notExtracted.get(stack) ?? [])]),
      patterns_unmatched: []
    };
  }
  return {
    files_total: files.length,
    files_parsed: count((f) => f.status === "ok", files),
    files_error: count((f) => f.status === "error", files),
    files_skipped: count((f) => f.status === "skipped", files),
    functions: count((n) => n.type === "function", nodes),
    calls_total: calls.length,
    calls_exact: count((e) => e.confidence === "exact", calls),
    calls_name_only: count((e) => e.confidence === "name-only", calls),
    calls_unresolved: count((e) => e.confidence === "unresolved", calls),
    routes_by_auth: {
      unauthenticated: count((r) => r.auth === "unauthenticated", routes),
      authenticated: count((r) => r.auth === "authenticated", routes),
      unknown: count((r) => r.auth === "unknown", routes)
    },
    coverage_matrix: coverage,
    config_errors: configs.errors.map((e) => ({ file: e.file, message: e.message }))
  };
}

async function assemble(prep) {
  const { o, files, langModules, configs } = prep;
  const available = await parserAvailable({ vendorDir: o.vendorDir });
  if (!available.ok) return { graph: null, reason: available.reason };

  const surfaces = new Map();
  const surfaceOf = (stack) => {
    if (!surfaces.has(stack)) surfaces.set(stack, loadSurface(stack, o.referencesDir));
    return surfaces.get(stack);
  };
  await extractAll(prep, surfaceOf);
  const parsed = files.filter((f) => f.extract);
  const stackOfPath = new Map(files.map((f) => [f.path, f.stack]));
  const notExtracted = new Map();
  const notExtractedOf = (stack) => (notExtracted.has(stack) ? notExtracted.get(stack) : notExtracted.set(stack, new Set()).get(stack));

  const { importMap, calls, routeTexts } = resolveAll(parsed, langModules, configs, new Set(files.map((f) => f.path)));
  const routes = buildRoutes(parsed, routeTexts, importMap, (path) => surfaceOf(stackOfPath.get(path)), notExtractedOf);

  const nodes = sortNodes([...files.map(fileNode), ...parsed.flatMap(extractNodes), ...routes.map((r) => r.node)]);
  const edges = sortEdges([...importEdges(parsed, importMap), ...callEdges(calls, parsed), ...routeEdges(routes)]);
  const graph = { version: 1, generated_by: GENERATED_BY, stats: buildStats(prep, nodes, edges, notExtracted), nodes, edges };

  const v = validate("graph", graph);
  if (!v.valid) {
    const e = v.errors[0] ?? {};
    return { graph: null, reason: `internal: graph failed schema validation: ${e.instancePath ?? ""} ${e.message ?? "invalid"}`.replace(/\s+/g, " ").trim() };
  }
  return { graph };
}

export async function buildGraph(opts) {
  return assemble(await prepare(opts));
}

// ---- CLI ------------------------------------------------------------------------------------------

const USAGE = "usage: build-graph.mjs --file <in.json> --out <out.json> [--checkpoint-dir <abs>]\n";

function fail(code, message) {
  process.stderr.write(message.endsWith("\n") ? message : message + "\n");
  process.exit(code);
}

function writeOut(outFile, output) {
  try {
    writeFileSync(outFile, JSON.stringify(output, null, 2) + "\n");
  } catch (e) {
    fail(2, "cannot write --out: " + e.message);
  }
}

async function main(args) {
  const fi = args.indexOf("--file");
  const oi = args.indexOf("--out");
  const ci = args.indexOf("--checkpoint-dir");
  if (ci !== -1 && (!args[ci + 1] || args[ci + 1].startsWith("--"))) fail(2, USAGE.trimEnd() + "   (--checkpoint-dir requires a path argument)");
  if (fi === -1 || oi === -1 || !args[fi + 1] || !args[oi + 1]) fail(2, USAGE);
  const checkpointDir = ci !== -1 ? args[ci + 1] : null;
  const outFile = args[oi + 1];

  let input;
  try {
    input = JSON.parse(readFileSync(args[fi + 1], "utf8"));
  } catch (e) {
    fail(2, "cannot read --file: " + e.message);
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) fail(1, "bad input: expected a JSON object");

  let prep;
  try {
    prep = await prepare({
      projectDir: input.projectDir, scopeRealpath: input.scope_realpath, stacks: input.stacks, frameworks: input.frameworks,
      excludes: input.excludes, referencesDir: input.referencesDir, vendorDir: input.vendorDir
    });
  } catch (e) {
    fail(e instanceof InputError ? 1 : 2, (e instanceof InputError ? "bad input: " : "cannot read project: ") + e.message);
  }

  let digests = null;
  if (checkpointDir) {
    digests = { inputDigest: inputDigest(prep), versionDigest: versionDigest(versionFiles(prep.o.vendorDir)) };
    const lookup = cacheLookup({ checkpointDir, helperName: "build-graph", ...digests, requiredPayloadKey: "output" });
    if (lookup.hit) {
      writeOut(outFile, lookup.wrapper.output);
      process.stderr.write("build-graph: cache hit\n");
      process.exit(0);
    }
  }

  let result;
  try {
    result = await assemble(prep);
  } catch (e) {
    result = { graph: null, reason: "internal: " + (e?.message || String(e)) };
  }
  const output = result.graph ?? { graph: null, reason: result.reason };
  writeOut(outFile, output);
  if (digests && result.graph) { // a { graph: null } envelope is never cached: it may be transient
    try {
      cacheStore({ checkpointDir, helperName: "build-graph", ...digests, payload: { output } });
    } catch (e) {
      process.stderr.write("build-graph: cache store failed (non-fatal): " + e.message + "\n");
    }
  }
  process.exit(0);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  await main(process.argv.slice(2));
}
