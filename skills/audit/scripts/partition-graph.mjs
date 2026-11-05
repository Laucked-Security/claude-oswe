// SP10 partition-by-reachability (spec §3.2) — zero runtime dependencies, Node >= 20. Turns the
// application graph (schemas/graph.schema.json) into the orchestrator's partition shape
// { partition_id, stack, files[] }, so surface-scan.mjs and allocate-budget.mjs consume it unchanged.
// PURE function of its input: no filesystem access (besides the CLI's --file / --out), no Date, no
// randomness; the output does not depend on the order of the graph's nodes and edges.
//
// API: partitionGraph({ graph, fallback_partitions })
//        -> { mode: "graph" | "fallback", partitions: [{ partition_id, stack, files }], orphan_partition_ids }
//      throws InputError (message "bad input: ...") on malformed input. `graph` is the graph object
//      itself or null — the API never sees build-graph's { graph: null, reason } envelope: the CLI's
//      --graph <path> unwraps it (see CLI below);
//      `fallback_partitions` is the orchestrator's own directory partitioning.
//
// CLI: node partition-graph.mjs --file <in.json> --out <out.json> [--graph <graph.json>]
//   input:  { "graph": <graph | null>, "fallback_partitions": [ { partition_id, stack, files[] } ] }
//   output: the API result, pretty-printed.
//   exit 0 ok / 1 malformed input (missing or invalid fallback_partitions, graph that is neither null nor
//   an object with nodes[] and edges[], graph failing validate("graph")) / 2 IO | usage.
//   --graph <graph.json> (optional): read the graph from that file instead of the input's "graph" key, which it
//   supersedes (the key may then be omitted). The file is the graph itself or build-graph's envelope:
//   { "graph": null, "reason" } is graph null, { "graph": <object> } is that object. Unreadable / unparsable
//   => exit 2, like --file; the loaded graph is validated like an inline one.
//
// Fallback — the zero-regression guarantee. graph === null, or no route yields a group (in particular a
// graph with zero `route` nodes), => mode "fallback": `partitions` is `fallback_partitions` passed
// through untouched (same array, same objects, same key order), so its JSON is byte-for-byte the
// orchestrator's own partitions; orphan_partition_ids is [].
//
// Graph mode.
//  1. Reachability. From every route, its own file plus the file of every function reached from the
//     route's `handles` and `uses_middleware` targets by following `calls` edges of confidence `exact`
//     or `name-only` (never `unresolved`), transitively, cycle-safe. Function -> file is the function
//     node's `file`. A route whose file has no `file` node (so no stack) is ignored; an edge naming an
//     unknown function id is ignored.
//  2. Grouping. Group key = (stack of the route file's `file` node, route auth, module) where module is
//     the first path segment of the route file ("root" for a top-level file). Partition id =
//     g-<stack>-<auth>-<module>, every character outside [A-Za-z0-9_.-] replaced by "_" (groups whose
//     sanitised ids coincide are one group, so ids stay unique).
//  3. Exclusive ownership. A file is emitted once. Groups claim in AUTH ORDER — unauthenticated, then
//     unknown, then authenticated (then stack, module, id) — so a callee shared by an unauthenticated
//     and an authenticated route lands with the most exposed surface. Pass 1: each group, in that order,
//     claims its own route files — a route file is always where its routes are, so the group that
//     exposes `/health` keeps server.js even when another group's middleware lives there. Pass 2: each
//     group, in that order, claims the reachable files nobody claimed yet (the first group wins). A group
//     left with no file is omitted. `files` are sorted by plain string comparison.
//  4. Orphans. A file no group claimed stays with the directory partition the orchestrator put it in:
//     for each fallback partition (input order) holding at least one unclaimed file, emit
//     { partition_id: "<fallback id>-orphan", stack: <fallback stack>, files: <those files, sorted> } and
//     list the id in orphan_partition_ids. A file listed in several fallback partitions is emitted once
//     (the first wins). Files the graph never parsed (templates, configs) are orphans like any other: a
//     file the orchestrator chose to analyse is never dropped. A file in no fallback partition and no
//     group is not emitted — the orchestrator chose not to analyse it.
//  5. Order. Group partitions sorted by partition_id, then orphan partitions in fallback order.
//
// Paths are compared in graph/text.mjs's pathKey form (backslashes -> "/", leading "./" stripped, case folded
// on win32 only); an emitted path keeps the spelling of the first occurrence seen.
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "./validate-output.mjs";
import { pathKey } from "./graph/text.mjs";

export class InputError extends Error {}

const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isStringArray = (v) => Array.isArray(v) && v.every((x) => typeof x === "string");
const FOLLOWED_CONFIDENCE = new Set(["exact", "name-only"]);

// ---- input ------------------------------------------------------------------------------------------

function checkInput(input) {
  if (!isObject(input)) throw new InputError("bad input: expected an object { graph, fallback_partitions }");
  const { graph, fallback_partitions } = input;
  if (!Array.isArray(fallback_partitions)) {
    throw new InputError("bad input: fallback_partitions must be an array of { partition_id, stack, files[] }");
  }
  fallback_partitions.forEach((p, i) => {
    if (!isObject(p) || typeof p.partition_id !== "string" || typeof p.stack !== "string" || !isStringArray(p.files)) {
      throw new InputError(`bad input: fallback_partitions[${i}] must be { partition_id: string, stack: string, files: string[] }`);
    }
  });
  if (graph === null) return;
  if (!isObject(graph) || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges)) {
    throw new InputError("bad input: graph must be null or an object with nodes[] and edges[]");
  }
  const v = validate("graph", graph);
  if (!v.valid) {
    const e = v.errors[0] ?? {};
    throw new InputError(`bad input: graph fails schema validation: ${e.instancePath ?? ""} ${e.message ?? "invalid"}`.replace(/\s+/g, " ").trim());
  }
}

// ---- graph index ------------------------------------------------------------------------------------

// Everything reachability needs, built in one pass over nodes and edges.
function indexGraph(graph) {
  const stackByFile = new Map(); // folded path -> stack
  const fileOfFunction = new Map(); // function id -> file path (graph spelling)
  const routes = [];
  for (const n of graph.nodes) {
    if (n.type === "file") stackByFile.set(pathKey(n.path), n.stack);
    else if (n.type === "function") fileOfFunction.set(n.id, n.file);
    else if (n.type === "route") routes.push(n);
  }
  const callees = new Map(); // function id -> followed callee ids
  const seeds = new Map(); // route id -> handler / middleware function ids
  const push = (map, key, value) => (map.has(key) ? map.get(key).push(value) : map.set(key, [value]));
  for (const e of graph.edges) {
    if (e.type === "calls") {
      if (e.to !== null && FOLLOWED_CONFIDENCE.has(e.confidence)) push(callees, e.from, e.to);
    } else if (e.type === "handles" || e.type === "uses_middleware") {
      push(seeds, e.from, e.to);
    }
  }
  return { stackByFile, fileOfFunction, routes, callees, seeds };
}

// Files of every function reachable from `seedIds` (the seeds included), in discovery order.
function reachableFiles(seedIds, { fileOfFunction, callees }) {
  const files = [];
  const visited = new Set();
  const queue = [...seedIds];
  for (let head = 0; head < queue.length; head++) {
    const id = queue[head];
    if (visited.has(id) || !fileOfFunction.has(id)) continue;
    visited.add(id);
    files.push(fileOfFunction.get(id));
    for (const next of callees.get(id) ?? []) queue.push(next);
  }
  return files;
}

// ---- grouping ---------------------------------------------------------------------------------------

const sanitize = (s) => s.replace(/[^A-Za-z0-9_.-]/g, "_");
const moduleOf = (path) => {
  const i = path.indexOf("/");
  return i > 0 ? path.slice(0, i) : "root";
};

// partition id -> { stack, routeFiles[], seeds[] }; routes without a file node are ignored.
function groupRoutes(index) {
  const groups = new Map();
  for (const r of index.routes) {
    const stack = index.stackByFile.get(pathKey(r.file));
    if (stack === undefined) continue;
    const module = moduleOf(r.file);
    const id = sanitize(`g-${stack}-${r.auth}-${module}`);
    if (!groups.has(id)) groups.set(id, { stack, auth: r.auth, module, routeFiles: [], seeds: [] });
    const group = groups.get(id);
    group.routeFiles.push(r.file);
    group.seeds.push(...(index.seeds.get(r.id) ?? []));
  }
  return groups;
}

// The claim order: the most exposed surface first — unauthenticated, then unknown, then authenticated
// — then stack, then module, then id (plain string comparison).
const AUTH_CLAIM_RANK = { unauthenticated: 0, unknown: 1, authenticated: 2 };
const claimOrder = (groups) =>
  [...groups.keys()].sort((a, b) => {
    const ga = groups.get(a);
    const gb = groups.get(b);
    return (AUTH_CLAIM_RANK[ga.auth] ?? 3) - (AUTH_CLAIM_RANK[gb.auth] ?? 3) || compare(ga.stack, gb.stack) || compare(ga.module, gb.module) || compare(a, b);
  });

// Exclusive ownership (header, "Exclusive ownership"). Returns the non-empty group partitions in
// sorted id order and the set of folded paths they claimed.
function claimGroupFiles(groups, index) {
  const order = claimOrder(groups);
  const ids = [...groups.keys()].sort(compare);
  const claimed = new Set();
  const filesOf = new Map(ids.map((id) => [id, []]));
  const claim = (id, path) => {
    const key = pathKey(path);
    if (claimed.has(key)) return;
    claimed.add(key);
    filesOf.get(id).push(path);
  };
  for (const id of order) for (const path of groups.get(id).routeFiles) claim(id, path);
  for (const id of order) for (const path of reachableFiles(groups.get(id).seeds, index)) claim(id, path);
  const partitions = [];
  for (const id of ids) {
    const files = filesOf.get(id).sort(compare);
    if (files.length > 0) partitions.push({ partition_id: id, stack: groups.get(id).stack, files });
  }
  return { partitions, claimed };
}

// ---- orphans ----------------------------------------------------------------------------------------

function orphanPartitions(fallbackPartitions, claimed) {
  const partitions = [];
  for (const p of fallbackPartitions) {
    const files = [];
    for (const path of p.files) {
      const key = pathKey(path);
      if (claimed.has(key)) continue;
      claimed.add(key); // a file listed in several fallback partitions is emitted once
      files.push(path);
    }
    if (files.length > 0) partitions.push({ partition_id: `${p.partition_id}-orphan`, stack: p.stack, files: files.sort(compare) });
  }
  return partitions;
}

// ---- API --------------------------------------------------------------------------------------------

export function partitionGraph(input) {
  checkInput(input);
  const { graph, fallback_partitions } = input;
  const fallback = () => ({ mode: "fallback", partitions: fallback_partitions, orphan_partition_ids: [] });
  if (graph === null) return fallback();
  const index = indexGraph(graph);
  const groups = groupRoutes(index);
  if (groups.size === 0) return fallback();
  const { partitions: groupPartitions, claimed } = claimGroupFiles(groups, index);
  const orphans = orphanPartitions(fallback_partitions, claimed);
  return {
    mode: "graph",
    partitions: [...groupPartitions, ...orphans],
    orphan_partition_ids: orphans.map((p) => p.partition_id)
  };
}

// ---- CLI --------------------------------------------------------------------------------------------

const USAGE = "usage: partition-graph.mjs --file <in.json> --out <out.json> [--graph <graph.json>]\n";

function fail(code, message) {
  process.stderr.write(message.endsWith("\n") ? message : message + "\n");
  process.exit(code);
}

function main(args) {
  const fi = args.indexOf("--file");
  const oi = args.indexOf("--out");
  const gi = args.indexOf("--graph");
  if (fi === -1 || !args[fi + 1] || oi === -1 || !args[oi + 1]) fail(2, USAGE);
  if (gi !== -1 && (!args[gi + 1] || args[gi + 1].startsWith("--"))) fail(2, USAGE);
  let input;
  try {
    input = JSON.parse(readFileSync(args[fi + 1], "utf8"));
  } catch (e) {
    fail(2, "cannot read --file: " + e.message);
  }
  if (gi !== -1) {
    let loaded;
    try {
      loaded = JSON.parse(readFileSync(args[gi + 1], "utf8"));
    } catch (e) {
      fail(2, "cannot read --graph: " + e.message);
    }
    // build-graph's envelope { graph: null, reason } => null, { graph: <object> } => that object; otherwise
    // the file is the graph itself (a graph has no "graph" key). It supersedes any inline "graph" key.
    const graph = isObject(loaded) && Object.hasOwn(loaded, "graph") ? loaded.graph : loaded;
    if (isObject(input)) input = { ...input, graph };
  }
  let result;
  try {
    result = partitionGraph(input);
  } catch (e) {
    if (e instanceof InputError) fail(1, e.message);
    throw e;
  }
  try {
    writeFileSync(args[oi + 1], JSON.stringify(result, null, 2) + "\n");
  } catch (e) {
    fail(2, "cannot write --out: " + e.message);
  }
  process.exit(0);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) main(process.argv.slice(2));
