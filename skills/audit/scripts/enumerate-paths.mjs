// SP10 candidate-path enumeration (spec §3.3) — zero runtime dependencies, Node >= 20. Turns the
// application graph (schemas/graph.schema.json) plus one partition into ranked STRUCTURAL candidate
// paths route -> ... -> sink, which the analyzer cites as `candidate_path_id` on a finding. PURE function
// of its input: no filesystem access (besides the CLI's --file / --out), no Date, no randomness; the output
// does not depend on the order of the graph's nodes and edges, so ids are stable for a given graph and
// partition.
//
// API: enumeratePaths({ graph, partition, max_depth = 6, max_paths = 50 })
//        -> { partition_id, candidate_paths: [ { id, route, hops, sink, min_confidence } ] }
//      throws InputError (message "bad input: ...") on malformed input. `partition` is { partition_id,
//      stack, files[] } as partition-graph.mjs emits it; `graph` is the graph object itself (never null:
//      the orchestrator skips this helper when there is no graph).
//
// CLI: node enumerate-paths.mjs --file <in.json> --out <out.json> [--graph <graph.json>]
//   input:  { "graph": <graph>, "partition": { partition_id, stack, files[] }, "max_depth"?: n, "max_paths"?: n }
//   output: the API result, pretty-printed.
//   exit 0 ok / 1 malformed input (graph null / not an object with nodes[] and edges[] / failing
//   validate("graph"); partition without a string partition_id or a files[] of strings; max_depth or
//   max_paths present but not a positive integer) / 2 IO | usage.
//   --graph <graph.json> (optional): read the graph from that file instead of the input's "graph" key, which it
//   supersedes (the key may then be omitted). The file is the graph itself or build-graph's envelope:
//   { "graph": null, "reason" } is graph null, { "graph": <object> } is that object. Unreadable / unparsable
//   => exit 2, like --file; the loaded graph is validated like an inline one.
//
// Candidates. Every `route` node whose file is in partition.files and whose handler is non-null is a root
// (a route with no handler produces nothing). From the handler, ONE shortest path per reachable function
// is computed over `calls` edges of confidence `exact` or `name-only` that have a target (never
// `unresolved`), through functions in ANY file of the graph: only the root — the route and its handler —
// is bound to partition.files (a route whose handler lives in another partition produces nothing), so a
// path from this partition's route into a callee owned by another partition is still listed (a shared
// helper is claimed by one partition only, see partition-graph.mjs). Cost = (hops, name-only edge count),
// compared lexicographically; ties go to the predecessor with the smaller function id (plain string
// comparison). It is a level-synchronous BFS with a secondary relaxation, so the work is linear in the
// edges even when the number of distinct paths is exponential. max_depth bounds the length of a candidate
// in hops: hops.length <= max_depth (the handler is hop 1), i.e. at most max_depth - 1 calls edges.
// Every `sink` whose enclosing_fn is a function on a settled shortest path yields one candidate for that
// (route, sink) pair; a module-level sink (enclosing_fn null) is never a candidate.
//
// A candidate: route = { file, line, http_method, path_pattern, auth } of the route node; hops = the
// functions from the handler to the sink's enclosing function inclusive, each { file, line: line_start,
// function: qualified_name, edge_confidence } where edge_confidence is the confidence of the edge that
// entered the hop ("exact" for the handler); sink = { file, line, class, callee }; min_confidence = the
// weakest edge_confidence among hops after the first ("exact" for a single hop).
//
// Ranking. Sorted by (sinkRank, auth === "unauthenticated" ? 0 : 1, hops.length, route id, sink id) with
// sinkRank cmd-exec|eval|deser 0, sql|nosql|template|include 1, file-write|file-read|ssrf|xxe 2, anything
// else 3. Plain string comparison throughout (never locale-aware). The first max_paths are kept and
// numbered CP-<partition_id>-<n>, 1-based, in that order.
//
// Paths are compared in graph/text.mjs's pathKey form (backslashes -> "/", leading "./" stripped, case folded
// on win32 only), as partition-graph.mjs does: a partition's file spelling can differ from the graph's.
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "./validate-output.mjs";
import { pathKey } from "./graph/text.mjs";

export class InputError extends Error {}

const DEFAULT_MAX_DEPTH = 6;
const DEFAULT_MAX_PATHS = 50;
const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isStringArray = (v) => Array.isArray(v) && v.every((x) => typeof x === "string");
const isPositiveInteger = (v) => Number.isInteger(v) && v > 0;
const FOLLOWED_CONFIDENCE = new Set(["exact", "name-only"]);
const SINK_RANK = {
  "cmd-exec": 0, eval: 0, deser: 0,
  sql: 1, nosql: 1, template: 1, include: 1,
  "file-write": 2, "file-read": 2, ssrf: 2, xxe: 2
};
const sinkRank = (cls) => SINK_RANK[cls] ?? 3;

// ---- input ------------------------------------------------------------------------------------------

function checkInput(input) {
  if (!isObject(input)) throw new InputError("bad input: expected an object { graph, partition, max_depth?, max_paths? }");
  const { graph, partition, max_depth, max_paths } = input;
  if (!isObject(graph) || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges)) {
    throw new InputError("bad input: graph must be an object with nodes[] and edges[] (this helper needs a graph)");
  }
  const v = validate("graph", graph);
  if (!v.valid) {
    const e = v.errors[0] ?? {};
    throw new InputError(`bad input: graph fails schema validation: ${e.instancePath ?? ""} ${e.message ?? "invalid"}`.replace(/\s+/g, " ").trim());
  }
  if (!isObject(partition) || typeof partition.partition_id !== "string" || partition.partition_id === "" || !isStringArray(partition.files)) {
    throw new InputError("bad input: partition must be { partition_id: non-empty string, files: string[] }");
  }
  if (max_depth !== undefined && !isPositiveInteger(max_depth)) throw new InputError("bad input: max_depth must be a positive integer");
  if (max_paths !== undefined && !isPositiveInteger(max_paths)) throw new InputError("bad input: max_paths must be a positive integer");
}

// ---- graph index ------------------------------------------------------------------------------------

// Everything the search needs, built in one pass over nodes and edges: the roots (routes in the partition's
// files whose handler is in them too) and the call graph over every function of the graph.
function indexGraph(graph, files) {
  const inPartition = new Set(files.map(pathKey));
  const has = (file) => inPartition.has(pathKey(file));
  const fnById = new Map(); // id -> function node, every file
  const candidates = []; // route nodes in the partition with a handler
  const sinksByFn = new Map(); // function id -> sink nodes enclosed by it
  const push = (map, key, value) => (map.has(key) ? map.get(key).push(value) : map.set(key, [value]));
  for (const n of graph.nodes) {
    if (n.type === "function") fnById.set(n.id, n);
    else if (n.type === "route" && n.handler !== null && has(n.file)) candidates.push(n);
    else if (n.type === "sink" && n.enclosing_fn !== null) push(sinksByFn, n.enclosing_fn, n);
  }
  // a root's handler must be a known function in the partition's files
  const routes = candidates.filter((r) => fnById.has(r.handler) && has(fnById.get(r.handler).file));
  const callees = new Map(); // function id -> [{ to, confidence }] between known functions
  for (const e of graph.edges) {
    if (e.type === "calls" && e.to !== null && FOLLOWED_CONFIDENCE.has(e.confidence) && fnById.has(e.from) && fnById.has(e.to)) {
      push(callees, e.from, { to: e.to, confidence: e.confidence });
    }
  }
  return { fnById, routes, sinksByFn, callees };
}

// ---- shortest paths ---------------------------------------------------------------------------------

// Shortest-path tree from `start`: function id -> { edges, nameOnly, pred, confidence } where `edges` is the
// hop count, `nameOnly` the name-only edge count, `pred` the previous function id (null for `start`) and
// `confidence` the confidence of the edge entering the function. Level-synchronous: when a level is
// expanded every node on it is final (all its predecessors sit one level up and were processed before),
// so a node found again at its own level is only ever improved by the (nameOnly, pred id) tie-break.
// At most maxDepth - 1 edges are followed, i.e. a path has at most maxDepth hops.
function shortestPathTree(start, { callees }, maxDepth) {
  const tree = new Map([[start, { edges: 0, nameOnly: 0, pred: null, confidence: "exact" }]]);
  let frontier = [start];
  for (let edges = 1; edges < maxDepth && frontier.length > 0; edges++) {
    const next = [];
    for (const from of frontier) {
      const base = tree.get(from).nameOnly;
      for (const { to, confidence } of callees.get(from) ?? []) {
        const nameOnly = base + (confidence === "exact" ? 0 : 1);
        const known = tree.get(to);
        if (known === undefined) {
          tree.set(to, { edges, nameOnly, pred: from, confidence });
          next.push(to);
        } else if (known.edges === edges && (nameOnly < known.nameOnly || (nameOnly === known.nameOnly && compare(from, known.pred) < 0))) {
          known.nameOnly = nameOnly;
          known.pred = from;
          known.confidence = confidence;
        }
      }
    }
    frontier = next;
  }
  return tree;
}

// ---- candidates -------------------------------------------------------------------------------------

// Lightweight ranking records, one per (route, sink): the hop lists are only built for the survivors.
function rankingRecords(index, maxDepth) {
  const records = [];
  for (const route of index.routes) {
    if (!index.fnById.has(route.handler)) continue; // handler unknown (indexGraph already dropped those outside the partition)
    const tree = shortestPathTree(route.handler, index, maxDepth);
    for (const [fnId, step] of tree) {
      for (const sink of index.sinksByFn.get(fnId) ?? []) {
        records.push({
          rank: sinkRank(sink.class),
          authRank: route.auth === "unauthenticated" ? 0 : 1,
          length: step.edges + 1,
          route, sink, fnId, tree
        });
      }
    }
  }
  return records;
}

const compareRecords = (a, b) =>
  a.rank - b.rank || a.authRank - b.authRank || a.length - b.length || compare(a.route.id, b.route.id) || compare(a.sink.id, b.sink.id);

function hopsOf({ fnId, tree }, fnById) {
  const hops = [];
  for (let id = fnId; id !== null; id = tree.get(id).pred) {
    const fn = fnById.get(id);
    hops.push({ file: fn.file, line: fn.line_start, function: fn.qualified_name, edge_confidence: tree.get(id).confidence });
  }
  return hops.reverse();
}

function candidateOf(record, n, partitionId, fnById) {
  const { route, sink } = record;
  const hops = hopsOf(record, fnById);
  return {
    id: `CP-${partitionId}-${n}`,
    route: { file: route.file, line: route.line, http_method: route.http_method, path_pattern: route.path_pattern, auth: route.auth },
    hops,
    sink: { file: sink.file, line: sink.line, class: sink.class, callee: sink.callee },
    min_confidence: hops.slice(1).some((h) => h.edge_confidence !== "exact") ? "name-only" : "exact"
  };
}

// ---- API --------------------------------------------------------------------------------------------

export function enumeratePaths(input) {
  checkInput(input);
  const { graph, partition, max_depth = DEFAULT_MAX_DEPTH, max_paths = DEFAULT_MAX_PATHS } = input;
  const index = indexGraph(graph, partition.files);
  const kept = rankingRecords(index, max_depth).sort(compareRecords).slice(0, max_paths);
  return {
    partition_id: partition.partition_id,
    candidate_paths: kept.map((record, i) => candidateOf(record, i + 1, partition.partition_id, index.fnById))
  };
}

// ---- CLI --------------------------------------------------------------------------------------------

const USAGE = "usage: enumerate-paths.mjs --file <in.json> --out <out.json> [--graph <graph.json>]\n";

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
    result = enumeratePaths(input);
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
