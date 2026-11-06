// SP10 structural proof (spec §3.4) — zero runtime dependencies, Node >= 20. Checks, on the application
// graph (schemas/graph.schema.json), whether each aggregated finding's source reaches its sink and whether
// each typed `call-path` chain transition is backed by a call path, and writes the verdicts in the shape of
// schemas/structural-check.schema.json. Runs deterministically BEFORE the LLM verifier; apply-verdicts
// --structural consumes the result ("strong static proof" + "absent" => "to verify"). PURE function of its
// input: no filesystem access (besides the CLI's --file / --out), no Date, no randomness; the output does
// not depend on the order of the graph's nodes and edges.
//
// API: checkChainStructure({ graph, findings, chains, max_depth = 6 })
//        -> { findings: { "OSWE-N": { structural_path, reason } },
//             transitions: { "CHAIN-N": [ { index, structural_path, reason } ] } }
//      enclosingFn(graph, file, line) -> the caller-side reading of the line: the innermost function node
//      containing it, except one opening on the line when an enclosing function contains it too; or null.
//      throws InputError (message "bad input: ...") on malformed input. `graph` is the graph object or null
//      (no graph: every finding and every transition is "n/a" with reason "graph unavailable"). `findings`
//      are the aggregated findings (finding_id OSWE-N, source / sink { file, line, ... }); `chains` are
//      chain.schema.json objects (chain_id CHAIN-N, transitions[] { from, to, kind?, from_anchor?, to_anchor? }).
//
// CLI: node check-chain-structure.mjs --file <in.json> --out <out.json> [--graph <graph.json>]
//   input:  { "graph": <graph> | null, "findings": [...], "chains": [...], "max_depth"?: n }
//   output: the API result, pretty-printed.
//   exit 0 ok / 1 malformed input (graph neither null nor a schema-valid graph; findings or chains not an
//   array of well-formed items, or with a duplicate id; max_depth present but not a positive integer) /
//   2 IO | usage.
//   --graph <graph.json> (optional): read the graph from that file instead of the input's "graph" key, which it
//   supersedes (the key may then be omitted). The file is the graph itself or build-graph's envelope:
//   { "graph": null, "reason" } is graph null, { "graph": <object> } is that object. Unreadable / unparsable
//   => exit 2, like --file; the loaded graph is validated like an inline one.
//
// Mapping. A location { file, line } maps to the function the graph itself anchored there when every
// `source` / `sink` node of the graph on that line — those of the location's own role (source nodes for
// a source end, sink nodes for a sink end) when there are any, else all of them — has the same non-null
// enclosing_fn (byte-precise: a callback opening on the sink's line does not capture a sink that precedes
// it). Otherwise it maps to the functions of that file containing the line (line_start <= line <=
// line_end): the innermost one (greatest line_start, then smallest line_end, then smaller id) — or, when
// that one OPENS on the line and an enclosing function contains the line too, BOTH the enclosing one
// (preferred) and the opening one: `dao.find(id, (err, rows) => {` is the caller's call and the callback's
// first line. A finding's source or sink read both ways must give one structural_path, else the verdict
// is n/a "ambiguous location: the line opens a nested function" (a parent reaches every closure it
// defines through `nests`); the two ends of one line are read together. A call-path transition's
// from_anchor is the caller's call site (the enclosing reading only), its to_anchor the entry it reaches
// (the opening function); anchors place expressions, so neither uses them. The location's file and the
// graph's paths compare in graph/text.mjs's pathKey form (backslashes -> "/", leading "./" stripped,
// case folded on win32 only).
//
// Connectivity. BFS over `calls` edges with a non-null `to` and over `nests` edges (a function lexically
// nested in another — a callback, a closure, a local helper — runs within it, so a nests edge is followed
// like an exact call and never counts as a non-exact one), at most max_depth edges. An "exact" search
// follows only `exact` calls and nests edges; an "any" search follows `exact` and `name-only` calls plus
// nests edges (never `unresolved`). Forward = from the source's function S toward the sink's function K;
// reverse = from K toward S.
//
// Decision table between a from-location (source) and a to-location (sink), evaluated in this order:
//   source maps to no function                      -> n/a    "source line maps to no function"
//   sink maps to no function                        -> n/a    "sink line maps to no function"
//   S === K                                         -> proven "same function"
//   forward exact path of n edges                   -> proven "forward exact path (<n> edges)"
//   reverse exact path                              -> n/a    "return-value flow not modelled"
//   forward or reverse "any" path                   -> n/a    "only non-exact edges connect source and sink"
//   a call reachable from S or from K is not exact  -> n/a    "graph incomplete on the path"
//   otherwise                                       -> absent "no connection within <max_depth> edges"
// "Reachable" = the forward closure over exact and name-only edges within max_depth edges; a call is
// checked when its caller lies fewer than max_depth edges from S (or K). Not exact = name-only, or
// unresolved with any `to` (null included). "absent" is a strong claim: the graph saw both ends, every
// call around them resolved exactly, and nothing links them.
//
// Per finding: the table between its source and its sink. Per chain transition (output in index order):
// no kind -> n/a "transition has no kind"; kind other than call-path -> n/a "transition kind <kind> not
// structurally checkable"; call-path -> the table between from_anchor and to_anchor when both are present,
// otherwise between the `from` finding's sink and the `to` finding's source (an id not among the findings,
// e.g. "entry" -> n/a "transition references unknown finding"). findings keys are in OSWE-N numeric order,
// transitions keys in CHAIN-N numeric order.
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "./validate-output.mjs";
import { pathKey } from "./graph/text.mjs";

export class InputError extends Error {}

const DEFAULT_MAX_DEPTH = 6;
const FINDING_ID = /^OSWE-[0-9]+$/;
const CHAIN_ID = /^CHAIN-[0-9]+$/;
const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isPositiveInteger = (v) => Number.isInteger(v) && v > 0;
const isLocation = (v) => isObject(v) && typeof v.file === "string" && Number.isInteger(v.line) && v.line >= 0;
const idNumber = (id) => Number(id.slice(id.indexOf("-") + 1));
const compareIds = (a, b) => idNumber(a) - idNumber(b) || compare(a, b);
const verdict = (structural_path, reason) => ({ structural_path, reason });
const GRAPH_UNAVAILABLE = "graph unavailable";

// ---- input ------------------------------------------------------------------------------------------

function checkGraph(graph) {
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

function checkFindings(findings) {
  if (!Array.isArray(findings)) throw new InputError("bad input: findings must be an array");
  const seen = new Set();
  findings.forEach((f, i) => {
    if (!isObject(f) || typeof f.finding_id !== "string" || !FINDING_ID.test(f.finding_id)) {
      throw new InputError(`bad input: findings[${i}] must be an object with a finding_id OSWE-N`);
    }
    if (seen.has(f.finding_id)) throw new InputError(`bad input: duplicate finding_id ${f.finding_id}`);
    seen.add(f.finding_id);
    if (!isLocation(f.source) || !isLocation(f.sink)) {
      throw new InputError(`bad input: findings[${i}] source and sink must be { file: string, line: integer >= 0 }`);
    }
  });
}

function checkTransition(t, where) {
  if (!isObject(t) || typeof t.from !== "string" || typeof t.to !== "string") {
    throw new InputError(`bad input: ${where} must be an object with string from and to`);
  }
  if (t.kind !== undefined && typeof t.kind !== "string") throw new InputError(`bad input: ${where}.kind must be a string`);
  for (const key of ["from_anchor", "to_anchor"]) {
    if (t[key] !== undefined && !isLocation(t[key])) throw new InputError(`bad input: ${where}.${key} must be { file: string, line: integer >= 0 }`);
  }
}

function checkChains(chains) {
  if (!Array.isArray(chains)) throw new InputError("bad input: chains must be an array");
  const seen = new Set();
  chains.forEach((c, i) => {
    if (!isObject(c) || typeof c.chain_id !== "string" || !CHAIN_ID.test(c.chain_id)) {
      throw new InputError(`bad input: chains[${i}] must be an object with a chain_id CHAIN-N`);
    }
    if (seen.has(c.chain_id)) throw new InputError(`bad input: duplicate chain_id ${c.chain_id}`);
    seen.add(c.chain_id);
    if (!Array.isArray(c.transitions)) throw new InputError(`bad input: chains[${i}].transitions must be an array`);
    c.transitions.forEach((t, j) => checkTransition(t, `chains[${i}].transitions[${j}]`));
  });
}

function checkInput(input) {
  if (!isObject(input)) throw new InputError("bad input: expected an object { graph, findings, chains, max_depth? }");
  checkGraph(input.graph);
  checkFindings(input.findings);
  checkChains(input.chains);
  if (input.max_depth !== undefined && !isPositiveInteger(input.max_depth)) throw new InputError("bad input: max_depth must be a positive integer");
}

// ---- graph index ------------------------------------------------------------------------------------

// The functions of `fns` containing `line`: `innermost` (greatest line_start, then smallest line_end,
// then smaller id, so the choice does not depend on node order) and `enclosing`, the innermost among
// those that opened BEFORE the line (null when none). When `innermost` opens on the line, a location
// there may sit in either: `dao.find(id, (err, rows) => {` is the caller's call and the callback's
// first line.
function containing(fns, line) {
  const inner = (a, b) => (a === null || b.line_start > a.line_start || (b.line_start === a.line_start && (b.line_end < a.line_end || (b.line_end === a.line_end && compare(b.id, a.id) < 0))) ? b : a);
  let innermost = null;
  let enclosing = null;
  for (const fn of fns) {
    if (fn.line_start > line || line > fn.line_end) continue;
    innermost = inner(innermost, fn);
    if (fn.line_start < line) enclosing = inner(enclosing, fn);
  }
  return { innermost, enclosing };
}

// The caller-side reading of a line: the innermost function containing it, except one opening on the
// line when an enclosing function contains the line too (header, "Mapping"); none => null.
export function enclosingFn(graph, file, line) {
  const key = pathKey(file);
  const { innermost, enclosing } = containing(graph.nodes.filter((n) => n.type === "function" && pathKey(n.file) === key), line);
  return innermost !== null && innermost.line_start === line && enclosing !== null ? enclosing : innermost;
}

function indexGraph(graph) {
  const fnsByFile = new Map(); // pathKey(file) -> function nodes
  const fnById = new Map(); // function id -> function node
  const anchors = new Map(); // "<pathKey(file)>\0<line>" -> enclosing_fn of every source / sink node on that line
  const push = (map, from, to) => (map.has(from) ? map.get(from).push(to) : map.set(from, [to]));
  for (const n of graph.nodes) {
    if (n.type === "function") {
      fnById.set(n.id, n);
      push(fnsByFile, pathKey(n.file), n);
    } else if (n.type === "source" || n.type === "sink") {
      push(anchors, `${pathKey(n.file)}\u0000${n.line}`, { type: n.type, fn: n.enclosing_fn });
    }
  }
  const exact = new Map(); // function id -> callee ids over exact edges
  const any = new Map(); // function id -> callee ids over exact and name-only edges
  const incomplete = new Set(); // function ids with an outgoing call that is not exact (any `to`, null included)
  for (const e of graph.edges) {
    if (e.type === "nests") {
      push(exact, e.from, e.to);
      push(any, e.from, e.to);
      continue;
    }
    if (e.type !== "calls") continue;
    if (e.confidence !== "exact") incomplete.add(e.from);
    if (e.to === null) continue;
    if (e.confidence === "exact") push(exact, e.from, e.to);
    if (e.confidence === "exact" || e.confidence === "name-only") push(any, e.from, e.to);
  }
  return { fnsByFile, fnById, anchors, exact, any, incomplete };
}

// The graph's own anchor for a line, as a function node: the enclosing_fn every source / sink node of
// the preferred role on that line shares (source nodes for a source end, sink nodes for a sink end), else
// every node of any role there; undefined when there is none, when they disagree or when it is
// module-level (null).
function anchorFor(index, key, line, role) {
  const all = index.anchors.get(`${key}\u0000${line}`);
  if (!all) return undefined;
  const preferred = all.filter((a) => a.type === role);
  const chosen = preferred.length ? preferred : all;
  const fn = chosen[0].fn;
  return fn !== null && chosen.every((a) => a.fn === fn) ? index.fnById.get(fn) : undefined;
}

// The functions a location may sit in, preferred reading first (header, "Mapping"). role: "source" /
// "sink" — a finding end, an expression on the line, which the graph's own anchors may place; "call-site"
// — a call-path transition's from_anchor, the caller's call (a callback opening on the line is its
// argument); "entry" — a to_anchor, the function control enters (the one opening on the line, if any).
// Anchors place expressions, not call sites or entries (a one-line `dao.find(id, (e, r) => eval(r))`
// anchors `eval` inside the callback while the call site is the caller's), so the two transition roles
// use the line rules only. [] when no function contains the line.
function candidates(index, { file, line }, role) {
  const key = pathKey(file);
  const anchored = role === "source" || role === "sink" ? anchorFor(index, key, line, role) : undefined;
  if (anchored) return [anchored];
  const { innermost, enclosing } = containing(index.fnsByFile.get(key) ?? [], line);
  if (innermost === null) return [];
  if (innermost.line_start !== line || enclosing === null) return [innermost];
  if (role === "entry") return [innermost];
  if (role === "call-site") return [enclosing];
  return [enclosing, innermost];
}

// ---- connectivity -----------------------------------------------------------------------------------

// Number of edges of the shortest path start -> target over `adjacency`, at most maxDepth; null if none.
// The distance does not depend on the order of the adjacency lists.
function distance(adjacency, start, target, maxDepth) {
  const seen = new Set([start]);
  let frontier = [start];
  for (let edges = 1; edges <= maxDepth && frontier.length > 0; edges++) {
    const next = [];
    for (const from of frontier) {
      for (const to of adjacency.get(from) ?? []) {
        if (to === target) return edges;
        if (!seen.has(to)) {
          seen.add(to);
          next.push(to);
        }
      }
    }
    frontier = next;
  }
  return null;
}

// Is every call reachable from `start` exact? The forward closure over exact and name-only edges, at most
// maxDepth edges deep: false as soon as a function on it at fewer than maxDepth edges from `start` (so its
// own calls are within the horizon) has a call that is not exact — name-only, or unresolved with any `to`.
function closureComplete(index, start, maxDepth) {
  const seen = new Set([start]);
  let frontier = [start];
  for (let edges = 0; edges < maxDepth && frontier.length > 0; edges++) {
    const next = [];
    for (const from of frontier) {
      if (index.incomplete.has(from)) return false;
      for (const to of index.any.get(from) ?? []) {
        if (!seen.has(to)) {
          seen.add(to);
          next.push(to);
        }
      }
    }
    frontier = next;
  }
  return true;
}

// ---- decision table ---------------------------------------------------------------------------------

const AMBIGUOUS_LOCATION = "ambiguous location: the line opens a nested function";

// The table between two locations. Each end is read as `candidates` says; a finding end on the line
// where a nested function opens is read both ways, and the verdict stands only when every reading
// agrees on structural_path (the preferred reading's reason), else n/a: a parent reaches every closure
// it defines through `nests`, so reading a location in the parent must never prove a path into an
// unrelated sibling closure. The two ends of one line are read together (one line, one reading).
function decide(index, fromLoc, toLoc, maxDepth, [fromRole, toRole] = ["source", "sink"]) {
  const ss = candidates(index, fromLoc, fromRole);
  if (!ss.length) return verdict("n/a", "source line maps to no function");
  const ks = candidates(index, toLoc, toRole);
  if (!ks.length) return verdict("n/a", "sink line maps to no function");
  const oneLine = ss.length === 2 && ks.length === 2 && fromLoc.line === toLoc.line && pathKey(fromLoc.file) === pathKey(toLoc.file);
  const pairs = oneLine ? [[ss[0], ks[0]], [ss[1], ks[1]]] : ss.flatMap((s) => ks.map((k) => [s, k]));
  const verdicts = pairs.map(([s, k]) => decideBetween(index, s, k, maxDepth));
  return verdicts.every((v) => v.structural_path === verdicts[0].structural_path) ? verdicts[0] : verdict("n/a", AMBIGUOUS_LOCATION);
}

// The table between two mapped functions (header, "Decision table").
function decideBetween(index, s, k, maxDepth) {
  if (s.id === k.id) return verdict("proven", "same function");
  const forward = distance(index.exact, s.id, k.id, maxDepth);
  if (forward !== null) return verdict("proven", `forward exact path (${forward} edges)`);
  if (distance(index.exact, k.id, s.id, maxDepth) !== null) return verdict("n/a", "return-value flow not modelled");
  if (distance(index.any, s.id, k.id, maxDepth) !== null || distance(index.any, k.id, s.id, maxDepth) !== null) {
    return verdict("n/a", "only non-exact edges connect source and sink");
  }
  if (!closureComplete(index, s.id, maxDepth) || !closureComplete(index, k.id, maxDepth)) return verdict("n/a", "graph incomplete on the path");
  return verdict("absent", `no connection within ${maxDepth} edges`);
}

function decideTransition(index, t, findingsById, maxDepth) {
  if (t.kind === undefined) return verdict("n/a", "transition has no kind");
  if (t.kind !== "call-path") return verdict("n/a", `transition kind ${t.kind} not structurally checkable`);
  if (t.from_anchor !== undefined && t.to_anchor !== undefined) return decide(index, t.from_anchor, t.to_anchor, maxDepth, ["call-site", "entry"]);
  const from = findingsById.get(t.from);
  const to = findingsById.get(t.to);
  if (from === undefined || to === undefined) return verdict("n/a", "transition references unknown finding");
  return decide(index, from.sink, to.source, maxDepth, ["sink", "source"]);
}

// ---- API --------------------------------------------------------------------------------------------

export function checkChainStructure(input) {
  checkInput(input);
  const { graph, findings, chains, max_depth = DEFAULT_MAX_DEPTH } = input;
  const index = graph === null ? null : indexGraph(graph);
  const unavailable = () => verdict("n/a", GRAPH_UNAVAILABLE);
  const findingsById = new Map(findings.map((f) => [f.finding_id, f]));

  const out = { findings: {}, transitions: {} };
  for (const f of [...findings].sort((a, b) => compareIds(a.finding_id, b.finding_id))) {
    out.findings[f.finding_id] = index === null ? unavailable() : decide(index, f.source, f.sink, max_depth);
  }
  for (const c of [...chains].sort((a, b) => compareIds(a.chain_id, b.chain_id))) {
    out.transitions[c.chain_id] = c.transitions.map((t, i) => ({
      index: i,
      ...(index === null ? unavailable() : decideTransition(index, t, findingsById, max_depth))
    }));
  }
  const v = validate("structural-check", out);
  if (!v.valid) throw new Error(`check-chain-structure produced an invalid result: ${JSON.stringify(v.errors[0])}`);
  return out;
}

// ---- CLI --------------------------------------------------------------------------------------------

const USAGE = "usage: check-chain-structure.mjs --file <in.json> --out <out.json> [--graph <graph.json>]\n";

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
    result = checkChainStructure(input);
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
