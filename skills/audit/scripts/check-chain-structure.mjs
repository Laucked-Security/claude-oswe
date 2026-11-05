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
//      enclosingFn(graph, file, line) -> the innermost function node containing the line, or null.
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
// Mapping. A location { file, line } maps to enclosingFn: the function node of that file with
// line_start <= line <= line_end, the innermost one when several match (greatest line_start, then smallest
// line_end, then smaller id). The location's file is normalised first (backslashes -> "/", leading "./"
// stripped) and then compared exactly with the graph's repo-relative paths.
//
// Connectivity. BFS over `calls` edges with a non-null `to`, at most max_depth edges. An "exact" search
// follows only `exact` edges; an "any" search follows `exact` and `name-only` edges (never `unresolved`).
// Forward = from the source's function S toward the sink's function K; reverse = from K toward S.
//
// Decision table between a from-location (source) and a to-location (sink), evaluated in this order:
//   source maps to no function                      -> n/a    "source line maps to no function"
//   sink maps to no function                        -> n/a    "sink line maps to no function"
//   S === K                                         -> proven "same function"
//   forward exact path of n edges                   -> proven "forward exact path (<n> edges)"
//   reverse exact path                              -> n/a    "return-value flow not modelled"
//   forward or reverse "any" path                   -> n/a    "only non-exact edges connect source and sink"
//   otherwise                                       -> absent "no connection within <max_depth> edges"
// "absent" is a strong claim: the graph saw both ends and found nothing linking them.
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

export class InputError extends Error {}

const DEFAULT_MAX_DEPTH = 6;
const FINDING_ID = /^OSWE-[0-9]+$/;
const CHAIN_ID = /^CHAIN-[0-9]+$/;
const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isPositiveInteger = (v) => Number.isInteger(v) && v > 0;
const isLocation = (v) => isObject(v) && typeof v.file === "string" && Number.isInteger(v.line) && v.line >= 0;
const normalisePath = (p) => p.replace(/\\/g, "/").replace(/^(\.\/)+/, "");
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

// The innermost of the functions containing `line`: greatest line_start, then smallest line_end, then
// smaller id, so the choice does not depend on node order.
function innermost(fns, line) {
  let best = null;
  for (const fn of fns) {
    if (fn.line_start > line || line > fn.line_end) continue;
    if (best === null || fn.line_start > best.line_start || (fn.line_start === best.line_start && (fn.line_end < best.line_end || (fn.line_end === best.line_end && compare(fn.id, best.id) < 0)))) {
      best = fn;
    }
  }
  return best;
}

export function enclosingFn(graph, file, line) {
  const path = normalisePath(file);
  return innermost(graph.nodes.filter((n) => n.type === "function" && n.file === path), line);
}

function indexGraph(graph) {
  const fnsByFile = new Map(); // file -> function nodes
  for (const n of graph.nodes) {
    if (n.type !== "function") continue;
    if (fnsByFile.has(n.file)) fnsByFile.get(n.file).push(n);
    else fnsByFile.set(n.file, [n]);
  }
  const exact = new Map(); // function id -> callee ids over exact edges
  const any = new Map(); // function id -> callee ids over exact and name-only edges
  const push = (map, from, to) => (map.has(from) ? map.get(from).push(to) : map.set(from, [to]));
  for (const e of graph.edges) {
    if (e.type !== "calls" || e.to === null) continue;
    if (e.confidence === "exact") push(exact, e.from, e.to);
    if (e.confidence === "exact" || e.confidence === "name-only") push(any, e.from, e.to);
  }
  return { fnsByFile, exact, any };
}

const mapLocation = ({ fnsByFile }, { file, line }) => innermost(fnsByFile.get(normalisePath(file)) ?? [], line);

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

// ---- decision table ---------------------------------------------------------------------------------

function decide(index, fromLoc, toLoc, maxDepth) {
  const s = mapLocation(index, fromLoc);
  if (s === null) return verdict("n/a", "source line maps to no function");
  const k = mapLocation(index, toLoc);
  if (k === null) return verdict("n/a", "sink line maps to no function");
  if (s.id === k.id) return verdict("proven", "same function");
  const forward = distance(index.exact, s.id, k.id, maxDepth);
  if (forward !== null) return verdict("proven", `forward exact path (${forward} edges)`);
  if (distance(index.exact, k.id, s.id, maxDepth) !== null) return verdict("n/a", "return-value flow not modelled");
  if (distance(index.any, s.id, k.id, maxDepth) !== null || distance(index.any, k.id, s.id, maxDepth) !== null) {
    return verdict("n/a", "only non-exact edges connect source and sink");
  }
  return verdict("absent", `no connection within ${maxDepth} edges`);
}

function decideTransition(index, t, findingsById, maxDepth) {
  if (t.kind === undefined) return verdict("n/a", "transition has no kind");
  if (t.kind !== "call-path") return verdict("n/a", `transition kind ${t.kind} not structurally checkable`);
  if (t.from_anchor !== undefined && t.to_anchor !== undefined) return decide(index, t.from_anchor, t.to_anchor, maxDepth);
  const from = findingsById.get(t.from);
  const to = findingsById.get(t.to);
  if (from === undefined || to === undefined) return verdict("n/a", "transition references unknown finding");
  return decide(index, from.sink, to.source, maxDepth);
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
