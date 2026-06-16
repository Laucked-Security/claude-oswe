// Deterministic, order-independent aggregation of per-partition analyzer findings into canonical
// findings. aggregateFindings(rawFindings) -> { ok, error, findings }
//   rawFindings: union of all analyzer-response `findings` (partition-scoped ids like "auth-F001").
//   Source finding_ids must be globally UNIQUE (a duplicate is an analyzer/orchestrator bug).
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";

const SEV = ["Info", "Low", "Medium", "High"];                 // analyzer never emits Critical
const CONF = ["to verify", "likely", "strong static proof"];
const AUTH = ["unauthenticated", "authenticated", "admin"];        // index 0 = most exposed

// Canonical serialization (recursively key-sorted) so equivalent objects with differently-ordered
// properties produce the SAME key — and no control bytes are used as separators.
function canon(x) {
  if (Array.isArray(x)) return "[" + x.map(canon).join(",") + "]";
  if (x && typeof x === "object") return "{" + Object.keys(x).sort().map((k) => JSON.stringify(k) + ":" + canon(x[k])).join(",") + "}";
  return JSON.stringify(x);
}
const locKey = (l) => canon({ file: l.file, line: l.line, symbol: l.symbol, kind: l.kind });
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const cmpCanon = (a, b) => cmp(canon(a), canon(b));
const uniqSortedObjects = (arr) => {
  const m = new Map();
  for (const x of arr) m.set(canon(x), x);
  return [...m.values()].sort(cmpCanon);
};
const uniqSortedStrings = (arr) => [...new Set(arr)].sort(cmp);

export function aggregateFindings(rawFindings) {
  const seen = new Set();
  for (const f of rawFindings) {
    if (seen.has(f.finding_id)) return { ok: false, error: `duplicate analyzer finding_id ${f.finding_id}`, findings: [] };
    seen.add(f.finding_id);
  }

  const groups = new Map();
  for (const f of rawFindings) {
    const key = canon({ vuln_class: f.vuln_class, source: locKey(f.source), sink: locKey(f.sink) });
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }

  const merged = [];
  for (const group of groups.values()) {
    const rep = [...group].sort((a, b) => cmp(a.finding_id, b.finding_id))[0];
    const union = (sel) => uniqSortedObjects(group.flatMap((f) => f[sel] || []));
    merged.push({
      finding_id: "PENDING",
      partition_id: rep.partition_id,
      title: rep.title,
      vuln_class: rep.vuln_class,
      source: rep.source,
      sink: rep.sink,
      auth: AUTH[Math.min(...group.map((f) => AUTH.indexOf(f.auth)))],
      transformations: union("transformations"),
      sanitizers: union("sanitizers"),
      prerequisites: uniqSortedStrings(group.flatMap((f) => f.prerequisites || [])),
      evidence: union("evidence"),
      provisional_severity: SEV[Math.max(...group.map((f) => SEV.indexOf(f.provisional_severity)))],
      // Confidence = MINIMUM over the group (conservative): when analyzers disagree, the least-sure
      // wins rather than letting "strong static proof" mask an "to verify".
      confidence: CONF[Math.min(...group.map((f) => CONF.indexOf(f.confidence)))],
      verification_status: "not-requested",
      partitions: uniqSortedStrings(group.map((f) => f.partition_id)),
      source_finding_ids: uniqSortedStrings(group.map((f) => f.finding_id))
    });
  }

  merged.sort((a, b) =>
    cmp(a.source.file, b.source.file) || cmp(a.source.line, b.source.line) ||
    cmp(a.sink.file, b.sink.file) || cmp(a.sink.line, b.sink.line) || cmp(a.vuln_class, b.vuln_class) ||
    // Final tiebreaker = the full canonical dedupe key, so groups that share file+line+class but
    // differ in symbol/kind get a TOTAL order (numbering never depends on arrival order).
    cmp(canon({ vc: a.vuln_class, s: locKey(a.source), k: locKey(a.sink) }), canon({ vc: b.vuln_class, s: locKey(b.source), k: locKey(b.sink) })));
  merged.forEach((f, i) => { f.finding_id = `OSWE-${i + 1}`; });

  return { ok: true, error: null, findings: merged };
}

// CLI: node aggregate-findings.mjs --file <in.json> --out <out.json>
//   in.json: { "findings": [ ...rawFindings ] }   exit 0 ok / 1 !ok / 2 usage|IO
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const fi = args.indexOf("--file"), oi = args.indexOf("--out");
  if (fi === -1 || oi === -1) { process.stderr.write("usage: aggregate-findings.mjs --file <in.json> --out <out.json>\n"); process.exit(2); }
  let input;
  try { input = JSON.parse(readFileSync(args[fi + 1], "utf8")); }
  catch (e) { process.stderr.write("cannot read --file: " + e.message + "\n"); process.exit(2); }
  const result = aggregateFindings(input.findings || []);
  try { writeFileSync(args[oi + 1], JSON.stringify(result, null, 2)); }
  catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
  process.exit(result.ok ? 0 : 1);
}
