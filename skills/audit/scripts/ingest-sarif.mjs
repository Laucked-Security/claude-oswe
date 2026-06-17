// Normalizes a SARIF 2.1.0 document into confined, length-bounded "leads" for the oswe audit.
// ingestSarif(projectDir, sarifText, ruleMap?) -> { ok, error, leads, stats }
// CLI: node ingest-sarif.mjs --file <input.json> --out <leads.json>
//   input.json: { "projectDir": "<abs>", "sarifPath": "<path under projectDir>" }
//   exit 0 ok / 1 malformed SARIF or a self-built lead that fails its schema / 2 IO|usage.
import { fileURLToPath, pathToFileURL } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";
import { relative, isAbsolute, resolve, sep } from "node:path";
import { confinePath } from "./confine-path.mjs";
import { sarifLead } from "./validators.mjs";

const MAX = { rule_id: 256, vuln_class_hint: 64, file: 1024, message: 512 };
const MAX_CODEFLOW = 64;
const ALIAS = { "semgrep-oss": "semgrep" };
const DROP_STAT = { bad_location: "dropped_bad_location", bad_uri: "dropped_bad_uri", missing: "dropped_missing", out_of_scope: "dropped_out_of_scope" };

const zeroStats = () => ({ total: 0, kept: 0, dropped_out_of_scope: 0, dropped_missing: 0, dropped_bad_uri: 0, dropped_bad_location: 0, unmapped_rules: 0 });

// UTF-8-safe truncation by code points, ellipsis on overflow.
function trunc(s, max) {
  if (typeof s !== "string") return "";
  const cp = Array.from(s);
  return cp.length <= max ? s : cp.slice(0, max - 1).join("") + "…";
}

function normTool(name) {
  if (typeof name !== "string" || !name.trim()) return "unknown";
  const k = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return ALIAS[k] || k || "unknown";
}

function loadDefaultRuleMap() {
  try { return JSON.parse(readFileSync(fileURLToPath(new URL("../references/sarif-rule-map.json", import.meta.url)), "utf8")); }
  catch { return {}; }
}

function mapVulnClass(tool, ruleId, ruleMap) {
  const table = ruleMap[tool];
  if (!Array.isArray(table) || !ruleId) return "unknown";
  for (const e of table) {
    if (e.rule === ruleId) return e.vuln_class;
    if (typeof e.prefix === "string" && ruleId.startsWith(e.prefix)) return e.vuln_class;
  }
  return "unknown";
}

// SARIF artifactLocation.uri (+ uriBaseId) -> absolute fs path string, or throw { tag } on a bad uri.
function uriToFsPath(uri, uriBaseId, baseUris, projectDir) {
  if (typeof uri !== "string" || !uri) { const e = new Error("no uri"); e.tag = "bad_uri"; throw e; }
  let p;
  const scheme = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(uri);
  if (scheme) {
    if (scheme[1].toLowerCase() !== "file") { const e = new Error("non-file scheme"); e.tag = "bad_uri"; throw e; }
    const auth = /^file:\/\/([^/]*)\//.exec(uri);
    if (auth && auth[1] && auth[1].toLowerCase() !== "localhost") { const e = new Error("non-local authority"); e.tag = "bad_uri"; throw e; }
    try { p = fileURLToPath(uri); } catch { const e = new Error("bad file uri"); e.tag = "bad_uri"; throw e; }
  } else {
    try { p = decodeURIComponent(uri); } catch { const e = new Error("bad percent-encoding"); e.tag = "bad_uri"; throw e; }
  }
  if (!isAbsolute(p)) {
    if (uriBaseId && baseUris && baseUris[uriBaseId] && typeof baseUris[uriBaseId].uri === "string") {
      let base = baseUris[uriBaseId].uri;
      try { base = base.startsWith("file:") ? fileURLToPath(base) : decodeURIComponent(base); } catch { /* use raw */ }
      p = resolve(isAbsolute(base) ? base : resolve(projectDir, base), p);
    } else {
      p = resolve(projectDir, p);
    }
  }
  return p;
}

// Resolve a SARIF Location to a confined { file, line }, or { drop: <reason> }.
function resolveLocation(location, baseUris, projectDir, realRoot) {
  const phys = location && location.physicalLocation;
  if (!phys) return { drop: "bad_location" };
  const line = phys.region && phys.region.startLine;
  if (!Number.isInteger(line) || line < 1) return { drop: "bad_location" };
  const al = phys.artifactLocation || {};
  let abs;
  try { abs = uriToFsPath(al.uri, al.uriBaseId, baseUris, projectDir); }
  catch { return { drop: "bad_uri" }; }
  let real;
  try { real = confinePath(projectDir, abs); }
  catch (e) { return { drop: e.code === "ENOENT" ? "missing" : "out_of_scope" }; }
  return { file: trunc(relative(realRoot, real).split(sep).join("/"), MAX.file), line };
}

export function ingestSarif(projectDir, sarifText, ruleMap = loadDefaultRuleMap()) {
  let doc;
  try { doc = JSON.parse(sarifText); }
  catch (e) { return { ok: false, error: "malformed SARIF: not JSON (" + e.message + ")", leads: [], stats: zeroStats() }; }
  if (!doc || typeof doc !== "object" || !Array.isArray(doc.runs)) {
    return { ok: false, error: "malformed SARIF: missing runs[]", leads: [], stats: zeroStats() };
  }
  if (doc.version !== "2.1.0") {
    return { ok: false, error: "unsupported SARIF version: " + doc.version + " (expected 2.1.0)", leads: [], stats: zeroStats() };
  }
  let realRoot;
  try { realRoot = confinePath(projectDir, "."); }
  catch (e) { return { ok: false, error: "bad projectDir: " + e.message, leads: [], stats: zeroStats() }; }

  const stats = zeroStats();
  const leads = [];
  let n = 0;
  for (const run of doc.runs) {
    const tool = normTool(run && run.tool && run.tool.driver && run.tool.driver.name);
    const baseUris = (run && run.originalUriBaseIds) || null;
    const rules = (run && run.tool && run.tool.driver && run.tool.driver.rules) || [];
    for (const res of (run && run.results) || []) {
      stats.total++;
      const primary = resolveLocation((res.locations || [])[0], baseUris, projectDir, realRoot);
      if (primary.drop) { stats[DROP_STAT[primary.drop]]++; continue; }

      let ruleId = typeof res.ruleId === "string" ? res.ruleId
        : (res.rule && typeof res.rule.id === "string") ? res.rule.id
          : (res.rule && Number.isInteger(res.rule.index) && rules[res.rule.index] && rules[res.rule.index].id) ? rules[res.rule.index].id
            : "";
      ruleId = ruleId || "unknown";
      const vc = mapVulnClass(tool, ruleId, ruleMap);
      if (vc === "unknown") stats.unmapped_rules++;

      const codeflow = [];
      const flow = (((res.codeFlows || [])[0] || {}).threadFlows || [])[0];
      for (const step of (flow && flow.locations) || []) {
        if (codeflow.length >= MAX_CODEFLOW) break;
        const sr = resolveLocation(step.location, baseUris, projectDir, realRoot);
        if (!sr.drop) codeflow.push(sr);
      }

      const lead = {
        lead_id: "L" + String(++n).padStart(3, "0"),
        tool: trunc(tool, 64),
        rule_id: trunc(ruleId, MAX.rule_id),
        vuln_class_hint: trunc(vc, MAX.vuln_class_hint),
        location: primary,
        message: trunc((res.message && res.message.text) || "", MAX.message)
      };
      if (codeflow.length) lead.codeflow = codeflow;

      if (!sarifLead(lead)) {
        return { ok: false, error: "self-built lead failed sarif-lead schema: " + JSON.stringify(sarifLead.errors), leads: [], stats };
      }
      leads.push(lead);
      stats.kept++;
    }
  }
  return { ok: true, error: null, leads, stats };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const fi = args.indexOf("--file"), oi = args.indexOf("--out");
  if (fi === -1 || !args[fi + 1] || oi === -1 || !args[oi + 1]) {
    process.stderr.write("usage: ingest-sarif.mjs --file <input.json> --out <leads.json>\n"); process.exit(2);
  }
  let input;
  try { input = JSON.parse(readFileSync(args[fi + 1], "utf8")); }
  catch (e) { process.stderr.write("cannot read --file: " + e.message + "\n"); process.exit(2); }
  if (typeof input.projectDir !== "string" || typeof input.sarifPath !== "string") {
    process.stderr.write("bad input: projectDir and sarifPath must be strings\n"); process.exit(2);
  }
  let sarifReal;
  try { sarifReal = confinePath(input.projectDir, input.sarifPath); }
  catch (e) { process.stderr.write("sarifPath rejected: " + e.message + "\n"); process.exit(2); }
  let text;
  try { text = readFileSync(sarifReal, "utf8"); }
  catch (e) { process.stderr.write("cannot read sarif: " + e.message + "\n"); process.exit(2); }
  const r = ingestSarif(input.projectDir, text);
  try { writeFileSync(args[oi + 1], JSON.stringify(r, null, 2)); }
  catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
  process.exit(r.ok ? 0 : 1);
}
