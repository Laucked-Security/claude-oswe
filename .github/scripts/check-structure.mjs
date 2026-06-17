#!/usr/bin/env node
// Structure / consistency gate for the oswe plugin — zero runtime deps, Node >= 20.
// Asserts the invariants that keep the audit pipeline honest and reviewable:
//   1. Every supported stack has a source->sink reference in skills/audit/references/.
//   2. The stack list is identical across: this gate, plugin.json description, and README.
//   3. Every test-fixtures/<stack>/vulnerable has EXPECTED.md AND at least one "VULN" marker.
//   4. Every test-fixtures/<stack>/safe exists and has NO EXPECTED.md (it is a negative control).
//   5. Each plugin schema has a matching validator name exported by validators.mjs (sanity).
// Exit 0 = all good; exit 1 = a violation (printed); exit 2 = the gate itself failed to run.
import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const STACKS = ["php", "node", "python", "java", "dotnet"];
const errors = [];
const ok = (m) => console.log(`  ok  ${m}`);
const bad = (m) => { errors.push(m); console.log(`  XX  ${m}`); };

const read = (p) => readFileSync(join(ROOT, p), "utf8");
const walk = (dir) => {
  const out = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
};

console.log("1) stack <-> reference parity");
for (const s of STACKS) {
  const ref = `skills/audit/references/${s}.md`;
  existsSync(join(ROOT, ref)) ? ok(ref) : bad(`missing reference for stack "${s}": ${ref}`);
}
// no stray reference files for unknown stacks
for (const f of readdirSync(join(ROOT, "skills/audit/references"))) {
  const s = f.replace(/\.md$/, "");
  if (f.endsWith(".md") && !STACKS.includes(s)) bad(`reference for unknown stack: ${f}`);
}

console.log("2) stack list consistency (gate vs plugin.json vs README)");
const pluginDesc = JSON.parse(read(".claude-plugin/plugin.json")).description || "";
const readme = read("README.md");
const labels = { php: "PHP", node: "Node", python: "Python", java: "Java", dotnet: ".NET" };
for (const s of STACKS) {
  pluginDesc.includes(labels[s]) ? ok(`plugin.json mentions ${labels[s]}`) : bad(`plugin.json description missing stack ${labels[s]}`);
  readme.includes(labels[s]) ? ok(`README mentions ${labels[s]}`) : bad(`README missing stack ${labels[s]}`);
}

console.log("3) vulnerable fixtures: EXPECTED.md + VULN marker");
for (const s of STACKS) {
  const dir = `test-fixtures/${s}/vulnerable`;
  const abs = join(ROOT, dir);
  if (!existsSync(abs)) { bad(`missing vulnerable fixture dir: ${dir}`); continue; }
  existsSync(join(abs, "EXPECTED.md")) ? ok(`${dir}/EXPECTED.md`) : bad(`${dir} missing EXPECTED.md`);
  const hasVuln = walk(abs).some((p) => {
    if (/EXPECTED\.md$/.test(p)) return false;
    try { return /\bVULN\b/.test(readFileSync(p, "utf8")); } catch { return false; }
  });
  hasVuln ? ok(`${dir} has a VULN marker`) : bad(`${dir} has no "VULN" marker in any source file`);
}

console.log("4) safe fixtures: present, NO EXPECTED.md (negative control)");
for (const s of STACKS) {
  const dir = `test-fixtures/${s}/safe`;
  const abs = join(ROOT, dir);
  if (!existsSync(abs)) { bad(`missing safe fixture dir: ${dir}`); continue; }
  existsSync(join(abs, "EXPECTED.md")) ? bad(`${dir} must NOT contain EXPECTED.md (it is a negative control)`) : ok(`${dir} (no EXPECTED.md)`);
}

console.log("5) schema <-> validator parity");
const validators = read("skills/audit/scripts/validators.mjs");
for (const f of readdirSync(join(ROOT, "skills/audit/schemas"))) {
  if (!f.endsWith(".schema.json")) continue;
  // validators.mjs exports the camelCased schema base, e.g. analyzer-response -> analyzerResponse
  const base = f.replace(/\.schema\.json$/, "");
  const exportName = base.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
  const re = new RegExp(`export const ${exportName}\\b`);
  re.test(validators) ? ok(`${f} -> export const ${exportName}`) : bad(`${f}: no "export const ${exportName}" in validators.mjs`);
}

console.log("6) sarif-rule-map.json validity");
try {
  const map = JSON.parse(read("skills/audit/references/sarif-rule-map.json"));
  const tools = Object.keys(map);
  tools.length ? ok(`sarif-rule-map has ${tools.length} tool(s): ${tools.join(", ")}`) : bad("sarif-rule-map.json has no tools");
  for (const t of tools) {
    if (!Array.isArray(map[t])) { bad(`sarif-rule-map["${t}"] is not an array`); continue; }
    for (const e of map[t]) {
      if (typeof e.vuln_class !== "string" || !e.vuln_class) bad(`sarif-rule-map["${t}"] entry missing vuln_class`);
      if (typeof e.prefix !== "string" && typeof e.rule !== "string") bad(`sarif-rule-map["${t}"] entry needs prefix or rule`);
    }
  }
  map.semgrep ? ok("sarif-rule-map has a semgrep table") : bad("sarif-rule-map.json missing 'semgrep' tool");
} catch (e) { bad("sarif-rule-map.json is not valid JSON: " + e.message); }

console.log("");
if (errors.length) {
  console.error(`FAIL: ${errors.length} structure violation(s).`);
  process.exit(1);
}
console.log("PASS: structure & consistency checks green.");
