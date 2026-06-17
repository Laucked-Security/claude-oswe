// Deterministically regenerate benchmark/subset-owasp.json from the OWASP BenchmarkJava ground truth.
// Zero deps, Node >= 20. The OWASP corpus itself is NOT committed (clone it under external/, gitignored):
//   git clone https://github.com/OWASP-Benchmark/BenchmarkJava external/BenchmarkJava
// Usage:
//   node benchmark/make-subset.mjs --truth external/BenchmarkJava/expectedresults-1.2.csv --out benchmark/subset-owasp.json [--per 4]
// Picks up to `per` real + `per` non-vulnerable cases PER CWE category, chosen by ascending test id
// (so the subset is reproducible and balanced). Cases outside the subset are coverage gaps, not scored.
import { readFileSync, writeFileSync } from "node:fs";

function parseTruth(text) {
  return text.split(/\r?\n/).slice(1)
    .filter((l) => l && !l.startsWith("#"))
    .map((l) => { const p = l.split(","); return { id: p[0].trim(), cat: p[1].trim(), real: p[2].trim() === "true", cwe: Number(p[3]) }; })
    .filter((r) => /^BenchmarkTest\d{5}$/.test(r.id));
}

export function buildSubset(rows, per) {
  const byCat = {};
  for (const r of rows) (byCat[r.cat] ??= []).push(r);
  const pick = [];
  for (const cat of Object.keys(byCat).sort()) {
    const list = byCat[cat].sort((a, b) => (a.id < b.id ? -1 : 1));
    pick.push(...list.filter((r) => r.real).slice(0, per), ...list.filter((r) => !r.real).slice(0, per));
  }
  return pick.sort((a, b) => (a.id < b.id ? -1 : 1));
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1].replace(/\\/g, "/")}`).href) {
  const args = process.argv.slice(2);
  const get = (f, d) => { const i = args.indexOf(f); return i === -1 ? d : args[i + 1]; };
  const truthPath = get("--truth"), outPath = get("--out"), per = Number(get("--per", "4"));
  if (!truthPath || !outPath) { process.stderr.write("usage: make-subset.mjs --truth <csv> --out <json> [--per 4]\n"); process.exit(2); }
  let rows;
  try { rows = parseTruth(readFileSync(truthPath, "utf8")); }
  catch (e) { process.stderr.write("cannot read --truth: " + e.message + "\n"); process.exit(2); }
  if (!rows.length) { process.stderr.write("no BenchmarkTest rows parsed from truth CSV\n"); process.exit(1); }
  const pick = buildSubset(rows, per);
  const manifest = {
    dataset: "owasp-benchmark-java-1.2",
    source: "https://github.com/OWASP-Benchmark/BenchmarkJava (expectedresults-1.2.csv)",
    note: `Stratified declared in-scope subset: up to ${per} real + ${per} non-vulnerable per CWE category, deterministic by ascending test id. Cases outside this list are recorded as coverage gaps, not scored. Regenerate with make-subset.mjs.`,
    generated: new Date().toISOString().slice(0, 10),
    per_category_real_and_not: per,
    count: pick.length,
    test_ids: pick.map((p) => p.id)
  };
  try { writeFileSync(outPath, JSON.stringify(manifest, null, 2) + "\n"); }
  catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
  process.stdout.write(`wrote ${outPath}: ${pick.length} ids (${pick.filter((p) => p.real).length} real / ${pick.filter((p) => !p.real).length} not)\n`);
}
