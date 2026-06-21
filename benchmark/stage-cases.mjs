// Stage one OWASP BenchmarkJava category for a scoped /oswe:audit --sarif run.
// Maintainer tooling, zero deps, Node >= 20. Outputs land under the gitignored external/.
//
// For the given category it: (1) copies that category's SUBSET testcode files into <out>/<cat>/,
// (2) copies the ENTIRE helpers/ tree into <out>/<cat>/org/owasp/benchmark/helpers/ (so any "safe
// source"/taint-barrier helper a case references — e.g. SeparateClassRequest.getTheValue → "bar" — is
// in audit scope; omitting them caused a false promotion once), and (3) filters the full Semgrep SARIF
// to that category's cases and rewrites each uri to the staged, repo-root-relative path.
//
// CLI:
//   node benchmark/stage-cases.mjs --category cmdi \
//     --subset benchmark/subset-owasp.json --truth external/BenchmarkJava/expectedresults-1.2.csv \
//     --sarif external/owasp-semgrep.sarif \
//     --corpus external/BenchmarkJava/src/main/java/org/owasp/benchmark \
//     --out external/bench-stage
// Prints the exact /oswe:audit command to run. exit 0 ok / 1 bad input / 2 IO|usage.
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

function subsetIdsForCategory(subset, truthCsv, category) {
  const cat = new Map();
  for (const l of truthCsv.split(/\r?\n/).slice(1)) {
    if (!l || l.startsWith("#")) continue;
    const p = l.split(",");
    if (/^BenchmarkTest\d{5}$/.test(p[0].trim())) cat.set(p[0].trim(), p[1].trim());
  }
  return subset.test_ids.filter((id) => cat.get(id) === category);
}

// All BenchmarkTestNNNNN ids present in the truth CSV (the full-2740 staging set, SP6 --all).
export function allTruthIds(truthCsv) {
  const ids = [];
  for (const l of truthCsv.split(/\r?\n/).slice(1)) {
    const t = l.trim();
    if (!t || t.startsWith("#")) continue;
    const id = t.split(",")[0].trim();
    if (/^BenchmarkTest\d{5}$/.test(id)) ids.push(id);
  }
  return ids;
}

// Copy a source tree into scope. Includes the file kinds a fixture might read to decide its own
// behaviour: .java (helpers/sources), .properties (benchmark.properties → hashAlg1/cryptoAlg1), .xml
// (e.g. xpathi's employees.xml). Other artifacts are skipped to keep the staged scope tight.
const STAGE_EXT = /\.(java|properties|xml)$/;
function copyTree(srcDir, dstDir) {
  mkdirSync(dstDir, { recursive: true });
  for (const e of readdirSync(srcDir)) {
    const s = join(srcDir, e), d = join(dstDir, e);
    if (statSync(s).isDirectory()) copyTree(s, d);
    else if (STAGE_EXT.test(e)) copyFileSync(s, d);
  }
}

// Filter+rewrite a Semgrep SARIF to only the given test ids; uri -> "<stageRel>/<id>.java".
export function filterSarif(sarif, ids, stageRel) {
  const run = (sarif.runs || [])[0];
  const want = new Set(ids);
  const results = [];
  for (const res of (run && run.results) || []) {
    const al = (((res.locations || [])[0] || {}).physicalLocation || {}).artifactLocation;
    const m = /BenchmarkTest(\d{5})/.exec((al && al.uri) || "");
    if (!m) continue;
    const id = "BenchmarkTest" + m[1];
    if (!want.has(id)) continue;
    res.locations[0].physicalLocation.artifactLocation.uri = `${stageRel}/${id}.java`;
    results.push(res);
  }
  return { version: "2.1.0", $schema: sarif.$schema || "https://json.schemastore.org/sarif-2.1.0.json", runs: [{ tool: run.tool, results }] };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const get = (f) => { const i = args.indexOf(f); return i === -1 ? null : args[i + 1]; };
  const all = args.includes("--all");
  const category = get("--category"), subsetPath = get("--subset"), truthPath = get("--truth"),
    sarifPath = get("--sarif"), corpus = get("--corpus"), outBase = get("--out") || "external/bench-stage";
  if (!truthPath || !sarifPath || !corpus || (!all && (!category || !subsetPath))) {
    process.stderr.write("usage: stage-cases.mjs (--all | --category <c> --subset <j>) --truth <csv> --sarif <s> --corpus <benchmarkRoot> [--out external/bench-stage]\n");
    process.exit(2);
  }
  let subset = null, truth, sarif;
  try { truth = readFileSync(truthPath, "utf8"); sarif = JSON.parse(readFileSync(sarifPath, "utf8")); if (subsetPath) subset = JSON.parse(readFileSync(subsetPath, "utf8")); }
  catch (e) { process.stderr.write("cannot read input: " + e.message + "\n"); process.exit(2); }

  const label = all ? "all" : category;
  const ids = all ? allTruthIds(truth) : subsetIdsForCategory(subset, truth, category);
  if (!ids.length) { process.stderr.write(all ? "truth has no BenchmarkTest cases\n" : `no subset cases for category "${category}"\n`); process.exit(1); }

  const stageRel = `${outBase}/${label}`;
  const testSrc = join(corpus, "testcode");
  const helpersSrc = join(corpus, "helpers");
  mkdirSync(stageRel, { recursive: true });
  for (const id of ids) {
    try { copyFileSync(join(testSrc, `${id}.java`), join(stageRel, `${id}.java`)); }
    catch (e) { process.stderr.write(`cannot copy ${id}: ${e.message}\n`); process.exit(2); }
  }
  copyTree(helpersSrc, join(stageRel, "org", "owasp", "benchmark", "helpers")); // full helpers tree in scope

  // Stage src/main/resources too: some cases read their algorithm/config from benchmark.properties
  // (e.g. hash cases do getProperty("hashAlg1","SHA512") but the file sets hashAlg1=MD5). Without the
  // properties in scope the analyzer can only see the strong-looking default and misjudges the case.
  const resourcesSrc = join(corpus, "..", "..", "..", "..", "resources"); // src/main/java/org/owasp/benchmark -> src/main/resources
  let stagedResources = 0;
  try { copyTree(resourcesSrc, join(stageRel, "resources")); stagedResources = 1; } catch { /* resources optional */ }

  const filtered = filterSarif(sarif, ids, stageRel);
  writeFileSync(`${outBase}/${label}.sarif`, JSON.stringify(filtered, null, 2));

  // Staging manifest: the reproducible STAGED scope (feeds report.json run.benchmark_test_ids[]).
  // Written INSIDE the stage dir (per-scope) so per-category staging does not clobber one shared file.
  // NB: this is the staged set, NOT the analyzed set — the budget may deprioritize some (#R3.3/#R4.1).
  writeFileSync(`${stageRel}/staged.json`, JSON.stringify({ generated: new Date().toISOString().slice(0, 10), label, count: ids.length, staged: ids }, null, 2) + "\n");

  process.stdout.write(
    `staged ${ids.length} ${label} cases + helpers${stagedResources ? " + resources" : ""} -> ${stageRel}\n` +
    `SARIF leads: ${filtered.runs[0].results.length} -> ${outBase}/${label}.sarif\n` +
    `manifest: ${stageRel}/staged.json (${ids.length} ids)\n` +
    `RUN:  /oswe:audit --sarif ${outBase}/${label}.sarif ${stageRel}\n`
  );
  process.exit(0);
}
