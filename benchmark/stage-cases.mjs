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

function copyTree(srcDir, dstDir) {
  mkdirSync(dstDir, { recursive: true });
  for (const e of readdirSync(srcDir)) {
    const s = join(srcDir, e), d = join(dstDir, e);
    if (statSync(s).isDirectory()) copyTree(s, d);
    else if (e.endsWith(".java")) copyFileSync(s, d);
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
  const category = get("--category"), subsetPath = get("--subset"), truthPath = get("--truth"),
    sarifPath = get("--sarif"), corpus = get("--corpus"), outBase = get("--out") || "external/bench-stage";
  if (!category || !subsetPath || !truthPath || !sarifPath || !corpus) {
    process.stderr.write("usage: stage-cases.mjs --category <c> --subset <j> --truth <csv> --sarif <s> --corpus <benchmarkRoot> [--out external/bench-stage]\n");
    process.exit(2);
  }
  let subset, truth, sarif;
  try { subset = JSON.parse(readFileSync(subsetPath, "utf8")); truth = readFileSync(truthPath, "utf8"); sarif = JSON.parse(readFileSync(sarifPath, "utf8")); }
  catch (e) { process.stderr.write("cannot read input: " + e.message + "\n"); process.exit(2); }

  const ids = subsetIdsForCategory(subset, truth, category);
  if (!ids.length) { process.stderr.write(`no subset cases for category "${category}"\n`); process.exit(1); }

  const stageRel = `${outBase}/${category}`;
  const testSrc = join(corpus, "testcode");
  const helpersSrc = join(corpus, "helpers");
  mkdirSync(stageRel, { recursive: true });
  for (const id of ids) {
    try { copyFileSync(join(testSrc, `${id}.java`), join(stageRel, `${id}.java`)); }
    catch (e) { process.stderr.write(`cannot copy ${id}: ${e.message}\n`); process.exit(2); }
  }
  copyTree(helpersSrc, join(stageRel, "org", "owasp", "benchmark", "helpers")); // full helpers tree in scope

  const filtered = filterSarif(sarif, ids, stageRel);
  writeFileSync(`${outBase}/${category}.sarif`, JSON.stringify(filtered, null, 2));

  process.stdout.write(
    `staged ${ids.length} ${category} cases + helpers -> ${stageRel}\n` +
    `SARIF leads: ${filtered.runs[0].results.length} -> ${outBase}/${category}.sarif\n` +
    `RUN:  /oswe:audit --sarif ${outBase}/${category}.sarif ${stageRel}\n`
  );
  process.exit(0);
}
