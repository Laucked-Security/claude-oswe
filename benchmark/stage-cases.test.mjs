import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { filterSarif } from "./stage-cases.mjs";

const CLI = fileURLToPath(new URL("./stage-cases.mjs", import.meta.url));

function makeCorpus() {
  const root = mkdtempSync(join(tmpdir(), "oswe-stage-"));
  const corpus = join(root, "corpus");
  const testcode = join(corpus, "testcode");
  mkdirSync(testcode, { recursive: true });
  mkdirSync(join(corpus, "helpers"), { recursive: true });
  for (const id of ["BenchmarkTest00001", "BenchmarkTest00002", "BenchmarkTest00003"]) {
    writeFileSync(join(testcode, `${id}.java`), `// ${id}\n`);
  }
  const truthP = join(root, "truth.csv");
  writeFileSync(truthP, "# h\nBenchmarkTest00001,cmdi,true,78\nBenchmarkTest00002,sqli,false,89\nBenchmarkTest00003,xss,true,79\n");
  const sarifP = join(root, "s.sarif");
  writeFileSync(sarifP, JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "Semgrep" } }, results: [
    { ruleId: "r", locations: [{ physicalLocation: { artifactLocation: { uri: "x/BenchmarkTest00001.java" } } }] }
  ] }] }));
  return { corpus, truthP, sarifP, out: join(root, "stage") };
}

const sarif = {
  version: "2.1.0",
  runs: [{
    tool: { driver: { name: "Semgrep", rules: [] } },
    results: [
      { ruleId: "r1", locations: [{ physicalLocation: { artifactLocation: { uri: "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00006.java" }, region: { startLine: 62 } } }] },
      { ruleId: "r2", locations: [{ physicalLocation: { artifactLocation: { uri: "x/BenchmarkTest00007.java" }, region: { startLine: 61 } } }] },
      { ruleId: "r3", locations: [{ physicalLocation: { artifactLocation: { uri: "x/BenchmarkTest99999.java" }, region: { startLine: 1 } } }] }, // out of subset
      { ruleId: "r4", locations: [{ physicalLocation: { artifactLocation: { uri: "x/Helper.java" }, region: { startLine: 1 } } }] } // no test id
    ]
  }]
};

test("filterSarif keeps only requested ids and rewrites uris to the staged path", () => {
  const out = filterSarif(sarif, ["BenchmarkTest00006", "BenchmarkTest00007"], "external/bench-stage/cmdi");
  assert.equal(out.runs[0].results.length, 2);
  assert.deepEqual(
    out.runs[0].results.map((r) => r.locations[0].physicalLocation.artifactLocation.uri),
    ["external/bench-stage/cmdi/BenchmarkTest00006.java", "external/bench-stage/cmdi/BenchmarkTest00007.java"]
  );
});

test("filterSarif drops results outside the id set and non-testcase files", () => {
  const out = filterSarif(sarif, ["BenchmarkTest00006"], "stage/c");
  assert.equal(out.runs[0].results.length, 1);
  assert.equal(out.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "stage/c/BenchmarkTest00006.java");
});

test("filterSarif preserves SARIF 2.1.0 envelope + tool driver", () => {
  const out = filterSarif(sarif, ["BenchmarkTest00006"], "s");
  assert.equal(out.version, "2.1.0");
  assert.equal(out.runs[0].tool.driver.name, "Semgrep");
});

// --- SP6 Task 7: --all bulk staging + manifest ---
test("SP6: --all stages every truth case and writes a staging manifest", () => {
  const { corpus, truthP, sarifP, out } = makeCorpus();
  const r = spawnSync(process.execPath, [CLI, "--all", "--truth", truthP, "--sarif", sarifP, "--corpus", corpus, "--out", out], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  // Manifest lives in the stage dir (per-scope), so per-category staging doesn't clobber it.
  const manifest = JSON.parse(readFileSync(join(out, "all", "staged.json"), "utf8"));
  assert.deepEqual([...manifest.staged].sort(), ["BenchmarkTest00001", "BenchmarkTest00002", "BenchmarkTest00003"]);
  assert.ok(existsSync(join(out, "all", "BenchmarkTest00002.java")));
});

test("SP6: --all does not require --category or --subset", () => {
  const { corpus, truthP, sarifP, out } = makeCorpus();
  const r = spawnSync(process.execPath, [CLI, "--all", "--truth", truthP, "--sarif", sarifP, "--corpus", corpus, "--out", out], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
});

test("SP6: --category X --all stages the FULL category (no --subset)", () => {
  const { corpus, truthP, sarifP, out } = makeCorpus(); // truth: 00001 cmdi, 00002 sqli, 00003 xss
  const r = spawnSync(process.execPath, [CLI, "--category", "cmdi", "--all", "--truth", truthP, "--sarif", sarifP, "--corpus", corpus, "--out", out], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const manifest = JSON.parse(readFileSync(join(out, "cmdi", "staged.json"), "utf8"));
  assert.deepEqual(manifest.staged, ["BenchmarkTest00001"]); // only the cmdi case, not the subset of 8
  assert.ok(existsSync(join(out, "cmdi", "BenchmarkTest00001.java")));
});
