import { test } from "node:test";
import assert from "node:assert/strict";
import { filterSarif } from "./stage-cases.mjs";

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
