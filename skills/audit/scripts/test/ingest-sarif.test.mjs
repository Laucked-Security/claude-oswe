import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ingestSarif } from "../ingest-sarif.mjs";
import { sarifLead } from "../validators.mjs";

// Build a temp project with the given relative files (each gets a trivial body).
function project(files) {
  const root = mkdtempSync(join(tmpdir(), "oswe-sarif-"));
  for (const rel of files) {
    const abs = join(root, rel);
    mkdirSync(join(abs, ".."), { recursive: true });
    writeFileSync(abs, "x\n".repeat(50));
  }
  return root;
}
const result = (uri, region = { startLine: 5 }, extra = {}) => ({
  version: "2.1.0",
  runs: [{
    tool: { driver: { name: "Semgrep OSS", rules: [] } },
    results: [{ ruleId: "java.lang.security.audit.sqli.x", message: { text: "SQLi" },
      locations: [{ physicalLocation: { artifactLocation: { uri }, region } }], ...extra }]
  }]
});

test("a well-formed result becomes a valid, repo-relative lead with normalized tool", () => {
  const root = project(["src/Foo.java"]);
  const r = ingestSarif(root, JSON.stringify(result("src/Foo.java")));
  assert.equal(r.ok, true, r.error);
  assert.equal(r.leads.length, 1);
  const lead = r.leads[0];
  assert.equal(lead.lead_id, "L001");
  assert.equal(lead.tool, "semgrep");                 // "Semgrep OSS" -> semgrep (alias)
  assert.equal(lead.vuln_class_hint, "sqli");          // from rule map prefix
  assert.equal(lead.location.file, "src/Foo.java");    // repo-relative, POSIX
  assert.equal(lead.location.line, 5);
  assert.equal(Boolean(sarifLead(lead)), true, JSON.stringify(sarifLead.errors));
});

test("file:// URI is converted via fileURLToPath", () => {
  const root = project(["a.java"]);
  const r = ingestSarif(root, JSON.stringify(result(pathToFileURL(join(root, "a.java")).href)));
  assert.equal(r.leads.length, 1);
  assert.equal(r.leads[0].location.file, "a.java");
});

test("percent-encoded relative uri is decoded", () => {
  const root = project(["a b.java"]);
  const r = ingestSarif(root, JSON.stringify(result("a%20b.java")));
  assert.equal(r.leads.length, 1);
  assert.equal(r.leads[0].location.file, "a b.java");
});

test("uriBaseId is resolved against originalUriBaseIds", () => {
  const root = project(["sub/a.java"]);
  const doc = {
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "semgrep", rules: [] } },
      originalUriBaseIds: { SRCROOT: { uri: pathToFileURL(join(root, "sub") + "/").href } },
      results: [{ ruleId: "x", message: { text: "m" },
        locations: [{ physicalLocation: { artifactLocation: { uri: "a.java", uriBaseId: "SRCROOT" }, region: { startLine: 3 } } }] }]
    }]
  };
  const r = ingestSarif(root, JSON.stringify(doc));
  assert.equal(r.leads.length, 1);
  assert.equal(r.leads[0].location.file, "sub/a.java");
});

test("a non-file scheme is dropped (dropped_bad_uri)", () => {
  const root = project(["a.java"]);
  const r = ingestSarif(root, JSON.stringify(result("https://evil/x")));
  assert.equal(r.leads.length, 0);
  assert.equal(r.stats.dropped_bad_uri, 1);
});

test("a UNC file authority is rejected (dropped_bad_uri)", () => {
  const root = project(["a.java"]);
  const r = ingestSarif(root, JSON.stringify(result("file://server/share/a.java")));
  assert.equal(r.leads.length, 0);
  assert.equal(r.stats.dropped_bad_uri, 1);
});

test("a path escaping the root is dropped (dropped_out_of_scope)", () => {
  const root = project(["a.java"]);
  // Use a REAL file in a sibling temp dir (mirrors confine-path.test.mjs): the file must EXIST so
  // confinePath's realpathSync succeeds and the containment check — not ENOENT — fires. A literal
  // "../../etc/passwd" would be dropped_missing on Windows (C:\etc\passwd doesn't exist), masking
  // the escape path. This is cross-platform (Linux/macOS/Windows).
  const outside = mkdtempSync(join(tmpdir(), "oswe-outside-"));
  writeFileSync(join(outside, "evil.java"), "x\n");
  const r = ingestSarif(root, JSON.stringify(result(pathToFileURL(join(outside, "evil.java")).href)));
  assert.equal(r.leads.length, 0);
  assert.equal(r.stats.dropped_out_of_scope, 1);
});

test("a missing artifact is dropped not aborted (dropped_missing)", () => {
  const root = project(["a.java"]);
  const r = ingestSarif(root, JSON.stringify(result("does-not-exist.java")));
  assert.equal(r.ok, true);
  assert.equal(r.leads.length, 0);
  assert.equal(r.stats.dropped_missing, 1);
});

test("a location with no startLine is dropped (dropped_bad_location)", () => {
  const root = project(["a.java"]);
  const r = ingestSarif(root, JSON.stringify(result("a.java", {})));
  assert.equal(r.leads.length, 0);
  assert.equal(r.stats.dropped_bad_location, 1);
});

test("ruleId absent is resolved via rule.index", () => {
  const root = project(["a.java"]);
  const doc = {
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "semgrep", rules: [{ id: "java.lang.security.audit.xss.y" }] } },
      results: [{ rule: { index: 0 }, message: { text: "m" },
        locations: [{ physicalLocation: { artifactLocation: { uri: "a.java" }, region: { startLine: 1 } } }] }]
    }]
  };
  const r = ingestSarif(root, JSON.stringify(doc));
  assert.equal(r.leads[0].rule_id, "java.lang.security.audit.xss.y");
  assert.equal(r.leads[0].vuln_class_hint, "xss");
});

test("multi-run SARIF tags each result with its own run's tool", () => {
  const root = project(["a.java", "b.java"]);
  const doc = {
    version: "2.1.0",
    runs: [
      { tool: { driver: { name: "semgrep" } }, results: [{ ruleId: "x", message: { text: "m" }, locations: [{ physicalLocation: { artifactLocation: { uri: "a.java" }, region: { startLine: 1 } } }] }] },
      { tool: { driver: { name: "CodeQL" } }, results: [{ ruleId: "y", message: { text: "m" }, locations: [{ physicalLocation: { artifactLocation: { uri: "b.java" }, region: { startLine: 2 } } }] }] }
    ]
  };
  const r = ingestSarif(root, JSON.stringify(doc));
  assert.equal(r.leads.length, 2);
  assert.deepEqual(r.leads.map((l) => l.tool), ["semgrep", "codeql"]);
  assert.equal(r.leads[1].vuln_class_hint, "unknown");   // codeql has no map table
});

test("an over-long message is truncated to maxLength", () => {
  const root = project(["a.java"]);
  const doc = { version: "2.1.0", runs: [{ tool: { driver: { name: "semgrep" } }, results: [{ ruleId: "x",
    message: { text: "z".repeat(900) }, locations: [{ physicalLocation: { artifactLocation: { uri: "a.java" }, region: { startLine: 1 } } }] }] }] };
  const r = ingestSarif(root, JSON.stringify(doc));
  assert.ok(r.leads[0].message.length <= 512);
});

test("codeflow longer than 64 steps is truncated to 64 valid steps", () => {
  const root = project(["a.java"]);
  const steps = Array.from({ length: 80 }, () => ({ location: { physicalLocation: { artifactLocation: { uri: "a.java" }, region: { startLine: 1 } } } }));
  const doc = {
    version: "2.1.0",
    runs: [{ tool: { driver: { name: "semgrep" } }, results: [{ ruleId: "x", message: { text: "m" },
      locations: [{ physicalLocation: { artifactLocation: { uri: "a.java" }, region: { startLine: 1 } } }],
      codeFlows: [{ threadFlows: [{ locations: steps }] }] }] }]
  };
  const r = ingestSarif(root, JSON.stringify(doc));
  assert.equal(r.leads[0].codeflow.length, 64);
  assert.equal(r.ok, true);
});

test("malformed JSON returns ok:false (CLI would exit 1)", () => {
  const root = project([]);
  const r = ingestSarif(root, "{not json");
  assert.equal(r.ok, false);
});

test("missing runs[] returns ok:false", () => {
  const root = project([]);
  const r = ingestSarif(root, JSON.stringify({ version: "2.1.0" }));
  assert.equal(r.ok, false);
});

test("a non-2.1.0 SARIF version is rejected (ok:false)", () => {
  const root = project([]);
  const r = ingestSarif(root, JSON.stringify({ version: "2.0.0", runs: [] }));
  assert.equal(r.ok, false);
});
