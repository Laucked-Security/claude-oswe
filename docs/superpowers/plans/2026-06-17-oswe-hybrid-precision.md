# OSWE Hybrid Precision Auditor (SP1+SP2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add SARIF ingestion + LLM precision triage + hybrid (LLM ⊕ SAST) union to the `oswe` plugin, plus a deterministic benchmark engine that scores precision/recall vs raw Semgrep on the OWASP Benchmark.

**Architecture:** Grafts onto the **ends** of the existing pipeline only. A new zero-dep helper `ingest-sarif.mjs` normalizes SARIF results into confined, bounded *leads*; the analyzer adjudicates each lead (promote→finding / refute / inconclusive); the existing deterministic aggregate→verify→verdict→report core is untouched except for carrying a new `origin`/`source_lead_ids` through the aggregator. A separate `benchmark/metrics.mjs` engine computes three confusion matrices from a sanitized run *ledger* + the OWASP ground-truth CSV.

**Tech Stack:** Node ≥ 20, ESM, `node --test`, JSON Schema (AJV dev-only via `build-validators.mjs`), zero runtime dependencies. Spec: `docs/superpowers/specs/2026-06-17-oswe-hybrid-precision-design.md`.

---

## File Structure

**New files:**
- `skills/audit/schemas/sarif-lead.schema.json` — the 8th schema (a normalized SARIF lead).
- `skills/audit/references/sarif-rule-map.json` — per-tool rule-id → `vuln_class` advisory table.
- `skills/audit/scripts/ingest-sarif.mjs` — SARIF → leads helper (+ CLI).
- `skills/audit/scripts/test/ingest-sarif.test.mjs` — its unit tests.
- `benchmark/metrics.mjs` — deterministic benchmark metrics engine (+ CLI).
- `benchmark/metrics.test.mjs` — its unit tests.
- `benchmark/fixtures/sample-ledger.json`, `benchmark/fixtures/sample-truth.csv` — committed test fixtures.
- `benchmark/subset-owasp.json` — declared in-scope OWASP test-id manifest (starter).
- `benchmark/README.md` — the manual run-orchestration procedure.

**Modified files:**
- `skills/audit/schemas/finding.schema.json`, `final-finding.schema.json` — add `origin`, `source_lead_ids`.
- `skills/audit/schemas/analyzer-response.schema.json` — add `adjudicated_leads[]`; forbid `origin:"both"` in raw analyzer findings.
- `skills/audit/scripts/build-validators.mjs` — register `sarif-lead` → `sarifLead`.
- `skills/audit/scripts/validators.mjs` — REGENERATED (never hand-edited).
- `skills/audit/scripts/aggregate-findings.mjs` + `test/aggregate-findings.test.mjs` — carry `origin`/`source_lead_ids` through the merge.
- `.github/scripts/check-structure.mjs` — validate `sarif-rule-map.json`.
- `.github/workflows/ci.yml` — add a `benchmark/` `node --test` step.
- `skills/audit/SKILL.md` — `--sarif` parse (§1), lead assignment (§2), adjudication (§3), gated report sections (§7).
- `agents/oswe-analyzer.md` — instruct lead adjudication + `origin`.

**Conventions to follow (from the existing code):**
- Helpers: ESM, `export function …`, then a `if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) { … }` CLI block. Exit `0` ok / `1` invalid input / `2` IO|usage.
- Tests: `node:test` + `node:assert/strict`; create temp project dirs with `mkdtempSync(join(tmpdir(), …))` and write **real files** when a path must pass `confinePath` (it calls `realpathSync`).
- After ANY schema change: run `npm run build` (regenerates `validators.mjs`) then `node --test`.

---

## Task 1: `sarif-lead` schema + build wiring + regeneration

**Files:**
- Create: `skills/audit/schemas/sarif-lead.schema.json`
- Modify: `skills/audit/scripts/build-validators.mjs:19-27` (EXPORT_NAME map)
- Modify (regenerate): `skills/audit/scripts/validators.mjs`
- Test: `skills/audit/scripts/test/sarif-lead.test.mjs` (create)

- [ ] **Step 1: Write the failing test**

Create `skills/audit/scripts/test/sarif-lead.test.mjs`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import { sarifLead } from "../validators.mjs";

const ok = {
  lead_id: "L001", tool: "semgrep", rule_id: "java.lang.security.audit.command-injection",
  vuln_class_hint: "command-injection", location: { file: "src/Foo.java", line: 42 },
  message: "Detected command injection"
};

test("a well-formed sarif-lead validates", () => {
  assert.equal(Boolean(sarifLead(ok)), true, JSON.stringify(sarifLead.errors));
});

test("optional codeflow validates", () => {
  assert.equal(Boolean(sarifLead({ ...ok, codeflow: [{ file: "src/A.java", line: 1 }, { file: "src/B.java", line: 9 }] })), true);
});

test("lead_id must match ^L[0-9]{3,}$", () => {
  assert.equal(Boolean(sarifLead({ ...ok, lead_id: "X1" })), false);
});

test("line < 1 is rejected", () => {
  assert.equal(Boolean(sarifLead({ ...ok, location: { file: "a", line: 0 } })), false);
});

test("unknown property is rejected (additionalProperties:false)", () => {
  assert.equal(Boolean(sarifLead({ ...ok, level: "error" })), false);
});

test("over-long rule_id is rejected (maxLength 256)", () => {
  assert.equal(Boolean(sarifLead({ ...ok, rule_id: "x".repeat(257) })), false);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/audit/scripts && node --test test/sarif-lead.test.mjs`
Expected: FAIL — `sarifLead` is not exported by `validators.mjs` (import is `undefined`, call throws).

- [ ] **Step 3: Create the schema**

Create `skills/audit/schemas/sarif-lead.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "sarif-lead.schema.json",
  "title": "OSWE SARIF Lead",
  "type": "object",
  "additionalProperties": false,
  "required": ["lead_id", "tool", "rule_id", "vuln_class_hint", "location", "message"],
  "properties": {
    "lead_id": { "type": "string", "pattern": "^L[0-9]{3,}$" },
    "tool": { "type": "string", "minLength": 1, "maxLength": 64 },
    "rule_id": { "type": "string", "minLength": 1, "maxLength": 256 },
    "vuln_class_hint": { "type": "string", "minLength": 1, "maxLength": 64 },
    "location": { "$ref": "#/$defs/loc" },
    "codeflow": { "type": "array", "maxItems": 64, "items": { "$ref": "#/$defs/loc" } },
    "message": { "type": "string", "maxLength": 512 }
  },
  "$defs": {
    "loc": {
      "type": "object", "additionalProperties": false,
      "required": ["file", "line"],
      "properties": {
        "file": { "type": "string", "minLength": 1, "maxLength": 1024 },
        "line": { "type": "integer", "minimum": 1 }
      }
    }
  }
}
```

- [ ] **Step 4: Register the export in `build-validators.mjs`**

In `skills/audit/scripts/build-validators.mjs`, add the entry to the `EXPORT_NAME` map (after `"report-summary.schema.json": "reportSummary"`, adding a comma):

```js
  "report-summary.schema.json": "reportSummary",
  "sarif-lead.schema.json": "sarifLead"
```

- [ ] **Step 5: Regenerate `validators.mjs` and run the test**

Run:
```bash
cd skills/audit/scripts && npm run build && node --test test/sarif-lead.test.mjs
```
Expected: build prints `validators.mjs generated (self-contained): …, sarifLead`; the test PASSES.

- [ ] **Step 6: Full suite still green**

Run: `cd skills/audit/scripts && node --test`
Expected: all tests PASS (existing 120 + the 6 new sarif-lead tests).

- [ ] **Step 7: Commit**

```bash
git add skills/audit/schemas/sarif-lead.schema.json skills/audit/scripts/build-validators.mjs skills/audit/scripts/validators.mjs skills/audit/scripts/test/sarif-lead.test.mjs
git commit -m "feat(schema): add sarif-lead schema (8th) + sarifLead validator export"
```

---

## Task 2: `finding` gains `origin` / `source_lead_ids` (inherited by `final-finding`)

**Files:**
- Modify: `skills/audit/schemas/finding.schema.json` (properties block) — the ONLY schema edit.
- Modify (regenerate): `skills/audit/scripts/validators.mjs`
- Test: `skills/audit/scripts/test/finding-origin.test.mjs` (create)

**Why only `finding.schema.json`:** `final-finding.schema.json` is `allOf: [ { "$ref": "finding.schema.json" }, …overrides ]` — it does **not** restate `finding`'s property set, it inherits it through the `$ref`. So adding `origin`/`source_lead_ids` to `finding.schema.json` is sufficient; the `final-finding` validator picks them up automatically. Do **not** edit `final-finding.schema.json`.

- [ ] **Step 1: Write the failing test**

Create `skills/audit/scripts/test/finding-origin.test.mjs`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import { validate } from "../validate-output.mjs";

const base = {
  finding_id: "OSWE-1", partition_id: "auth", title: "t", vuln_class: "sqli",
  source: { file: "a", line: 1, symbol: "s", kind: "http-param" },
  sink: { file: "b", line: 2, symbol: "q", kind: "query" },
  auth: "unauthenticated", provisional_severity: "High", confidence: "likely",
  verification_status: "not-requested", partitions: ["auth"], source_finding_ids: ["auth-F001"]
};

test("origin and source_lead_ids are accepted on a finding", () => {
  const f = { ...base, origin: "both", source_lead_ids: ["L001", "L002"] };
  assert.equal(validate("finding", f).valid, true, JSON.stringify(validate("finding", f).errors));
});

test("a finding with NO origin is still valid (backward compat)", () => {
  assert.equal(validate("finding", base).valid, true);
});

test("origin outside the enum is rejected", () => {
  assert.equal(validate("finding", { ...base, origin: "guessed" }).valid, false);
});

test("source_lead_ids must match ^L[0-9]{3,}$", () => {
  assert.equal(validate("finding", { ...base, source_lead_ids: ["nope"] }).valid, false);
});

test("final-finding inherits origin via its $ref to finding (no separate edit needed)", () => {
  const ff = { ...base, verification_status: "accepted", final_severity: "High", final_confidence: "likely", origin: "sast-lead", source_lead_ids: ["L001"] };
  assert.equal(validate("final-finding", ff).valid, true, JSON.stringify(validate("final-finding", ff).errors));
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/audit/scripts && node --test test/finding-origin.test.mjs`
Expected: FAIL — `origin`/`source_lead_ids` rejected by `additionalProperties:false` (both the `finding` and the inherited `final-finding` cases).

- [ ] **Step 3: Add the properties to both schemas**

In `skills/audit/schemas/finding.schema.json`, inside `properties` (after `"final_confidence"`), add:

```json
    "final_confidence": { "enum": ["strong static proof", "likely", "to verify"] },
    "origin": { "enum": ["llm-discovered", "sast-lead", "both"] },
    "source_lead_ids": { "type": "array", "items": { "type": "string", "pattern": "^L[0-9]{3,}$" } }
```

Neither field is added to `required` — both are optional. **Do not touch `final-finding.schema.json`** — it inherits these properties through its `$ref` to `finding.schema.json` (the Step-1 `final-finding` test proves it).

- [ ] **Step 4: Regenerate and run the test**

Run: `cd skills/audit/scripts && npm run build && node --test test/finding-origin.test.mjs`
Expected: PASS.

- [ ] **Step 5: Full suite still green (no regression on existing finding fixtures)**

Run: `cd skills/audit/scripts && node --test`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add skills/audit/schemas/finding.schema.json skills/audit/scripts/validators.mjs skills/audit/scripts/test/finding-origin.test.mjs
git commit -m "feat(schema): finding gains optional origin + source_lead_ids (final-finding inherits)"
```

---

## Task 3: `analyzer-response` gains `adjudicated_leads` + forbids `origin:"both"`

**Files:**
- Modify: `skills/audit/schemas/analyzer-response.schema.json`
- Modify (regenerate): `skills/audit/scripts/validators.mjs`
- Test: `skills/audit/scripts/test/adjudicated-leads.test.mjs` (create)

- [ ] **Step 1: Write the failing test**

Create `skills/audit/scripts/test/adjudicated-leads.test.mjs`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import { validate } from "../validate-output.mjs";

const finding = {
  finding_id: "auth-F001", partition_id: "auth", title: "t", vuln_class: "sqli",
  source: { file: "a", line: 1, symbol: "s", kind: "http-param" },
  sink: { file: "b", line: 2, symbol: "q", kind: "query" },
  auth: "unauthenticated", provisional_severity: "High", confidence: "likely",
  verification_status: "not-requested"
};
const resp = (over = {}) => ({
  partition_id: "auth", status: "ok", findings: [], coverage: { analyzed: ["auth"], skipped: [] }, ...over
});

test("adjudicated_leads with a promoted entry validates", () => {
  const r = resp({
    findings: [{ ...finding, origin: "sast-lead", source_lead_ids: ["L001"] }],
    adjudicated_leads: [{ lead_id: "L001", outcome: "promoted", finding_id: "auth-F001" }]
  });
  assert.equal(validate("analyzer-response", r).valid, true, JSON.stringify(validate("analyzer-response", r).errors));
});

test("a refuted lead requires a reason", () => {
  const bad = resp({ adjudicated_leads: [{ lead_id: "L001", outcome: "refuted" }] });
  assert.equal(validate("analyzer-response", bad).valid, false);
  const good = resp({ adjudicated_leads: [{ lead_id: "L001", outcome: "refuted", reason: "input is constant" }] });
  assert.equal(validate("analyzer-response", good).valid, true);
});

test("a promoted lead requires finding_id", () => {
  const bad = resp({ adjudicated_leads: [{ lead_id: "L001", outcome: "promoted" }] });
  assert.equal(validate("analyzer-response", bad).valid, false);
});

test("a raw analyzer finding with origin:both is rejected", () => {
  const r = resp({ findings: [{ ...finding, origin: "both" }] });
  assert.equal(validate("analyzer-response", r).valid, false);
});

test("absent adjudicated_leads is still valid (backward compat)", () => {
  assert.equal(validate("analyzer-response", resp()).valid, true);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/audit/scripts && node --test test/adjudicated-leads.test.mjs`
Expected: FAIL — `adjudicated_leads` rejected; `origin:"both"` currently accepted.

- [ ] **Step 3: Edit the schema**

In `skills/audit/schemas/analyzer-response.schema.json`:

(a) Add `adjudicated_leads` to `properties` (after the `coverage` property, with a comma):

```json
    "adjudicated_leads": {
      "type": "array",
      "items": {
        "type": "object", "additionalProperties": false,
        "required": ["lead_id", "outcome"],
        "properties": {
          "lead_id": { "type": "string", "pattern": "^L[0-9]{3,}$" },
          "outcome": { "enum": ["promoted", "refuted", "inconclusive"] },
          "finding_id": { "type": "string", "pattern": "^(.+-F[0-9]{3,}|OSWE-[0-9]+)$" },
          "reason": { "type": "string", "minLength": 1 }
        },
        "allOf": [
          { "if": { "properties": { "outcome": { "const": "promoted" } } }, "then": { "required": ["finding_id"] } },
          { "if": { "properties": { "outcome": { "const": "refuted" } } }, "then": { "required": ["reason"] } },
          { "if": { "properties": { "outcome": { "const": "inconclusive" } } }, "then": { "required": ["reason"] } }
        ]
      }
    }
```

(b) Forbid `origin:"both"` in raw analyzer findings — add a clause to the `findings.items.allOf` array (alongside the existing `verification_status` const and the orchestration-field `not`):

```json
          {
            "$comment": "origin:both is a derived value produced only by the aggregator.",
            "not": { "properties": { "origin": { "const": "both" } }, "required": ["origin"] }
          }
```

- [ ] **Step 4: Regenerate and run the test**

Run: `cd skills/audit/scripts && npm run build && node --test test/adjudicated-leads.test.mjs`
Expected: PASS.

- [ ] **Step 5: Full suite still green**

Run: `cd skills/audit/scripts && node --test`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add skills/audit/schemas/analyzer-response.schema.json skills/audit/scripts/validators.mjs skills/audit/scripts/test/adjudicated-leads.test.mjs
git commit -m "feat(schema): analyzer-response gains adjudicated_leads; forbid origin:both in raw findings"
```

---

## Task 4: `sarif-rule-map.json` + structure-gate validation

**Files:**
- Create: `skills/audit/references/sarif-rule-map.json`
- Modify: `.github/scripts/check-structure.mjs` (append a check)

- [ ] **Step 1: Create the mapping table**

Create `skills/audit/references/sarif-rule-map.json` (curated for the OWASP Benchmark CWE families Semgrep fires on; prefixes match Semgrep registry rule-id namespaces):

```json
{
  "semgrep": [
    { "prefix": "java.lang.security.audit.command-injection", "vuln_class": "command-injection" },
    { "prefix": "java.lang.security.audit.sqli", "vuln_class": "sqli" },
    { "prefix": "java.lang.security.audit.formatted-sql-string", "vuln_class": "sqli" },
    { "prefix": "java.lang.security.audit.tainted-sql-string", "vuln_class": "sqli" },
    { "prefix": "java.lang.security.audit.ldap-injection", "vuln_class": "ldap-injection" },
    { "prefix": "java.lang.security.audit.xpath-injection", "vuln_class": "xpath-injection" },
    { "prefix": "java.lang.security.audit.tainted-path-traversal", "vuln_class": "path-traversal" },
    { "prefix": "java.lang.security.audit.path-traversal", "vuln_class": "path-traversal" },
    { "prefix": "java.lang.security.audit.xss", "vuln_class": "xss" },
    { "prefix": "java.servlets.security.audit.tainted-cmd-from-http", "vuln_class": "command-injection" },
    { "prefix": "java.lang.security.audit.crypto.weak-hash", "vuln_class": "weak-hashing" },
    { "prefix": "java.lang.security.audit.crypto.desede-is-deprecated", "vuln_class": "weak-crypto" },
    { "prefix": "java.lang.security.audit.crypto.ecb-cipher", "vuln_class": "weak-crypto" },
    { "prefix": "java.lang.security.audit.crypto.weak-random", "vuln_class": "weak-randomness" },
    { "prefix": "java.lang.security.audit.cookie-missing-secure-flag", "vuln_class": "insecure-cookie" },
    { "prefix": "java.lang.security.audit.formatted-trust-boundary", "vuln_class": "trust-boundary" }
  ]
}
```

- [ ] **Step 2: Add the structure-gate check**

In `.github/scripts/check-structure.mjs`, after the section `"5) schema <-> validator parity"` block (before the final `console.log("")`), insert:

```js
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
```

- [ ] **Step 3: Run the gate**

Run: `node .github/scripts/check-structure.mjs`
Expected: prints section 6 with `ok` lines; final `PASS: structure & consistency checks green.`

- [ ] **Step 4: Commit**

```bash
git add skills/audit/references/sarif-rule-map.json .github/scripts/check-structure.mjs
git commit -m "feat(sarif): add rule->vuln_class map + structure-gate validation"
```

---

## Task 5: `ingest-sarif.mjs` — full helper (TDD)

**Files:**
- Create: `skills/audit/scripts/ingest-sarif.mjs`
- Test: `skills/audit/scripts/test/ingest-sarif.test.mjs`

This helper depends on `confine-path.mjs` (path confinement) and `validators.mjs` (`sarifLead`) from Tasks 1–3.

- [ ] **Step 1: Write the failing test**

Create `skills/audit/scripts/test/ingest-sarif.test.mjs`. The helper confines paths with `realpathSync`, so the test writes **real files** into a temp project dir and references them from synthetic SARIF.

```js
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/audit/scripts && node --test test/ingest-sarif.test.mjs`
Expected: FAIL — module `ingest-sarif.mjs` not found.

- [ ] **Step 3: Write the implementation**

Create `skills/audit/scripts/ingest-sarif.mjs`:

```js
// Normalizes a SARIF 2.1.0 document into confined, length-bounded "leads" for the oswe audit.
// ingestSarif(projectDir, sarifText, ruleMap?) -> { ok, error, leads, stats }
// CLI: node ingest-sarif.mjs --file <input.json> --out <leads.json>
//   input.json: { "projectDir": "<abs>", "sarifPath": "<path under projectDir>" }
//   exit 0 ok / 1 malformed SARIF or a self-built lead that fails its schema / 2 IO|usage.
import { fileURLToPath } from "node:url";
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd skills/audit/scripts && node --test test/ingest-sarif.test.mjs`
Expected: all PASS.

- [ ] **Step 5: Full suite green**

Run: `cd skills/audit/scripts && node --test`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add skills/audit/scripts/ingest-sarif.mjs skills/audit/scripts/test/ingest-sarif.test.mjs
git commit -m "feat(sarif): ingest-sarif.mjs — SARIF 2.1.0 -> confined bounded leads"
```

---

## Task 6: `aggregate-findings.mjs` carries `origin` / `source_lead_ids`

**Files:**
- Modify: `skills/audit/scripts/aggregate-findings.mjs:44-66` (the per-group merge)
- Modify: `skills/audit/scripts/test/aggregate-findings.test.mjs` (add cases)

- [ ] **Step 1: Write the failing tests** (append to `test/aggregate-findings.test.mjs`)

```js
test("origin is carried through; same-origin merge keeps its origin", () => {
  const a = raw("auth-F001", "auth", { origin: "sast-lead", source_lead_ids: ["L001"] });
  const r = aggregateFindings([a]);
  assert.equal(r.findings[0].origin, "sast-lead");
  assert.deepEqual(r.findings[0].source_lead_ids, ["L001"]);
});

test("an llm finding and a sast-lead finding on the same key merge to origin:both", () => {
  const a = raw("auth-F001", "auth", { origin: "llm-discovered" });
  const b = raw("api-F003", "api", { origin: "sast-lead", source_lead_ids: ["L002"] });
  const r = aggregateFindings([a, b]);
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].origin, "both");
  assert.deepEqual(r.findings[0].source_lead_ids, ["L002"]);
});

test("absent origin defaults to llm-discovered, and source_lead_ids is OMITTED when no lead", () => {
  const r = aggregateFindings([raw("auth-F001", "auth")]);
  assert.equal(r.findings[0].origin, "llm-discovered");
  assert.equal(r.findings[0].source_lead_ids, undefined);   // omitted, not [] (spec §3.5)
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd skills/audit/scripts && node --test test/aggregate-findings.test.mjs`
Expected: FAIL — `origin` is `undefined` on merged findings.

- [ ] **Step 3: Implement the merge change**

In `skills/audit/scripts/aggregate-findings.mjs`, add a constant near the other ordering arrays (after line 10):

```js
const originOf = (f) => f.origin || "llm-discovered";
```

Then inside the `for (const group of groups.values())` loop, before `merged.push({ … })`, compute:

```js
    const origins = new Set(group.map(originOf));
    const mergedOrigin = origins.size === 1 ? [...origins][0]
      : (origins.has("llm-discovered") && origins.has("sast-lead")) ? "both"
        : (origins.has("both") ? "both" : [...origins].sort()[0]);
    const leadIds = uniqSortedStrings(group.flatMap((f) => f.source_lead_ids || []));
```

Then add `origin` to the pushed object as its **last** field (after `source_finding_ids: …`), and attach `source_lead_ids` **only when there is at least one lead** (spec §3.5 — omitted, not `[]`, for pure-LLM findings). Change the tail of the `merged.push({ … })` statement to:

```js
      source_finding_ids: uniqSortedStrings(group.map((f) => f.finding_id)),
      origin: mergedOrigin
    });
    if (leadIds.length) merged[merged.length - 1].source_lead_ids = leadIds;
```

(That is: `origin` goes inside the object literal; the `if (leadIds.length) …` line goes immediately **after** the `merged.push(…);` call, mutating the object just pushed.)

- [ ] **Step 4: Run to verify pass**

Run: `cd skills/audit/scripts && node --test test/aggregate-findings.test.mjs`
Expected: PASS (new cases + all existing aggregate tests).

- [ ] **Step 5: Full suite green**

Run: `cd skills/audit/scripts && node --test`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add skills/audit/scripts/aggregate-findings.mjs skills/audit/scripts/test/aggregate-findings.test.mjs
git commit -m "feat(aggregate): carry origin (both on merge) + source_lead_ids union"
```

---

## Task 7: `benchmark/metrics.mjs` — full engine (TDD)

**Files:**
- Create: `benchmark/metrics.mjs`
- Test: `benchmark/metrics.test.mjs`

- [ ] **Step 1: Write the failing test**

Create `benchmark/metrics.test.mjs`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import { computeMetrics, parseTruthCsv } from "./metrics.mjs";

// truth: T1 real(cwe89), T2 not-real, T3 real(cwe78), T4 real(cwe22), T5 not-real
const truth = parseTruthCsv(
  "# test name, category, real vulnerability, cwe\n" +
  "BenchmarkTest00001,sqli,true,89\n" +
  "BenchmarkTest00002,sqli,false,89\n" +
  "BenchmarkTest00003,cmdi,true,78\n" +
  "BenchmarkTest00004,pathtraver,true,22\n" +
  "BenchmarkTest00005,xss,false,79\n"
);

const ledger = {
  dataset: "owasp-benchmark-1.2", subset: "benchmark/subset-owasp.json", generated: "2026-06-17",
  entries: [
    // flagged TP, oswe promotes -> correct
    { test_id: "BenchmarkTest00001", semgrep_flagged: true, oswe_covered: true, oswe_adjudication: "promoted", oswe_independent: false, cwe: 89 },
    // flagged FP, oswe refutes -> fp_refuted
    { test_id: "BenchmarkTest00002", semgrep_flagged: true, oswe_covered: true, oswe_adjudication: "refuted", oswe_independent: false, cwe: 89 },
    // flagged TP, oswe refutes -> recall_cost
    { test_id: "BenchmarkTest00003", semgrep_flagged: true, oswe_covered: true, oswe_adjudication: "refuted", oswe_independent: false, cwe: 78 },
    // missed real, oswe covered + independent -> fn_recovered (hybrid tp)
    { test_id: "BenchmarkTest00004", semgrep_flagged: false, oswe_covered: true, oswe_adjudication: "no-lead", oswe_independent: true, cwe: 22 },
    // missed not-real, oswe covered, not independent -> hybrid tn
    { test_id: "BenchmarkTest00005", semgrep_flagged: false, oswe_covered: true, oswe_adjudication: "no-lead", oswe_independent: false, cwe: 79 }
  ]
};

test("semgrep_raw matrix", () => {
  const m = computeMetrics(ledger, truth).semgrep_raw;
  // flagged: T1(real)->tp, T2(!real)->fp, T3(real)->tp ; missed: T4(real)->fn, T5(!real)->tn
  assert.deepEqual([m.tp, m.fp, m.fn, m.tn], [2, 1, 1, 1]);
});

test("oswe_over_semgrep matrix (flagged only)", () => {
  const m = computeMetrics(ledger, truth).oswe_over_semgrep;
  // T1 promoted+real->tp ; T2 refuted+!real->tn ; T3 refuted+real->fn
  assert.deepEqual([m.tp, m.fp, m.fn, m.tn], [1, 0, 1, 1]);
});

test("hybrid matrix (flagged group a + covered-missed group b)", () => {
  const m = computeMetrics(ledger, truth).hybrid;
  // group a: T1 tp, T2 tn, T3 fn ; group b: T4 tp, T5 tn
  assert.deepEqual([m.tp, m.fp, m.fn, m.tn], [2, 0, 1, 2]);
});

test("headline deltas", () => {
  const d = computeMetrics(ledger, truth).deltas;
  assert.deepEqual(d, { fp_refuted: 1, recall_cost: 1, fn_recovered: 1 });
});

test("denominator identity holds for hybrid", () => {
  const r = computeMetrics(ledger, truth);
  const m = r.hybrid;
  assert.equal(m.tp + m.fp + m.fn + m.tn, r.total - (r.excluded.inconclusive + r.excluded.not_analyzed + r.excluded.not_covered));
});

test("inconclusive and not-analyzed flagged leads are excluded, not scored", () => {
  const l = { ...ledger, entries: [
    { test_id: "BenchmarkTest00001", semgrep_flagged: true, oswe_covered: true, oswe_adjudication: "inconclusive", oswe_independent: false, cwe: 89 },
    { test_id: "BenchmarkTest00002", semgrep_flagged: true, oswe_covered: false, oswe_adjudication: "not-analyzed", oswe_independent: false, cwe: 89 }
  ] };
  const r = computeMetrics(l, truth);
  assert.equal(r.excluded.inconclusive, 1);
  assert.equal(r.excluded.not_analyzed, 1);
  assert.equal(r.oswe_over_semgrep.tp + r.oswe_over_semgrep.fp + r.oswe_over_semgrep.fn + r.oswe_over_semgrep.tn, 0);
});

test("uncovered Semgrep-missed case is excluded (not_covered), never an fn", () => {
  const l = { ...ledger, entries: [
    { test_id: "BenchmarkTest00004", semgrep_flagged: false, oswe_covered: false, oswe_adjudication: "no-lead", oswe_independent: false, cwe: 22 }
  ] };
  const r = computeMetrics(l, truth);
  assert.equal(r.excluded.not_covered, 1);
  assert.equal(r.hybrid.fn, 0);
});

test("a covered Semgrep-missed real vuln NOT found is an honest hybrid fn (regression guard)", () => {
  const l = { ...ledger, entries: [
    { test_id: "BenchmarkTest00004", semgrep_flagged: false, oswe_covered: true, oswe_adjudication: "no-lead", oswe_independent: false, cwe: 22 }
  ] };
  const r = computeMetrics(l, truth);
  assert.equal(r.ok, true);
  assert.equal(r.hybrid.fn, 1);
});

test("coherence: flagged with no-lead adjudication is rejected", () => {
  const l = { ...ledger, entries: [{ test_id: "BenchmarkTest00001", semgrep_flagged: true, oswe_covered: true, oswe_adjudication: "no-lead", oswe_independent: false, cwe: 89 }] };
  assert.equal(computeMetrics(l, truth).ok, false);
});

test("coherence: missed without no-lead adjudication is rejected", () => {
  const l = { ...ledger, entries: [{ test_id: "BenchmarkTest00005", semgrep_flagged: false, oswe_covered: true, oswe_adjudication: "refuted", oswe_independent: false, cwe: 79 }] };
  assert.equal(computeMetrics(l, truth).ok, false);
});

test("coherence: flagged not-analyzed must be uncovered", () => {
  const l = { ...ledger, entries: [{ test_id: "BenchmarkTest00001", semgrep_flagged: true, oswe_covered: true, oswe_adjudication: "not-analyzed", oswe_independent: false, cwe: 89 }] };
  assert.equal(computeMetrics(l, truth).ok, false);
});

test("a ledger test_id absent from truth is rejected", () => {
  const l = { ...ledger, entries: [{ test_id: "BenchmarkTest99999", semgrep_flagged: true, oswe_covered: true, oswe_adjudication: "promoted", oswe_independent: false, cwe: 1 }] };
  assert.equal(computeMetrics(l, truth).ok, false);
});

test("an unknown TOP-LEVEL ledger field is rejected", () => {
  const l = { ...ledger, bogus: 1 };
  assert.equal(computeMetrics(l, truth).ok, false);
});

test("a missing/empty dataset (top-level metadata) is rejected", () => {
  const { dataset, ...rest } = ledger;
  assert.equal(computeMetrics(rest, truth).ok, false);
});

test("cwe mismatch is non-fatal and only bumps cwe_mismatches", () => {
  const l = { ...ledger, entries: [{ test_id: "BenchmarkTest00001", semgrep_flagged: true, oswe_covered: true, oswe_adjudication: "promoted", oswe_independent: false, cwe: 999 }] };
  const r = computeMetrics(l, truth);
  assert.equal(r.ok, true);
  assert.equal(r.cwe_mismatches, 1);
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd benchmark && node --test metrics.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

Create `benchmark/metrics.mjs`:

```js
// Deterministic benchmark metrics for the hybrid auditor. Zero runtime deps, Node >= 20.
// computeMetrics(ledger, truthMap) -> { ok, error, semgrep_raw, oswe_over_semgrep, hybrid, excluded, deltas, cwe_mismatches, total }
// CLI: node metrics.mjs --ledger <ledger.json> --truth <expectedresults.csv> --out <report.json> [--md <report.md>]
//   exit 0 ok / 1 ledger<->truth or schema/coherence violation / 2 IO|usage.
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";

const ADJ = new Set(["promoted", "refuted", "inconclusive", "not-analyzed", "no-lead"]);

export function parseTruthCsv(text) {
  const map = new Map();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const p = line.split(",").map((s) => s.trim());
    if (p.length < 4 || !/^BenchmarkTest\d{5}$/.test(p[0])) continue;
    map.set(p[0], { real: p[2].toLowerCase() === "true", cwe: parseInt(p[3], 10), category: p[1] });
  }
  return map;
}

function validateLedger(ledger, truth) {
  if (!ledger || typeof ledger !== "object" || !Array.isArray(ledger.entries)) return "ledger.entries[] missing";
  // Top level: additionalProperties:false + required string metadata (spec §3.7.1).
  const topAllowed = new Set(["dataset", "subset", "generated", "entries"]);
  for (const k of Object.keys(ledger)) if (!topAllowed.has(k)) return `unknown top-level ledger field: ${k}`;
  for (const k of ["dataset", "subset", "generated"]) if (typeof ledger[k] !== "string" || !ledger[k]) return `ledger.${k} must be a non-empty string`;
  const seen = new Set();
  const allowed = new Set(["test_id", "semgrep_flagged", "oswe_covered", "oswe_adjudication", "oswe_independent", "cwe"]);
  for (const e of ledger.entries) {
    for (const k of Object.keys(e)) if (!allowed.has(k)) return `unknown ledger field: ${k}`;
    if (!/^BenchmarkTest\d{5}$/.test(e.test_id)) return `bad test_id: ${e.test_id}`;
    if (seen.has(e.test_id)) return `duplicate test_id: ${e.test_id}`;
    seen.add(e.test_id);
    if (typeof e.semgrep_flagged !== "boolean") return `${e.test_id}: semgrep_flagged not boolean`;
    if (typeof e.oswe_covered !== "boolean") return `${e.test_id}: oswe_covered not boolean`;
    if (typeof e.oswe_independent !== "boolean") return `${e.test_id}: oswe_independent not boolean`;
    if (!ADJ.has(e.oswe_adjudication)) return `${e.test_id}: bad oswe_adjudication`;
    // coherence keyed on semgrep_flagged
    if (e.semgrep_flagged) {
      if (e.oswe_adjudication === "no-lead") return `${e.test_id}: flagged lead cannot be "no-lead"`;
      const notAnalyzed = e.oswe_adjudication === "not-analyzed";
      if (notAnalyzed !== (e.oswe_covered === false)) return `${e.test_id}: not-analyzed <=> !covered violated`;
    } else if (e.oswe_adjudication !== "no-lead") {
      return `${e.test_id}: semgrep_flagged=false requires adjudication "no-lead"`;
    }
    if (!truth.has(e.test_id)) return `${e.test_id}: absent from truth CSV`;
  }
  return null;
}

const emptyCM = () => ({ tp: 0, fp: 0, fn: 0, tn: 0 });
function add(cm, predVuln, real) {
  if (predVuln && real) cm.tp++;
  else if (predVuln && !real) cm.fp++;
  else if (!predVuln && real) cm.fn++;
  else cm.tn++;
}
function finalize(cm) {
  const { tp, fp, fn, tn } = cm;
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const fpr = fp + tn ? fp / (fp + tn) : 0;
  const youden = recall - fpr;
  return { tp, fp, fn, tn, precision, recall, fpr, youden };
}

export function computeMetrics(ledger, truth) {
  const err = validateLedger(ledger, truth);
  if (err) return { ok: false, error: err };
  const m1 = emptyCM(), m2 = emptyCM(), m3 = emptyCM();
  const excluded = { inconclusive: 0, not_analyzed: 0, not_covered: 0 };
  const deltas = { fp_refuted: 0, recall_cost: 0, fn_recovered: 0 };
  let cwe_mismatches = 0;
  for (const e of ledger.entries) {
    const t = truth.get(e.test_id);
    const real = t.real;
    if (real && Number.isInteger(e.cwe) && e.cwe !== t.cwe) cwe_mismatches++;
    add(m1, e.semgrep_flagged, real);
    if (e.semgrep_flagged) {
      if (e.oswe_adjudication === "promoted" || e.oswe_adjudication === "refuted") {
        const pred = e.oswe_adjudication === "promoted";
        add(m2, pred, real); add(m3, pred, real);
        if (!real && !pred) deltas.fp_refuted++;
        if (real && !pred) deltas.recall_cost++;
      } else if (e.oswe_adjudication === "inconclusive") excluded.inconclusive++;
      else excluded.not_analyzed++;
    } else if (e.oswe_covered) {
      const pred = e.oswe_independent === true;
      add(m3, pred, real);
      if (real && pred) deltas.fn_recovered++;
    } else {
      excluded.not_covered++;
    }
  }
  return {
    ok: true, error: null,
    semgrep_raw: finalize(m1), oswe_over_semgrep: finalize(m2), hybrid: finalize(m3),
    excluded, deltas, cwe_mismatches, total: ledger.entries.length
  };
}

function toMarkdown(r) {
  const row = (name, m) => `| ${name} | ${m.tp} | ${m.fp} | ${m.fn} | ${m.tn} | ${m.precision.toFixed(3)} | ${m.recall.toFixed(3)} | ${m.fpr.toFixed(3)} | ${m.youden.toFixed(3)} |`;
  return [
    "# OSWE Hybrid Benchmark", "",
    `Total scored entries: ${r.total} — excluded: inconclusive ${r.excluded.inconclusive}, not-analyzed ${r.excluded.not_analyzed}, not-covered ${r.excluded.not_covered}.`,
    `CWE mismatches (diagnostic): ${r.cwe_mismatches}.`, "",
    "| matrix | tp | fp | fn | tn | precision | recall | fpr | youden |",
    "|---|---|---|---|---|---|---|---|---|",
    row("semgrep_raw", r.semgrep_raw),
    row("oswe_over_semgrep", r.oswe_over_semgrep),
    row("hybrid", r.hybrid), "",
    `Deltas: FP refuted **${r.deltas.fp_refuted}**, recall cost **${r.deltas.recall_cost}**, FN recovered **${r.deltas.fn_recovered}**.`, ""
  ].join("\n");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const get = (flag) => { const i = args.indexOf(flag); return i === -1 ? null : args[i + 1]; };
  const ledgerPath = get("--ledger"), truthPath = get("--truth"), outPath = get("--out"), mdPath = get("--md");
  if (!ledgerPath || !truthPath || !outPath) {
    process.stderr.write("usage: metrics.mjs --ledger <l.json> --truth <t.csv> --out <r.json> [--md <r.md>]\n"); process.exit(2);
  }
  let ledger, truth;
  try { ledger = JSON.parse(readFileSync(ledgerPath, "utf8")); }
  catch (e) { process.stderr.write("cannot read --ledger: " + e.message + "\n"); process.exit(2); }
  try { truth = parseTruthCsv(readFileSync(truthPath, "utf8")); }
  catch (e) { process.stderr.write("cannot read --truth: " + e.message + "\n"); process.exit(2); }
  const r = computeMetrics(ledger, truth);
  try {
    writeFileSync(outPath, JSON.stringify(r, null, 2));
    if (mdPath && r.ok) writeFileSync(mdPath, toMarkdown(r));
  } catch (e) { process.stderr.write("cannot write output: " + e.message + "\n"); process.exit(2); }
  if (!r.ok) { process.stderr.write("metrics error: " + r.error + "\n"); process.exit(1); }
  process.exit(0);
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd benchmark && node --test metrics.test.mjs`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add benchmark/metrics.mjs benchmark/metrics.test.mjs
git commit -m "feat(benchmark): deterministic metrics engine (3 matrices, deltas, coherence)"
```

---

## Task 8: Benchmark fixtures, subset manifest, README

**Files:**
- Create: `benchmark/fixtures/sample-ledger.json`
- Create: `benchmark/fixtures/sample-truth.csv`
- Create: `benchmark/subset-owasp.json`
- Create: `benchmark/README.md`
- Test: extend `benchmark/metrics.test.mjs` to exercise the committed fixtures end-to-end + `--md`.

- [ ] **Step 1: Create the committed truth + ledger fixtures**

Create `benchmark/fixtures/sample-truth.csv`:

```text
# test name, category, real vulnerability, cwe
BenchmarkTest00001,sqli,true,89
BenchmarkTest00002,sqli,false,89
BenchmarkTest00003,cmdi,true,78
BenchmarkTest00004,pathtraver,true,22
BenchmarkTest00005,xss,false,79
```

Create `benchmark/fixtures/sample-ledger.json`:

```json
{
  "dataset": "owasp-benchmark-1.2",
  "subset": "benchmark/subset-owasp.json",
  "generated": "2026-06-17",
  "entries": [
    { "test_id": "BenchmarkTest00001", "semgrep_flagged": true, "oswe_covered": true, "oswe_adjudication": "promoted", "oswe_independent": false, "cwe": 89 },
    { "test_id": "BenchmarkTest00002", "semgrep_flagged": true, "oswe_covered": true, "oswe_adjudication": "refuted", "oswe_independent": false, "cwe": 89 },
    { "test_id": "BenchmarkTest00003", "semgrep_flagged": true, "oswe_covered": true, "oswe_adjudication": "refuted", "oswe_independent": false, "cwe": 78 },
    { "test_id": "BenchmarkTest00004", "semgrep_flagged": false, "oswe_covered": true, "oswe_adjudication": "no-lead", "oswe_independent": true, "cwe": 22 },
    { "test_id": "BenchmarkTest00005", "semgrep_flagged": false, "oswe_covered": true, "oswe_adjudication": "no-lead", "oswe_independent": false, "cwe": 79 }
  ]
}
```

Create `benchmark/subset-owasp.json` (starter manifest — the declared in-scope ids; the maintainer expands it for real runs):

```json
{
  "dataset": "owasp-benchmark-1.2",
  "note": "Declared in-scope OWASP Benchmark test ids. Cases outside this list are recorded as coverage gaps, not scored.",
  "test_ids": ["BenchmarkTest00001", "BenchmarkTest00002", "BenchmarkTest00003", "BenchmarkTest00004", "BenchmarkTest00005"]
}
```

- [ ] **Step 2: Add a fixture-driven test to `benchmark/metrics.test.mjs`**

Add these imports **at the top of the file** (next to the existing `computeMetrics`/`parseTruthCsv` import), then append the three tests below:

```js
import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const HERE = dirname(fileURLToPath(import.meta.url));

test("committed sample ledger + truth score consistently", () => {
  const ledger = JSON.parse(readFileSync(join(HERE, "fixtures/sample-ledger.json"), "utf8"));
  const truth = parseTruthCsv(readFileSync(join(HERE, "fixtures/sample-truth.csv"), "utf8"));
  const r = computeMetrics(ledger, truth);
  assert.equal(r.ok, true, r.error);
  assert.deepEqual([r.hybrid.tp, r.hybrid.fp, r.hybrid.fn, r.hybrid.tn], [2, 0, 1, 2]);
});

test("CLI writes JSON to --out and a table to --md, exit 0", () => {
  const tmp = mkdtempSync(join(tmpdir(), "oswe-bench-"));
  const outJson = join(tmp, "r.json"), outMd = join(tmp, "r.md");
  const res = spawnSync(process.execPath, [join(HERE, "metrics.mjs"),
    "--ledger", join(HERE, "fixtures/sample-ledger.json"),
    "--truth", join(HERE, "fixtures/sample-truth.csv"),
    "--out", outJson, "--md", outMd], { encoding: "utf8" });
  assert.equal(res.status, 0, res.stderr);
  assert.equal(JSON.parse(readFileSync(outJson, "utf8")).ok, true);
  assert.match(readFileSync(outMd, "utf8"), /hybrid \| 2 \| 0 \| 1 \| 2/);
});

test("subset manifest is valid JSON with test_ids", () => {
  const m = JSON.parse(readFileSync(join(HERE, "subset-owasp.json"), "utf8"));
  assert.ok(Array.isArray(m.test_ids) && m.test_ids.length > 0);
});
```

- [ ] **Step 3: Create `benchmark/README.md`**

````markdown
# OSWE Hybrid Benchmark

Measures the precision/recall delta of the hybrid auditor vs raw Semgrep on the
[OWASP Benchmark](https://github.com/OWASP/Benchmark) (v1.2, Apache-2.0).

## Two stages

1. **Metrics engine (`metrics.mjs`)** — deterministic, zero-dep, CI-tested. Consumes a sanitized
   *ledger* (`benchmark/fixtures/sample-ledger.json` shows the shape) + the official
   `expectedresults-1.2.csv` and prints confusion matrices + deltas. Run:
   ```bash
   node benchmark/metrics.mjs --ledger <ledger.json> --truth expectedresults-1.2.csv \
                              --out report.json --md BENCHMARK.md
   ```
2. **Run orchestration (manual, expensive — NOT in CI).** Produces a ledger:
   1. `git clone https://github.com/OWASP/Benchmark external/owasp-benchmark` (gitignored).
   2. Run Semgrep once to a pinned SARIF: `semgrep --config p/owasp-top-ten --sarif -o owasp.sarif external/owasp-benchmark/src/...`.
   3. In your own Claude Code session (subscription quota — **not** nested `claude -p`),
      run `/oswe:audit --sarif owasp.sarif <subset paths>` over the ids in `subset-owasp.json`.
   4. Assemble the ledger (one entry per in-scope `test_id`) from the audit output, per the
      `oswe_covered`/`oswe_adjudication`/`oswe_independent` fields documented in the spec §3.7.1.

The ledger is **sanitized by construction** (test ids + booleans + cwe only — no code, paths, or
secrets), so a sample ledger is committed safely. The raw audit `leads`/intermediates are NOT
committed (they live under `.oswe/tmp/` and are purged).
````

- [ ] **Step 4: Run benchmark tests**

Run: `cd benchmark && node --test`
Expected: all PASS (engine tests + 3 fixture tests).

- [ ] **Step 5: Commit**

```bash
git add benchmark/fixtures benchmark/subset-owasp.json benchmark/README.md benchmark/metrics.test.mjs
git commit -m "feat(benchmark): committed fixtures, subset manifest, run-procedure README"
```

---

## Task 9: CI — add a `benchmark/` test step

**Files:**
- Modify: `.github/workflows/ci.yml` (the `test` job)

- [ ] **Step 1: Add the step**

In `.github/workflows/ci.yml`, in the `test` job's `steps:`, after the `"Run validator + helper unit tests"` step (which has `working-directory: skills/audit/scripts`), insert:

```yaml
      - name: Run benchmark engine unit tests
        working-directory: benchmark
        run: node --test
```

- [ ] **Step 2: Verify YAML locally**

Run: `node -e "const f=require('fs').readFileSync('.github/workflows/ci.yml','utf8'); if(!/working-directory: benchmark/.test(f)) throw new Error('benchmark step missing'); console.log('ci.yml has the benchmark step')"`
Expected: prints `ci.yml has the benchmark step`.

- [ ] **Step 3: Run the benchmark tests once more (sanity, the command CI will run)**

Run: `cd benchmark && node --test`
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: run benchmark/ node --test on Node 20 & 22"
```

---

## Task 10: `oswe-analyzer` agent — adjudicate leads + set `origin`

**Files:**
- Modify: `agents/oswe-analyzer.md`

Read the current agent first to match its tone and the response contract it documents.

- [ ] **Step 1: Read the existing agent**

Run: `cat agents/oswe-analyzer.md`
Note where it describes the `analyzer-response` it must emit (findings + coverage).

- [ ] **Step 2: Add the lead-adjudication contract**

Add a new section to `agents/oswe-analyzer.md` (after the section describing the findings it emits). Insert verbatim:

```markdown
## SARIF leads (when provided)

Your dispatch may include a list of **SARIF leads** for your partition: each is
`{ lead_id, tool, rule_id, vuln_class_hint, location {file,line}, codeflow?, message }`. A lead is a
*third-party tool's suspicion*, **not** a confirmed finding. For **every** lead assigned to you, read
the cited code and decide:

- **promoted** — it is a real source→sink you can substantiate. Emit a normal `finding` for it AND an
  `adjudicated_leads` entry `{ lead_id, outcome: "promoted", finding_id }` whose `finding_id` matches
  that finding. On the promoted finding set `origin: "sast-lead"` and `source_lead_ids: [<lead_id>]`.
  (If you ALSO found it independently, still set `origin: "sast-lead"` — the aggregator upgrades it to
  `"both"` when it merges with your independent finding. **Never emit `origin: "both"` yourself.**)
- **refuted** — the cited code is not exploitable (constant input, effective sanitizer, unreachable,
  wrong sink). Emit `{ lead_id, outcome: "refuted", reason: "<evidence-based, file:line>" }` and **no**
  finding. This is the precision win — be specific about WHY.
- **inconclusive** — you cannot decide from the available source. Emit `{ lead_id, outcome:
  "inconclusive", reason: "<what's missing>" }`.

Rules: produce **exactly one** `adjudicated_leads` entry per assigned lead (never drop one); your own
independently-discovered findings (not tied to a lead) set `origin: "llm-discovered"` (or omit
`origin`). The `vuln_class_hint` is advisory — trust the code, not the hint.
```

- [ ] **Step 3: Sanity-check the agent file parses as a valid plugin agent**

Run: `node -e "const f=require('fs').readFileSync('agents/oswe-analyzer.md','utf8'); if(!/adjudicated_leads/.test(f)) throw new Error('missing'); console.log('analyzer agent documents adjudicated_leads')"`
Expected: prints the confirmation.

- [ ] **Step 4: Commit**

```bash
git add agents/oswe-analyzer.md
git commit -m "docs(agent): analyzer adjudicates SARIF leads (promote/refute/inconclusive) + sets origin"
```

---

## Task 11: `SKILL.md` — `--sarif` parse, lead assignment, adjudication, gated report

**Files:**
- Modify: `skills/audit/SKILL.md` (§1, §2, §3, §7)

This is declarative orchestration prose; the gate is content-conformance (does it instruct the exact contracts the helpers/schemas enforce?), not code tests. Make four localized insertions.

- [ ] **Step 1: §1 Entry & recon — parse `--sarif` and ingest leads**

In `skills/audit/SKILL.md`, in `### 1. Entry & recon`, after the confinement paragraph (the `confine-path.mjs` step), insert:

```markdown
- **Optional `--sarif <path>` (additive to the scope arg).** If `$ARGUMENTS` contains `--sarif <path>`,
  confine `<path>` with `confine-path.mjs` (same temp-file + `trap` discipline), then ingest it:
  write `{ "projectDir": "<CLAUDE_PROJECT_DIR>", "sarifPath": "<confined path>" }` to a literal temp
  file and run
  `( trap 'rm -f "${CLAUDE_PROJECT_DIR}/.oswe/tmp/sarif-in-<token>.json" "${CLAUDE_PROJECT_DIR}/.oswe/tmp/leads-<token>.json"' EXIT; node "${CLAUDE_PLUGIN_ROOT}/skills/audit/scripts/ingest-sarif.mjs" --file "${CLAUDE_PROJECT_DIR}/.oswe/tmp/sarif-in-<token>.json" --out "${CLAUDE_PROJECT_DIR}/.oswe/tmp/leads-<token>.json" )`.
  Exit 1 = malformed SARIF → note it and proceed with **no leads** (the audit still runs LLM-only);
  exit 2 = our IO/usage bug → fix the call. On exit 0, read the `leads[]` and `stats` into orchestration
  state. **No `--sarif` → leads = `[]` and the rest of the pipeline is byte-for-byte unchanged.**
```

- [ ] **Step 2: §2 Partition — assign leads to partitions**

In `### 2. Partition & prioritize`, append:

```markdown
- **Assign each SARIF lead to the partition that contains its `location.file`.** A lead whose file is
  in no analyzed partition (excluded dir, or beyond the partition budget) is recorded as a **coverage
  gap ("lead not analyzed")** — never silently dropped (the precision ledger must account for every lead).
```

- [ ] **Step 3: §3 Analyze — require adjudication of every assigned lead**

In `### 3. Analyze`, after the bullet about binding each response to its partition, insert:

```markdown
- **Leads.** Pass each partition's assigned leads to its analyzer (inline or subagent). The
  `analyzer-response` must contain **exactly one `adjudicated_leads` entry per assigned lead** (the
  schema validates the entry shape; binding checks the 1:1 coverage). A `promoted` entry's `finding_id`
  must match a `finding` in the same response, and that finding must carry the `lead_id` in
  `source_lead_ids` with `origin: "sast-lead"`. **Reject (and treat as a binding mismatch — retry once,
  else coverage gap) any response that:** omits a lead, references an unknown `lead_id`, promotes to a
  missing `finding_id`, or emits a raw finding with `origin: "both"` (a `"both"` origin is produced only
  by the aggregator). Record every `refuted` lead (with reason) for the report's "Refuted SAST leads"
  annex, and every `inconclusive`/`not-analyzed` lead for Coverage.
```

- [ ] **Step 4: §7 Report — gate the new sections on `leads.length > 0`**

In `### 7. Report` (and the Report-format section), insert:

```markdown
- **Hybrid sections — only when leads were ingested (`leads.length > 0`).** When SARIF leads were
  ingested, add to the report: (a) a one-line **origin breakdown** in the executive summary
  (counts of LLM-only / SAST-only / both findings, from each final finding's `origin`); and (b) an
  annex **"Refuted SAST leads"** listing each refuted lead's `lead_id`, `rule_id`, `file:line`, and
  reason. `inconclusive`/`not-analyzed` leads are listed under **Coverage**, not here. **With no
  `--sarif` (leads empty), neither section is emitted and the Markdown is identical to today's output.**
```

- [ ] **Step 5: Verify the four insertions are present**

Run: `node -e "const f=require('fs').readFileSync('skills/audit/SKILL.md','utf8'); for (const s of ['ingest-sarif.mjs','Assign each SARIF lead','adjudicated_leads entry per assigned lead','only when leads were ingested']) if(!f.includes(s)) throw new Error('missing: '+s); console.log('SKILL.md has all four hybrid insertions')"`
Expected: prints the confirmation.

- [ ] **Step 6: Plugin validation (local gate)**

Run: `claude plugin validate . --strict`
Expected: PASS. (If the Claude CLI is unavailable in this environment, note it and rely on the structure gate + tests; this is a release gate run locally per the README.)

- [ ] **Step 7: Commit**

```bash
git add skills/audit/SKILL.md
git commit -m "feat(skill): --sarif ingestion, lead partition+adjudication, gated hybrid report sections"
```

---

## Task 12: End-to-end non-regression + a tiny SARIF demo fixture

**Files:**
- Create: `test-fixtures/sarif-demo/results.sarif` + a short `test-fixtures/sarif-demo/README.md`
- Verify: existing fixtures unchanged on the no-`--sarif` path

- [ ] **Step 1: Confirm zero-regression — full suite + structure gate**

Run:
```bash
cd skills/audit/scripts && node --test && cd ../../.. && node .github/scripts/check-structure.mjs && cd benchmark && node --test
```
Expected: all PASS; structure gate `PASS`. (No-`--sarif` behavior is unchanged because `origin` is optional and the report sections are gated.)

- [ ] **Step 2: Create a tiny demo SARIF over an existing fixture**

Create `test-fixtures/sarif-demo/README.md`:

````markdown
# SARIF ingestion demo

A tiny SARIF pointing at the committed Python vulnerable fixture, to demonstrate `--sarif` ingestion:

```bash
/oswe:audit --sarif test-fixtures/sarif-demo/results.sarif test-fixtures/python/vulnerable
```

`L001` points at the real SSTI sink (expected: **promoted** into the OSWE finding) and `L002` at a
benign line (expected: **refuted** with a reason). This exercises both adjudication outcomes.
````

Create `test-fixtures/sarif-demo/results.sarif` (adjust the two `startLine` values to a real
sink line and a benign line in `test-fixtures/python/vulnerable` after reading that fixture).
**CRITICAL — the `uri` MUST be relative to `CLAUDE_PROJECT_DIR` (the repo root), NOT to the audit
scope sub-path.** In the real pipeline `ingest-sarif.mjs` is invoked with `projectDir = CLAUDE_PROJECT_DIR`
(`E:/claude-oswe`), and a bare `uri` like `app.py` would resolve to `E:/claude-oswe/app.py` (which does
not exist) → the lead is dropped as `missing` and the hybrid path never runs. A real Semgrep SARIF run
at the repo root emits repo-root-relative paths, so use the full repo-relative path:

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": { "driver": { "name": "Semgrep OSS", "rules": [] } },
      "results": [
        {
          "ruleId": "python.flask.security.audit.render-template-string.render-template-string",
          "message": { "text": "Potential SSTI via render_template_string" },
          "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "test-fixtures/python/vulnerable/app.py" }, "region": { "startLine": 1 } } }]
        },
        {
          "ruleId": "python.lang.security.audit.benign.placeholder",
          "message": { "text": "Heuristic match (likely benign)" },
          "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "test-fixtures/python/vulnerable/app.py" }, "region": { "startLine": 2 } } }]
        }
      ]
    }
  ]
}
```

- [ ] **Step 3: Read the Python fixture and fix the two line numbers**

Run: `cat -n test-fixtures/python/vulnerable/app.py` (or whatever the single source file is named — list the dir first with `ls test-fixtures/python/vulnerable`).
Set `L001`'s `startLine` to the real `render_template_string` sink line, and `L002`'s to a benign line (e.g. an import). Keep both `uri`s as the **repo-root-relative** `test-fixtures/python/vulnerable/app.py` (see the CRITICAL note in Step 2). Update `results.sarif` accordingly.

- [ ] **Step 4: Validate the demo SARIF ingests cleanly**

Run from repo root. **Pass `projectDir = the repo root` (`process.cwd()`), exactly as the real
pipeline does** — NOT the scope sub-path. (An earlier version of this step passed the fixture subdir
as `projectDir`, which masked a uri-base bug: bare `app.py` validated there but was dropped `missing`
in the real `/oswe:audit` run where projectDir is the repo root.)
```bash
node --input-type=module -e '
const { ingestSarif } = await import("./skills/audit/scripts/ingest-sarif.mjs");
const { readFileSync } = await import("node:fs");
const r = ingestSarif(process.cwd(), readFileSync("test-fixtures/sarif-demo/results.sarif","utf8"));
console.log(JSON.stringify(r.stats), r.leads.map(l=>l.lead_id+":"+l.location.file+":"+l.location.line+":"+l.vuln_class_hint));
if(!r.ok || r.leads.length!==2 || r.stats.dropped_missing!==0) throw new Error("demo SARIF did not yield 2 kept leads: "+JSON.stringify(r.stats));
'
```
Expected: `ok`, `kept:2`, `dropped_missing:0`, both `location.file` = `test-fixtures/python/vulnerable/app.py`. (If a lead drops, the `uri` is wrong — it must be repo-root-relative.)

- [ ] **Step 5: Commit**

```bash
git add test-fixtures/sarif-demo
git commit -m "test(fixture): tiny SARIF demo over the python fixture (promote + refute)"
```

---

## Task 13: Final verification + README mention

**Files:**
- Modify: `README.md` (Usage + a short "Hybrid / SARIF" note)

- [ ] **Step 1: Add the usage line + a short section to `README.md`**

In the `## Usage` block, add under the existing two commands:

```text
/oswe:audit --sarif results.sarif        # also adjudicate a SAST's findings (Semgrep/CodeQL SARIF)
/oswe:audit --sarif results.sarif src/api  # ...restricted to a sub-path
```

And add a short section after "Supported stacks":

```markdown
## Hybrid mode — make your SAST precise (optional)

Pass a SARIF file and `oswe` treats each result as a **lead**: it reads the cited code and either
**promotes** it into a proven finding (chained + verified like any other) or **refutes** it with a
reason. You get your SAST's scale and rule coverage, plus `oswe`'s discovery of the logic/auth bugs
SAST misses — and a report where every item is proven or explicitly refuted. A reproducible benchmark
(`benchmark/`) scores the precision/recall delta vs raw Semgrep on the OWASP Benchmark.
```

- [ ] **Step 2: Structure gate (README stack list still consistent)**

Run: `node .github/scripts/check-structure.mjs`
Expected: `PASS`.

- [ ] **Step 3: Full green sweep**

Run:
```bash
cd skills/audit/scripts && node --test && cd ../../.. && node .github/scripts/check-structure.mjs && cd benchmark && node --test && cd ..
```
Expected: every command PASS / green.

- [ ] **Step 4: Regen-in-sync check (mirror CI's regen-check job)**

Run: `cd skills/audit/scripts && npm run build && git diff --quiet -- validators.mjs && echo "validators.mjs in sync" || echo "OUT OF SYNC — commit the regenerated file"`
Expected: `validators.mjs in sync` (it was regenerated and committed in Tasks 1–3).

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs(readme): document --sarif hybrid mode + benchmark"
```

---

## Self-Review notes (spec coverage)

- Spec §3.1 ingest-sarif → Task 5 (incl. all URI/line/truncation/codeflow cases). §3.2 rule map → Task 4.
  §3.3 sarif-lead schema → Task 1. §3.4 adjudicated_leads + forbid origin:both → Task 3 (+ SKILL Task 11).
  §3.5 finding origin/source_lead_ids → Task 2. §3.6 aggregator merge → Task 6. §3.7 + §3.7.1 metrics +
  ledger contract → Task 7; §3.8 run procedure → Task 8 (README). §4 pipeline integration → Tasks 10–11.
  §5 testing (incl. benchmark CI step) → Tasks 7–9, 12. §6 security (confinement, two-artifact split) →
  Tasks 5, 8. §7 backward-compat (gated report) → Tasks 11–12. §8 success criteria → Task 13 sweep.
- Type/name consistency: `ingestSarif`, `computeMetrics`, `parseTruthCsv`, `sarifLead`, ledger fields
  (`semgrep_flagged`/`oswe_covered`/`oswe_adjudication`/`oswe_independent`/`cwe`), and stat keys
  (`dropped_*`) are used identically across tasks and match the spec.
- The OWASP Benchmark corpus itself is cloned under `external/` (gitignored) per Task 8 README — not
  committed. Only the sanitized sample ledger + a synthetic truth CSV are committed.
