# SP8 — CI Exports (SARIF + JUnit)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or
> superpowers:executing-plans. Steps use checkbox syntax. Every export task is a **pure deterministic
> transform of `report.json`** — fully TDD-able, zero LLM cost.

**Goal:** Turn oswe's canonical `report.json` into the two artifacts that make it adoptable in CI — a
**SARIF 2.1.0** file for GitHub/GitLab code scanning (including oswe's *validation-layer* enrichment: the
SAST leads it refuted) and a **JUnit XML** file for a clean pipeline pass/fail gate.

**Architecture:** Standalone, zero-dependency Node helpers that read a `report.json` and emit SARIF / JUnit.
They are decoupled from the audit (run once, transform anytime — important for CI replay) AND invoked by
the SKILL at the end of a run so every audit drops `.sarif`/`.xml` next to the `.md`/`.html`/`.json`.

**Tech stack:** existing — Node ≥ 20 zero-dep helpers, `node:test`, the canonical `report.schema.json`
(`run`/`coverage`/`findings`/`chains`/`verdicts`/`lead_adjudications`).

---

## 0. Why now (grounded)

`report.json` (SP6) is proven on real data. Exports are the cheapest high-value next step: a pure transform,
no model calls, and the thing that turns "impressive local tool" into "runs in your CI." SARIF also lands
oswe's differentiating position — **a validation layer over SAST**: it already records, in
`report.json.lead_adjudications[]`, which ingested Semgrep leads it **refuted** (the 552-FP headroom on
BenchmarkJava). Exporting those as SARIF suppressions tells a code-scanning dashboard *"oswe assessed these
SAST alerts as not exploitable"* — something no SAST tool does for itself.

### Load-bearing fact: `OSWE-N` is NOT a stable cross-run id
`aggregate-findings.mjs:85` assigns `finding_id = OSWE-${i+1}` by **positional index** after a deterministic
sort. Stable within a run, but indices **shift** when findings are added/removed. SARIF `partialFingerprints`
and any future baseline/diff need a **content-based** fingerprint, not `OSWE-N`. SP8 introduces that
fingerprint (Task 1) and every export keys on it.

---

## 1. Files touched

| File | Task | Responsibility |
|---|---|---|
| `skills/audit/scripts/finding-fingerprint.mjs` (**new**) + test | 1 | content-based stable fingerprint for a finding and a chain (shared by SARIF + future baseline/diff) |
| `skills/audit/scripts/export-sarif.mjs` (**new**) + test | 2,3 | `report.json` → SARIF 2.1.0 (findings + chains as codeFlows + fingerprints), then lead-adjudication enrichment |
| `skills/audit/scripts/export-junit.mjs` (**new**) + test | 4 | `report.json` → JUnit XML with severity→failure mapping + `--fail-on` threshold |
| `skills/audit/SKILL.md` | 5 | §7: emit `.sarif` + `.xml` next to the report, best-effort (cannot fail the audit) |
| `README.md`, `benchmark/BENCHMARK.md` | 6 | document the exports + a copy-paste CI snippet |

No schema changes — exports read the existing `report.json`. No new runtime deps.

---

## 2. Design

### 2.1 Fingerprint (Task 1)
`fingerprintFinding(f)` = `sha256Hex` (reuse `cache-wrap.mjs`'s `sha256Hex`) of a canonical string built
from the **content that identifies the vuln**, NOT its positional id:
`\`${f.vuln_class}|${f.source.file}:${f.source.line}|${f.sink.file}:${f.sink.line}\``.
Return the first 16 hex chars (enough to avoid collision at oswe scale, compact for dashboards).
`fingerprintChain(c)` = `sha256Hex` of `\`${c.entry_point.file}:${c.entry_point.line}|${c.final_impact}|${c.finding_ids.join(",")}\``
— but since `finding_ids` are positional, use the **member fingerprints** instead: join the sorted
`fingerprintFinding` of each member (resolved from the report's findings) so the chain id is also
content-stable. Pure, deterministic, order-independent.

### 2.2 SARIF (Tasks 2–3)
SARIF 2.1.0, one `run`, `tool.driver.name = "oswe"`, `informationUri` to the repo.
- **Rules** (`tool.driver.rules[]`): one per distinct `vuln_class` encountered, `id = vuln_class`,
  `name`, `defaultConfiguration.level` from severity mapping, `properties.cwe` when known (e.g.
  `trust-boundary` → `"CWE-501"`).
- **Severity → SARIF level:** `Critical`/`High` → `error`; `Medium` → `warning`; `Low`/`Info` → `note`.
  A `rejected` finding is **not** emitted as an active result (it was refuted).
- **Findings → results:** `ruleId = vuln_class`, `level` from `final_severity` (fallback
  `provisional_severity`), `message.text = title`, primary `location` = `source` (`physicalLocation` with
  `artifactLocation.uri` + `region.startLine`), the `sink` as a `relatedLocations` entry, and
  `partialFingerprints = { "oswe/v1": fingerprintFinding(f) }`. **Hygiene (`trust-boundary`) findings** are
  emitted at `note` with a `properties.lane = "hygiene"` tag so a dashboard can filter them from exploit
  findings.
- **Chains → results with `codeFlows`:** the exploit chain becomes one result (`ruleId = "exploit-chain"`,
  `level = error` for Critical) whose `codeFlows[0].threadFlows[0].locations[]` are the chain transitions
  (entry → each finding's loc), so a reviewer sees the **proof path** in the dashboard. `partialFingerprints
  = { "oswe/v1": fingerprintChain(c) }`.
- **Lead-adjudication enrichment (Task 3 — the differentiator):** for each `lead_adjudications[]` entry:
  - `outcome:"refuted"` → emit a result with `ruleId = "sast-lead-refuted"`, `level = "note"`, message =
    the lead's `reason`, location from `lead.location`, and a `suppressions: [{ kind: "external",
    justification: <reason> }]` — i.e. oswe marks this SAST alert suppressed/not-exploitable.
  - `outcome:"promoted"` → already represented by the corresponding finding (resolved via `finding_id` /
    `source_finding_ids`); do **not** double-emit.
  - `outcome:"inconclusive"` → result `ruleId = "sast-lead-inconclusive"`, `level = "note"`, no suppression.

### 2.3 JUnit (Task 4)
One `<testsuite name="oswe">`; each finding/chain is a `<testcase>` (classname = `vuln_class` or
`exploit-chain`, name = the content fingerprint). Mapping driven by `--fail-on <critical|high|medium>`
(default `high`):
- A finding/chain at or above the threshold severity that is **accepted/downgraded** → `<failure>` (with
  message = title + file:line). Critical chains always fail under any threshold.
- Below threshold, or `rejected`, or hygiene `Low/Info` → a **passing** testcase (refuted leads → `<skipped>`
  with the reason, so they're visible but non-failing).
- Emit `tests`/`failures`/`skipped` counts on the suite. The XML itself is what CI reads; the helper exits
  `0` on successful write regardless of failures (CI decides on the XML), `2` on IO/usage.

---

## 3. Bite-sized plan

### Task 1: content-based fingerprint helper

**Files:** create `skills/audit/scripts/finding-fingerprint.mjs`, `skills/audit/scripts/test/finding-fingerprint.test.mjs`

- [ ] **Step 1: Failing test**

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import { fingerprintFinding, fingerprintChain } from "../finding-fingerprint.mjs";

const f = (over = {}) => ({ vuln_class: "sqli", source: { file: "a.js", line: 10 }, sink: { file: "b.js", line: 20 }, ...over });

test("same content -> same fingerprint regardless of finding_id (OSWE-N is positional)", () => {
  assert.equal(fingerprintFinding({ ...f(), finding_id: "OSWE-1" }), fingerprintFinding({ ...f(), finding_id: "OSWE-9" }));
});
test("different sink line -> different fingerprint", () => {
  assert.notEqual(fingerprintFinding(f()), fingerprintFinding(f({ sink: { file: "b.js", line: 21 } })));
});
test("fingerprint is 16 lowercase hex chars", () => {
  assert.match(fingerprintFinding(f()), /^[0-9a-f]{16}$/);
});
test("chain fingerprint is stable and order-independent over members", () => {
  const findings = [f({ finding_id: "OSWE-1" }), f({ finding_id: "OSWE-2", sink: { file: "c.js", line: 5 } })];
  const c = { entry_point: { file: "a.js", line: 1 }, final_impact: "unauth-rce", finding_ids: ["OSWE-1", "OSWE-2"] };
  const c2 = { ...c, finding_ids: ["OSWE-2", "OSWE-1"] };
  assert.equal(fingerprintChain(c, findings), fingerprintChain(c2, findings));
});
```

- [ ] **Step 2: Run, confirm FAIL** — `cd skills/audit/scripts && node --test test/finding-fingerprint.test.mjs`.
- [ ] **Step 3: Implement** — reuse `sha256Hex` from `cache-wrap.mjs`. `fingerprintFinding` hashes the
  `vuln_class|source|sink` string, slice(0,16). `fingerprintChain(c, findings)` maps each `finding_id` to
  its finding, computes member fingerprints, sorts them, hashes `entry|impact|sortedMemberFps`.
- [ ] **Step 4: Run, confirm PASS** + full dir suite green.
- [ ] **Step 5: Commit** — `git add skills/audit/scripts/finding-fingerprint.* skills/audit/scripts/test/finding-fingerprint.test.mjs && git commit -m "feat(sp8): content-based finding/chain fingerprint"`

### Task 2: export-sarif.mjs — findings + chains

**Files:** create `skills/audit/scripts/export-sarif.mjs`, `skills/audit/scripts/test/export-sarif.test.mjs`

- [ ] **Step 1: Failing test** — `buildSarif(report)` returns an object with `version:"2.1.0"`,
  `runs[0].tool.driver.name === "oswe"`, one result per non-rejected finding with correct `level`
  (High→error, Low→note), `partialFingerprints["oswe/v1"]` present, a hygiene finding tagged
  `properties.lane === "hygiene"`, and a Critical chain emitted as a result with a non-empty
  `codeFlows[0].threadFlows[0].locations`. A `rejected` finding produces NO result.

```js
const report = {
  run: { run_id: "r", generated: "2026-06-23", scope: ["src"] },
  coverage: { analyzed: [], skipped: [] },
  findings: [
    { finding_id:"OSWE-1", vuln_class:"sqli", final_severity:"High", verification_status:"accepted", title:"SQLi", source:{file:"a.js",line:10,symbol:"q",kind:"http"}, sink:{file:"b.js",line:20,symbol:"query",kind:"sql"}, direct_flow:true, partitions:["p"], source_finding_ids:["p-F1"] },
    { finding_id:"OSWE-2", vuln_class:"trust-boundary", final_severity:"Low", verification_status:"accepted", title:"CWE-501", source:{file:"c.js",line:5,symbol:"p",kind:"http"}, sink:{file:"c.js",line:7,symbol:"setAttribute",kind:"session"}, direct_flow:true, partitions:["p"], source_finding_ids:["p-F2"] },
    { finding_id:"OSWE-3", vuln_class:"xss", verification_status:"rejected", title:"refuted", source:{file:"d.js",line:1,symbol:"x",kind:"http"}, sink:{file:"d.js",line:2,symbol:"w",kind:"html"}, partitions:["p"], source_finding_ids:["p-F3"] }
  ],
  chains: [], verdicts: []
};
const s = buildSarif(report);
assert.equal(s.version, "2.1.0");
assert.equal(s.runs[0].results.filter(r=>r.ruleId!=="sast-lead-refuted").length, 2); // OSWE-1, OSWE-2; OSWE-3 rejected -> none
```

- [ ] **Step 2: Run, confirm FAIL.**
- [ ] **Step 3: Implement** per §2.2 (rules, level map, finding results, chain codeFlows, fingerprints via
  Task 1). Also a self-consistency test: feed the output through the existing `ingest-sarif.mjs` parser and
  confirm it reads oswe's own SARIF without error (oswe can read what it writes).
- [ ] **Step 4: Run, confirm PASS** + full dir suite green.
- [ ] **Step 5: Commit** — `git add skills/audit/scripts/export-sarif.* skills/audit/scripts/test/export-sarif.test.mjs && git commit -m "feat(sp8): SARIF export (findings + chain codeFlows + fingerprints)"`

### Task 3: SARIF lead-adjudication enrichment (the differentiator)

**Files:** modify `skills/audit/scripts/export-sarif.mjs` + its test

- [ ] **Step 1: Failing test** — a report with `lead_adjudications:[{lead_id:"L1",outcome:"refuted",reason:"input is constant",test_id:"BenchmarkTest00001",location:{file:"a.js",line:9}}]` produces a SARIF result with `ruleId:"sast-lead-refuted"`, `level:"note"`, `suppressions[0].kind === "external"`, and the reason in the message; a `promoted` lead does NOT add an extra result (it's the finding).
- [ ] **Step 2: Run, confirm FAIL.**
- [ ] **Step 3: Implement** the `lead_adjudications` pass per §2.2.
- [ ] **Step 4: Run, confirm PASS** + full dir suite green.
- [ ] **Step 5: Commit** — `git add skills/audit/scripts/export-sarif.mjs skills/audit/scripts/test/export-sarif.test.mjs && git commit -m "feat(sp8): SARIF enrichment — refuted SAST leads as suppressions"`

### Task 4: export-junit.mjs

**Files:** create `skills/audit/scripts/export-junit.mjs`, `skills/audit/scripts/test/export-junit.test.mjs`

- [ ] **Step 1: Failing test** — `buildJunit(report, { failOn:"high" })` returns XML text where: an accepted
  High finding yields a `<testcase>` containing `<failure`; a Critical chain yields `<failure`; a Low
  hygiene finding yields a passing testcase (no `<failure>`); a refuted lead yields `<skipped`. The
  `<testsuite>` carries correct `tests`/`failures`/`skipped` counts. Valid XML (parse-check: no unescaped
  `<`/`&` in messages).

```js
const xml = buildJunit(report, { failOn: "high" });
assert.match(xml, /<testsuite name="oswe"/);
assert.match(xml, /<failure/);                 // the High finding
assert.ok(!/<failure[^>]*>[^]*trust-boundary/.test(xml)); // hygiene Low does NOT fail
```

- [ ] **Step 2: Run, confirm FAIL.**
- [ ] **Step 3: Implement** per §2.3: severity threshold map, XML escaping (`& < > " '`), suite counts,
  CLI `--file <report.json> --out <junit.xml> [--fail-on critical|high|medium]`, exit 0/2.
- [ ] **Step 4: Run, confirm PASS** + full dir suite green.
- [ ] **Step 5: Commit** — `git add skills/audit/scripts/export-junit.* skills/audit/scripts/test/export-junit.test.mjs && git commit -m "feat(sp8): JUnit export with --fail-on severity threshold"`

### Task 5: SKILL emits the exports

**Files:** modify `skills/audit/SKILL.md`

- [ ] **Step 1: Edit §7** — after `report.json`, run `export-sarif.mjs` and `export-junit.mjs` to write
  `oswe-report-YYYY-MM-DD-HHMM.sarif` and `.xml` next to the other artifacts, under the same `trap` pattern,
  **best-effort**: like the HTML and report.json, an export failure (exit 1/2) is noted in the chat summary
  and never fails the audit. State that the `.sarif` is REDACTED-safe (it carries file:line + messages, the
  same content already in the `.md`).
- [ ] **Step 2: Manual verification** — SP5 smoke / a real run produces a valid `.sarif` + `.xml`.
- [ ] **Step 3: Commit** — `git add skills/audit/SKILL.md && git commit -m "feat(sp8): audit emits SARIF + JUnit alongside the report"`

### Task 6: docs + CI snippet

**Files:** modify `README.md`, `benchmark/BENCHMARK.md`

- [ ] **Step 1: Edit** — README: a short "CI integration" subsection with a GitHub Actions snippet
  (`upload-sarif` action consuming `oswe-report-*.sarif`; the `.xml` consumed by the test reporter), and a
  one-liner on the validation-layer angle (refuted SAST leads appear as suppressions). Note exports are a
  standalone transform: `node skills/audit/scripts/export-sarif.mjs --file <report.json> --out out.sarif`.
- [ ] **Step 2: Run** `node .github/scripts/check-structure.mjs` → PASS; update test counts if the badge drifts.
- [ ] **Step 3: Commit** — `git add README.md benchmark/BENCHMARK.md && git commit -m "docs(sp8): CI integration — SARIF/JUnit exports"`

### Task 7: exports gate read

- [ ] Generate a `.sarif` from a committed sample report (e.g. the trustbound run) and confirm:
  - it parses as JSON and has `version:"2.1.0"`, `runs[0].tool.driver.name:"oswe"`;
  - every result has a `partialFingerprints["oswe/v1"]` matching `^[0-9a-f]{16}$`;
  - the refuted Semgrep leads appear as `sast-lead-refuted` results with suppressions;
  - the JUnit `--fail-on high` produces failures only for accepted High+/Critical.
- [ ] Note in BENCHMARK.md that the trustbound run exports cleanly (with counts).

## 4. Non-goals (v1)

- No full official SARIF-2.1.0 JSON-schema validation in CI (heavy schema); tests assert the structural
  shape oservers need + a round-trip through `ingest-sarif.mjs`. GitHub code scanning is the real acceptance.
- No GitLab-specific format (its code-quality JSON) — SARIF covers GitLab SAST too; revisit if needed.
- No `.oswe.yml` config file yet (the `--fail-on` flag suffices for v1; a config file is a later cap).
- No baseline/diff — but Task 1's fingerprint is the foundation it will reuse.

## 5. Gates (success criteria)

| Gate | Threshold |
|---|---|
| SARIF output | valid JSON, `version:"2.1.0"`, parses back through `ingest-sarif.mjs` |
| fingerprints | every result has `partialFingerprints["oswe/v1"]` = stable 16-hex, identical across two runs of the same report |
| validation-layer | refuted `lead_adjudications` → `sast-lead-refuted` results with `suppressions` |
| JUnit | `--fail-on high` fails on accepted High+/Critical only; hygiene/refuted never fail |
| determinism | same `report.json` → byte-identical `.sarif`/`.xml` |
| no regression | full pipeline + benchmark suites green; structure PASS |

## 6. Self-review

- Format coverage: SARIF (Tasks 2–3) + JUnit (Task 4), both decided in scope.
- Differentiator (refuted SAST leads in SARIF): Task 3, keyed on the existing `lead_adjudications` data.
- The `OSWE-N`-is-positional risk is handled once (Task 1 fingerprint) and reused everywhere.
- Everything is a deterministic transform of `report.json` → fully TDD; only Task 5 (SKILL prompt) is
  audit-verified. No schema/no new dep.
- Type consistency: `fingerprintFinding`/`fingerprintChain` signatures fixed in Task 1, reused in Tasks 2–3.
