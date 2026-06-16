# OSWE HTML Report Export — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit a self-contained visual HTML report (inline CSS + SVG charts, zero runtime dependency) alongside the canonical redaction-safe Markdown report on every `/oswe:audit` run.

**Architecture:** A new zero-dependency Node helper `render-html.mjs` turns the redacted `.md` (body, via a fixed-scope Markdown→HTML converter) plus a non-sensitive `summary.json` (four inline SVG charts) into one `.html`. A new `report-summary.schema.json` (compiled into the standalone `validators.mjs`) guards the summary. SKILL phase 7 builds the summary and calls the helper; an HTML failure never aborts the audit (the `.md` stays canonical).

**Tech Stack:** Node ≥ 20 ESM; existing AJV-standalone validator toolchain (`build-validators.mjs` → `validators.mjs`, dev-only `ajv`); `node:test`.

**Spec:** `docs/superpowers/specs/2026-06-16-oswe-report-export-design.md`.

**Branch:** `feat/oswe-html-report` (already created off `master`).

> **Shell prerequisite:** verification commands use POSIX sh (Git Bash / the Bash tool on Windows), not PowerShell. Run helper commands from `skills/audit/scripts/` where noted.

---

## File Structure

Created:

| Path | Responsibility |
|------|----------------|
| `skills/audit/schemas/report-summary.schema.json` | Strict schema for the non-sensitive summary (counts, closed-set graph labels). |
| `skills/audit/scripts/render-html.mjs` | Zero-dep helper: escaping, MD→HTML converter, 4 SVG charts, document assembly, CLI (atomic write). |
| `skills/audit/scripts/test/render-html.test.mjs` | Unit + CLI tests for the helper. |

Modified:

| Path | Change |
|------|--------|
| `skills/audit/scripts/build-validators.mjs` | Add `report-summary.schema.json → reportSummary` to the export map. |
| `skills/audit/scripts/validators.mjs` | **Generated** — regenerated to add the `reportSummary` export (do not hand-edit). |
| `skills/audit/scripts/validate-output.mjs` | Add the `report-summary` kind (lets the schema be validated via `validate()` and gives an orchestrator CLI). |
| `skills/audit/scripts/test/validate-output.test.mjs` | Add `report-summary` schema tests. |
| `skills/audit/SKILL.md` | Phase 7: build summary + call `render-html.mjs`; never gate the audit. Report-format "HTML export" note. |
| `README.md`, `.claude-plugin/plugin.json` | Mention the HTML report. |

---

## Task 1: report-summary schema + validator wiring

**Files:**
- Create: `skills/audit/schemas/report-summary.schema.json`
- Modify: `skills/audit/scripts/build-validators.mjs`
- Modify: `skills/audit/scripts/validate-output.mjs`
- Generated: `skills/audit/scripts/validators.mjs`
- Test: `skills/audit/scripts/test/validate-output.test.mjs`

- [ ] **Step 1: Create the schema**

Create `skills/audit/schemas/report-summary.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "report-summary.schema.json",
  "title": "OSWE HTML Report Summary",
  "type": "object",
  "additionalProperties": false,
  "required": ["meta", "severity_counts", "finding_status_counts", "coverage", "chains"],
  "properties": {
    "meta": {
      "type": "object",
      "additionalProperties": false,
      "required": ["target", "stack", "date", "verdict", "proof_level"],
      "properties": {
        "target": { "type": "string", "maxLength": 4096 },
        "stack": { "type": "string", "maxLength": 512 },
        "date": { "type": "string", "maxLength": 64 },
        "verdict": { "enum": ["unauth-rce", "no-critique"] },
        "proof_level": { "type": ["string", "null"], "maxLength": 64 }
      }
    },
    "severity_counts": {
      "type": "object",
      "additionalProperties": false,
      "required": ["Critique", "Haute", "Moyenne", "Basse", "Info"],
      "properties": {
        "Critique": { "type": "integer", "minimum": 0 },
        "Haute": { "type": "integer", "minimum": 0 },
        "Moyenne": { "type": "integer", "minimum": 0 },
        "Basse": { "type": "integer", "minimum": 0 },
        "Info": { "type": "integer", "minimum": 0 }
      }
    },
    "finding_status_counts": {
      "type": "object",
      "additionalProperties": false,
      "required": ["accepted", "downgraded", "rejected", "not-requested"],
      "properties": {
        "accepted": { "type": "integer", "minimum": 0 },
        "downgraded": { "type": "integer", "minimum": 0 },
        "rejected": { "type": "integer", "minimum": 0 },
        "not-requested": { "type": "integer", "minimum": 0 }
      }
    },
    "coverage": {
      "type": "object",
      "additionalProperties": false,
      "required": ["analyzed", "skipped"],
      "properties": {
        "analyzed": { "type": "integer", "minimum": 0 },
        "skipped": { "type": "integer", "minimum": 0 }
      }
    },
    "chains": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "severity", "entry_auth", "final_impact", "nodes", "edges"],
        "properties": {
          "id": { "type": "string", "pattern": "^CHAIN-[0-9]+$" },
          "severity": { "enum": ["Critique", "Haute", "Moyenne", "Basse", "Info"] },
          "entry_auth": { "enum": ["unauthenticated", "authenticated", "admin"] },
          "final_impact": { "enum": ["unauth-rce", "other"] },
          "nodes": {
            "type": "array",
            "items": { "type": "string", "pattern": "^(entry|RCE|OSWE-[0-9]+)$" }
          },
          "edges": {
            "type": "array",
            "items": {
              "type": "object",
              "additionalProperties": false,
              "required": ["from", "to", "verdict"],
              "properties": {
                "from": { "type": "string", "pattern": "^(entry|RCE|OSWE-[0-9]+)$" },
                "to": { "type": "string", "pattern": "^(entry|RCE|OSWE-[0-9]+)$" },
                "verdict": { "enum": ["accepted", "downgraded", "rejected"] }
              }
            }
          }
        }
      }
    }
  }
}
```

- [ ] **Step 2: Wire the export into the build tool**

In `skills/audit/scripts/build-validators.mjs`, find the `EXPORT_NAME` map:

```js
const EXPORT_NAME = {
  "finding.schema.json": "finding",
  "final-finding.schema.json": "finalFinding",
  "analyzer-response.schema.json": "analyzerResponse",
  "chain.schema.json": "chain",
  "verdict.schema.json": "verdict",
  "verifier-response.schema.json": "verifierResponse"
};
```

Add the new entry (so the map becomes):

```js
const EXPORT_NAME = {
  "finding.schema.json": "finding",
  "final-finding.schema.json": "finalFinding",
  "analyzer-response.schema.json": "analyzerResponse",
  "chain.schema.json": "chain",
  "verdict.schema.json": "verdict",
  "verifier-response.schema.json": "verifierResponse",
  "report-summary.schema.json": "reportSummary"
};
```

- [ ] **Step 3: Add the kind to validate-output**

In `skills/audit/scripts/validate-output.mjs`, find the `KIND_TO_EXPORT` map and add the `report-summary` line:

```js
const KIND_TO_EXPORT = {
  "analyzer-response": "analyzerResponse",
  "verifier-response": "verifierResponse",
  "finding": "finding",
  "final-finding": "finalFinding",
  "chain": "chain",
  "verdict": "verdict",
  "report-summary": "reportSummary"
};
```

- [ ] **Step 4: Regenerate the standalone validators**

Run (ajv is a dev dependency, already installed in `scripts/node_modules`):
```bash
( cd skills/audit/scripts && node build-validators.mjs )
```
Expected: prints `validators.mjs generated (self-contained): … report-summary.schema.json` and the file now exports `reportSummary`. Confirm zero residual require/import (the script asserts this itself).

- [ ] **Step 5: Write the schema tests**

In `skills/audit/scripts/test/validate-output.test.mjs`, append (the file already imports `validate` and `test`/`assert`):

```js
const validSummary = (overrides = {}) => ({
  meta: { target: "t", stack: "s", date: "2026-06-16 10:15", verdict: "unauth-rce", proof_level: "preuve statique forte" },
  severity_counts: { Critique: 1, Haute: 2, Moyenne: 0, Basse: 0, Info: 0 },
  finding_status_counts: { accepted: 2, downgraded: 0, rejected: 0, "not-requested": 0 },
  coverage: { analyzed: 2, skipped: 0 },
  chains: [{ id: "CHAIN-1", severity: "Critique", entry_auth: "unauthenticated", final_impact: "unauth-rce",
             nodes: ["entry", "OSWE-1", "OSWE-2", "RCE"],
             edges: [{ from: "entry", to: "OSWE-1", verdict: "accepted" }, { from: "OSWE-1", to: "OSWE-2", verdict: "accepted" }] }],
  ...overrides
});

test("report-summary: valid summary passes", () => {
  assert.equal(validate("report-summary", validSummary()).valid, true);
});
test("report-summary: empty chains + zero counts passes (safe report)", () => {
  const r = validate("report-summary", validSummary({
    severity_counts: { Critique: 0, Haute: 0, Moyenne: 0, Basse: 0, Info: 0 },
    chains: []
  }));
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});
test("report-summary: free-text node label is rejected", () => {
  const s = validSummary();
  s.chains[0].nodes = ["<img onerror=x>"];
  assert.equal(validate("report-summary", s).valid, false);
});
test("report-summary: final_impact outside enum is rejected", () => {
  const s = validSummary();
  s.chains[0].final_impact = "rce";
  assert.equal(validate("report-summary", s).valid, false);
});
test("report-summary: additionalProperties is rejected", () => {
  const s = validSummary();
  s.extra = 1;
  assert.equal(validate("report-summary", s).valid, false);
});
test("report-summary: missing a severity key is rejected", () => {
  const s = validSummary();
  delete s.severity_counts.Info;
  assert.equal(validate("report-summary", s).valid, false);
});
```

- [ ] **Step 6: Run the tests**

Run: `( cd skills/audit/scripts && node --test )`
Expected: all existing tests still pass **plus** the 6 new `report-summary` tests; `# fail 0`.

- [ ] **Step 7: Confirm the validator is still dependency-free**

Run (temporarily hide node_modules and load the generated file):
```bash
( cd skills/audit/scripts && mv node_modules .nm_hidden && node -e "import('./validators.mjs').then(v=>{if(typeof v.reportSummary!=='function')throw new Error('no reportSummary export');console.log('reportSummary loads with NO node_modules OK')}).catch(e=>{console.error(e);process.exit(1)})"; mv .nm_hidden node_modules )
```
Expected: `reportSummary loads with NO node_modules OK`. (The `mv` back always runs.)

- [ ] **Step 8: Commit**

```bash
git add skills/audit/schemas/report-summary.schema.json skills/audit/scripts/build-validators.mjs skills/audit/scripts/validate-output.mjs skills/audit/scripts/validators.mjs skills/audit/scripts/test/validate-output.test.mjs
git commit -m "feat(oswe): add report-summary schema + reportSummary validator export"
```

---

## Task 2: render-html.mjs — escaping + Markdown→HTML converter

**Files:**
- Create: `skills/audit/scripts/render-html.mjs`
- Test: `skills/audit/scripts/test/render-html.test.mjs`

- [ ] **Step 1: Write the failing tests**

Create `skills/audit/scripts/test/render-html.test.mjs`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import { escapeHtml, mdToHtml } from "../render-html.mjs";

test("escapeHtml escapes the four dangerous chars", () => {
  assert.equal(escapeHtml(`<a href="x">&`), "&lt;a href=&quot;x&quot;&gt;&amp;");
});
test("headings render h1/h2/h3", () => {
  assert.match(mdToHtml("# A\n## B\n### C"), /<h1>A<\/h1>[\s\S]*<h2>B<\/h2>[\s\S]*<h3>C<\/h3>/);
});
test("bold then italic, asterisk-only, longer delimiter first", () => {
  assert.equal(mdToHtml("**a** and *b*").includes("<strong>a</strong> and <em>b</em>"), true);
});
test("underscores stay literal (no <em>)", () => {
  const h = mdToHtml("render_template_string and __class__ and SECRET_KEY");
  assert.equal(h.includes("<em>"), false);
  assert.equal(h.includes("render_template_string"), true);
});
test("inline code is escaped and not emphasis-formatted", () => {
  const h = mdToHtml("`a*b*c` and `<script>`");
  assert.equal(h.includes("<code>a*b*c</code>"), true);
  assert.equal(h.includes("<code>&lt;script&gt;</code>"), true);
});
test("table renders thead/tbody", () => {
  const h = mdToHtml("| A | B |\n|---|---|\n| 1 | 2 |");
  assert.match(h, /<table><thead><tr><th>A<\/th><th>B<\/th><\/tr><\/thead><tbody><tr><td>1<\/td><td>2<\/td><\/tr><\/tbody><\/table>/);
});
test("blockquote, list, hr, strikethrough render", () => {
  assert.match(mdToHtml("> note"), /<blockquote>note<\/blockquote>/);
  assert.match(mdToHtml("- x\n- y"), /<ul><li>x<\/li><li>y<\/li><\/ul>/);
  assert.match(mdToHtml("---"), /<hr>/);
  assert.match(mdToHtml("~~gone~~"), /<del>gone<\/del>/);
});
test("malicious MD is escaped, never live tags", () => {
  const evil = "# <script>alert(1)</script>\n\n| <img onerror=x> | b |\n|---|---|\n| `\"><img onerror=y>` | 2 |";
  const h = mdToHtml(evil);
  assert.equal(/<script\b/i.test(h), false);
  assert.equal(/<img\b/i.test(h), false);
  assert.equal(h.includes("&lt;script&gt;"), true);
  assert.equal(h.includes("&lt;img onerror=x&gt;"), true);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `( cd skills/audit/scripts && node --test test/render-html.test.mjs )`
Expected: FAIL — `Cannot find module '../render-html.mjs'` (file not created yet).

- [ ] **Step 3: Implement escaping + the converter**

Create `skills/audit/scripts/render-html.mjs`:

```js
// render-html.mjs — Zero runtime dependency. Renders a self-contained visual HTML report from the
// redaction-safe Markdown report (--md) plus a non-sensitive summary JSON (--summary), to --out.
// Body = MD->HTML over a FIXED construct set; charts (added later) = inline SVG from the summary.
// All MD- and summary-derived text is HTML-escaped; the document carries a strict CSP and no script.

// ---------- escaping ----------
export function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ---------- inline Markdown (operates after escaping) ----------
function formatEmphasis(escaped) {
  // asterisk-only emphasis; underscores stay literal; bold (**) before italic (*).
  return escaped
    .replace(/\*\*([^*]+?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+?)\*/g, "<em>$1</em>")
    .replace(/~~([^~]+?)~~/g, "<del>$1</del>");
}

function renderInline(text) {
  // Protect inline code spans first: their content is escaped but never emphasis-formatted.
  const parts = [];
  const re = /`([^`]+)`/g;
  let last = 0, m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parts.push({ code: false, s: text.slice(last, m.index) });
    parts.push({ code: true, s: m[1] });
    last = m.index + m[0].length;
  }
  if (last < text.length) parts.push({ code: false, s: text.slice(last) });
  return parts
    .map((p) => (p.code ? `<code>${escapeHtml(p.s)}</code>` : formatEmphasis(escapeHtml(p.s))))
    .join("");
}

// ---------- block Markdown ----------
export function mdToHtml(md) {
  const lines = String(md).replace(/\r\n/g, "\n").split("\n");
  const out = [];
  let i = 0;
  const isSep = (l) => l.includes("-") && /^\s*\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)*\|?\s*$/.test(l);
  const splitRow = (l) => {
    let s = l.trim();
    if (s.startsWith("|")) s = s.slice(1);
    if (s.endsWith("|")) s = s.slice(0, -1);
    return s.split("|").map((c) => c.trim());
  };
  const isStructural = (l) =>
    /^\s*$/.test(l) || /^(#{1,3})\s+/.test(l) || /^---+\s*$/.test(l) || /^>\s?/.test(l) || /^[-*]\s+/.test(l);
  while (i < lines.length) {
    const line = lines[i];
    if (/^\s*$/.test(line)) { i++; continue; }
    const h = /^(#{1,3})\s+(.*)$/.exec(line);
    if (h) { const n = h[1].length; out.push(`<h${n}>${renderInline(h[2].trim())}</h${n}>`); i++; continue; }
    if (/^---+\s*$/.test(line)) { out.push("<hr>"); i++; continue; }
    if (line.includes("|") && i + 1 < lines.length && isSep(lines[i + 1])) {
      const header = splitRow(line);
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].includes("|") && !/^\s*$/.test(lines[i])) { rows.push(splitRow(lines[i])); i++; }
      let t = "<table><thead><tr>" + header.map((c) => `<th>${renderInline(c)}</th>`).join("") + "</tr></thead><tbody>";
      for (const r of rows) t += "<tr>" + r.map((c) => `<td>${renderInline(c)}</td>`).join("") + "</tr>";
      t += "</tbody></table>";
      out.push(t); continue;
    }
    if (/^>\s?/.test(line)) {
      const buf = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) { buf.push(renderInline(lines[i].replace(/^>\s?/, ""))); i++; }
      out.push(`<blockquote>${buf.join("<br>")}</blockquote>`); continue;
    }
    if (/^[-*]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^[-*]\s+/.test(lines[i])) { items.push(`<li>${renderInline(lines[i].replace(/^[-*]\s+/, ""))}</li>`); i++; }
      out.push(`<ul>${items.join("")}</ul>`); continue;
    }
    const para = [];
    while (i < lines.length && !isStructural(lines[i]) && !(lines[i].includes("|") && i + 1 < lines.length && isSep(lines[i + 1]))) {
      para.push(renderInline(lines[i])); i++;
    }
    out.push(`<p>${para.join("<br>")}</p>`);
  }
  return out.join("\n");
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `( cd skills/audit/scripts && node --test test/render-html.test.mjs )`
Expected: PASS — all converter/escaping tests green.

- [ ] **Step 5: Commit**

```bash
git add skills/audit/scripts/render-html.mjs skills/audit/scripts/test/render-html.test.mjs
git commit -m "feat(oswe): render-html escaping + fixed-scope Markdown->HTML converter"
```

---

## Task 3: render-html.mjs — the four SVG charts

**Files:**
- Modify: `skills/audit/scripts/render-html.mjs` (append chart functions)
- Test: `skills/audit/scripts/test/render-html.test.mjs` (append chart tests)

- [ ] **Step 1: Write the failing tests**

Append to `skills/audit/scripts/test/render-html.test.mjs`:

```js
import { severityDonut, coverageBar, statusBar, chainDiagram } from "../render-html.mjs";

const SEV = { Critique: 1, Haute: 2, Moyenne: 0, Basse: 0, Info: 0 };
const CHAINS = [{ id: "CHAIN-1", severity: "Critique", entry_auth: "unauthenticated", final_impact: "unauth-rce",
                  nodes: ["entry", "OSWE-1", "OSWE-2", "RCE"],
                  edges: [{ from: "entry", to: "OSWE-1", verdict: "accepted" }, { from: "OSWE-1", to: "OSWE-2", verdict: "accepted" }] }];

test("severity donut reflects counts and total, no NaN", () => {
  const svg = severityDonut(SEV);
  assert.equal(svg.includes("Critique: 1"), true);
  assert.equal(svg.includes("Haute: 2"), true);
  assert.equal(svg.includes(">3<"), true);          // total in the center
  assert.equal(/NaN/.test(svg), false);
});
test("empty donut: grey ring + 'No findings', no NaN", () => {
  const svg = severityDonut({ Critique: 0, Haute: 0, Moyenne: 0, Basse: 0, Info: 0 });
  assert.equal(svg.includes("No findings"), true);
  assert.equal(svg.includes("#dddddd"), true);
  assert.equal(/NaN/.test(svg), false);
});
test("chain diagram: node/edge counts match; zero chains -> note", () => {
  const svg = chainDiagram(CHAINS);
  assert.equal((svg.match(/<rect /g) || []).length, 4);    // 4 nodes
  assert.equal((svg.match(/<polygon /g) || []).length, 2); // 2 edge arrowheads
  assert.equal(chainDiagram([]).includes("No exploit chains"), true);
});
test("coverage and status bars reflect counts, no NaN on empty", () => {
  assert.equal(coverageBar({ analyzed: 2, skipped: 0 }).includes("analyzed 2"), true);
  assert.equal(statusBar({ accepted: 2, downgraded: 0, rejected: 0, "not-requested": 0 }).includes("accepted 2"), true);
  assert.equal(/NaN/.test(statusBar({ accepted: 0, downgraded: 0, rejected: 0, "not-requested": 0 })), false);
  assert.equal(/NaN/.test(coverageBar({ analyzed: 0, skipped: 0 })), false);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `( cd skills/audit/scripts && node --test test/render-html.test.mjs )`
Expected: FAIL — `severityDonut`/`coverageBar`/`statusBar`/`chainDiagram` are not exported yet.

- [ ] **Step 3: Implement the charts**

Append to `skills/audit/scripts/render-html.mjs`:

```js
// ---------- charts (inline SVG, deterministic, computed from the summary) ----------
const SEVERITIES = ["Critique", "Haute", "Moyenne", "Basse", "Info"];
const SEV_COLOR = { Critique: "#b00020", Haute: "#e65100", Moyenne: "#f9a825", Basse: "#1565c0", Info: "#607d8b" };

export function severityDonut(counts) {
  const total = SEVERITIES.reduce((a, s) => a + (counts[s] || 0), 0);
  const cx = 90, cy = 90, r = 60, sw = 26, C = 2 * Math.PI * r;
  let ring = "";
  if (total === 0) {
    ring = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#dddddd" stroke-width="${sw}"></circle>`
         + `<text x="${cx}" y="${cy + 5}" text-anchor="middle" class="donut-empty">No findings</text>`;
  } else {
    let offset = 0;
    for (const s of SEVERITIES) {
      const v = counts[s] || 0;
      if (!v) continue;
      const seg = (v / total) * C;
      ring += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${SEV_COLOR[s]}" stroke-width="${sw}"`
            + ` stroke-dasharray="${seg.toFixed(3)} ${(C - seg).toFixed(3)}" stroke-dashoffset="${(-offset).toFixed(3)}"`
            + ` transform="rotate(-90 ${cx} ${cy})"></circle>`;
      offset += seg;
    }
    ring += `<text x="${cx}" y="${cy + 6}" text-anchor="middle" class="donut-total">${total}</text>`;
  }
  let legend = "", ly = 26;
  for (const s of SEVERITIES) {
    legend += `<rect x="190" y="${ly - 11}" width="12" height="12" fill="${SEV_COLOR[s]}"></rect>`
            + `<text x="208" y="${ly}" class="legend">${escapeHtml(s)}: ${counts[s] || 0}</text>`;
    ly += 22;
  }
  return `<svg viewBox="0 0 340 180" role="img" aria-label="Severity counts" class="chart">${ring}${legend}</svg>`;
}

export function coverageBar(coverage) {
  const a = coverage.analyzed || 0, s = coverage.skipped || 0, tot = a + s;
  const W = 300, H = 26;
  const aw = tot === 0 ? 0 : (a / tot) * W;
  const sw = tot === 0 ? 0 : (s / tot) * W;
  const base = tot === 0 ? `<rect x="0" y="0" width="${W}" height="${H}" fill="#dddddd"></rect>` : "";
  return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Coverage" class="chart bar">`
    + base
    + `<rect x="0" y="0" width="${aw.toFixed(2)}" height="${H}" fill="#2e7d32"></rect>`
    + `<rect x="${aw.toFixed(2)}" y="0" width="${sw.toFixed(2)}" height="${H}" fill="#c62828"></rect>`
    + `<text x="6" y="17" class="bar-label">analyzed ${a}</text>`
    + `<text x="${W - 6}" y="17" text-anchor="end" class="bar-label">skipped ${s}</text>`
    + `</svg>`;
}

const STATUSES = ["accepted", "downgraded", "rejected", "not-requested"];
const STATUS_COLOR = { accepted: "#2e7d32", downgraded: "#f9a825", rejected: "#9e9e9e", "not-requested": "#1565c0" };

export function statusBar(counts) {
  const tot = STATUSES.reduce((acc, k) => acc + (counts[k] || 0), 0);
  const W = 320, H = 26;
  let x = 0, rects = "";
  if (tot === 0) {
    rects = `<rect x="0" y="0" width="${W}" height="${H}" fill="#dddddd"></rect>`
          + `<text x="6" y="17" class="bar-label">no findings</text>`;
  } else {
    for (const k of STATUSES) {
      const v = counts[k] || 0;
      if (!v) continue;
      const w = (v / tot) * W;
      rects += `<rect x="${x.toFixed(2)}" y="0" width="${w.toFixed(2)}" height="${H}" fill="${STATUS_COLOR[k]}"></rect>`;
      x += w;
    }
  }
  let legend = "", lx = 0;
  for (const k of STATUSES) {
    legend += `<rect x="${lx}" y="34" width="12" height="12" fill="${STATUS_COLOR[k]}"></rect>`
            + `<text x="${lx + 16}" y="44" class="legend">${escapeHtml(k)} ${counts[k] || 0}</text>`;
    lx += 80;
  }
  return `<svg viewBox="0 0 ${W} 52" role="img" aria-label="Finding statuses" class="chart bar">${rects}${legend}</svg>`;
}

export function chainDiagram(chains) {
  if (!chains || chains.length === 0) return `<p class="muted">No exploit chains.</p>`;
  const svgs = [];
  for (const ch of chains) {
    const nodes = ch.nodes;
    const boxW = 92, boxH = 34, gap = 38, x0 = 10, y = 26;
    const width = x0 * 2 + nodes.length * boxW + (nodes.length - 1) * gap;
    const xOf = (idx) => x0 + idx * (boxW + gap);
    let g = "";
    for (const e of ch.edges) {
      const fi = nodes.indexOf(e.from), ti = nodes.indexOf(e.to);
      if (fi < 0 || ti < 0) continue;
      const x1 = xOf(fi) + boxW, x2 = xOf(ti), my = y + boxH / 2;
      g += `<line x1="${x1}" y1="${my}" x2="${x2}" y2="${my}" class="edge"></line>`
         + `<polygon points="${x2},${my} ${x2 - 7},${my - 4} ${x2 - 7},${my + 4}" class="arrow"></polygon>`
         + `<text x="${((x1 + x2) / 2).toFixed(1)}" y="${my - 6}" text-anchor="middle" class="edge-label">${escapeHtml(e.verdict)}</text>`;
    }
    nodes.forEach((n, idx) => {
      const isRce = n === "RCE";
      const crit = ch.severity === "Critique" || ch.final_impact === "unauth-rce";
      const cls = isRce ? (crit ? "node node-rce-crit" : "node node-rce") : (n === "entry" ? "node node-entry" : "node");
      const label = n === "entry" && ch.entry_auth === "unauthenticated" ? "entry (unauth)" : n;
      g += `<rect x="${xOf(idx)}" y="${y}" width="${boxW}" height="${boxH}" rx="5" class="${cls}"></rect>`
         + `<text x="${xOf(idx) + boxW / 2}" y="${y + boxH / 2 + 5}" text-anchor="middle" class="node-label">${escapeHtml(label)}</text>`;
    });
    svgs.push(`<div class="chain"><div class="chain-id">${escapeHtml(ch.id)} — ${escapeHtml(ch.severity)}</div>`
      + `<svg viewBox="0 0 ${width} 76" role="img" aria-label="Exploit chain ${escapeHtml(ch.id)}" class="chart">${g}</svg></div>`);
  }
  return svgs.join("\n");
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `( cd skills/audit/scripts && node --test test/render-html.test.mjs )`
Expected: PASS — all converter + chart tests green.

- [ ] **Step 5: Commit**

```bash
git add skills/audit/scripts/render-html.mjs skills/audit/scripts/test/render-html.test.mjs
git commit -m "feat(oswe): render-html SVG charts (severity donut, chain diagram, coverage/status bars)"
```

---

## Task 4: render-html.mjs — document assembly + CLI (atomic write)

**Files:**
- Modify: `skills/audit/scripts/render-html.mjs` (append `renderReport` + CLI; add validators import)
- Test: `skills/audit/scripts/test/render-html.test.mjs` (append assembly + CLI tests)

- [ ] **Step 1: Write the failing tests**

Append to `skills/audit/scripts/test/render-html.test.mjs`:

```js
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { renderReport } from "../render-html.mjs";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "..", "render-html.mjs");

const fullSummary = () => ({
  meta: { target: "test-fixtures/python/vulnerable", stack: "Python / Flask 3.0.3", date: "2026-06-16 10:15", verdict: "unauth-rce", proof_level: "preuve statique forte" },
  severity_counts: { Critique: 1, Haute: 2, Moyenne: 0, Basse: 0, Info: 0 },
  finding_status_counts: { accepted: 2, downgraded: 0, rejected: 0, "not-requested": 0 },
  coverage: { analyzed: 2, skipped: 0 },
  chains: [{ id: "CHAIN-1", severity: "Critique", entry_auth: "unauthenticated", final_impact: "unauth-rce",
             nodes: ["entry", "OSWE-1", "OSWE-2", "RCE"],
             edges: [{ from: "entry", to: "OSWE-1", verdict: "accepted" }, { from: "OSWE-1", to: "OSWE-2", verdict: "accepted" }] }]
});

test("renderReport: meta fields are escaped, never live tags", () => {
  const s = fullSummary();
  s.meta.target = "<img src=x onerror=1>";
  s.meta.stack = `a"&b`;
  const html = renderReport({ md: "# ok", summary: s });
  assert.equal(/<img\b/i.test(html), false);
  assert.equal(html.includes("&lt;img src=x onerror=1&gt;"), true);
  assert.equal(html.includes("a&quot;&amp;b"), true);
});
test("renderReport: self-contained + CSP, no active/external markup", () => {
  const html = renderReport({ md: "# ok\n\nbody `code`", summary: fullSummary() });
  assert.equal(html.includes(`content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"`), true);
  for (const tag of ["<script", "<img", "<iframe", "<object", "<embed", "<link"]) {
    assert.equal(html.toLowerCase().includes(tag), false, "must not emit " + tag);
  }
  assert.equal(/\ssrc=/.test(html), false);
  assert.equal(/\shref=/.test(html), false);
});
test("renderReport: escaped active markup in body is allowed", () => {
  const html = renderReport({ md: "value `<img src=x>`", summary: fullSummary() });
  assert.equal(html.includes("&lt;img src=x&gt;"), true);
  assert.equal(/<img\b/i.test(html), false);
});
test("renderReport: deterministic", () => {
  const a = renderReport({ md: "# A\n\n- x", summary: fullSummary() });
  const b = renderReport({ md: "# A\n\n- x", summary: fullSummary() });
  assert.equal(a, b);
});

function mkdir() { return mkdtempSync(join(tmpdir(), "oswe-html-")); }

test("CLI: valid input writes html, exit 0", () => {
  const d = mkdir();
  const md = join(d, "r.md"), sum = join(d, "s.json"), out = join(d, "r.html");
  writeFileSync(md, "# Report\n\nbody");
  writeFileSync(sum, JSON.stringify(fullSummary()));
  execFileSync(process.execPath, [SCRIPT, "--md", md, "--summary", sum, "--out", out]);
  assert.equal(existsSync(out), true);
  assert.equal(readFileSync(out, "utf8").includes("OSWE Audit Report"), true);
  rmSync(d, { recursive: true, force: true });
});
test("CLI: invalid summary -> exit 1, no html, no tmp leftover", () => {
  const d = mkdir();
  const md = join(d, "r.md"), sum = join(d, "s.json"), out = join(d, "r.html");
  writeFileSync(md, "# Report");
  const bad = fullSummary();
  bad.chains[0].nodes = ["<img onerror=x>"]; // schema-invalid node label
  writeFileSync(sum, JSON.stringify(bad));
  let code = 0;
  try { execFileSync(process.execPath, [SCRIPT, "--md", md, "--summary", sum, "--out", out], { stdio: "pipe" }); }
  catch (e) { code = e.status; }
  assert.equal(code, 1);
  assert.equal(existsSync(out), false);
  assert.equal(readdirSync(d).some((f) => f.includes(".tmp-")), false);
  rmSync(d, { recursive: true, force: true });
});
test("CLI: missing flags / nonexistent files -> exit 2", () => {
  const d = mkdir();
  let code = 0;
  try {
    execFileSync(process.execPath, [SCRIPT, "--md", join(d, "nope.md"), "--summary", join(d, "nope.json"), "--out", join(d, "o.html")], { stdio: "pipe" });
  } catch (e) { code = e.status; }
  assert.equal(code, 2);
  let code2 = 0;
  try { execFileSync(process.execPath, [SCRIPT, "--md", join(d, "x.md")], { stdio: "pipe" }); }
  catch (e) { code2 = e.status; }
  assert.equal(code2, 2);
  rmSync(d, { recursive: true, force: true });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `( cd skills/audit/scripts && node --test test/render-html.test.mjs )`
Expected: FAIL — `renderReport` is not exported and the script has no CLI yet.

- [ ] **Step 3: Implement document assembly + CLI**

Append to `skills/audit/scripts/render-html.mjs`:

```js
// ---------- document assembly ----------
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync, renameSync, unlinkSync } from "node:fs";
import * as validators from "./validators.mjs";

const CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'";
const STYLE = `
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#111;background:#fff;line-height:1.45}
h1,h2,h3{line-height:1.2}
table{border-collapse:collapse;margin:0.6rem 0;width:100%}
th,td{border:1px solid #ccc;padding:4px 8px;text-align:left;vertical-align:top;font-size:0.92rem}
th{background:#f3f3f3}
code{background:#f3f3f3;padding:0 3px;border-radius:3px;font-family:ui-monospace,Consolas,monospace;font-size:0.9em}
blockquote{border-left:3px solid #bbb;margin:0.6rem 0;padding:0.2rem 0.8rem;color:#444}
hr{border:0;border-top:1px solid #ddd;margin:1.2rem 0}
del{color:#999}
.charts{display:flex;flex-wrap:wrap;gap:1.5rem;align-items:flex-start;margin:1rem 0 1.5rem}
.chart{max-width:100%}
.node{fill:#eceff1;stroke:#607d8b}
.node-entry{fill:#e3f2fd;stroke:#1565c0}
.node-rce{fill:#ffe0b2;stroke:#e65100}
.node-rce-crit{fill:#ffcdd2;stroke:#b00020}
.node-label{font-size:12px;fill:#111}
.edge{stroke:#888;stroke-width:1.5}
.arrow{fill:#888}
.edge-label{font-size:10px;fill:#555}
.legend,.bar-label,.donut-total,.donut-empty{font-size:12px;fill:#111}
.chain-id{font-weight:600;margin-top:0.4rem}
.muted{color:#777}
@media print{body{margin:0.6rem}.chain,h2{page-break-inside:avoid}h2{page-break-before:always}h1{page-break-before:avoid}}
`;

export function renderReport({ md, summary }) {
  const m = summary.meta;
  const verdictText = m.verdict === "unauth-rce" ? "Unauthenticated RCE found" : "No Critique chain";
  const head =
    `<header><h1>OSWE Audit Report</h1>`
    + `<p class="muted">${escapeHtml(m.target)} — ${escapeHtml(m.stack)} — ${escapeHtml(m.date)}</p>`
    + `<p><strong>${escapeHtml(verdictText)}</strong>${m.proof_level ? " — " + escapeHtml(m.proof_level) : ""}</p></header>`;
  const charts =
    `<section class="charts">`
    + severityDonut(summary.severity_counts)
    + coverageBar(summary.coverage)
    + statusBar(summary.finding_status_counts)
    + `</section>`
    + `<section class="chains-section"><h2>Exploit chains (diagram)</h2>${chainDiagram(summary.chains)}</section>`;
  const body = `<section class="report-body">${mdToHtml(md)}</section>`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${CSP}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSWE Audit Report</title>
<style>${STYLE}</style>
</head>
<body>
${head}
${charts}
${body}
</body>
</html>
`;
}

// ---------- CLI: node render-html.mjs --md <report.md> --summary <summary.json> --out <report.html> ----------
function isMain() {
  return Boolean(process.argv[1]) && fileURLToPath(import.meta.url) === process.argv[1];
}

if (isMain()) {
  const args = process.argv.slice(2);
  const flag = (name) => { const i = args.indexOf(name); return i !== -1 ? args[i + 1] : undefined; };
  const mdPath = flag("--md"), sumPath = flag("--summary"), outPath = flag("--out");
  const fail2 = (msg) => { process.stderr.write("render-html: " + msg + "\n"); process.exit(2); };
  if (!mdPath || !sumPath || !outPath) {
    fail2("usage: render-html.mjs --md <report.md> --summary <summary.json> --out <report.html>");
  }
  let md, sumRaw;
  try { md = readFileSync(mdPath, "utf8"); } catch (e) { fail2("cannot read --md " + mdPath + ": " + e.message); }
  try { sumRaw = readFileSync(sumPath, "utf8"); } catch (e) { fail2("cannot read --summary " + sumPath + ": " + e.message); }
  let summary;
  try { summary = JSON.parse(sumRaw); } catch (e) { fail2("invalid JSON in --summary: " + e.message); }
  if (!validators.reportSummary(summary)) {
    process.stderr.write("render-html: invalid summary: " + JSON.stringify(validators.reportSummary.errors || []) + "\n");
    process.exit(1);
  }
  let html;
  try { html = renderReport({ md, summary }); } catch (e) { fail2("render failed: " + e.message); }
  const tmp = outPath + ".tmp-" + process.pid;
  try {
    writeFileSync(tmp, html);
    renameSync(tmp, outPath);   // atomic: never leaves a partial report.html
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* nothing to clean */ }
    fail2("cannot write --out " + outPath + ": " + e.message);
  }
  process.exit(0);
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `( cd skills/audit/scripts && node --test test/render-html.test.mjs )`
Expected: PASS — assembly + CLI tests green.

- [ ] **Step 5: Run the full script test suite**

Run: `( cd skills/audit/scripts && node --test )`
Expected: every test passes (`# fail 0`) — the MVP regression plus the new `report-summary` and `render-html` tests.

- [ ] **Step 6: Commit**

```bash
git add skills/audit/scripts/render-html.mjs skills/audit/scripts/test/render-html.test.mjs
git commit -m "feat(oswe): render-html document assembly + CLI with atomic write"
```

---

## Task 5: SKILL phase-7 integration (HTML never gates the audit)

**Files:**
- Modify: `skills/audit/SKILL.md`

- [ ] **Step 1: Extend phase 7 to emit the HTML**

In `skills/audit/SKILL.md`, find the `### 7. Report` section. It currently reads:

```
### 7. Report
Write `${CLAUDE_PROJECT_DIR}/.oswe/reports/oswe-report-YYYY-MM-DD-HHMM.md` (always relative to the
project root) and print a chat summary. Findings are reported by **`final_severity`** (falling back
to `provisional_severity` only for `not-requested` items). See Report format below.
**Then purge temp:** `rm -rf "${CLAUDE_PROJECT_DIR}/.oswe/tmp"` (the report is `[REDACTED]`-safe; the
raw intermediate files are not — see Temp-file hygiene). This runs on the success path; on any abort
earlier in the pipeline, purge before exiting too.
```

Replace it with (insert the HTML-export paragraph **before** the purge line, so the temp summary is purged with everything else):

```
### 7. Report
Write `${CLAUDE_PROJECT_DIR}/.oswe/reports/oswe-report-YYYY-MM-DD-HHMM.md` (always relative to the
project root) and print a chat summary. Findings are reported by **`final_severity`** (falling back
to `provisional_severity` only for `not-requested` items). See Report format below.

**Then emit the visual HTML report (alongside the `.md`, same basename).** Build a **non-sensitive
`summary` object** (see "HTML export" below) from the final findings/chains/`gaps` plus the
orchestrator's aggregated analyzer-coverage state, write it to a literal `.oswe/tmp/` path (file tool,
no shell interpolation), and run the tested helper under the usual `trap`:
`( trap 'rm -f "${CLAUDE_PROJECT_DIR}/.oswe/tmp/summary-<token>.json"' EXIT; node "${CLAUDE_PLUGIN_ROOT}/skills/audit/scripts/render-html.mjs" --md "${CLAUDE_PROJECT_DIR}/.oswe/reports/oswe-report-YYYY-MM-DD-HHMM.md" --summary "${CLAUDE_PROJECT_DIR}/.oswe/tmp/summary-<token>.json" --out "${CLAUDE_PROJECT_DIR}/.oswe/reports/oswe-report-YYYY-MM-DD-HHMM.html" )`.
**The HTML can never fail the audit.** On a non-zero exit (1 = summary the orchestrator built wrong;
2 = IO), note `HTML export failed: <reason>; Markdown report at <path>` in the chat summary and
continue — the `.md` is the guaranteed artifact. The atomic write means a failure never leaves a
partial `.html`.

**Then purge temp:** `rm -rf "${CLAUDE_PROJECT_DIR}/.oswe/tmp"` (the report is `[REDACTED]`-safe; the
raw intermediate files are not — see Temp-file hygiene). This runs on the success path; on any abort
earlier in the pipeline, purge before exiting too.
```

- [ ] **Step 2: Add the "HTML export" subsection to the report format**

In `skills/audit/SKILL.md`, find the end of the `## Report format` section (the `- **Chat summary**:`
line). Immediately after that line, add a new subsection:

```
### HTML export (visual report, alongside the Markdown)
Every audit also writes `oswe-report-YYYY-MM-DD-HHMM.html` next to the `.md` via the tested
`render-html.mjs` helper (zero-dependency; the audited repo never executes it). The helper renders the
**redaction-safe `.md`** as the body (so the HTML inherits its `[REDACTED]` safety) plus four inline
SVG charts computed from a **non-sensitive `summary`** you build — counts and closed-set graph labels
only, **never** secrets, code excerpts, or `file:line`. The `summary` shape (validated by
`report-summary.schema.json`; `additionalProperties:false`, so build it exactly):
- `meta`: `{ target, stack, date, verdict ("unauth-rce"|"no-critique"), proof_level (string|null) }`.
- `severity_counts`: `{ Critique, Haute, Moyenne, Basse, Info }` — **`Critique` = number of accepted
  Critique chains**; the other four = findings by **reported** severity (the same selection the
  Markdown uses: `final_severity` for accepted/downgraded, `provisional_severity` for not-requested;
  **rejected findings excluded**).
- `finding_status_counts`: `{ accepted, downgraded, rejected, not-requested }` — findings per
  `verification_status` (sum = all findings, rejected included).
- `coverage`: `{ analyzed, skipped }` — analyzed partitions vs coverage gaps.
- `chains[]`: `{ id (^CHAIN-[0-9]+$), severity, entry_auth, final_impact ("unauth-rce"|"other" — map
  any non-`unauth-rce` chain impact to `other`), nodes[], edges[{from,to,verdict}] }`, where every
  node / edge endpoint is exactly `entry`, `RCE`, or `^OSWE-[0-9]+$` (no free text). A safe audit has
  `chains: []` and all-zero `severity_counts`.
```

- [ ] **Step 3: Verify the SKILL marker gate still passes**

Run (the MVP marker gate, unchanged):
```bash
missing=0; for s in "disable-model-invocation: true" "node --version" "confine-path.mjs" "aggregate-findings.mjs" "validate-batch.mjs" "apply-verdicts.mjs" "retriedBatchIds" "retriedPartitionIds" "Temp-file hygiene" "orchestrator-input" "expected_targets" "final-finding"; do if grep -q -- "$s" skills/audit/SKILL.md; then echo "OK: $s"; else echo "MISSING: $s"; missing=$((missing+1)); fi; done; echo "missing=$missing"
```
Expected: every line `OK:`, `missing=0`.

- [ ] **Step 4: Verify the HTML-export edits landed**

Run:
```bash
grep -q "render-html.mjs" skills/audit/SKILL.md && grep -q "HTML can never fail the audit" skills/audit/SKILL.md && grep -q "HTML export (visual report" skills/audit/SKILL.md && echo "html-export wiring OK"
sed -n '1,5p' skills/audit/SKILL.md
```
Expected: prints `html-export wiring OK`; the first 5 lines are the unchanged frontmatter (`---` / `name: audit` / `description:` / `disable-model-invocation: true` / `---`).

- [ ] **Step 5: Plugin still validates**

Run: `claude plugin validate . --strict`
Expected: `✔ Validation passed`. (If `claude` is unavailable, note it and proceed — the final gate is Task 7.)

- [ ] **Step 6: Commit**

```bash
git add skills/audit/SKILL.md
git commit -m "feat(oswe): SKILL phase-7 emits visual HTML report (never gates the audit)"
```

---

## Task 6: User-facing docs (README + manifest)

**Files:**
- Modify: `README.md`
- Modify: `.claude-plugin/plugin.json`

- [ ] **Step 1: Note the HTML report in the README**

In `README.md`, find this line (under `## Scope`, written in Phase 2):

```
PHP (Laravel/Symfony/vanilla), Node.js (Express/Nest), Python (Flask/Django), Java (Spring), and .NET (ASP.NET).
```

Immediately after it, add a new paragraph:

```

Each audit writes a redaction-safe Markdown report to `.oswe/reports/` **and**, alongside it, a
self-contained visual HTML report (`oswe-report-*.html`) with severity, exploit-chain, coverage, and
finding-status charts. The HTML is a single zero-dependency file (inline CSS + SVG, no scripts) —
open it in a browser and `Ctrl+P → Save as PDF` for a shareable PDF.
```

- [ ] **Step 2: Mention HTML in the manifest description**

In `.claude-plugin/plugin.json`, find this exact line:

```
  "description": "Deep white-box OSWE-style web app security audit via /oswe:audit (PHP, Node.js, Python, Java, .NET)",
```

Replace it with:

```
  "description": "Deep white-box OSWE-style web app security audit via /oswe:audit (PHP, Node.js, Python, Java, .NET) — Markdown + visual HTML reports",
```

- [ ] **Step 3: Verify**

Run:
```bash
node -e "JSON.parse(require('fs').readFileSync('.claude-plugin/plugin.json'))" && echo "manifest JSON valid"
grep -q "visual HTML report" README.md && echo "README updated"
grep -q "Markdown + visual HTML reports" .claude-plugin/plugin.json && echo "manifest updated"
```
Expected: `manifest JSON valid`, `README updated`, `manifest updated`.

- [ ] **Step 4: Commit**

```bash
git add README.md .claude-plugin/plugin.json
git commit -m "docs(oswe): document the visual HTML report output"
```

---

## Task 7: Final validation, regression, and acceptance

**Files:** none (verification only)

- [ ] **Step 1: Full script regression**

Run: `( cd skills/audit/scripts && node --test )`
Expected: `# fail 0`. This is the MVP 88 + the new `report-summary` (6) + `render-html` tests.

- [ ] **Step 2: Validator still dependency-free (with the new export)**

Run:
```bash
( cd skills/audit/scripts && mv node_modules .nm_hidden && node -e "import('./render-html.mjs').then(()=>import('./validators.mjs')).then(v=>{if(typeof v.reportSummary!=='function')throw new Error('no reportSummary');console.log('render-html + validators load with NO node_modules OK')}).catch(e=>{console.error(e);process.exit(1)})"; mv .nm_hidden node_modules )
```
Expected: `render-html + validators load with NO node_modules OK`.

- [ ] **Step 3: Plugin validates strictly**

Run: `claude plugin validate . --strict`
Expected: `✔ Validation passed`.

- [ ] **Step 4: End-to-end smoke render from a real report**

Pick the most recent existing report and render it with a hand-written summary to prove the CLI path
end-to-end (this does not need the orchestrator):
```bash
MD=$(ls -t .oswe/reports/oswe-report-*.md | head -1)
mkdir -p .oswe/tmp
cat > .oswe/tmp/smoke-summary.json <<'JSON'
{ "meta": { "target": "smoke", "stack": "smoke", "date": "2026-06-16 00:00", "verdict": "unauth-rce", "proof_level": "preuve statique forte" },
  "severity_counts": { "Critique": 1, "Haute": 2, "Moyenne": 0, "Basse": 0, "Info": 0 },
  "finding_status_counts": { "accepted": 2, "downgraded": 0, "rejected": 0, "not-requested": 0 },
  "coverage": { "analyzed": 2, "skipped": 0 },
  "chains": [ { "id": "CHAIN-1", "severity": "Critique", "entry_auth": "unauthenticated", "final_impact": "unauth-rce",
               "nodes": ["entry","OSWE-1","OSWE-2","RCE"],
               "edges": [ {"from":"entry","to":"OSWE-1","verdict":"accepted"}, {"from":"OSWE-1","to":"OSWE-2","verdict":"accepted"} ] } ] }
JSON
node skills/audit/scripts/render-html.mjs --md "$MD" --summary .oswe/tmp/smoke-summary.json --out .oswe/tmp/smoke.html
echo "exit=$?"
grep -c "default-src 'none'" .oswe/tmp/smoke.html
grep -ciE "<script|<iframe|<object|<embed" .oswe/tmp/smoke.html
rm -rf .oswe/tmp
```
Expected: `exit=0`; the CSP line count is `1`; the active-tag count is `0`. (`.oswe/tmp` is gitignored and purged.)

- [ ] **Step 5: Manual visual check (user-run, like the Phase-2 E2E gate)**

In the user's interactive session, run `/oswe:audit test-fixtures/python/vulnerable` and
`/oswe:audit test-fixtures/python/safe`, then open the two produced `.html` files in a browser. The
controller confirms:
- vulnerable: severity donut shows Critique=1/Haute=2; the chain diagram shows
  `entry (unauth) → OSWE-1 → OSWE-2 → RCE` (RCE red), coverage/status bars populated; `Ctrl+P` preview
  is clean (page breaks before sections).
- safe: empty-state grey donut + "No findings", "No exploit chains", coverage bar populated.

This is a convenience check, not a merge blocker (the `.md` E2E already gates correctness); record the
two verdicts.

- [ ] **Step 6: Finish the branch**

Once Steps 1–4 are green (and Step 5 reviewed), use `superpowers:finishing-a-development-branch` to
merge `feat/oswe-html-report` into `master` (or open a PR per user preference).

---

## Acceptance criteria (from spec §11)

- [ ] `render-html.mjs` exists, zero runtime deps, atomic write, exit-code contract (0/1/2) per spec §3.1.
- [ ] `report-summary.schema.json` added; `build-validators.mjs` exports `reportSummary`; `validators.mjs`
      regenerated (7 validators) and still loads with no `node_modules`.
- [ ] SKILL phase 7 emits the `.html` alongside the `.md`; HTML failure never aborts the audit.
- [ ] All `render-html`/`report-summary` tests pass; MVP regression still green; `claude plugin
      validate . --strict` passes.
- [ ] Manual check: vulnerable-fixture `.html` (donut + chain diagram + bars; clean print) and
      safe-fixture `.html` (empty-state donut, "No exploit chains").
- [ ] README + manifest mention the HTML report.

## Out of scope (per spec §10)

- No true binary PDF generator (no vendored PDF lib, no headless browser).
- No configurable themes, no JS interactivity, no multi-report dashboard.
- No changes to the `finding`/`chain`/`verdict`/`analyzer-response`/`verifier-response` schemas or to
  the `aggregate-findings`/`apply-verdicts`/`confine-path`/`validate-*` helpers.
- No Markdown features beyond the fixed set in §4 of the spec.
