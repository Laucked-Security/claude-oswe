# OSWE Plugin — HTML Report Export Design

**Status:** approved-design (pending written-spec review)
**Date:** 2026-06-16
**Depends on:** merged MVP + Phase 2 (the `oswe` plugin on `master`).
**Branch (implementation):** `feat/oswe-html-report` (off `master`).

## 1. Goal

Every `/oswe:audit` run already writes a redaction-safe Markdown report to
`.oswe/reports/oswe-report-YYYY-MM-DD-HHMM.md`. This feature adds, **alongside** it and with the
**same basename**, a self-contained visual HTML report
`.oswe/reports/oswe-report-YYYY-MM-DD-HHMM.html` containing the report body plus four SVG charts.
The user can `Ctrl+P → “Save as PDF”` in a browser to obtain a PDF — so we satisfy the “PDF” need
without a true binary-PDF generator.

The Markdown remains the **canonical, single redacted source of truth**; the HTML is its visual
rendering. Zero regression: the existing `.md` and all current E2E tooling (which compares `.md`
against `EXPECTED.md`) are untouched.

## 2. Hard constraints (inherited from the project)

- **Zero runtime dependency.** Like `validators.mjs`, the renderer runs with **no `node_modules`**:
  no charting library, no Markdown library, no headless browser. Charts are hand-built inline SVG;
  Markdown→HTML is a small purpose-built converter.
- **Self-contained output.** One `.html` file: all CSS in a `<style>` block, all charts inline
  `<svg>`, **no `<script>`**, no external fonts/images/stylesheets, no network access.
- **Node ≥ 20**, ESM, same `--file`/`--out` CLI discipline and exit-code contract as the other five
  helpers (`0` ok / `1` invalid input / `2` IO|usage).
- **Security tool posture.** The audited repo is **untrusted data**; the renderer must never let
  repo-derived text become live HTML/SVG markup (see §6).

## 3. Components

### 3.1 New helper: `skills/audit/scripts/render-html.mjs`

```
node render-html.mjs --md <report.md> --summary <summary.json> --out <report.html>
```

- Reads the redaction-safe `.md` and the non-sensitive `summary.json`.
- **Validates the summary** (kind `report-summary`, via the generated `./validators.mjs`) before
  rendering. An invalid summary is an **orchestrator-input bug** → exit 1, **no HTML written**.
- Renders a single self-contained HTML document:
  - **Body** = Markdown→HTML conversion of the `.md` (the converter scope is fixed; see §4).
  - **Charts** = four inline SVGs computed from the summary (see §5).
- **Atomic write (adjustment 1).** Writes to `${out}.tmp-<pid>` then `fs.renameSync` to `${out}`.
  A crash mid-render never leaves a partial `report.html`; the `.tmp-<pid>` file is removed on any
  error path and is never renamed.
- Exit codes: `0` success; `1` invalid `--summary` (schema-invalid → no output); `2` IO/usage
  (missing/unreadable `--md` or `--summary`, missing flags, unwritable `--out` target dir).

### 3.2 New schema: `skills/audit/schemas/report-summary.schema.json`

JSON Schema draft 2020-12 describing the summary object (§7). It is compiled into the standalone
validator the same way as the existing six:

- **Adjustment 3 — explicit export.** Add to `build-validators.mjs`’s `EXPORT_NAME` map:
  `"report-summary.schema.json": "reportSummary"`, then regenerate `validators.mjs`
  (`node build-validators.mjs`). `render-html.mjs` imports `{ reportSummary }` from `./validators.mjs`
  (which remains zero-dependency). The committed `validators.mjs` now exports seven validators.

### 3.3 Pipeline integration: `skills/audit/SKILL.md` phase 7

Phase 7 becomes (additive; step 1 is exactly today’s behaviour):

1. Write the `.md` report (**unchanged**).
2. Build the `summary` object from the **final findings/chains/gaps plus the orchestrator’s
   aggregated coverage** (adjustment 2 — `analyzed`/`skipped` come from the orchestrator’s
   analyzer-coverage state and `gaps[]`, not from the settled `apply-verdicts` result alone).
   Write it to a literal `.oswe/tmp/` path under a `trap … rm` like every other helper input.
3. Run `render-html.mjs --md … --summary … --out <same-basename>.html`.
4. Purge `.oswe/tmp/` (as today).

**Resilience — the HTML can never fail the audit (§ from review).** If `render-html.mjs` exits
non-zero, the orchestrator logs in the chat summary
(`HTML export failed: <reason>; Markdown report at <path>`) and continues normally (temp still
purged). The `.md` is the guaranteed artifact; the `.html` is a convenience.

## 4. Markdown→HTML converter scope (fixed, minimal)

The converter interprets **only** the constructs the OSWE report format uses; everything else is
emitted as escaped literal text. Supported:

- ATX headings `#`, `##`, `###`
- GFM pipe tables (header row + `|---|` separator + body rows)
- `**bold**`
- `` `inline code` ``
- blockquote `> `
- unordered lists `- `
- strikethrough `~~text~~` (used for refuted/`réfutée` findings)
- horizontal rule `---`

Explicitly **not** interpreted (rendered as escaped text): raw HTML, images, Markdown links,
reference links, footnotes, nested/ordered lists, code fences with language execution, autolinks.
(If the report later needs one of these, it’s a deliberate scope extension with its own test.)

## 5. Charts (inline SVG, deterministic, computed from the summary)

All four are pure functions of the summary; no randomness, no time, no layout engine.

1. **Severity donut.** Segments for Critique/Haute/Moyenne/Basse/Info with fixed colors + a legend
   showing each count. **Adjustment 4 — empty state:** when the total of all severity counts is `0`
   (the typical *safe* fixture), render a single grey ring (no segment maths, **no division by
   zero**) with a “No findings” label and a zeroed legend.
2. **Exploit-chain diagram.** Per chain: boxes `entry → OSWE-1 → … → RCE` connected by arrows
   labeled with each transition verdict (`accepted`/`downgraded`/`rejected`). `entry` is marked
   *unauthenticated* when `entry_auth === "unauthenticated"`; the terminal `RCE` node is red when the
   chain severity is Critique. When there are zero chains, the section renders a short
   “No exploit chains” note instead of an empty SVG.
3. **Coverage bar.** A horizontal bar split analyzed vs skipped from `summary.coverage`.
4. **Finding-status bar.** A stacked bar of accepted / downgraded / rejected / not-requested from
   `summary.finding_status_counts`.

## 6. Security

- **Universal escaping before formatting.** Every piece of text taken from the `.md` is HTML-escaped
  (`&`, `<`, `>`, `"`) **before** any formatting transformation is applied, and formatting is then
  applied only via controlled, whitelisted substitutions on the already-escaped text. The converter
  passes **no raw HTML** through. A finding title containing `<img onerror=…>` must render as
  `&lt;img onerror=…&gt;`, never execute.
- **Adjustment 7 — SVG text is escaped too.** Every dynamic label injected into an SVG `<text>` node,
  and every dynamic `meta` field placed into the HTML (target, stack, date, proof level), is escaped
  with the same function. SVG is active content, so node labels (`entry`, `OSWE-N`, optional
  `vuln_class`, `RCE`) and `meta.*` get the identical treatment — defense in depth even though the
  chart labels are already a constrained set.
- **Single redaction point.** The `.md` is the only redacted source; the HTML body inherits its
  `[REDACTED]` safety. The summary carries **only non-sensitive aggregates** (counts, enum labels,
  `OSWE-N` ids) — no secrets, no code excerpts, no `file:line`. The `.html` is written to the
  persistent, safe `.oswe/reports/`; the transient `summary.json` lives in `.oswe/tmp/` under a
  `trap … rm` and is purged at phase-7 end (and on any abort), exactly like the other helper inputs.
- **Print CSS.** An `@media print` block makes `Ctrl+P → Save as PDF` clean (page breaks before each
  chain/finding section, dark-on-white). No interactivity is required for printing.

## 7. The `summary` JSON (non-sensitive aggregates only)

Built by the orchestrator in phase 7 from the final findings/chains/gaps + aggregated coverage.
Shape (validated by `report-summary.schema.json`):

```json
{
  "meta": {
    "target": "test-fixtures/python/vulnerable",
    "stack": "Python / Flask 3.0.3",
    "date": "2026-06-16 10:15",
    "verdict": "unauth-rce",
    "proof_level": "preuve statique forte"
  },
  "severity_counts": { "Critique": 1, "Haute": 2, "Moyenne": 0, "Basse": 0, "Info": 0 },
  "finding_status_counts": { "accepted": 2, "downgraded": 0, "rejected": 0, "not-requested": 0 },
  "coverage": { "analyzed": 2, "skipped": 0 },
  "chains": [
    {
      "id": "CHAIN-1",
      "severity": "Critique",
      "entry_auth": "unauthenticated",
      "final_impact": "unauth-rce",
      "nodes": ["entry", "OSWE-1", "OSWE-2", "RCE"],
      "edges": [
        { "from": "entry",  "to": "OSWE-1", "verdict": "accepted" },
        { "from": "OSWE-1", "to": "OSWE-2", "verdict": "accepted" }
      ]
    }
  ]
}
```

Schema rules: `meta.verdict` ∈ {`unauth-rce`, `no-critique`}; `meta.proof_level` is a string or
`null`; severity keys are exactly the five severities (integers ≥ 0); `finding_status_counts` keys
are exactly the four statuses (integers ≥ 0); `coverage.analyzed`/`skipped` integers ≥ 0; `chains`
is an array (possibly empty); each chain’s `severity` ∈ the five severities, `entry_auth` ∈
{`unauthenticated`,`authenticated`,`admin`}, `edges[].verdict` ∈ {`accepted`,`downgraded`,
`rejected`}; node/label strings are bounded. `additionalProperties:false` throughout so an
orchestrator mistake is caught as exit 1.

## 8. Testing (`skills/audit/scripts/test/render-html.test.mjs`, added to `node --test`)

- **MD→HTML constructs:** each supported construct (headings, table, bold, inline code, blockquote,
  list, hr, strikethrough) renders to the expected tag(s).
- **Security / escaping:** a `.md` whose heading, a table cell, and an inline-code span each contain
  `<script>alert(1)</script>` and `"><img onerror=x>` renders them as entities — **no live tags**.
- **SVG label escaping (adjustment 7):** a summary/meta with `<`/`>`/`"`/`&` in `target`/`stack`
  (and a node label) yields escaped `<text>`/header content — no raw markup injected into SVG.
- **Charts from summary:** a given summary yields SVG carrying the right counts/segments; the chain
  diagram’s node/edge counts equal the summary’s; coverage/status bars reflect their counts.
- **Empty states (adjustment 4):** all-zero `severity_counts` → grey empty-ring donut, **no NaN /
  no division by zero**; zero `chains` → “No exploit chains” note.
- **Self-contained (adjustment 5):** the generated document contains **no active/external markup
  emitted by the renderer** — no real `<script`, `<img`, `<iframe`, `<object`, `<embed`, `<link`
  tags and no `href=`/`src=` attributes in generated tags. Escaped occurrences inside text
  (`&lt;img src=…&gt;`) are **accepted**. The only tags the renderer emits are the document chrome
  plus the SVG whitelist (`<svg> <g> <rect> <circle> <path> <text> <line> <polygon>` etc.).
- **CLI behaviour (adjustment 6):**
  - invalid `--summary` (schema-invalid) → **exit 1** and **no final `report.html`** (atomic write +
    early validation guarantee this);
  - missing `--md`/`--summary` flag, nonexistent `--md`/`--summary` file, or unwritable `--out`
    directory → **exit 2**;
  - on every error path, any `.tmp-<pid>` scratch file is removed (no leftover partial output).
- **Determinism:** same `--md` + `--summary` → **byte-identical** `.html`.

The existing MVP regression (currently 88 tests) must still pass; this only adds tests.

## 9. Docs

- `README.md`: note that each audit also produces a self-contained visual HTML report next to the
  Markdown, printable to PDF from a browser.
- `.claude-plugin/plugin.json`: description may mention “Markdown + HTML reports” (optional, minor).
- `skills/audit/SKILL.md`: extend the “Report” / “Report format” section with an **HTML export**
  subsection describing phase-7 step 2–4 and the never-gates-the-audit rule.

## 10. Out of scope (YAGNI)

- No true binary PDF generator (no vendored PDF lib, no headless browser).
- No configurable themes, no JS interactivity, no multi-report dashboard/aggregation.
- No changes to the `finding`/`chain`/`verdict`/`analyzer-response`/`verifier-response` schemas or to
  `aggregate-findings`/`apply-verdicts`/`confine-path`/`validate-*` helpers.
- No new Markdown features beyond §4’s fixed set.

## 11. Acceptance criteria

- `render-html.mjs` exists, zero runtime deps, atomic write, exit-code contract per §3.1.
- `report-summary.schema.json` added; `build-validators.mjs` exports `reportSummary`; `validators.mjs`
  regenerated (7 validators) and still loads with no `node_modules`.
- SKILL phase 7 emits the `.html` alongside the `.md`; HTML failure never aborts the audit.
- All §8 tests pass; MVP regression still green; `claude plugin validate . --strict` passes.
- Manual check: open a vulnerable-fixture `.html` (donut + chain diagram + bars render; Ctrl+P → PDF
  looks clean) and a safe-fixture `.html` (empty-state donut, “No exploit chains”).
- README/manifest/SKILL updated.
