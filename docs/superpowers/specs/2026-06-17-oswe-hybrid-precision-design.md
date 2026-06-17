# OSWE Plugin — Hybrid Precision Auditor Design (SP1 + SP2)

**Status:** approved-design (pending written-spec review)
**Date:** 2026-06-17
**Depends on:** merged MVP + Phase 2 + HTML report (the `oswe` plugin on `master`).
**Branch (implementation):** `feat/oswe-hybrid-precision` (off `master`).

## 0. Context & ambition

`oswe` is today a white-box, LLM-orchestrated auditor with a deterministic decision layer
(tested zero-dependency Node helpers, JSON-Schema-gated I/O, a verifier that can downgrade/reject,
deterministic Critical gating). It finds and chains vulnerabilities toward unauthenticated RCE and
writes a redaction-safe Markdown + HTML report.

The chosen ambition is **technical superiority over SAST tools, on the precision axis**: SAST tools
(Semgrep, CodeQL, …) win on scale and rule breadth but drown the user in false positives. `oswe`'s
structural advantage is semantic reasoning that can *prove or refute* a candidate. The goal of this
project is therefore:

> Make `oswe` a **hybrid, precision-first auditor**: ingest a SAST's findings (SARIF) for scale and
> rule coverage, keep `oswe`'s own LLM discovery for the logic/auth bugs SAST structurally misses,
> and run the LLM precision layer over the **union** so that every reported item is **proven**,
> **real-under-a-stated-precondition**, or **explicitly refuted with a reason** — and **prove the
> precision gain with numbers** against raw Semgrep on ground-truth data.

This spec covers **SP1 (SARIF ingestion + precision triage + benchmark)** and **SP2 (hybrid union of
LLM discovery and SAST leads)** together, since one mechanism (the analyzer adjudicating leads)
delivers both. Out of scope are SP3 (full-scale triage of thousands of leads) and SP4 (more
benchmark datasets) — see §9.

## 1. Goal

1. `oswe` can **ingest a SARIF 2.1.0 file** (`/oswe:audit --sarif <file> [scope]`) and treat each
   result as a **lead** to investigate.
2. Each lead is **adjudicated** by the analyzer to a proper `finding` (promoted) or an explicit
   **refutation** (with reason) — never silently accepted.
3. LLM-discovered findings and SAST-promoted findings are **merged/deduped** deterministically; a
   finding carries its `origin` (`llm-discovered` | `sast-lead` | `both`).
4. A **deterministic benchmark metrics engine** computes precision/recall/FPR for **raw Semgrep** vs
   **oswe-over-Semgrep** vs the **hybrid bonus**, on a declared subset of the OWASP Benchmark, from a
   run **ledger** + the official ground-truth CSV.
5. **Zero regression:** with no `--sarif`, `/oswe:audit` behaves exactly as today (pure LLM); the
   existing helpers, schemas, Critical gating, and E2E fixtures are untouched except for the additive
   changes named in §3.

## 2. Hard constraints (inherited from the project)

- **Zero runtime dependency.** `ingest-sarif.mjs` and `benchmark/metrics.mjs` run with **no
  `node_modules`** — SARIF and CSV are parsed by hand / `JSON.parse`. AJV stays dev-only (used only
  to regenerate `validators.mjs`).
- **Node ≥ 20**, ESM, the same `--file`/`--out` CLI discipline and exit-code contract as the existing
  helpers (`0` ok / `1` invalid input / `2` IO|usage).
- **Security-tool posture.** The audited repo **and the ingested SARIF** are **untrusted data**.
  SARIF-supplied paths are normalized then confined to the project root (§3.1 — URI decoding +
  `confine-path` reuse); SARIF strings (`rule_id`, `message`, `vuln_class_hint`) are data, never
  instructions, and are **length-bounded at ingestion** so they can never balloon a report or a temp
  file: the `sarif-lead` schema fixes `maxLength` (`rule_id` ≤ 256, `vuln_class_hint` ≤ 64, `message`
  ≤ 512), and `ingest-sarif.mjs` **truncates** any longer value (UTF-8-safe, ellipsis `…`) **before**
  it is ever written. The report annex prints only the (already-truncated, HTML-escaped) `rule_id`.
- **Secrets never leave.** Redaction (`[REDACTED]`, `file:line` only) is unchanged. Two distinct
  artifacts must not be conflated (see §6): the **raw `leads[]`** (and analyzer intermediates) carry
  `file:line` + rule messages → they live under `.oswe/tmp/` and are purged like all other intermediate
  data; the **benchmark ledger** (§3.7.1) is a *sanitized* record — `test_id` + booleans + `cwe` only,
  **no messages, no paths, no secrets** — which is why a sample ledger is safe to commit.
- **The deterministic core is sacred.** No changes to `apply-verdicts.mjs`, `validate-batch.mjs`,
  `confine-path.mjs`, `validate-output.mjs`, the `chain`/`verifier-response`/`report-summary` schemas,
  or the Critical-gating logic. The hybrid grafts onto the **ends** of the pipeline only.

## 3. Components

### 3.1 New helper: `skills/audit/scripts/ingest-sarif.mjs`

```
node ingest-sarif.mjs --file <input.json> --out <leads.json>
```

- `--file` input JSON: `{ "projectDir": "<abs>", "sarifPath": "<path under projectDir>" }`.
- Reads & parses the SARIF 2.1.0 document. **Iterate every `run` in `runs[]`** (a SARIF file may hold
  several runs / several tools); for each run derive its **`tool`** once from
  `run.tool.driver.name`, **normalized** = lowercased, non-alphanumerics collapsed to `-`, trimmed
  (e.g. `"Semgrep OSS"` → `"semgrep-oss"`, `"Semgrep"` → `"semgrep"`); a known-alias map folds common
  variants to a canonical key (`semgrep-oss`→`semgrep`). A run missing `tool.driver.name` → `tool` =
  `"unknown"`. Then for every `run.results[]` (the result inherits its run's `tool`):
  - extract `ruleId` (fall back to `rule.id`/`rule.index`→`run.tool.driver.rules[index].id` when
    `ruleId` is absent), `message.text`, `level`, and the **primary location**
    (`locations[0].physicalLocation.artifactLocation.uri` + `region.startLine`);
  - **line resolution** — `region.startLine` is **optional** in valid SARIF, but `sarif-lead.line`
    requires `>= 1`. If a location has a `physicalLocation` but **no `region.startLine`** (or it is
    `< 1`/non-integer), the location is **dropped and counted in `dropped_bad_location`** — we do
    **not** silently default to line 1 (a wrong line would mislead the analyzer and corrupt the
    benchmark join). For the **primary** location this drops the whole lead; for a **codeflow** step it
    omits that step (codeflow is advisory).
  - if present, extract the first `codeFlows[0].threadFlows[0].locations[]` as an ordered
    `codeflow[]` of `{file,line}` (the taint source→…→sink path), each subject to the same line/URI
    rules;
  - **truncate** `rule_id`/`vuln_class_hint`/`message` to the schema `maxLength` (UTF-8-safe, §2)
    before storing;
  - **normalize then confine every path** (the primary `uri`, each codeflow file `uri`). The
    `artifactLocation.uri` is a SARIF URI, **not** a filesystem path, so `ingest-sarif.mjs` first
    derives a path before reusing `confinePath()`:
    1. **scheme** — a `file:` URI is converted with `node:url` **`fileURLToPath()`** (it handles
       `file:///path`, `file:///C:/...` drive letters, and percent-decoding portably); a `file:` URI
       whose **authority is a non-local host** (UNC `file://server/share`) is **rejected** →
       `dropped_bad_uri` (authority must be empty or `localhost`). Any **other scheme**
       (`http(s):`, `git:`, …) → `dropped_bad_uri`. A `uri` with **no scheme** is treated as a plain
       (relative or absolute) path and skips `fileURLToPath`.
    2. **percent-decode** — only for the no-scheme path case (`decodeURIComponent`; `fileURLToPath`
       already decoded the `file:` case); a malformed escape → `dropped_bad_uri`.
    3. **uriBaseId** — if the location carries `uriBaseId` and the run declares
       `originalUriBaseIds[<id>].uri`, resolve against that base (itself confined); otherwise a
       **relative** uri resolves against `projectDir`, and an **absolute** uri is taken as-is (it will
       still have to pass confinement);
    4. **confine** the resulting path with `confinePath(projectDir, path)` (reuses the exact
       `confine-path.mjs` logic: `realpathSync` canonicalization, reject `../`, symlink/junction,
       sibling-prefix). Because `confinePath` resolves the **real** path and **throws `ENOENT` on a
       missing file**, `ingest-sarif.mjs` catches: an **escape** → drop, count in
       `dropped_out_of_scope`; a **missing file** (`ENOENT`, e.g. a stale or generated path) → drop,
       count in `dropped_missing` — neither aborts the run;
    5. **store repo-relative** — convert the returned absolute real path back via
       `path.relative(realRoot, realPath)` with POSIX separators, so `location.file` matches the
       repo-relative form the analyzer and the schema expect.
    A **dropped primary location drops the whole lead**; a dropped **codeflow** step is simply omitted
    from `codeflow[]` (it is advisory — the lead survives on its primary location).
  - map `ruleId` → `vuln_class_hint` via a **per-tool mapping table** (§3.2). Unknown rule → hint
    `"unknown"` (still a valid lead; the analyzer decides from the code).
- Emits `{ ok, error, leads: [ <sarif-lead> ], stats: { total, kept, dropped_out_of_scope, dropped_missing, dropped_bad_uri, dropped_bad_location, unmapped_rules } }`.
- Assigns each lead a stable `lead_id` = `L<NNN>` in document order (zero-padded, ≥ 3 digits).
- **Self-validates each emitted lead** against the `sarif-lead` schema before writing, by importing
  the generated `sarifLead` validator **directly from `./validators.mjs`** — the **same pattern
  `render-html.mjs` uses for `reportSummary`**, so `validate-output.mjs` stays **frozen** (its fixed
  `KIND_TO_EXPORT` is not touched; no `sarif-lead` kind is added there). `build-validators.mjs` gains
  `sarif-lead` in its schema list so `sarifLead` is exported from the regenerated `validators.mjs`. A
  lead the helper builds that fails its own schema is an **ingestion bug** → exit 1 (we never emit an
  invalid lead).
- Exit `0` ok / `1` malformed SARIF (not parseable / not SARIF 2.1.0) **or a self-built lead that
  fails the `sarif-lead` schema** / `2` IO|usage.
- **Unit-tested**: well-formed SARIF (single-location + codeflow), out-of-scope path dropped
  (`dropped_out_of_scope`), unknown rule → `unknown` hint, malformed JSON → exit 1, missing **input**
  `--file` → exit 2, **tool-name normalization** (`"Semgrep OSS"`→`semgrep`), **multi-run SARIF** (two
  runs / two tools, each result tagged with its own run's tool), **`ruleId` absent → resolved via
  `rule.index`**, and the URI cases: **`file://` scheme stripped**, **percent-encoded uri decoded**,
  **`uriBaseId` resolved**, **non-file scheme dropped** (`dropped_bad_uri`), **UNC `file://host/share`
  rejected** (`dropped_bad_uri`), **`file:///C:/…` drive-letter path** handled via `fileURLToPath`,
  **missing artifact path dropped not aborted** (`dropped_missing`), **location with no
  `region.startLine` dropped** (`dropped_bad_location`), and an **over-long `message`/`rule_id`
  truncated** to `maxLength`.

### 3.2 Rule→vuln_class mapping table

A small committed JSON, `skills/audit/references/sarif-rule-map.json`, keyed by the **normalized
`tool`** key from §3.1 (`"semgrep"`, …), mapping rule-id **prefixes/globs** to an `oswe` `vuln_class`.
A tool with no entry (or `tool:"unknown"`) → every lead gets hint `"unknown"`. Curated for the
Semgrep rule families that fire on the OWASP Benchmark CWE categories (command injection, SQLi,
path traversal, XSS, weak crypto/hashing, LDAP/XPath injection, trust-boundary, insecure cookie,
weak randomness). The table is **advisory only** — a wrong/`unknown` hint never forces a verdict; the
analyzer establishes the real `vuln_class` from the code. Mismatch between hint and the analyzer's
conclusion is allowed and recorded.

### 3.3 New schema: `skills/audit/schemas/sarif-lead.schema.json` (the 8th)

```jsonc
{
  "lead_id":        "^L[0-9]{3,}$",
  "tool":           "string, maxLength 64",   // normalized driver name, e.g. "semgrep"
  "rule_id":        "string, maxLength 256",
  "vuln_class_hint":"string, maxLength 64",    // an oswe vuln_class or "unknown"
  "location":       { "file": "string maxLength 1024", "line": "integer>=1" },
  "codeflow":       [ { "file": "string maxLength 1024", "line": "integer>=1" } ],   // optional, maxItems 64
  "message":        "string, maxLength 512"
}
```
`additionalProperties:false`. Every string field carries a `maxLength` (above); `ingest-sarif.mjs`
**truncates at ingestion** so an over-long SARIF value is bounded *before* it reaches the schema, the
report, or a temp file (§2). `file` paths are repo-relative POSIX (normalized + confined by §3.1).

### 3.4 Extended schema: `analyzer-response`

Add an **optional** `adjudicated_leads[]`. Each element:
```jsonc
{
  "lead_id":   "^L[0-9]{3,}$",
  "outcome":   "promoted" | "refuted" | "inconclusive",
  "finding_id":"^<P>-F[0-9]{3,}$",   // REQUIRED iff outcome=="promoted"; must match a finding in THIS response
  "reason":    "string"               // REQUIRED for refuted|inconclusive (the evidence-based reason)
}
```
Orchestrator binding rule (SKILL, not schema): **every lead assigned to a partition must appear
exactly once** in that partition's `adjudicated_leads`; a `promoted` lead's `finding_id` must match a
`finding` in the same response and that finding must carry the lead in `source_lead_ids`. A lead
assigned but not adjudicated → the partition is treated like any other binding mismatch (retry once,
else coverage gap) — leads must never silently vanish, or the precision count is wrong.
**A raw analyzer finding's `origin` may only be absent, `"llm-discovered"`, or `"sast-lead"` — never
`"both"`.** `"both"` is a *derived* value computed **only by the aggregator** when an `llm-discovered`
and a `sast-lead` finding dedupe to the same key (§3.6); the binding step rejects an analyzer response
that emits `origin:"both"` directly (orchestrator-built inline) or treats it as a subagent binding
mismatch (retry once, else gap). (The `finding` schema still *permits* `"both"` because the same schema
validates post-aggregation findings; the constraint on raw analyzer output is enforced at binding.)

### 3.5 Extended schemas: `finding` and `final-finding`

Add:
- `origin`: `"llm-discovered" | "sast-lead" | "both"` (**optional**; **absent ⇒ treated as
  `"llm-discovered"`** by the aggregator and report). Making it optional-with-default is deliberate:
  every existing finding JSON / fixture stays valid unchanged, preserving the zero-regression promise
  (§7). A **raw analyzer** finding sets only absent / `"llm-discovered"` / `"sast-lead"`; **`"both"` is
  produced solely by the aggregator on merge** (§3.6, enforced at binding §3.4).
- `source_lead_ids`: `[ "^L[0-9]{3,}$" ]` (optional; present iff the finding was promoted from / merged
  with ≥ 1 lead).

### 3.6 Modified helper: `aggregate-findings.mjs` (light)

The dedupe key and merge math are **unchanged**. Add to the per-group merge (treating an **absent**
`origin` as `"llm-discovered"`):
- `origin` = `"both"` if the group contains both `llm-discovered` and `sast-lead` members; else the
  single kind present.
- `source_lead_ids` = sorted-unique union of members' `source_lead_ids`.
New unit tests: an LLM finding and a SAST-lead finding on the same key merge to `origin:"both"` with
unioned `source_lead_ids`; same-origin merges keep their origin.

### 3.7 Benchmark — `benchmark/metrics.mjs` (deterministic, tested, CI-run)

```
node benchmark/metrics.mjs --ledger <ledger.json> --truth <expectedresults.csv> \
                           --out <report.json> [--md <report.md>]
```

- **`--out`** always receives the machine-readable JSON result. **`--md`** is **optional**; when given,
  the human-readable comparison table is written there (the run procedure §3.8 passes
  `--md benchmark/BENCHMARK.md`). When omitted, no Markdown is written — there is no implicit/default MD
  path.
- **Ledger** = the run record consumed here; its exact contract is **§3.7.1** (no longer "see §3.8").
- **Truth** = the official `expectedresults-1.2.csv` (`# test name, category, real vulnerability, cwe`).
  The loader skips the leading comment/header line and maps `test name` (e.g. `BenchmarkTest00001`) →
  `{ real: bool, cwe: int, category: str }`.
- Computes three confusion matrices vs ground truth, each → `{ tp, fp, tn, fn, precision, recall, fpr, youden }`:
  1. **`semgrep_raw`** — `semgrep_flagged===true` ⇔ predicted-vuln.
  2. **`oswe_over_semgrep`** — restricted to test cases where `semgrep_flagged===true`: `promoted` ⇔
     predicted-vuln, `refuted` ⇔ predicted-safe (`inconclusive`/`not-analyzed` → **excluded** from the
     matrix and counted separately in `excluded:{inconclusive,not_analyzed}`, never silently scored).
  3. **`hybrid`** — scored over **two disjoint groups**, predicted-label then compared to `real`:
     - **(a) Semgrep-flagged** cases — identical to matrix 2: `promoted`→predicted-vuln,
       `refuted`→predicted-safe; `inconclusive`/`not-analyzed`→**excluded**.
     - **(b) Semgrep-missed** cases (`semgrep_flagged===false`) **that oswe covered**
       (`oswe_covered===true`): `oswe_independent===true`→predicted-vuln, else→predicted-safe. A
       Semgrep-missed case **oswe did not cover** (`oswe_covered===false`) is **excluded** (a coverage
       gap, not a prediction) and counted in `excluded.not_covered`.

     Cells over **a∪b**: `tp`=predicted-vuln∧`real`, `fp`=predicted-vuln∧¬`real`, `fn`=predicted-safe∧`real`,
     `tn`=predicted-safe∧¬`real`. Note the two consequences the reviewer flagged: a **Semgrep-missed real
     vuln that oswe covered but did not find** (`oswe_independent:false`) is an honest **`fn`**; the same
     case **uncovered** is **excluded** (never an `fn`). A Semgrep lead that is `inconclusive`/`not-analyzed`
     is **excluded** (never scored either way). **Denominator** of each rate = `tp+fp+fn+tn` =
     `total_entries − excluded.(inconclusive + not_analyzed + not_covered)`; all `excluded` counts are
     emitted alongside the matrix so the denominator is auditable.
- Headline deltas: **`fp_refuted`** (Semgrep FPs oswe correctly refuted = matrix-2 cases `semgrep_flagged ∧ ¬real ∧ refuted`),
  **`recall_cost`** (real vulns oswe wrongly refuted = `semgrep_flagged ∧ real ∧ refuted`),
  **`fn_recovered`** (real vulns oswe found that Semgrep missed = `¬semgrep_flagged ∧ real ∧ oswe_covered ∧ oswe_independent`).
- Fully deterministic; **unit-tested** with a committed fixture ledger + a small synthetic truth CSV
  (every confusion cell, every rate, all three deltas, and `excluded` hand-checked).
- Exit `0` ok / `1` ledger↔truth inconsistency (a ledger `test_id` absent from truth; a ledger row that
  is schema-invalid per §3.7.1) / `2` IO|usage (unreadable/missing `--ledger`/`--truth`, unwritable out).

### 3.7.1 Ledger contract (the exact JSON `metrics.mjs` consumes)

A single committed JSON. `metrics.mjs` validates it against this shape before scoring (a violation →
exit 1). One entry per OWASP Benchmark test case **in the declared subset**:

```jsonc
{
  "dataset":  "owasp-benchmark-1.2",
  "subset":   "benchmark/subset-owasp.json",   // provenance of the in-scope ids
  "generated":"2026-06-17",                     // run date (informational)
  "entries": [
    {
      "test_id":         "BenchmarkTest00001",  // ^BenchmarkTest[0-9]{5}$ — joins to truth
      "semgrep_flagged": true,                   // did the pinned Semgrep SARIF flag this case?
      "oswe_covered":    true,                   // did oswe analyze the partition containing this case?
      "oswe_adjudication": "promoted",           // "promoted"|"refuted"|"inconclusive"|"not-analyzed"
                                                 //   (the flagged lead's outcome; "not-analyzed" = over budget / excluded dir;
                                                 //    when semgrep_flagged=false there is no lead → MUST be "not-analyzed")
      "oswe_independent": false,                 // did oswe find a vuln here on its OWN (no Semgrep lead)? (only meaningful when oswe_covered)
      "cwe":   78                                // CWE asserted by Semgrep/oswe for this case (informational; cross-checked vs truth)
    }
    // … one per in-scope test case
  ]
}
```

Rules `metrics.mjs` enforces (any violation → exit 1): `additionalProperties:false` at both levels;
`test_id` unique and matching the pattern; `oswe_adjudication` from the closed set; `oswe_covered` and
`oswe_independent` boolean. **Coherence:** `oswe_adjudication==="not-analyzed"` ⟺ `oswe_covered===false`
(a not-analyzed case is by definition uncovered, and vice-versa); when `semgrep_flagged===false` the
`oswe_adjudication` **must** be `"not-analyzed"` (there is no Semgrep lead to adjudicate — coverage is
carried by `oswe_covered`, the vuln signal by `oswe_independent`). For a `semgrep_flagged:false` case the
`oswe_adjudication` is ignored by matrix 2; matrix 3 uses `oswe_covered`+`oswe_independent` (§3.7). Every
`test_id` MUST exist in the truth CSV (else exit 1) — guaranteeing the join is total.

### 3.8 Run orchestration (expensive, manual, documented — NOT in CI)

`benchmark/README.md` documents the maintainer procedure to produce a ledger: clone OWASP Benchmark
under `external/` (gitignored, Apache-2.0), run Semgrep once to produce a pinned SARIF, run
`/oswe:audit --sarif <sarif>` over the **declared subset** in the maintainer's own Claude session
(subscription quota — **not** nested `claude -p`, which bills separate API credit), and assemble the
ledger from the audit output. The subset is a committed manifest `benchmark/subset-owasp.json` (a
fixed list of `BenchmarkTestNNNNN` ids sampled across all CWE categories) so the result is
reproducible and affordable. The metrics engine (§3.7) and a committed sample ledger are what CI
exercises (via the new `benchmark/` `node --test` step, §5); the large LLM run is occasional and manual.

## 4. Pipeline integration (SKILL.md changes)

The strict order is preserved; the edits are localized:

- **§1 Entry & recon** — parse a new optional `--sarif <path>` out of `$ARGUMENTS` (the existing
  scope argument still works; `--sarif` is additive). If present: confine the SARIF path, run
  `ingest-sarif.mjs` → `leads[]`, hold them in orchestration state. No `--sarif` → leads = `[]`,
  identical to today.
- **§2 Partition** — assign each lead to the partition containing its `location.file`. A lead whose
  file falls outside every analyzed partition (excluded dir, over budget) is recorded as a coverage
  gap **(lead not analyzed)** — never dropped from the ledger.
- **§3 Analyze** — each analyzer (inline or subagent) additionally receives its partition's leads and
  **must** return one `adjudicated_leads` entry per assigned lead (§3.4). The same schema gate +
  partition-binding + one-retry-budget rules apply; an unadjudicated/mis-bound lead is a binding
  mismatch handled by the existing retry logic.
- **§4 Aggregate** — unchanged call; the helper now carries `origin`/`source_lead_ids` (§3.6).
- **§5–§6b** — **unchanged.** Promoted findings flow through chain-building, verification, and
  Critical gating exactly like LLM-discovered findings.
- **§7 Report** — additive **and gated on `--sarif`**. The new sections appear **only when leads were
  ingested** (`leads.length > 0`); on the no-`--sarif` path the report is emitted exactly as today,
  with **no** origin line and **no** leads annex (this is what makes the byte-for-byte / unchanged-
  `EXPECTED.md` claim in §7 true):
  - Executive summary gains a one-line **origin breakdown** (LLM-only / SAST-only / both).
  - A new annex **"Refuted SAST leads"** lists each `refuted` lead (`lead_id`, `rule_id`, `file:line`,
    reason) — this is the visible precision win. `inconclusive`/`not-analyzed` leads go in **Coverage**.
  - The HTML `summary` (and `report-summary.schema.json`) are **unchanged**; the (gated) origin
    breakdown and refuted-leads annex render through the existing Markdown→HTML body path (no new SVG,
    no schema change — staying inside the locked HTML contract).

## 5. Testing strategy

- **`ingest-sarif.mjs`**: the full §3.1 case list (well-formed incl. codeflow; the URI cases —
  `file://`, percent-encoding, `uriBaseId`, non-file scheme dropped, missing artifact dropped not
  aborted; out-of-scope drop; tool normalization + multi-run; `ruleId`-via-index; over-long string
  truncation; malformed document → exit 1; missing input `--file` → exit 2). Every emitted lead is
  asserted valid against the `sarifLead` validator.
- **`aggregate-findings.mjs`**: the §3.6 origin/lead-id merge cases, added to the existing suite.
- **`benchmark/metrics.mjs`**: fixture ledger + synthetic truth CSV; every confusion-matrix cell (all
  three matrices), every derived rate, the three headline deltas, and `excluded.{inconclusive,
  not_analyzed,not_covered}` hand-checked — **including** a Semgrep-missed real vuln that is *covered
  but not found* (counts as hybrid `fn`) vs *uncovered* (excluded, not `fn`), and the denominator
  identity `tp+fp+fn+tn == total − excluded`; the coherence rules (`not-analyzed ⟺ ¬covered`;
  `¬semgrep_flagged ⇒ adjudication=="not-analyzed"`) → exit 1; ledger↔truth inconsistency → exit 1;
  schema-invalid ledger row → exit 1; malformed CSV / missing file → exit 2.
  **`ingest-sarif.mjs` lives under `skills/audit/scripts/`** so its tests are picked up by the existing
  CI `node --test` step automatically. **`benchmark/metrics.mjs` lives under `benchmark/`**, which the
  current CI does **not** test — so `.github/workflows/ci.yml` gains a **new step** in the `test` job,
  `working-directory: benchmark`, `run: node --test` (zero-dep, no install), on both Node 20 & 22. (The
  benchmark engine is deliberately kept out of the plugin runtime tree — it is maintainer tooling, not
  shipped plugin code.)
- **Schema parity**: `validators.mjs` regenerated (`npm run build`) for the 8th schema + the
  `analyzer-response`/`finding`/`final-finding` extensions; `check-structure.mjs` gains the
  `sarif-lead` schema↔validator parity check and a check that `sarif-rule-map.json` is valid JSON with
  the expected tool keys.
- **E2E non-regression**: the existing 6 stack fixtures and their `EXPECTED.md` must pass **unchanged**
  on the no-`--sarif` path (proves zero regression). One **new** small fixture: a tiny SARIF over an
  existing fixture proving (a) a true lead is promoted into the expected finding and (b) a deliberately
  bogus lead is refuted with a reason.
- Target: keep the suite green (currently 120 tests) and add the new helper/metrics tests on top; CI
  matrix (Node 20 & 22) + structure gate + validators-in-sync regen check all stay green.

## 6. Security considerations

- The SARIF file is **untrusted input**: URIs decoded + confined (§3.1), strings length-bounded and
  treated as data (§2). A SARIF that points outside the repo, uses a non-file scheme, contains
  traversal, references a missing file, or is malformed must never read or write outside the root and
  never crash the audit into an unsafe state — a bad *location* is dropped-and-counted (ingestion
  continues), a malformed *document* aborts ingestion cleanly (exit 1).
- **Two artifacts, two security postures** (do not conflate — §2):
  - the **raw `leads[]`** and analyzer intermediates carry `file:line` + (bounded) rule messages →
    they live under `.oswe/tmp/` and are purged at start/end/abort like all intermediate data; the
    **report** stays redaction-safe;
  - the **benchmark ledger** (§3.7.1) is **sanitized by construction** — `test_id` + booleans + `cwe`
    only, no messages/paths/secrets — so a *sample* ledger is committed safely and `BENCHMARK.md`
    (aggregate rates only) carries nothing sensitive.
- A malicious SARIF cannot inflate severity: leads only ever become findings via the analyzer reading
  real code, and Critical gating is unchanged and deterministic.

## 7. Backward compatibility & rollout

- `/oswe:audit` with no `--sarif` is byte-for-byte the current behavior. Because `origin` is optional
  and **absent ⇒ `llm-discovered`** (§3.5), no existing finding JSON, fixture, or `EXPECTED.md` needs
  to change; **the report's origin breakdown and refuted-leads annex are gated on `leads.length > 0`
  (§4), so with no `--sarif` neither appears** and the Markdown is identical to today's output.
- Ship behind the implementation branch `feat/oswe-hybrid-precision`; merge `--no-ff` after the E2E
  non-regression + the new fixture + the metrics suite are green, mirroring prior phases.

## 8. Success criteria

1. `ingest-sarif.mjs`, the `sarif-lead` schema, the `analyzer-response`/`finding`/`final-finding`
   extensions, and the `aggregate-findings` merge changes are implemented, schema-gated, and unit-tested;
   `validators.mjs` regenerated and in sync.
2. `/oswe:audit --sarif <file>` ingests leads, the analyzer adjudicates every assigned lead, promoted
   findings flow through the unchanged verify/verdict pipeline, and the report shows the origin
   breakdown + refuted-leads annex (both gated on `leads.length > 0`).
3. The no-`--sarif` path passes all existing E2E fixtures unchanged, with **no** origin line / leads
   annex in the output (zero regression).
4. `benchmark/metrics.mjs` consumes a ledger of the §3.7.1 shape + the OWASP truth CSV, computes the
   three confusion matrices + headline deltas + `excluded` deterministically, is unit-tested, and
   writes `BENCHMARK.md` when `--md` is given (from a committed sample ledger).
5. `node --test` (both `skills/audit/scripts/` and the new `benchmark/` CI step), `check-structure.mjs`,
   the validators-in-sync regen check, and `claude plugin validate . --strict` (local gate) all green.

## 9. Out of scope (future sub-projects)

- **SP3 — scale**: triaging hundreds–thousands of leads affordably (prioritization, partial-coverage
  budgeting beyond the current 12-partition cap). This spec **bounds** the benchmark to a declared
  subset and records the rest as coverage gaps; it does not solve full-scale triage.
- **SP4 — more datasets**: Juliet/SARD, real CVE repos, publishable cross-tool comparison.
- **Running Semgrep ourselves** as a first-class feature (we ingest a SARIF; an optional `semgrep`
  shell-out may be added later, but the benchmark uses a pinned SARIF for reproducibility).
- **Product surface**: CI/IDE integrations, multi-project dashboards, finding-debt tracking over time
  (these belong to the "commercial product" ambition, not chosen here).
