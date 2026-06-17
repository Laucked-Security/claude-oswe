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
  SARIF-supplied paths are confined to the project root with the exact `confine-path` logic; SARIF
  strings (rule ids, messages) are data, never instructions, and are never written into a report
  except as already-bounded, escaped text.
- **Secrets never leave.** Redaction (`[REDACTED]`, `file:line` only) is unchanged; leads and ledgers
  live under `.oswe/tmp/` and are purged like all other intermediate data.
- **The deterministic core is sacred.** No changes to `apply-verdicts.mjs`, `validate-batch.mjs`,
  `confine-path.mjs`, `validate-output.mjs`, the `chain`/`verifier-response`/`report-summary` schemas,
  or the Critical-gating logic. The hybrid grafts onto the **ends** of the pipeline only.

## 3. Components

### 3.1 New helper: `skills/audit/scripts/ingest-sarif.mjs`

```
node ingest-sarif.mjs --file <input.json> --out <leads.json>
```

- `--file` input JSON: `{ "projectDir": "<abs>", "sarifPath": "<path under projectDir>" }`.
- Reads & parses the SARIF 2.1.0 document. For every `runs[].results[]`:
  - extract `ruleId`, `message.text`, `level`, and the **primary location**
    (`locations[0].physicalLocation.artifactLocation.uri` + `region.startLine`);
  - if present, extract the first `codeFlows[0].threadFlows[0].locations[]` as an ordered
    `codeflow[]` of `{file,line}` (the taint source→…→sink path);
  - **confine every path** (uri, codeflow files) to `projectDir` using the same normalization
    `confine-path.mjs` uses (reject `../`, symlink/junction, sibling-prefix escapes). A result whose
    primary location escapes the root is **dropped** and counted in `dropped_out_of_scope`.
  - map `ruleId` → `vuln_class_hint` via a **per-tool mapping table** (§3.2). Unknown rule → hint
    `"unknown"` (still a valid lead; the analyzer decides from the code).
- Emits `{ ok, error, leads: [ <sarif-lead> ], stats: { total, kept, dropped_out_of_scope, unmapped_rules } }`.
- Assigns each lead a stable `lead_id` = `L<NNN>` in document order (zero-padded, ≥ 3 digits).
- Exit `0` ok / `1` malformed SARIF (not parseable / not SARIF 2.1.0) / `2` IO|usage.
- **Unit-tested**: well-formed SARIF (single-location + codeflow), out-of-scope path dropped,
  unknown rule → `unknown` hint, malformed JSON → exit 1, missing file → exit 2.

### 3.2 Rule→vuln_class mapping table

A small committed JSON, `skills/audit/references/sarif-rule-map.json`, keyed by tool
(`"semgrep"`, …), mapping rule-id **prefixes/globs** to an `oswe` `vuln_class`. Curated for the
Semgrep rule families that fire on the OWASP Benchmark CWE categories (command injection, SQLi,
path traversal, XSS, weak crypto/hashing, LDAP/XPath injection, trust-boundary, insecure cookie,
weak randomness). The table is **advisory only** — a wrong/`unknown` hint never forces a verdict; the
analyzer establishes the real `vuln_class` from the code. Mismatch between hint and the analyzer's
conclusion is allowed and recorded.

### 3.3 New schema: `skills/audit/schemas/sarif-lead.schema.json` (the 8th)

```jsonc
{
  "lead_id":        "^L[0-9]{3,}$",
  "tool":           "string",            // e.g. "semgrep"
  "rule_id":        "string",
  "vuln_class_hint":"string",            // an oswe vuln_class or "unknown"
  "location":       { "file": "string", "line": "integer>=1" },
  "codeflow":       [ { "file": "string", "line": "integer>=1" } ],   // optional
  "message":        "string"
}
```
`additionalProperties:false`. Paths are repo-relative (already confined by §3.1).

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

### 3.5 Extended schemas: `finding` and `final-finding`

Add:
- `origin`: `"llm-discovered" | "sast-lead" | "both"` (**optional**; **absent ⇒ treated as
  `"llm-discovered"`** by the aggregator and report). Making it optional-with-default is deliberate:
  every existing finding JSON / fixture stays valid unchanged, preserving the zero-regression promise
  (§7). New SAST-promoted findings set `"sast-lead"`; the aggregator computes `"both"` on merge (§3.6).
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

### 3.7 Benchmark — `benchmark/metrics.mjs` (deterministic, tested, CI-able)

```
node benchmark/metrics.mjs --ledger <ledger.json> --truth <expectedresults.csv> --out <report.json>
```

- **Ledger** (produced by a run; see §3.8 for shape) lists, per OWASP Benchmark test case in the
  declared subset: whether Semgrep flagged it (from the SARIF), and oswe's adjudication
  (`promoted`/`refuted`/`inconclusive`/`not-analyzed`), plus oswe's independent discoveries.
- **Truth** = the official `expectedresults-1.2.csv` (`test name, category, real vulnerability, CWE`).
- Computes three confusion matrices vs ground truth, each → `{ tp, fp, tn, fn, precision, recall, fpr, youden }`:
  1. **`semgrep_raw`** — Semgrep flagged ⇔ predicted-vuln.
  2. **`oswe_over_semgrep`** — among Semgrep leads, `promoted` ⇔ predicted-vuln, `refuted` ⇔ predicted-safe
     (`inconclusive`/`not-analyzed` → excluded and counted separately, never silently scored).
  3. **`hybrid`** — `oswe_over_semgrep` plus oswe's independent discoveries on cases Semgrep missed
     (recovered false-negatives).
- Headline deltas: **`fp_refuted`** (Semgrep FPs oswe correctly refuted), **`recall_cost`** (real vulns
  oswe wrongly refuted), **`fn_recovered`** (real vulns oswe found that Semgrep missed).
- Emits a JSON result **and** a human `BENCHMARK.md` table. Fully deterministic; **unit-tested** with a
  fixture ledger + a small synthetic truth CSV (every metric hand-checked).
- Exit `0` ok / `1` ledger↔truth inconsistency (a ledger test-id absent from truth, etc.) / `2` IO|usage.

### 3.8 Run orchestration (expensive, manual, documented — NOT in CI)

`benchmark/README.md` documents the maintainer procedure to produce a ledger: clone OWASP Benchmark
under `external/` (gitignored, Apache-2.0), run Semgrep once to produce a pinned SARIF, run
`/oswe:audit --sarif <sarif>` over the **declared subset** in the maintainer's own Claude session
(subscription quota — **not** nested `claude -p`, which bills separate API credit), and assemble the
ledger from the audit output. The subset is a committed manifest `benchmark/subset-owasp.json` (a
fixed list of `BenchmarkTestNNNNN` ids sampled across all CWE categories) so the result is
reproducible and affordable. The metrics engine (§3.7) and a committed sample ledger are what CI and
`node --test` exercise; the large LLM run is occasional and manual.

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
- **§7 Report** — additive:
  - Executive summary gains a one-line **origin breakdown** (LLM-only / SAST-only / both).
  - A new annex **"Refuted SAST leads"** lists each `refuted` lead (`lead_id`, `rule_id`, `file:line`,
    reason) — this is the visible precision win. `inconclusive`/`not-analyzed` leads go in **Coverage**.
  - The HTML `summary` (and `report-summary.schema.json`) are **unchanged**; the origin breakdown and
    refuted-leads annex render through the existing Markdown→HTML body path (no new SVG, no schema
    change — staying inside the locked HTML contract).

## 5. Testing strategy

- **`ingest-sarif.mjs`**: the §3.1 cases (well-formed incl. codeflow, out-of-scope drop, unknown-rule
  hint, malformed → exit 1, missing file → exit 2).
- **`aggregate-findings.mjs`**: the §3.6 origin/lead-id merge cases, added to the existing suite.
- **`benchmark/metrics.mjs`**: fixture ledger + synthetic truth CSV; every confusion-matrix cell,
  every derived rate, and the three headline deltas hand-checked; ledger↔truth inconsistency → exit 1.
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

- The SARIF file is **untrusted input**: paths confined (§3.1), strings treated as data. A SARIF that
  points outside the repo, contains traversal, or is malformed must never read or write outside the
  root, never crash the audit into an unsafe state (exit 1, audit aborts the ingestion cleanly).
- Leads and the ledger contain raw `file:line` and rule messages → they live under `.oswe/tmp/` and are
  purged at start/end/abort like all intermediate data. The **report** stays redaction-safe.
- A malicious SARIF cannot inflate severity: leads only ever become findings via the analyzer reading
  real code, and Critical gating is unchanged and deterministic.

## 7. Backward compatibility & rollout

- `/oswe:audit` with no `--sarif` is byte-for-byte the current behavior. Because `origin` is optional
  and **absent ⇒ `llm-discovered`** (§3.5), no existing finding JSON, fixture, or `EXPECTED.md` needs
  to change; findings are reported exactly as today and the origin breakdown line simply reads
  "LLM-only".
- Ship behind the implementation branch `feat/oswe-hybrid-precision`; merge `--no-ff` after the E2E
  non-regression + the new fixture + the metrics suite are green, mirroring prior phases.

## 8. Success criteria

1. `ingest-sarif.mjs`, the `sarif-lead` schema, the `analyzer-response`/`finding`/`final-finding`
   extensions, and the `aggregate-findings` merge changes are implemented, schema-gated, and unit-tested;
   `validators.mjs` regenerated and in sync.
2. `/oswe:audit --sarif <file>` ingests leads, the analyzer adjudicates every assigned lead, promoted
   findings flow through the unchanged verify/verdict pipeline, and the report shows the origin
   breakdown + refuted-leads annex.
3. The no-`--sarif` path passes all existing E2E fixtures unchanged (zero regression).
4. `benchmark/metrics.mjs` computes the three confusion matrices + headline deltas deterministically,
   is unit-tested, and produces a `BENCHMARK.md` from a committed sample ledger + the OWASP truth CSV.
5. `claude plugin validate . --strict`, `node --test`, and `check-structure.mjs` all green.

## 9. Out of scope (future sub-projects)

- **SP3 — scale**: triaging hundreds–thousands of leads affordably (prioritization, partial-coverage
  budgeting beyond the current 12-partition cap). This spec **bounds** the benchmark to a declared
  subset and records the rest as coverage gaps; it does not solve full-scale triage.
- **SP4 — more datasets**: Juliet/SARD, real CVE repos, publishable cross-tool comparison.
- **Running Semgrep ourselves** as a first-class feature (we ingest a SARIF; an optional `semgrep`
  shell-out may be added later, but the benchmark uses a pinned SARIF for reproducibility).
- **Product surface**: CI/IDE integrations, multi-project dashboards, finding-debt tracking over time
  (these belong to the "commercial product" ambition, not chosen here).
```
