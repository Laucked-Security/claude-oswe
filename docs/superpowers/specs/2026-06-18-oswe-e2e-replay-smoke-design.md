# OSWE E2E Replay Smoke Test Design

**Status:** approved (review converged — 4 rounds)
**Date:** 2026-06-18
**Depends on:** merged MVP + Phase 2 + HTML report + Hybrid Precision (SP1+SP2) + Budget-Allocated Coverage (SP3) — the `oswe` plugin on `master`.
**Branch (implementation):** `feat/oswe-e2e-replay-smoke` (off `master`).

## 0. Context & thesis

The plugin has rich unit coverage (189 pipeline tests + 32 benchmark) but **no test exercises the
assembly of the 8 helpers in the order the SKILL prescribes**. Each helper is solid in isolation;
their CLI contracts (flags, exit codes, JSON shapes) are what the SKILL composes at audit time. A
silent break in that composition — a helper renamed, a flag changed, a schema updated without
synchronising downstream — would slip past the existing suite and only surface when the maintainer
runs `/oswe:audit` live.

An external code review flagged this gap explicitly. The fix is **a deterministic E2E replay**: feed
the pipeline pre-baked analyzer/verifier responses and verify the helpers chain together correctly,
produce a structurally valid report, and preserve SP3's coverage-class semantics.

> **From fixed inputs, with no agents, the SKILL's deterministic pipeline produces a valid report
> by passing the right contracts, in the right order, with SP3 included.**

That is what this test proves. It does **not** prove agent analysis quality, perfect SKILL adherence
by the model, byte-for-byte reproduction of any real audit, or benchmark re-validation. Those
boundaries are stated so the test cannot be misread.

## 1. Goal

1. A single `node --test` file under `skills/audit/scripts/test/` that exercises the **full helper
   chain** — `confine-path → surface-scan → allocate-budget → aggregate-findings → validate-output →
   validate-batch → apply-verdicts → render-html` — via each helper's **real CLI**.
2. The fixture exercises **three of the four SP3 coverage classes by construction** — `analyzed`,
   `deprioritized`, `unreadable-partition`. The 4th class, `unsupported-stack`, is intentionally
   left to `allocate-budget`'s unit tests (adding a fourth dummy partition just to populate it
   would multiply the pipeline run without adding orchestration coverage).
3. Assertions are **structural invariants + targeted semantic checks**, never byte-for-byte snapshots
   (a wording change in the SKILL or a helper's prose must not break this test; only a real
   orchestration regression should).
4. The test **fails loudly** when: a helper is renamed; a CLI flag (`--file`/`--out`) is changed; an
   exit-code contract changes; a schema breaks an intermediate object; SP3 stops emitting one of its
   gap classes; `render-html` loses XSS-escape discipline or its CSP.

## 2. Hard constraints

- **Zero runtime dependency.** Test uses only `node:test`, `node:assert/strict`, `node:fs`,
  `node:os`, `node:path`, `node:child_process`. No new deps.
- **Real CLIs everywhere.** Each helper invoked via `spawnSync(process.execPath, [helperPath,
  ...args])` with its **documented CLI surface** — `--file`/`--out` for the JSON-in/JSON-out helpers
  (`surface-scan`, `allocate-budget`, `aggregate-findings`, `ingest-sarif`, `apply-verdicts`);
  `<kind> --file <p>` for `validate-output`; `--file <p>` only for `validate-batch` (no `--out`,
  exit code carries the verdict); `--file <p>` for `confine-path` (prints the confined path to
  stdout); `--md <p> --summary <p> --out <p>` for `render-html`. Using imports would test composition
  without testing the CLI contract — defeating the purpose.
- **No persistent state.** All inputs/outputs in a per-test `mkdtempSync` directory, removed in
  `t.after()`. The repo working tree is untouched after the test runs.
- **No agent invocation.** All analyzer/verifier outputs are pre-baked JSON literals in the test
  file. No `claude` CLI dependency.
- **Single test function.** One `test(...)` block tells the end-to-end story; splitting into N
  micro-tests would lose the narrative. Assertions are dense *within* the test.
- **CI-friendly.** Runs in the existing `test` job (already iterates `skills/audit/scripts && node
  --test`), under both Node 20 & 22, on Ubuntu. No new workflow.

## 3. Fixture — the synthetic scenario

A temp project dir created at test time with **three partitions** designed to exercise the four
gap-class semantics deterministically:

### 3.1 `partA` (Python, supported, scannable, vulnerable surface)
One file `a/app.py` containing both an attacker-controlled source and a dangerous sink, with no auth
marker — guarantees `hasSource && hasSink && source_and_auth_files < sources` → unauth fail-safe →
the highest score in the fixture. **Lands in `analyze[]`.**

```python
from flask import request, render_template_string
def view():
    tpl = request.args.get("t", "")
    return render_template_string(tpl)
```

### 3.2 `partB` (Python, supported, scannable, low surface)
One file `b/util.py` containing only a neutral import — no source, no sink. Score = 0. **Lands in
`gaps[]` as `deprioritized`** when budget=1.

```python
import json
def to_str(x): return json.dumps(x)
```

### 3.3 `partC` (Python, supported, all-unreadable)
The partition's `files[]` references one **missing** path and one **out-of-scope** sibling-temp
file (real file outside `projectDir`, mirrors the cross-platform pattern of `confine-path.test.mjs`
and the SP3 skip-classification test). Every file skipped → `scannable:false` with
`skipped_missing` + `skipped_out_of_scope`. **Lands in `gaps[]` as `unreadable-partition`.**

### 3.4 `budget = 1`
- `analyze` = [`partA`] (single-slot, top-scored).
- `gaps` = [`partB`(deprioritized), `partC`(unreadable-partition)].
- Two of the four coverage classes populated; `analyzed` covers the third; `unsupported-stack` is
  intentionally left to unit tests (adding a Perl partition just to populate it would not improve
  the assembly story).

### 3.5 Pre-baked agent responses (literals in the test file)

- **Analyzer response for `partA`**: status `ok`, one raw finding with `source` on the `request.args`
  line and `sink` on the `render_template_string` line, `provisional_severity: High`, **`confidence:
  "strong static proof"`** (required field per `finding.schema.json`; the post-apply assertion
  `final_confidence === "strong static proof"` is downstream of this — the verifier-accepted finding
  carries its provisional confidence forward), `auth: unauthenticated`, `verification_status:
  not-requested`. Schema-valid (passes `validate-output analyzer-response`).
- **Chain** (built by the test as the SKILL would): single transition `entry → OSWE-1` (the canonical
  ID `aggregate-findings` assigns to the merged finding); `entry_point.auth: unauthenticated`,
  `final_impact: unauth-rce`; **`severity: "High"`** with **`confidence: "strong static proof"`**
  (required by `chain.schema.json:7`; we pick strong proof so the post-apply assertion
  `chain.confidence === "strong static proof"` is reachable — Critical gating requires every member
  at strong proof AND the chain's natural confidence to be strong proof) and
  **`verification_status: "not-requested"`** pre-apply. NOT `"Critical"` — `chain.schema.json:36`
  makes Critical mutually exclusive with `not-requested` (the schema's `if/then` clause says a
  Critical chain MUST also be `verification_status:"accepted"`, `confidence:"strong static proof"`,
  etc., which the candidate can't be). Only `apply-verdicts` elevates the chain to Critical after
  the verifier accepts it.
- **Verifier responses — TWO separate batches** (required by `apply-verdicts.mjs:105`, which enforces
  *1-5 findings XOR exactly 1 chain per batch*):
  - **Batch `b-find`**: `expected_targets: [{ target_type:"finding", target_id:"OSWE-1" }]`,
    `response.status:"ok"`, `response.verdicts:[{ target_type:"finding", target_id:"OSWE-1",
    verdict:"accepted", justification:"<text>" }]`. Schema-valid per `verdict.schema.json` (which
    requires only `target_type`, `target_id`, `verdict`, `justification`; **no `severity_floor` /
    `confidence_floor` fields exist** — earlier draft was wrong; the schema is
    `additionalProperties:false`).
  - **Batch `b-chain`**: `expected_targets: [{ target_type:"chain", target_id:"CHAIN-1" }]`,
    `response.status:"ok"`, `response.verdicts:[{ target_type:"chain", target_id:"CHAIN-1",
    verdict:"accepted", justification:"<text>", transition_verdicts:[{ from:"entry", to:"OSWE-1",
    verdict:"accepted", justification:"<text>" }] }]`. The `transition_verdicts` field is
    schema-required for chain verdicts (`verdict.schema.json:30`).
- **Report-summary** for `render-html`: minimal valid `report-summary.schema.json` instance with one
  `CHAIN-1` declared and an `entry → OSWE-1 → RCE` edge.
- **XSS canary**: a small `<img src=x onerror=alert(1)>` payload embedded in the **Markdown body**
  (a code-line excerpt or evidence quote) the test feeds to `render-html`. The final HTML must NOT
  contain the raw `<img src=x onerror=` sequence intact (it must be HTML-escaped or otherwise
  defanged) — this redoes `render-html`'s XSS contract in an end-to-end setting, not just a unit one.

## 4. Pipeline executed (the test's spawnSync sequence)

In order, with each step's input file written to the temp dir and output path captured:

1. `confine-path.mjs` × 1 — confines `partA/a/app.py`-style paths to the temp `projectDir`. Asserts
   exit 0 + non-empty stdout.
2. `surface-scan.mjs` — input: `{ projectDir, referencesDir, partitions: [partA, partB, partC] }`.
   Output: `{ ok: true, vectors: [...] }` with `content_key`, skip counts for `partC`, `scannable:
   false` for `partC`.
3. `allocate-budget.mjs` — input: `{ budget: 1, vectors }`. Output: `{ ok: true, analyze: [{
   partition_id: "partA", ...}], gaps: [partB-deprioritized, partC-unreadable-partition] }`.
4. `validate-output.mjs analyzer-response --file <r>` — asserts the pre-baked analyzer response
   passes its schema (the same gate the SKILL §3 applies before aggregating). Schema-gating analyzer
   responses is part of the contract; smoke-testing the pipeline without it would let a malformed
   response slip through here that the live pipeline would catch.
5. `aggregate-findings.mjs` — input: the single raw analyzer finding (would-be partA output) wrapped
   as `{ findings: [...] }`. Output: a canonical finding with `finding_id: "OSWE-1"`.
6. `validate-output.mjs finding` — asserts the OSWE-1 object passes.
7. **(In-test)** the test constructs the chain object (the SKILL builds chains in-text, not via a
   helper — there is no `chain-build.mjs`). The candidate's `severity` is **`"High"`** with
   `verification_status:"not-requested"` (NOT `"Critical"` — `chain.schema.json:36` makes Critical
   incompatible with `not-requested` pre-apply; only `apply-verdicts` elevates to Critical).
   Validated via `validate-output.mjs chain`.
8. `validate-output.mjs verifier-response --file <b-find.response>` — asserts the finding-batch
   verifier response passes its schema.
9. `validate-output.mjs verifier-response --file <b-chain.response>` — asserts the chain-batch
   verifier response passes its schema (with its required `transition_verdicts`).
10. `validate-batch.mjs` × **2** — once per batch (the SKILL's per-batch local check, §6 Step A):
    - call A: `{ findings:[OSWE-1], chains:[CHAIN-1], batch: b-find-wrapper }` — exit 0.
    - call B: `{ findings:[OSWE-1], chains:[CHAIN-1], batch: b-chain-wrapper }` — exit 0.
    (Both batches always carry the FULL findings + chains arrays; the batch's `expected_targets`
    alone declares what it covers. This matches `apply-verdicts.mjs` `applyVerdicts` semantics.)
11. `apply-verdicts.mjs` — input: `{ findings, chains, batches: [b-find-wrapper, b-chain-wrapper] }`.
    Output: `{ ok: true, findings:[accepted], chains:[accepted], gaps:[], decisions:[...] }`.
12. `validate-output.mjs final-finding` — asserts the mutated OSWE-1 (post-apply) passes the
    `final-finding` kind.
13. `validate-output.mjs chain` — asserts the **mutated CHAIN-1** (post-apply, now Critical-accepted
    with `verification_status:"accepted"`) re-passes the `chain` schema. SKILL §6b ligne 274 requires
    re-validating returned chains as well as findings; pre-apply and post-apply chain states differ
    significantly (severity, confidence, verification_status), so both validations are necessary.
14. `render-html.mjs` — `--md <generated-md>` + `--summary <summary.json>` + `--out <html>`. Asserts
    exit 0 and the HTML file exists.

The Markdown body fed to `render-html` is **constructed by the test** (a minimal canonical report
matching what the SKILL §7 prose would produce: a `## Exploit chains` section with `CHAIN-1`, a
`## Detailed findings` section with `OSWE-1`, a `## Coverage` section naming the three classes the
allocator populated, and the XSS canary in an evidence excerpt). The test doesn't need a real
report renderer — it only needs to prove `render-html` consumes a SKILL-shaped Markdown without
crashing and produces a well-formed, safe HTML.

## 5. Assertions

### 5.1 Per-step intermediate outputs
- Each `spawnSync` returns the expected exit code (0 for success steps; deliberate exit 1/2 is
  not exercised here — those are unit-tested elsewhere).
- `surface-scan` output: `r.ok === true`; each vector has a `content_key` (64-hex sha256);
  `partA.scannable === true && partA.sources > 0 && partA.sinks > 0 && partA.source_and_auth_files
  === 0`; `partB.scannable === true && partB.sources === 0`; `partC.scannable === false &&
  (partC.skipped_missing > 0 || partC.skipped_out_of_scope > 0)`.
- `allocate-budget` output: `r.ok === true`; `analyze.length === 1 && analyze[0].partition_id ===
  "partA"`; **`new Set(gaps.map(g => g.gap_class))` deep-equals `new Set(["deprioritized",
  "unreadable-partition"])`** — the targeted semantic check that locks SP3's class taxonomy.
- `aggregate-findings` output: `r.ok === true`; the single finding has `finding_id === "OSWE-1"`.
- `validate-batch` exit 0.
- `apply-verdicts` output: `r.ok === true`. **Finding** (carries `final_severity`/`final_confidence`):
  `verification_status === "accepted"`, `final_severity === "High"`, `final_confidence === "strong
  static proof"`. **Chain** (carries `severity`/`confidence`, NOT `final_severity` — see
  `chain.schema.json:32-33`): `verification_status === "accepted"`, `severity === "Critical"`,
  `confidence === "strong static proof"` (Critical gating rule fires: every member accepted at
  strong proof, `entry_point.auth === "unauthenticated"`, `final_impact === "unauth-rce"` — see
  `apply-verdicts.mjs:309-314`).
- `render-html` exit 0; the output file exists and is non-empty.

### 5.2 Markdown invariants (on the body the test fed to render-html)
- Contains `CHAIN-1`, `OSWE-1`.
- Contains the three coverage-class labels populated (`Analyzed`, `Deprioritized`,
  `Unreadable partition`).
- If the fixture produced skip counts, the Markdown mentions them (e.g. `skipped_missing` or
  `skipped_out_of_scope` appears in the coverage line for `partC`).

### 5.3 HTML invariants (on render-html's output)
- Contains `<title>` (HTML well-formed).
- Contains the CSP meta tag `default-src 'none'`.
- Contains at least one `<svg` (the severity donut chart, mandated by the locked HTML contract).
- Contains `CHAIN-1` and `OSWE-1` (preserved from the body).
- Contains **zero** `<script` tags.
- **XSS canary**: the raw sequence `<img src=x onerror=` does **not** appear in the HTML
  (escaping/defanging preserves the contract).

### 5.4 What the test does NOT assert
- No byte-for-byte snapshot of MD or HTML.
- No prose wording (any string a reader might naturally tweak in the SKILL or a helper).
- No timing/perf.
- No stack-specific coverage beyond Python (other stacks already covered by `surface-scan` unit
  tests against their `surface` blocks).

## 6. Failure modes the test catches (and the ones it doesn't)

**Catches** (the regressions this test was built for):
- A helper is renamed (the `spawnSync` of the missing binary fails).
- A CLI flag is renamed (`--file` → `--input`; the helper exits non-zero on bad usage).
- A helper changes its exit-code contract (e.g. emitting 0 on a malformed input — `apply-verdicts`
  asserts `r.ok`).
- A schema gains a required field that intermediates no longer carry (validate-output fails).
- SP3 stops emitting one of its gap classes (the `deepEqual` on the `Set` of `gap_class` values
  breaks).
- `render-html` loses CSP, gains a `<script>`, or stops escaping HTML in the body (the HTML
  invariants break).
- An aggregator regression that no longer assigns `OSWE-1` to the merged finding (chain assertion
  breaks).

**Does NOT catch** (by design):
- Whether the analyzer finds the right vulnerability (the analyzer response is pre-baked).
- Whether the verifier downgrades a weak chain (the verifier response is pre-baked accepted).
- Whether the model follows the SKILL.md prose (no model invoked).
- Whether a real audit's report wording matches a previous one (no golden snapshot).

## 7. Security considerations

- The test creates a sibling-temp file (the `partC` escape target) to make the cross-platform escape
  case fire — same pattern as `confine-path.test.mjs` and the SP3 skip-classification test. Cleaned
  up in `t.after()`.
- The XSS canary (`<img src=x onerror=alert(1)>`) is embedded only in test-controlled inputs to
  `render-html`. It is asserted *escaped* in the output; if the assertion ever passes-then-flips
  to the raw payload, the test fails — which is the protective behavior.
- No network. No external process beyond `node` itself.

## 8. Success criteria

1. `skills/audit/scripts/test/e2e-replay.test.mjs` exists with one `test(...)` function executing
   the §4 pipeline via `spawnSync` and asserting all §5 invariants.
2. `skills/audit/scripts/test/fixtures/e2e-smoke/` contains any small reusable JSON literals if the
   test grows large; otherwise the literals stay inline in the test file (a single file is fine for
   the initial scenario — `surface-scan.test.mjs` already keeps fixtures inline).
3. `cd skills/audit/scripts && node --test` is green (190 pipeline tests = current 189 + 1 new) on
   both Node 20 & 22 in CI.
4. The test runs in well under 5 seconds (~15 short spawnSync calls: confine-path, surface-scan,
   allocate-budget, validate-output analyzer-response, aggregate-findings, validate-output finding,
   validate-output chain (pre-apply candidate), validate-output verifier-response ×2,
   validate-batch ×2, apply-verdicts, validate-output final-finding, validate-output chain
   (post-apply mutated), render-html; no I/O beyond a handful of small
   temp files).
5. The README test-count badge is bumped accordingly.

## 9. Out of scope (future)

- A second fixture exercising `unsupported-stack` (covered by `allocate-budget` unit tests; adding
  it here would just multiply the pipeline run without new orchestration coverage).
- Multi-stack fixtures (Java/PHP/Node/.NET) — surface-scan unit tests exercise each `surface`
  block; one Python E2E proves orchestration.
- Golden replay of a real audit (`oswe-report-…`-style snapshot) — explicitly deferred; the
  external review's "golden replay later" framing applies. Would need timestamp normalization,
  redaction normalization, and a captured-response fixture set, all distinct sub-problems.
- A CLI tool `tools/orchestrate-replay.mjs` extracted from the test for manual debugging — YAGNI
  until the test is itself used for debug iteration enough to justify it.
- Performance assertions (the test stays a smoke; perf belongs in a separate harness if it ever
  becomes a need).
