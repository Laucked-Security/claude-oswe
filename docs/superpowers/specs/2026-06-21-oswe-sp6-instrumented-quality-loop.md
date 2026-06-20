# SP6 — Instrumented Finding-Quality Loop

> **Status:** design spec (rev 3 — incorporates review rounds #1–#6 and #R2.1–#R2.6).
> Phases 0–1 are unconditional and have a bite-sized plan below.
> Phases 2–3 are **metric-gated** — they get their own plans only after the Phase-1 ledger read.

**Goal:** Raise the *quality* of findings (proof, refutation, recall, independent discovery) — not the
volume of reports — and make every step of that improvement a number on the existing benchmark harness,
so the expensive bets (app graph, framework catalogs) are *triggered by measurement instead of intuition*.

**Architecture:** A gated loop. Instrument first (you cannot gate what you cannot measure), then make the
cheap prompt/schema changes (counterexample verifier + enforced proof structure), measure the delta, read
the ledger to diagnose residual failures, and only build deterministic static tooling (graph, catalogs)
**if** the ledger says the residual misses are *structural* rather than *reasoning* errors.

**Tech stack:** existing — Node ≥ 20 zero-dep helpers, AJV-generated standalone validators, deterministic
`benchmark/metrics.mjs`, the **full OWASP BenchmarkJava 2740** corpus.

---

## 0. Why this shape (grounded in the repo)

The 88-case subset already scores **precision 1.000 / recall 0.976** for `oswe_over_semgrep`. So precision
is saturated there → the counterexample verifier's gate is **non-regression**, and signal comes from the
**full 2740** (recall, independent discovery) plus new proof/refutation metrics.

**Three load-bearing facts the plan must respect (review #R2):**

1. **The ledger is case-level; several quality metrics are finding-level.** A single OWASP case can yield
   more than one finding, so a per-case boolean `proof_complete` cannot honestly back a per-finding rate
   (#R2.3). The ledger therefore carries **counters**, not booleans, and metrics sum them.
2. **The full 2740 is populated incrementally** (oswe-auditing 2740 cases is a large campaign). The
   benchmark must distinguish *"audited and missed"* (structural/reasoning signal) from *"not yet
   audited"* (no signal). Without an `oswe_attempted` flag, thousands of un-run cases degrade to
   `oswe_covered:false` and **falsely inflate `structural_fn_share` toward Phase 3** (#R2.2).
3. **`report.json` needs a deterministic bridge to the benchmark.** The audit emits `report.json`; the
   benchmark keys on `test_id`. A dedicated extractor (`extract-oswe-adjudications.mjs`) maps one to the
   other — nothing is derived by hand (#R2.1).
4. **The report must capture audit *activity*, not just findings (review #R3).** Two states would be lost
   if the report only listed findings: (a) a case *audited with zero findings* — needed so it counts as
   `oswe_attempted:true` not a structural miss (#R3.1); (b) a Semgrep lead *refuted before becoming a
   finding* — the headline precision result (15/15 FPs refuted) lives in `adjudicated_leads`, not in
   `findings` (#R3.2). So `report.json` carries `coverage` + `lead_adjudications[]`, mirroring the
   existing `analyzer-response` contract (`analyzer-response.schema.json:35,50`).
5. **"Staged" ≠ "analyzed" (review #R4.1).** The budget analyzes only the partitions in `allocate-budget`'s
   `analyze[]`; everything in `gaps[]`/deprioritized is recorded as a coverage gap and **never analyzed**
   (`SKILL.md:139–142`). So `oswe_attempted`/`covered` must come from the **per-case analysis status**, not
   from the staging manifest — otherwise a full-2740 staging inflates `attempted_real_share`. The report
   therefore carries `coverage.benchmark_cases[{test_id,status,reason}]` (status mirrors the coverage
   taxonomy: `analyzed`/`deprioritized`/`gap`/`unsupported`/`unreadable`); `run.benchmark_test_ids[]` only
   records the *staged scope* (the denominator), and a staged-but-`deprioritized` case is `attempted:false`.

What already exists (do not rebuild): per-finding proof shape in `finding.schema.json`
(`source`/`transformations[]`/`sanitizers[].why_insufficient`/`sink`); chain proof in `chain.schema.json`
(`transitions[].evidence` required, Critical pinned to accepted+unauth-rce); `verdict.schema.json`;
the deterministic scorer/ledger; **AJV standalone validator generation** (`build-validators.mjs` →
`validators.mjs`, consumed by `validate-output.mjs`).

---

## 1. The loop

```
Phase 0  Instrument   ──▶ report.json + extractor + enriched ledger (counters+attempted) + metrics + 2740 baseline
Phase 1  Refute+prove ──▶ counterexample verifier (enforced) + enforced proof  (cheap: prompt+schema)
            │ measure on subset (non-regression) + full 2740
            ▼
   READ THE LEDGER (only if attempted_real_share ≥ threshold) ── structural vs reasoning?
            │
   ┌────────┴─────────┐
   │ mostly reasoning │ mostly structural
   ▼                  ▼
Phase 2            Phase 3
search passes +    app graph + source/sink/sanitizer catalogs
neg-search +       (the expensive bet — only if the ledger earns it)
2x verify
```

---

## 2. Files touched (map)

| File | Phase | Change |
|---|---|---|
| `skills/audit/schemas/report.schema.json` (**new**) | 0 | canonical artifact `{ run, coverage, findings[final-finding], chains[chain], verdicts[verdict], lead_adjudications[] }`. `run` carries `run_id`,`generated`,`scope`, optional `benchmark_test_ids[]` (**staged scope only**) / `path_map`. `coverage.benchmark_cases[{test_id,status,reason}]` carries **per-case analysis status** (`analyzed`/`deprioritized`/`gap`/`unsupported`/`unreadable`) — the source of `oswe_attempted`/`covered`, not the staging manifest (#R4.1); also represents a zero-finding analyzed case (#R3.1). `lead_adjudications[]` mirrors `analyzer-response.adjudicated_leads[]` **plus a `test_id` (or `location{file,line}`)** so each refuted lead resolves to its `BenchmarkTestNNNNN` in a multi-case report (#R3.2, #R4.2) |
| `skills/audit/scripts/write-report.mjs` (**new**) + test | 0 | emit + AJV-validate `report.json` |
| `skills/audit/scripts/build-validators.mjs` | 0 | add `"report.schema.json":"report"` to `EXPORT_NAME`; regenerate `validators.mjs` (#R2.4) |
| `skills/audit/scripts/validate-output.mjs` | 0 | add `"report":"report"` to `KIND_TO_EXPORT` (#R2.4) |
| `skills/audit/SKILL.md` | 0 | write `report.json` next to `.md`/`.html` |
| `benchmark/extract-oswe-adjudications.mjs` (**new**) + test | 0 | `report.json[] → oswe-adjudications.json` keyed by `test_id`; derive per-case **counters** + `oswe_attempted` (#R2.1) |
| `benchmark/build-ledger.mjs` + test | 0 | carry `oswe_attempted` + counters (`accepted_high_findings`,`proof_complete_high_findings`,`ce_resolved_high_findings`,`accepted_critical_chains`,`proof_complete_critical_chains`,`chain_reached_rce`) (#R2.2, #R2.3) |
| `benchmark/metrics.mjs` + test | 0 | `quality` block summing counters; `attempted_real_share`; structural diagnostic over **attempted** cases only |
| `benchmark/score-semgrep.mjs` + test | 0 | add `--all` (cases = every truth id); assert `cases.length === truth.size` (#R2.5) |
| `benchmark/stage-cases.mjs`, `benchmark/results/*` | 0 | stage full 2740; commit sanitized `ledger-full.json` + `baseline-sp6.json` |
| `skills/audit/schemas/verdict.schema.json` | 1 | structured `counterexamples[]` |
| `skills/audit/scripts/{validate-batch,apply-verdicts}.mjs` + tests | 1 | enforce: `accepted` ⇒ every CE `checked && refuted`; `rejected`/`downgraded` ⇒ ≥1 CE holds, cited (#3) |
| `skills/audit/schemas/finding.schema.json` | 1 | add `direct_flow:boolean`; proof-completeness for High |
| `skills/audit/schemas/final-finding.schema.json` | 1 | require complete proof for **accepted High findings** (#4) |
| `skills/audit/scripts/aggregate-findings.mjs` + test | 1 | propagate `direct_flow` (#2) |
| `agents/oswe-analyzer.md`, `agents/oswe-verifier.md`, `skills/audit/SKILL.md` | 1 | `direct_flow` semantics + mandatory counterexample checklist |

---

## 3. Corpus contract (locked: full OWASP BenchmarkJava 2740)

- Truth: `external/BenchmarkJava/expectedresults-1.2.csv` (all 2740).
- Flagged baseline: `score-semgrep.mjs --all` → `flagged.json` with `cases.length === 2740` (#R2.5).
- Staging: `stage-cases.mjs --all` (or `--ids <json>`) over the full set — currently `--category`+`--subset`
  only (`stage-cases.mjs:66`); add the bulk mode **and emit a staging manifest** listing the
  `BenchmarkTestNNNNN` actually staged, so the **staged scope** is reproducible and feeds
  `run.benchmark_test_ids[]` (#R3.3). The *analyzed* set is narrower and authoritative — it comes from
  `coverage.benchmark_cases[].status` (#R4.1), not the manifest. Already stages `helpers/` + `src/main/resources`.
- Committed (sanitized — ids + booleans/counters + CWE only): `benchmark/results/ledger-full.json`,
  `benchmark/results/baseline-sp6.json`.
- The 88-case `subset-owasp.json` is **kept as a precision negative-control**.
- **Incremental population (#R2.2):** Semgrep+truth cover all 2740 from day one; oswe coverage grows over
  time. Each case carries `oswe_attempted`. `build-ledger.mjs:8` already degrades absent cases safely, but
  **the structural diagnostic excludes `oswe_attempted:false` cases**, and the Phase-3 gate is only read
  once `attempted_real_share ≥ 0.80` (configurable). Below that threshold the gate read is *blocked*, not
  guessed.

Phase 0 ends when: `report.json` emits+validates, the extractor produces `oswe-adjudications.json`, the
ledger carries attempted+counters, metrics compute, and baselines are committed.

---

## 4. New metrics = the gates

Deterministic, in a `metrics.mjs` `quality` block. Counter-based (#R2.3), attempt-aware (#R2.2),
finding/chain-split (#4), scoped to enforced targets (#R2.6).

| Metric | Definition | Gate |
|---|---|---|
| `precision` (subset) | unchanged scorer | **non-regression ≥ 1.000** — every phase |
| `finding_proof_complete_rate` | Σ `proof_complete_high_findings` ÷ Σ `accepted_high_findings` | Phase 1: **= 1.000** |
| `chain_proof_complete_rate` | Σ `proof_complete_critical_chains` ÷ Σ `accepted_critical_chains` | Phase 1: **= 1.000** |
| `ce_resolved_rate` | Σ `ce_resolved_high_findings` ÷ Σ `accepted_high_findings` — **High findings only** (chain edges are already refuted via `transition_verdicts`; chain-level CE deferred) (#R2.6) | Phase 1: **= 1.000** + validator rejects unresolved (#3) |
| `recall` (full 2740) | tp ÷ (tp+fn), existing scorer | Phase 2: **> baseline**, precision held |
| `independent_discovery_rate` | `oswe_independent:true` ÷ real findings | Phase 2: **> baseline** |
| `attempted_real_share` | real cases with `oswe_attempted:true` ÷ real cases | **gate-read precondition ≥ 0.80** (#R2.2) |
| `real_not_found` | real, `oswe_attempted:true`, neither `promoted` nor independently discovered (matrix-independent, #5) | denominator |
| `covered_fn` | `real_not_found` with `oswe_covered:true` (reasoning miss) | diagnostic |
| `structural_fn` | `real_not_found` with `oswe_covered:false` (coverage/structure miss) | diagnostic |
| `structural_fn_share` | `structural_fn ÷ real_not_found` | **decides Phase 3** (only when `attempted_real_share ≥ 0.80`) |

`real_not_found` is restricted to **attempted** cases and computed independently of `m1/m2/m3` (which
exclude `not_covered`), so it neither double-counts un-run cases nor contradicts the existing scorer.

---

## 5. Phase 0 + 1 — bite-sized plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or
> superpowers:executing-plans. Phases 2–3 are intentionally **not** planned here — gated on §4.

### Task 1: Canonical `report.json` artifact + validator wiring (#1, #R2.4)

**Files:** Create `skills/audit/schemas/report.schema.json`, `skills/audit/scripts/write-report.mjs`,
`skills/audit/scripts/test/write-report.test.mjs`; modify `build-validators.mjs`, `validate-output.mjs`.

- [ ] **Step 1: Failing test** — `buildReport({run,findings,chains,verdicts})` AJV-validates; missing
  `run.run_id` fails; `validate("report", r)` resolves via the generated validators.
- [ ] **Step 2: Run, confirm FAIL.**
- [ ] **Step 3: Implement** — `report.schema.json` (`additionalProperties:false`):
  - `run` requires `run_id`,`generated`,`scope`; optional `benchmark_test_ids` (array of
    `^BenchmarkTest[0-9]{5}$`, the **staged scope**) and `path_map` (object) for benchmark mode.
  - `coverage` (object, mirrors `analyzer-response` `coverage`: `analyzed[]`, `skipped[]`) **plus**
    `benchmark_cases` (array of `{ test_id (^BenchmarkTest[0-9]{5}$), status (enum
    analyzed/deprioritized/gap/unsupported/unreadable), reason? }`) — the authoritative per-case analysis
    status (#R4.1) that also represents a zero-finding *analyzed* case (#R3.1).
  - `findings` `$ref` final-finding; `chains` `$ref` chain; `verdicts` `$ref` verdict.
  - `lead_adjudications` extends the `adjudicated_leads` item shape from `analyzer-response.schema.json`
    (`lead_id`,`outcome` ∈ promoted/refuted/inconclusive, optional `finding_id`/`reason`) **with a required
    resolver — `test_id` (^BenchmarkTest[0-9]{5}$) or `location{file,line}`** — so each refuted lead maps
    to its case in a multi-case report (#R3.2, #R4.2).

  Add `"report.schema.json":"report"` to `EXPORT_NAME` (`build-validators.mjs:19`) and `"report":"report"`
  to `KIND_TO_EXPORT` (`validate-output.mjs:6`). Run `build-validators.mjs` to regenerate `validators.mjs`.
- [ ] **Step 4: Run, confirm PASS** (incl. `validate-output` smoke for `report`).
- [ ] **Step 5: Commit** — `rtk git add skills/audit/schemas/report.schema.json skills/audit/scripts/ && rtk git commit -m "feat(sp6): canonical report.json artifact wired into validators"`

### Task 2: SKILL emits report.json

**Files:** Modify `skills/audit/SKILL.md`

- [ ] **Step 1: Edit** the report step (~`SKILL.md:396`) to also run `write-report.mjs` → REDACTED-safe
  `.oswe/reports/oswe-report-YYYY-MM-DD-HHMM.json`.
- [ ] **Step 2: Manual verification** via SP5 smoke; a valid `report.json` appears.
- [ ] **Step 3: Commit** — `rtk git add skills/audit/SKILL.md && rtk git commit -m "feat(sp6): audit writes canonical report.json"`

### Task 3: `extract-oswe-adjudications.mjs` — report.json → benchmark map (#R2.1)

**Files:** Create `benchmark/extract-oswe-adjudications.mjs` + `.test.mjs`

- [ ] **Step 1: Failing tests** — three cases:
  1. **finding case:** `report.json` resolving findings to `BenchmarkTest00008` → entry with
     `adjudication` (promoted/refuted/inconclusive), `covered`, `independent`, `oswe_attempted:true`, and
     counters `accepted_high_findings`,`proof_complete_high_findings`,`ce_resolved_high_findings`,
     `accepted_critical_chains`,`proof_complete_critical_chains`,`chain_reached_rce`.
  2. **zero-finding analyzed case (#R3.1):** `BenchmarkTest00010` has `coverage.benchmark_cases` status
     `analyzed` but no `findings` → `oswe_attempted:true`, `covered:true`, all counters `0`.
  3. **staged-but-deprioritized case (#R4.1):** `BenchmarkTest00012` ∈ `run.benchmark_test_ids` but its
     `coverage.benchmark_cases` status is `deprioritized` → `oswe_attempted:false`, `covered:false`.
  4. **refuted-lead-no-finding, multi-case (#R3.2, #R4.2):** two `lead_adjudications` entries
     `{lead_id:"L001",outcome:"refuted",test_id:"BenchmarkTest00011"}` and
     `{lead_id:"L002",outcome:"promoted",test_id:"BenchmarkTest00013"}` → `00011.adjudication:"refuted"`
     and `00013.adjudication:"promoted"`, **not mixed**.

```js
const map = extractAdjudications([REPORT_FIXTURE]);
assert.equal(map.BenchmarkTest00008.oswe_attempted, true);
assert.equal(map.BenchmarkTest00008.accepted_high_findings, 2);
assert.equal(map.BenchmarkTest00010.oswe_attempted, true);    // analyzed, no finding
assert.equal(map.BenchmarkTest00010.accepted_high_findings, 0);
assert.equal(map.BenchmarkTest00012.oswe_attempted, false);   // staged but deprioritized
assert.equal(map.BenchmarkTest00011.adjudication, "refuted");  // FP refuted, no finding, resolved by test_id
assert.equal(map.BenchmarkTest00013.adjudication, "promoted");
```

- [ ] **Step 2: Run, confirm FAIL.**
- [ ] **Step 3: Implement** — `oswe_attempted`/`covered` come from `coverage.benchmark_cases[].status`
  (`analyzed` ⇒ attempted+covered; `deprioritized`/`gap`/`unsupported`/`unreadable` ⇒ attempted:false),
  **not** from `run.benchmark_test_ids[]` (staged scope) nor finding presence (#R4.1, #R3.1).
  `adjudication` for a case resolves from `lead_adjudications[]` whose `test_id`/`location` maps to that
  case (#R4.2), falling back to a finding's promotion only when no lead entry exists. Counters derive from
  findings/chains/verdicts: `proof_complete` per High finding = source+sink AND (`transformations`
  non-empty OR `direct_flow`); `ce_resolved` per accepted High finding = every `counterexamples[]` entry
  `checked && refuted`; chain counters from accepted Critical chains; `chain_reached_rce` = any chain
  `final_impact:"unauth-rce"`.
- [ ] **Step 4: Run, confirm PASS.**
- [ ] **Step 5: Commit** — `rtk git add benchmark/extract-oswe-adjudications.* && rtk git commit -m "feat(sp6): deterministic report.json -> benchmark adjudications extractor"`

### Task 4: Ledger carries attempted + counters (#R2.2, #R2.3)

**Files:** Modify `benchmark/build-ledger.mjs`, `benchmark/build-ledger.test.mjs`

- [ ] **Step 1: Failing test** — a map entry with counters + `oswe_attempted` surfaces on the ledger entry;
  an absent case degrades to `oswe_attempted:false`, all counters `0`.
- [ ] **Step 2: Run, confirm FAIL.**
- [ ] **Step 3: Implement** — read `o.oswe_attempted` (default `false`) and the six counters (default `0`)
  onto each entry; keep the `metrics.mjs` `allowed` field set in sync.
- [ ] **Step 4: Run, confirm PASS.**
- [ ] **Step 5: Commit** — `rtk git add benchmark/build-ledger.* && rtk git commit -m "feat(sp6): ledger carries oswe_attempted + finding/chain counters"`

### Task 5: metrics.mjs `quality` block (#R2.2, #R2.3, #R2.6, #4, #5)

**Files:** Modify `benchmark/metrics.mjs`, `benchmark/metrics.test.mjs`

- [ ] **Step 1: Failing test** — `computeMetrics(ledger, truth).quality` exposes the §4 fields; verify
  `finding_proof_complete_rate` sums counters across two findings in one case; verify a `not-attempted`
  real case is excluded from `structural_fn` but counted in `attempted_real_share` denominator.
- [ ] **Step 2: Run, confirm FAIL.**
- [ ] **Step 3: Implement** the `quality` block exactly per §4 (counter sums; `real_not_found` over
  attempted cases; `/0` guards). Leave `m1/m2/m3` untouched.
- [ ] **Step 4: Run, confirm PASS.**
- [ ] **Step 5: Commit** — `rtk git add benchmark/metrics.* && rtk git commit -m "feat(sp6): attempt-aware, counter-based quality metrics"`

### Task 6: `score-semgrep.mjs --all` for full 2740 (#R2.5)

**Files:** Modify `benchmark/score-semgrep.mjs`, `benchmark/score-semgrep.test.mjs`

- [ ] **Step 1: Failing test** — with `--all`, `cases.length === truth.size` and every flagged decision is
  CWE-matched; `--subset` path unchanged.
- [ ] **Step 2: Run, confirm FAIL.**
- [ ] **Step 3: Implement** — when `--all` is present, build `cases` from `[...truth.keys()]` instead of
  `subset.test_ids`; keep `--subset` optional in that mode.
- [ ] **Step 4: Run, confirm PASS.**
- [ ] **Step 5: Commit** — `rtk git add benchmark/score-semgrep.* && rtk git commit -m "feat(sp6): score-semgrep --all covers full 2740"`

### Task 7: `stage-cases.mjs --all` + manifest, then lock corpus + baseline (#R3.3)

**Files:** Modify `benchmark/stage-cases.mjs` + test; create `benchmark/results/{ledger-full,baseline-sp6}.json`

- [ ] **Step 1: Failing test** — `stage-cases.mjs --all` (or `--ids <json>`) stages every truth case and
  writes a **staging manifest** (`staged.json` listing the `BenchmarkTestNNNNN` staged); assert the manifest
  count equals the corpus size. `--category`+`--subset` mode stays unchanged.
- [ ] **Step 2: Run, confirm FAIL** (current script requires `--category`+`--subset`, `stage-cases.mjs:66`).
- [ ] **Step 3: Implement** the bulk mode + manifest; the manifest feeds `run.benchmark_test_ids[]`.
- [ ] **Step 4:** stage full set, run `score-semgrep --all`, build ledger, run metrics → snapshot; commit
  sanitized `ledger-full.json` + `baseline-sp6.json`.
- [ ] **Step 5: Commit** — `rtk git add benchmark/stage-cases.* benchmark/results/ && rtk git commit -m "feat(sp6): stage-cases --all + manifest; full 2740 corpus + locked baseline"`

### Task 8: verdict schema — structured counterexamples

**Files:** Modify `skills/audit/schemas/verdict.schema.json` + validator test; regenerate `validators.mjs`

- [ ] **Step 1: Failing test** — well-formed `counterexamples[]` validates; bad enum fails.
- [ ] **Step 2: Run, confirm FAIL.**
- [ ] **Step 3: Implement** — add to `verdict.schema.json`:

```json
"counterexamples": {
  "type": "array",
  "items": {
    "type": "object", "additionalProperties": false,
    "required": ["hypothesis", "checked", "refuted"],
    "properties": {
      "hypothesis": { "type": "string", "minLength": 1 },
      "checked": { "type": "boolean" }, "refuted": { "type": "boolean" },
      "evidence": { "type": "array", "items": { "$ref": "finding.schema.json#/$defs/fileline" } },
      "note": { "type": "string" }
    }
  }
}
```
  require it (non-empty) when `target_type:"finding"` and `verdict` ∈ {accepted, downgraded} via `allOf`.
  Regenerate `validators.mjs`.
- [ ] **Step 4: Run, confirm PASS.**
- [ ] **Step 5: Commit** — `rtk git add skills/audit/schemas/verdict.schema.json skills/audit/scripts/ && rtk git commit -m "feat(sp6): verdicts carry structured counterexamples"`

### Task 9: ENFORCE counterexample resolution (#3)

**Files:** Modify `skills/audit/scripts/apply-verdicts.mjs` (or `validate-batch.mjs`) + test

- [ ] **Step 1: Failing test** — `accepted` with any CE `checked:false`/`refuted:false` is rejected;
  `rejected`/`downgraded` with no holding CE (`refuted:false`) is rejected; valid cases pass.
- [ ] **Step 2: Run, confirm FAIL.**
- [ ] **Step 3: Implement** — `accepted` ⇒ every CE `checked===true && refuted===true`;
  `rejected`/`downgraded` ⇒ ≥1 CE `checked===true && refuted===false`. Use the existing `verifier-output`
  error path.
- [ ] **Step 4: Run, confirm PASS.**
- [ ] **Step 5: Commit** — `rtk git add skills/audit/scripts/apply-verdicts.mjs skills/audit/scripts/test/ && rtk git commit -m "feat(sp6): accepted findings must refute every counterexample"`

### Task 10: `direct_flow` — schema + aggregator propagation (#2)

**Files:** Modify `skills/audit/schemas/finding.schema.json`, `skills/audit/scripts/aggregate-findings.mjs`
+ test, `agents/oswe-analyzer.md`; regenerate `validators.mjs`.

- [ ] **Step 1: Failing test** — `aggregateFindings([{...base, direct_flow:true}]).findings[0].direct_flow === true`.
- [ ] **Step 2: Run, confirm FAIL** (`aggregate-findings.mjs:54` rebuilds a fixed field set).
- [ ] **Step 3: Implement** — add `direct_flow:{ "type":"boolean" }` to `finding.schema.json`; in the merge
  object add `...(group.some(f => f.direct_flow) ? { direct_flow: true } : {})`; document in
  `oswe-analyzer.md`. Regenerate validators.
- [ ] **Step 4: Run, confirm PASS.**
- [ ] **Step 5: Commit** — `rtk git add skills/audit/schemas/finding.schema.json skills/audit/scripts/ agents/oswe-analyzer.md && rtk git commit -m "feat(sp6): direct_flow propagated through aggregation"`

### Task 11: enforce complete proof for accepted High findings (#4)

**Files:** Modify `skills/audit/schemas/final-finding.schema.json` + validator test; regenerate validators.

- [ ] **Step 1: Failing test** — accepted `final-finding` `final_severity:"High"` with neither
  `transformations` (non-empty) nor `direct_flow:true` → **fails**; the same finding with a non-empty
  `transformations` (or `direct_flow:true`) → **passes**; a `rejected` finding is exempt. (No Critical case
  — Critical is a chain property; a final-finding has no `chain` field — #R3.4.)
- [ ] **Step 2: Run, confirm FAIL.**
- [ ] **Step 3: Implement** — extend the existing `allOf`: non-rejected branch additionally requires, when
  `final_severity:"High"`, source+sink and (`transformations` non-empty OR `direct_flow:true`). Regenerate.
- [ ] **Step 4: Run, confirm PASS.**
- [ ] **Step 5: Commit** — `rtk git add skills/audit/schemas/final-finding.schema.json skills/audit/scripts/ && rtk git commit -m "feat(sp6): accepted High findings require a complete proof chain"`

### Task 12: verifier runs the counterexample checklist (prompt)

**Files:** Modify `agents/oswe-verifier.md`, `skills/audit/SKILL.md`

- [ ] **Step 1: Edit `oswe-verifier.md`** — mandatory per-finding checklist into `counterexamples[]` before
  any `accepted`/`downgraded`: auth blocks; real sanitizer breaks payload; source not attacker-controlled;
  type/encoding inert; runtime config disables sink; sink unreachable; precondition unrealistic. Accept only
  if every checked hypothesis is `refuted:true` (enforced Task 9); else downgrade/reject citing the holder.
- [ ] **Step 2: Edit `SKILL.md`** — High verdicts without a resolved `counterexamples[]` are a
  `verifier-output` error (retry/coverage-gap).
- [ ] **Step 3: Manual verification** — SP5 smoke; verdicts carry resolved `counterexamples[]` and validate.
  If smoke can't exercise it, say so — no result-cooking.
- [ ] **Step 4: Commit** — `rtk git add agents/oswe-verifier.md skills/audit/SKILL.md && rtk git commit -m "feat(sp6): verifier must refute a counterexample checklist before accepting"`

### Task 13: Phase-1 gate read

- [ ] Run subset + full-2740, emit `report.json`, extract adjudications, rebuild ledgers, run `metrics.mjs`.
- [ ] **Assert Phase-1 gates:** subset `precision` ≥ 1.000; `finding_proof_complete_rate` = 1.000;
  `chain_proof_complete_rate` = 1.000; `ce_resolved_rate` = 1.000.
- [ ] **Precondition the Phase-3 read:** only if `attempted_real_share ≥ 0.80`. Otherwise keep auditing.
- [ ] **Read `structural_fn_share`** → high → write **Phase 3** (graph + catalogs); low (`covered_fn`
  dominates) → write **Phase 2** (search passes + negative search + 2× verify), defer the graph.
- [ ] Record decision + numbers in `benchmark/BENCHMARK.md`.

---

## 6. Non-goals (v1)

- No app graph / framework catalogs until §4 `structural_fn_share` earns it (Phase 3, conditional).
- No numeric calibrated confidence — keep auditable enums.
- No runtime/Docker dynamic confirmation.
- No chain-level counterexamples or Critical double-verifier until Phase 2 (chain edges already refuted via
  `transition_verdicts`).

## 7. Review-findings closure

- #1/#R2.1 — report.json + **Task 3 `extract-oswe-adjudications.mjs`** bridge; report carries
  `benchmark_test_ids[]`/`path_map`.
- #2 — `direct_flow` propagated (Task 10).
- #3 — CE enforced by validator (Task 9); `ce_resolved_rate` gate.
- #4 — finding vs chain proof split; no Critical final-finding asserted.
- #5 — `real_not_found` matrix-independent denominator.
- #6 — corpus locked to full 2740.
- #R2.2 — `oswe_attempted` flag; structural diagnostic excludes un-run cases; Phase-3 read gated on
  `attempted_real_share ≥ 0.80`.
- #R2.3 — ledger carries **counters**; finding-level rates sum them across multi-finding cases.
- #R2.4 — `report.schema.json` wired into `build-validators.mjs` + `validate-output.mjs` + regenerated.
- #R2.5 — `score-semgrep.mjs --all`, asserts `cases.length === truth.size`.
- #R2.6 — `ce_resolved_rate` scoped to High findings; chain edges via existing `transition_verdicts`.
- #R3.1 — `report.json` carries `coverage` + `run.benchmark_test_ids[]`; extractor sets `oswe_attempted`
  from the audited set, not from finding presence; zero-finding case tested.
- #R3.2 — `report.json` carries `lead_adjudications[]` (mirrors `analyzer-response.adjudicated_leads`); a
  Semgrep FP refuted with no emitted finding is reconstructable; tested.
- #R3.3 — `stage-cases.mjs --all`/`--ids` + staging manifest feeding `run.benchmark_test_ids[]`.
- #R3.4 — Task 11 corrected: completeness condition is `transformations` non-empty OR `direct_flow:true`
  (no `chain` field on a final-finding).
- #R4.1 — `oswe_attempted`/`covered` derive from `coverage.benchmark_cases[].status` (analyzed vs
  deprioritized/gap), not the staging manifest; `run.benchmark_test_ids[]` is staged scope only; tested via
  the staged-but-deprioritized case.
- #R4.2 — `lead_adjudications[]` carry a `test_id`/`location` resolver; multi-case test asserts two
  refuted/promoted leads don't cross-attribute.
- #R4.3 — §7 closure uses `benchmark_test_ids[]` (plural), consistent with the body.
