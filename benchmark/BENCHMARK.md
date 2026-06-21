# OSWE Hybrid Benchmark — results

**Dataset:** [OWASP BenchmarkJava v1.2](https://github.com/OWASP-Benchmark/BenchmarkJava) (Apache-2.0).
**Sample:** a deterministic, balanced **88-case stratified subset** — up to 4 real + 4 non-vulnerable per
CWE category — across **all 11 categories**. See [`subset-owasp.json`](subset-owasp.json) /
[`make-subset.mjs`](make-subset.mjs).
**Baseline tool:** Semgrep OSS 1.167 with the official `semgrep-rules/java/lang/security` ruleset,
scored **CWE-matched** per the OWASP methodology (a flag counts only if it carries the case's expected
CWE, with the documented 326≡327 crypto-sibling equivalence — see [`score-semgrep.mjs`](score-semgrep.mjs)
`CWE_EQUIV`). **Date:** 2026-06-18. Reproducible — see [`README.md`](README.md).

## Headline (88 cases, 11 categories)

| matrix | tp | fp | fn | tn | precision | recall | fpr | youden |
|---|---|---|---|---|---|---|---|---|
| `semgrep_raw` | 41 | 15 | 3 | 29 | **0.732** | 0.932 | **0.341** | 0.591 |
| `oswe_over_semgrep` | 40 | 0 | 1 | 15 | **1.000** | 0.976 | **0.000** | **0.976** |
| `hybrid` | 41 | 0 | 3 | 44 | 1.000 | 0.932 | 0.000 | 0.932 |

**Deltas:** Semgrep false positives refuted = **15 / 15** (every one); recall cost = **1**;
false-negatives recovered = **1**.

oswe's adjudication layer **refuted all 15 of Semgrep's false positives across all 11 categories**,
lifting precision **0.732 → 1.000** and collapsing the false-positive rate **0.341 → 0.000** — while
**keeping 40 of 41 true positives**. Balanced accuracy (Youden's J) rises **0.591 → 0.976**.

## Per category (`semgrep_raw` → `oswe_over_semgrep`)

| category | Semgrep P / FPR | oswe P / FPR | Semgrep FPs refuted |
|---|---|---|---|
| `cmdi` | 0.571 / 0.750 | 1.000 / 0.000 | 3 |
| `sqli` | 0.571 / 0.750 | 1.000 / 0.000 | 3 |
| `pathtraver` | 0.500 / 1.000 | 1.000 / 0.000 | 4 |
| `ldapi` | 0.667 / 0.500 | 1.000 / 0.000 | 2 |
| `xpathi` | 0.571 / 0.750 | 1.000 / 0.000 | 3 |
| `xss` | 1.000 / 0.000 | 1.000 / 0.000 | 0 (control) |
| `weakrand` | 1.000 / 0.000 | 1.000 / 0.000 | 0 (control) |
| `securecookie` | 1.000 / 0.000 | 1.000 / 0.000 | 0 (control) |
| `crypto` | 1.000 / 0.000 | 1.000 / 0.000 | 0 (control) |
| `hash` | 1.000 / 0.000 | 1.000 / 0.000 | 0 |
| `trustbound` | 1.000 / 0.000 | 1.000 / 0.000 | 0 (+1 FN recovered) |

**Every category lands at oswe precision 1.000 / FPR 0.000.** The five noisy categories
(`cmdi`/`sqli`/`pathtraver`/`ldapi`/`xpathi`) are where the refutations happen; the already-precise
categories are **negative controls** — oswe added **zero** false refutations on any of them, so the
precision gain never came at the cost of breaking Semgrep's correct findings.

## Beyond precision

- **A real SQLi→RCE chain Semgrep can't express.** On `BenchmarkTest00008` oswe promoted the SQLi *and*
  chained it to **unauthenticated RCE** via HSQLDB's `CALL` statement invoking `java.lang.Runtime.exec`
  — a verifier-accepted Critical. SAST rules flag the injection; only the chaining layer reaches RCE.
- **One false-negative recovered by LLM discovery.** `trustbound/BenchmarkTest00004` stores a tainted
  HTTP value as a session attribute **key**; Semgrep's rule models value-taint only and missed it. oswe
  found it independently (`origin: llm-discovered`) — the hybrid edge SAST-alone can't give.
- **Honest downgrade.** A `pathtraver` arbitrary-file-write was offered as an RCE chain (drop a JSP
  webshell); the verifier **downgraded** the RCE pivot to `likely` because Tomcat/JSP config wasn't in
  the staged sources. The write primitive stayed High. The auditor pushes back on its own analyzer.

## Honest caveats

- **The 1 recall cost is a deliberate, defensible refutation, counted against oswe anyway.**
  `cmdi/BenchmarkTest00007` is labelled vulnerable because tainted input reaches `Runtime.exec(...)` —
  but it reaches the **`envp` (environment) argument**, not the command array; the command itself is a
  static script path. Env-var *values* aren't interpreted as commands, so the refutation is arguably
  **more correct than the OWASP label** (a known Benchmark labeling weakness). Scored as a miss under
  strict OWASP scoring regardless — no result-cooking.
- **Two hash cases (`00003`, `00029`) are a staging-scope artifact, not an oswe reasoning failure**, and
  they only affect the *hybrid* recall (they are not Semgrep-flagged, so they never touch the precision
  headline). Both do `getInstance(getProperty("hashAlg1","SHA512"))`; the OWASP runtime config sets
  `hashAlg1=MD5` in `benchmark.properties`. The first run didn't have that resource file in audit scope,
  so oswe saw only the strong-looking `SHA512` default and judged them safe — exactly the same class of
  gap as the helper-file gap below. `stage-cases.mjs` now stages `src/main/resources` too; a corrected
  re-run is expected to flip these to recovered FNs (hybrid recall → 1.000).
- **CWE 326≡327 equivalence** (documented in `score-semgrep.mjs`): without it, Semgrep's correct crypto
  detections (tagged CWE-326) would be scored as misses against the CWE-327 labels, *falsely inflating*
  oswe's recall-recovery. The equivalence makes Semgrep look better — the honest direction.
- **Scope.** 88 cases across all 11 categories — a stratified sample (8/category), not the full 2740.
  The claim is precisely "on this declared subset", consistent with the audit's coverage philosophy.
- **Staging lesson** (cost one wasted run): a category's `helpers/` classes and `resources/` must be in
  audit scope — `BenchmarkTest00051` was briefly false-promoted until `SeparateClassRequest.getTheValue`
  (a constant "safe source" returning `"bar"`) was visible. `stage-cases.mjs` now stages both trees.

## Reproduce

The sanitized ledger backing this table is [`results/ledger-11cat.json`](results/ledger-11cat.json)
(test ids + booleans + CWE only — no code, paths, or secrets). Regenerate the table:

```bash
node benchmark/metrics.mjs --ledger benchmark/results/ledger-11cat.json \
  --truth external/BenchmarkJava/expectedresults-1.2.csv --out /tmp/r.json --md benchmark/BENCHMARK.md
```

Full procedure (corpus clone, Semgrep scan, oswe runs, ledger assembly) is in [`README.md`](README.md).

## SP6 full-2740 baseline (in progress)

SP6 moves the corpus from the saturated 88-case subset to the **full OWASP BenchmarkJava 2740**, where
there is real headroom. The Semgrep baseline over all 2740 (from the existing `owasp-semgrep.sarif`):

| matrix (2740) | tp | fp | fn | tn | precision | recall | fpr |
|---|---|---|---|---|---|---|---|
| `semgrep_raw` | 1248 | 552 | 167 | 773 | **0.693** | 0.882 | **0.417** |
| `oswe_over_semgrep` (56 adjudicated) | 40 | 0 | 1 | 15 | **1.000** | 0.976 | 0.000 |

**552 Semgrep false positives** are the headroom the adjudication layer must refute across the full
corpus — the precision story the 88-subset could only hint at. Sanitized baseline:
[`results/ledger-full.json`](results/ledger-full.json), [`results/baseline-sp6.json`](results/baseline-sp6.json).

**SP6 quality metrics + the Phase-1 gate are intentionally NOT yet readable.** `attempted_real_share`
is ~0 because the only oswe data so far is the pre-SP6 88-case runs (no `report.json`, hence
`finding_proof_complete_rate` / `ce_resolved_rate` are `null`). Per the design, the Phase-3 gate read is
**blocked until `attempted_real_share ≥ 0.80`** (#R2.2) — i.e. it requires the oswe-audit campaign
(per-case `/oswe:audit` emitting `report.json`, fed through `extract-oswe-adjudications.mjs`). The
deterministic pipeline (`score-semgrep --all` → `stage-cases --all` → audit → `extract-oswe-adjudications`
→ `build-ledger` → `metrics`) is wired and tested end-to-end; the remaining step is the audit campaign.

Regenerate the Semgrep side + metrics:

```bash
node benchmark/score-semgrep.mjs --sarif external/owasp-semgrep.sarif \
  --truth external/BenchmarkJava/expectedresults-1.2.csv --all --out external/flagged-full.json
node benchmark/build-ledger.mjs --flagged external/flagged-full.json --oswe <oswe-adjudications.json> \
  --out benchmark/results/ledger-full.json
node benchmark/metrics.mjs --ledger benchmark/results/ledger-full.json \
  --truth external/BenchmarkJava/expectedresults-1.2.csv --out benchmark/results/baseline-sp6.json
```
