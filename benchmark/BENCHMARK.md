# OSWE Hybrid Benchmark — results

**Dataset:** [OWASP BenchmarkJava v1.2](https://github.com/OWASP-Benchmark/BenchmarkJava) (Apache-2.0).
**Sample:** a deterministic, balanced **32-case stratified subset** — 4 real + 4 non-vulnerable per CWE
category — across **4 of the 11 categories** (`cmdi`, `sqli`, `xss`, `pathtraver`).
See [`subset-owasp.json`](subset-owasp.json) (the full 88-case subset) and [`make-subset.mjs`](make-subset.mjs).
**Baseline tool:** Semgrep OSS 1.167 with the official `semgrep-rules/java/lang/security` ruleset,
scored **CWE-matched** per the OWASP Benchmark methodology (a flag counts only if it carries the case's
expected CWE). **Date:** 2026-06-18. Fully reproducible — see [`README.md`](README.md).

## Headline (32 cases, 4 categories)

| matrix | tp | fp | fn | tn | precision | recall | fpr | youden |
|---|---|---|---|---|---|---|---|---|
| `semgrep_raw` | 16 | 10 | 0 | 6 | **0.615** | 1.000 | **0.625** | 0.375 |
| `oswe_over_semgrep` | 15 | 0 | 1 | 10 | **1.000** | 0.938 | **0.000** | **0.938** |
| `hybrid` | 15 | 0 | 1 | 16 | 1.000 | 0.938 | 0.000 | 0.938 |

**Deltas:** Semgrep false positives refuted = **10 / 10**; recall cost = **1**; false-negatives
recovered = 0.

oswe's adjudication layer **refuted every one of Semgrep's 10 false positives** while keeping its true
positives — lifting precision **0.615 → 1.000** and collapsing the false-positive rate **0.625 → 0.000**.
Balanced accuracy (Youden's J) rises **0.375 → 0.938**.

## Per category (`semgrep_raw` → `oswe_over_semgrep`)

| category | Semgrep P / FPR | oswe P / FPR | Semgrep FPs refuted |
|---|---|---|---|
| `cmdi` | 0.571 / 0.750 | 1.000 / 0.000 | 3 / 3 |
| `sqli` | 0.571 / 0.750 | 1.000 / 0.000 | 3 / 3 |
| `xss` | 1.000 / 0.000 | 1.000 / 0.000 | 0 / 0 (control) |
| `pathtraver` | 0.500 / 1.000 | 1.000 / 0.000 | 4 / 4 |

`xss` is the **negative control**: Semgrep was already precise there (0 FPs), and oswe correctly
**did not over-refute** — it promoted all 4 real findings and added no false refutations. `pathtraver`
is the most dramatic: Semgrep flagged *every* non-vulnerable case (FPR 1.000); oswe refuted all four.

## Honest caveats

- **Scope.** 32 cases across 4 of 11 categories — a stratified sample, not the full 2740-case corpus.
  The claim is precisely "on this declared subset", consistent with the audit's coverage philosophy.
- **The 1 recall cost is a deliberate, defensible refutation, counted against oswe anyway.**
  `BenchmarkTest00007` (cmdi) is labelled vulnerable by OWASP because tainted input reaches
  `Runtime.exec(...)` — but it reaches the **`envp` (environment) argument**, not the command array;
  the command itself is a static script path. Env-var *values* are not interpreted as commands, so the
  refutation is arguably **more correct than the OWASP label** (a known Benchmark labeling weakness).
  We score it as a false-negative under strict OWASP scoring regardless — no result-cooking.
- **`recall 1.000` for Semgrep here** reflects that these four categories are "easy" for Semgrep's
  interprocedural taint rules (it flagged every real vuln in-subset), so there were no false-negatives
  for the hybrid to recover (`fn_recovered = 0`). On harder categories that gap may appear.
- **One staging lesson** (cost a wasted run): a category's `helpers/` classes must be in audit scope —
  `BenchmarkTest00051` was briefly false-promoted until `SeparateClassRequest.getTheValue` (a constant
  "safe source" returning `"bar"`) was visible. `stage-cases.mjs` now always stages the full helpers tree.

## Reproduce

The sanitized ledger backing this table is [`results/ledger-4cat.json`](results/ledger-4cat.json)
(test ids + booleans + CWE only — no code, paths, or secrets). Regenerate the table:

```bash
node benchmark/metrics.mjs --ledger benchmark/results/ledger-4cat.json \
  --truth external/BenchmarkJava/expectedresults-1.2.csv --out /tmp/r.json --md benchmark/BENCHMARK.md
```

Full procedure (corpus clone, Semgrep scan, oswe runs, ledger assembly) is in [`README.md`](README.md).
