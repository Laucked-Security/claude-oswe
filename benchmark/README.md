# OSWE Hybrid Benchmark

Measures the precision/recall delta of the **hybrid auditor** vs **raw Semgrep** on
[OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) (v1.2, Apache-2.0 — note the
repo moved from `OWASP/Benchmark`). The thesis: Semgrep is noisy (high FPR); oswe's adjudication layer
refutes the false positives while keeping the true positives, so **oswe-over-Semgrep beats raw Semgrep
on precision** — and the hybrid additionally recovers vulns Semgrep missed.

Everything here is **maintainer tooling** (zero-dep, lives outside the plugin runtime). The corpus,
Semgrep rules, SARIF, and intermediate JSON live under the gitignored `external/`. Only the metrics
engine, the scorer, the ledger builder, their tests, the stratified subset, and a sanitized sample
ledger are committed.

## The four committed tools

| Tool | Role | Tested |
|---|---|---|
| `make-subset.mjs` | Re-derive `subset-owasp.json` (88 cases, 4 real + 4 not per CWE category) from the truth CSV | — |
| `score-semgrep.mjs` | Semgrep SARIF → raw-Semgrep baseline (CWE-matched) + per-case `semgrep_flagged` map (`flagged.json`) | ✅ |
| `build-ledger.mjs` | `flagged.json` + your oswe-adjudication map → a §3.7.1 ledger | ✅ |
| `metrics.mjs` | ledger + truth CSV → 3 confusion matrices + deltas (`BENCHMARK.md`) | ✅ |

## Stage A — offline, automatable (no Claude quota)

```bash
# 1. Get the corpus + the official Semgrep rules (registry is often blocked by a corp CA; clone instead)
git clone https://github.com/OWASP-Benchmark/BenchmarkJava external/BenchmarkJava
git clone https://github.com/semgrep/semgrep-rules        external/semgrep-rules

# 2. (Re)generate the declared stratified subset (already committed; this just verifies reproducibility)
node benchmark/make-subset.mjs \
  --truth external/BenchmarkJava/expectedresults-1.2.csv \
  --out   benchmark/subset-owasp.json

# 3. Scan the OWASP testcode with the official Java security rules, OFFLINE, to a pinned SARIF.
#    Always disable the phone-home or `semgrep` hangs; never rely on `--config p/...` (needs the registry).
SEMGREP_SEND_METRICS=off semgrep scan --disable-version-check --metrics off \
  --config external/semgrep-rules/java/lang/security \
  --sarif --output external/owasp-semgrep.sarif \
  external/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode

# 4. Compute the raw-Semgrep baseline + emit flagged.json (the semgrep_flagged map per subset case)
node benchmark/score-semgrep.mjs \
  --sarif  external/owasp-semgrep.sarif \
  --truth  external/BenchmarkJava/expectedresults-1.2.csv \
  --subset benchmark/subset-owasp.json \
  --out    external/flagged.json \
  --md     external/baseline.md
```

**Reference baseline** (official `java/lang/security` rules, CWE-matched, 2026-06-17):

| scope | precision | recall | FPR | (tp/fp/fn/tn) |
|---|---|---|---|---|
| subset (88) | 0.712 | 0.841 | 0.341 | 37/15/7/29 |
| full (2740) | 0.669 | 0.790 | 0.417 | 1118/552/297/773 |

The **15 subset false positives** (552 full) are the noise oswe must refute to win on precision.

## Stage B — the oswe runs (your Claude session, uses subscription quota)

`/oswe:audit --sarif …` cannot be billed to nested `claude -p` (separate, exhausted API credit) — run it
**interactively in your own session**. The SARIF you feed it must use **repo-root-relative** `uri`s
(the bare-`app.py` lesson): `external/owasp-semgrep.sarif` already does, since Semgrep was run from the
repo root.

For each in-scope `test_id` in `subset-owasp.json`, run the audit over that test case and record how oswe
treated it. Assemble a single **oswe-adjudication map** `external/oswe-adjudications.json` keyed by test id:

```jsonc
{
  // a case Semgrep FLAGGED → how oswe adjudicated the lead:
  "BenchmarkTest00006": { "adjudication": "promoted" },   // real vuln, oswe confirmed
  "BenchmarkTest00010": { "adjudication": "refuted" },    // Semgrep FP, oswe refuted (the win)
  // a case Semgrep MISSED → did oswe cover it, and did it find the vuln on its own:
  "BenchmarkTest00021": { "covered": true, "independent": true },   // recovered FN
  "BenchmarkTest00024": { "covered": true, "independent": false }   // correctly silent
}
```
A case you don't run degrades safely (flagged → `not-analyzed`; missed → uncovered `no-lead`) and is
**excluded** from the matrices, not scored as a win or loss. You can run a **single CWE category first**
(e.g. the 8 `cmdi` cases) to prove the precision lift before doing all 88.

## Stage C — assemble the number (offline)

```bash
node benchmark/build-ledger.mjs \
  --flagged external/flagged.json \
  --oswe    external/oswe-adjudications.json \
  --out     external/ledger.json

node benchmark/metrics.mjs \
  --ledger external/ledger.json \
  --truth  external/BenchmarkJava/expectedresults-1.2.csv \
  --out    external/report.json \
  --md     benchmark/BENCHMARK.md     # <- the committable, sanitized result
```

`BENCHMARK.md` has three rows — `semgrep_raw`, `oswe_over_semgrep`, `hybrid` — plus the headline deltas
(`fp_refuted`, `recall_cost`, `fn_recovered`). The **ledger is sanitized by construction** (test ids +
booleans + cwe only — no code, paths, or secrets), so a real ledger and `BENCHMARK.md` are safe to commit.
The raw `leads`/SARIF/intermediates stay under gitignored `external/`.

> Sanity check of the chain (no quota): build a synthetic "oracle" oswe map that perfectly refutes
> Semgrep's FPs and recovers its misses; Stage C then yields `oswe_over_semgrep` precision 1.000 —
> the upper bound. Real numbers fall between the raw baseline and that bound.
