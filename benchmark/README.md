# OSWE Hybrid Benchmark

Measures the precision/recall delta of the hybrid auditor vs raw Semgrep on the
[OWASP Benchmark](https://github.com/OWASP/Benchmark) (v1.2, Apache-2.0).

## Two stages

1. **Metrics engine (`metrics.mjs`)** — deterministic, zero-dep, CI-tested. Consumes a sanitized
   *ledger* (`benchmark/fixtures/sample-ledger.json` shows the shape) + the official
   `expectedresults-1.2.csv` and prints confusion matrices + deltas. Run:
   ```bash
   node benchmark/metrics.mjs --ledger <ledger.json> --truth expectedresults-1.2.csv \
                              --out report.json --md BENCHMARK.md
   ```
2. **Run orchestration (manual, expensive — NOT in CI).** Produces a ledger:
   1. `git clone https://github.com/OWASP/Benchmark external/owasp-benchmark` (gitignored).
   2. Run Semgrep once to a pinned SARIF: `semgrep --config p/owasp-top-ten --sarif -o owasp.sarif external/owasp-benchmark/src/...`.
   3. In your own Claude Code session (subscription quota — **not** nested `claude -p`),
      run `/oswe:audit --sarif owasp.sarif <subset paths>` over the ids in `subset-owasp.json`.
   4. Assemble the ledger (one entry per in-scope `test_id`) from the audit output, per the
      `oswe_covered`/`oswe_adjudication`/`oswe_independent` fields documented in the spec §3.7.1.

The ledger is **sanitized by construction** (test ids + booleans + cwe only — no code, paths, or
secrets), so a sample ledger is committed safely. The raw audit `leads`/intermediates are NOT
committed (they live under `.oswe/tmp/` and are purged).
