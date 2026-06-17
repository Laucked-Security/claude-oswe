# SARIF ingestion demo

A tiny SARIF pointing at the committed Python vulnerable fixture, to demonstrate `--sarif` ingestion:

```bash
/oswe:audit --sarif test-fixtures/sarif-demo/results.sarif test-fixtures/python/vulnerable
```

`L001` points at the real SSTI sink (expected: **promoted** into the OSWE finding) and `L002` at a
benign line (expected: **refuted** with a reason). This exercises both adjudication outcomes.
