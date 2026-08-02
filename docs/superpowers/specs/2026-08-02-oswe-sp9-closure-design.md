# SP9 — Honest NodeGoat Campaign Closure

**Status:** approved closure design.

## Goal

Close SP9 without changing the auditor or the scoring method after observing the campaign. Publish the
result actually produced by the existing NodeGoat runs, including the negative multi-file-chain signal,
and make the architectural decision from that evidence.

## Campaign artifacts

The `external/NodeGoat/app/routes` report is the canonical campaign run because it is the run that
engaged every vulnerability class in the seven-entry declared truth set. Its scorer output becomes
`benchmark/results/nodegoat-baseline.json` without hand-editing the computed fields.

The `external/NodeGoat/app/data` score remains a supplementary per-area result. It is not combined with
the canonical score: aggregating after observation would introduce a new scoring method and make the
published baseline harder to reproduce.

The canonical result is expected to record:

- documented-set recall: 7/7 (`1.000`);
- accepted or downgraded findings outside the declared set: 6, pending code-level triage;
- accepted chains: 1;
- accepted multi-file chains: 0;
- structural misses: 0;
- reasoning misses: 0.

## Ground-truth correction

`benchmark/nodegoat-truth.json` remains a seven-entry, file-anchored manifest. Its descriptive note will
be corrected to say that five entries have distinct `route_file` and sink `file` values, while the open
redirect and missing-access-control entries both live in `app/routes/index.js`. The vulnerability data
and recall denominator do not change.

## Extra-finding triage

Each of the six canonical `extra[]` entries will be checked against the local NodeGoat source and
tutorial material. `benchmark/BENCHMARK.md` will record, for each entry, the relevant source/sink path
and one of three outcomes:

- confirmed issue outside the seven-entry declared set;
- overlapping or duplicate representation of a declared issue;
- unsupported/noisy finding.

This triage is explanatory only. It must not mutate the scorer output or retroactively expand the recall
denominator.

## Gate reading and architectural decision

SP9 closes with a mixed result:

- real-app detection recall is validated on the declared source-to-sink set;
- cross-file findings show that route-to-DAO evidence can be surfaced;
- the only accepted exploit chain is the same-file contributions `eval` chain, so multi-file proof-graph
  engagement is not validated;
- with no misses, neither structural nor reasoning misses dominate.

Therefore SP10 App Graph is **not justified by this campaign**. The zero multi-file-chain result remains
an explicit validation gap, not a passing result and not a reason to manufacture an app-graph project
without evidence of structural misses.

## Documentation and repository state

`benchmark/BENCHMARK.md` will gain the complete SP9 table, extra-finding triage, limitations, and decision.
`README.md` will update the test count from 375 to 380 (320 pipeline plus 60 benchmark tests) and will not
claim that NodeGoat demonstrated a multi-file exploit chain.

The canonical baseline and supplementary data score will be tracked. The temporary
`nodegoat-routes-baseline.json` name will be retired after its byte-equivalent canonical replacement is
verified.

## Verification

Closure requires fresh evidence for all of the following:

1. Re-score the routes report and compare it byte-for-byte with the canonical baseline.
2. Re-score the data report and compare it byte-for-byte with the supplementary score.
3. Run `node --test` in `skills/audit/scripts` (320 tests).
4. Run `node --test` in `benchmark` (60 tests).
5. Run `node .github/scripts/check-structure.mjs`.
6. Run `git diff --check` and confirm that only intended SP9 artifacts remain changed.

## Non-goals

- No auditor, schema, prompt, or scorer behavior change.
- No new NodeGoat audit run.
- No dynamic exploitation.
- No post-hoc aggregation of the two campaign reports.
- No SP10 implementation.
