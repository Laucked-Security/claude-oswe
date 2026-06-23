# SP9 — Real-App Validation on NodeGoat

> **Status:** design spec. This is a **validation campaign**, not a code build. The deterministic parts
> (ground truth + scoring) are TDD; the audit campaign is user-run; the gate read decides whether the
> app-graph (deferred since SP6) finally earns its place — **on evidence, not intuition.**

**Goal:** Test whether oswe's BenchmarkJava result (precision 1.000 / recall 1.000) holds on a **real,
multi-file Express application** — and let the outcome decide the next big architectural question.

**Architecture:** Mirror the BenchmarkJava harness against OWASP **NodeGoat** (already in
`external/NodeGoat/`): encode a documented ground truth, run `/oswe:audit` over the app (Node stack), score
the result with a NodeGoat-specific ledger/metrics, and read a gate that distinguishes *reasoning* misses
from *structural* (cross-file reachability) misses.

**Tech stack:** existing — Node ≥ 20 zero-dep helpers, `node:test`; `external/NodeGoat` (Express/MongoDB,
intentionally vulnerable; vulns documented in `app/views/tutorial/` + the public OWASP NodeGoat map).

---

## 0. Why NodeGoat is the honest next test

BenchmarkJava is **synthetic, single-sink-per-file** — the easiest terrain for a source→sink tool. The
whole SP6 apparatus (multi-hop chains, reachability, auth boundaries, the proof-graph) is barely exercised
there; only cmdi produced chains, and even those are single-file. The public README now claims
**precision 1.000 / recall 1.000** — a claim only validated on that easy terrain.

NodeGoat is the opposite: a **real app** with routes → middleware/auth → controllers → services → sinks
across files, sessions, an ORM/NoSQL layer, and templating. It is exactly where:
- **cross-file reachability** decides whether a finding is real (the analyzer must connect a route to a
  handler in another file);
- **auth boundaries** matter (NodeGoat has authenticated vs unauthenticated endpoints);
- a **structural blind spot** would show up as the analyzer never *seeing* that a route reaches a sink.

So NodeGoat answers two things at once: (1) is the precision/recall real or synthetic-inflated? (2) is the
residual failure mode *reasoning* (the model misjudged code it saw) or *structural* (the model never saw
the route→sink wiring because it's spread across files/partitions)? **That second answer is the
graph-vs-no-graph decision**, finally made on real data.

---

## 1. Ground truth (the testable core)

NodeGoat has a **known, documented** vulnerability set (OWASP Top-10-aligned: NoSQL/SQL injection, command
injection via the contributions `eval`, SSRF, XSS, access-control/IDOR, weak crypto, redirect, etc.),
described in `app/views/tutorial/` and the upstream tutorial. SP9 encodes this as a deterministic truth
manifest the scorer consumes — the analogue of `expectedresults-1.2.csv`.

`benchmark/nodegoat-truth.json` (committed, hand-curated from the tutorial, **citable**):
```json
{
  "app": "NodeGoat",
  "source": "https://github.com/OWASP/NodeGoat (app/views/tutorial)",
  "vulns": [
    { "id": "ng-a1-nosqli", "owasp": "A1", "vuln_class": "nosql-injection",
      "file": "app/data/allocations-dao.js", "note": "userId from req used unsanitised in query",
      "auth": "authenticated" },
    { "id": "ng-a1-cmdi", "owasp": "A1", "vuln_class": "code-injection",
      "file": "app/routes/contributions.js", "note": "eval() on attacker-controlled numeric fields" }
    /* …each documented NodeGoat vuln, file-anchored, with expected vuln_class + auth precondition… */
  ]
}
```
Each entry is **file-anchored** (not line-pinned — a real app's lines drift), with the expected `vuln_class`
and the minimum attacker capability (`auth`). The curation is from NodeGoat's own tutorial, so it is
auditable and honest about scope ("the documented set", like the BenchmarkJava "declared subset").

---

## 2. Files touched

| File | Task | Responsibility |
|---|---|---|
| `benchmark/nodegoat-truth.json` (**new**) | 1 | curated, file-anchored documented-vuln manifest |
| `benchmark/score-nodegoat.mjs` (**new**) + test | 2 | score a `report.json` against `nodegoat-truth.json` → recall (documented vulns found), noise (accepted findings with no truth match), chain/auth engagement, structural-miss classification |
| `benchmark/results/nodegoat-baseline.json` (**new**) | 4 | committed sanitized score of the campaign run |
| `benchmark/BENCHMARK.md` | 4 | the NodeGoat result + the gate decision |
| `external/nodegoat-stage/` (gitignored) | 3 | staged scope for the audit (or audit the repo in place) |

No schema changes. The audit consumes the existing Node reference (`skills/audit/references/node.md`) and
emits the canonical `report.json` SP9 scores.

---

## 3. Methodology / plan

### Task 1: curate `benchmark/nodegoat-truth.json` (deterministic)
- [ ] Read `external/NodeGoat/app/views/tutorial/` and the route/data files to enumerate each documented
  vuln. Encode it file-anchored with `vuln_class` + `auth`. Cross-check against the upstream OWASP NodeGoat
  vuln list. Aim for completeness over the documented set; mark anything ambiguous with a `"note"`.
- [ ] Commit — `git add benchmark/nodegoat-truth.json && git commit -m "feat(sp9): NodeGoat documented-vuln ground truth"`

### Task 2: `score-nodegoat.mjs` (deterministic, TDD)
- [ ] **Failing test** — `scoreNodegoat(report, truth)` returns:
  - `recall` = documented vulns with ≥1 accepted oswe finding in the same `file` and compatible
    `vuln_class` ÷ total documented;
  - `found[]` / `missed[]` (the documented vulns hit/missed);
  - `extra[]` = accepted oswe findings with **no** truth match (candidate noise — but a real app has real
    bugs beyond the tutorial set, so `extra` is reported, **not** auto-scored as FP);
  - `chains` = count of accepted chains, `multi_file_chains` = chains whose transitions span ≥2 files
    (did the proof-graph apparatus actually engage on a real app?);
  - `structural_missed[]` = `missed` vulns whose file fell in a partition oswe recorded as
    `deprioritized`/`gap`/not-analyzed in `coverage.benchmark_cases`-equivalent coverage → the model never
    saw it (structural), vs `reasoning_missed[]` = file WAS analyzed but no finding (reasoning).
- [ ] Implement; full benchmark suite green.
- [ ] Commit — `git add benchmark/score-nodegoat.* && git commit -m "feat(sp9): NodeGoat scorer (recall, chain engagement, structural vs reasoning miss)"`

### Task 3: stage + run the audit (USER-RUN)
- [ ] Audit NodeGoat with the Node stack (after session reload). NodeGoat is one app, but the 12-partition
  budget cap (`SKILL.md:124`) means a single run analyzes only ~12 partitions — for an app this size, run
  **per-area** (routes, data/DAO, services) or raise nothing and accept the budget, recording coverage
  honestly. Emit `report.json`. (Optionally use SP8 exports to eyeball the SARIF in a viewer.)
- [ ] `node benchmark/score-nodegoat.mjs --report .oswe/reports/<nodegoat>.json --truth benchmark/nodegoat-truth.json --out benchmark/results/nodegoat-baseline.json`

### Task 4: gate read + decision
- [ ] Read the scorer output and decide:
  - **recall** on the documented set — does the BenchmarkJava recall generalize to a real app?
  - **`multi_file_chains` > 0?** — did oswe actually build cross-file exploit chains (the SP6 apparatus
    working on real structure), or did it only find isolated sinks?
  - **`structural_missed` vs `reasoning_missed`** — THE decision:
    - structural dominates (oswe missed vulns because the route→sink wiring spans partitions it never
      connected) → **the app-graph finally earns its place**: write SP10 = App Graph / framework
      reachability (Express routes → handlers → sinks), now justified by real evidence.
    - reasoning dominates (oswe saw the files but misjudged) → graph still not the answer; the lever is
      better Node-stack reasoning (search passes / catalogs), not structure.
- [ ] Record the numbers + decision in `benchmark/BENCHMARK.md`. Commit the sanitized baseline.

## 4. Non-goals (v1)

- No dynamic/runtime exploitation — static analysis only (NodeGoat ships a Docker target, but SP9 is a
  static-audit validation, consistent with oswe's identity).
- No claim of completeness beyond NodeGoat's documented set (honest scope, like the declared subset).
- No app-graph build in SP9 — SP9 only **decides whether** it's justified; building it is SP10 *iff* the
  gate says structural.
- No new vuln classes chased mid-campaign — if oswe surfaces real undocumented bugs (`extra[]`), note them
  as a credibility win, don't expand scope.

## 5. Gates (success criteria — what "validated" means)

| Signal | Reading |
|---|---|
| `recall` on documented set | the headline: does real-app recall hold near the benchmark's? |
| `extra[]` triaged | are the non-truth findings real bugs (win) or noise (precision risk)? |
| `multi_file_chains` | proof that chains/reachability engage on real structure, not just isolated sinks |
| `structural_missed` share | **the architectural decision**: high → SP10 app-graph; low → reasoning work |
| determinism | same NodeGoat checkout + same report → same score |

## 6. Self-review

- The honest risk this addresses: the public 1.000/1.000 claim is only synthetic-terrain-validated. SP9
  stress-tests it on real code.
- Deterministic core (truth + scorer, Tasks 1–2) is TDD and citable; the campaign (Task 3) is user-run; the
  decision (Task 4) is evidence-based and explicitly reopens — or keeps closed — the app-graph question.
- Consistent with the project's method since SP6: instrument, run on harder data, let the gate decide.
- Depends on SP8 only loosely (SARIF is a nice-to-have for eyeballing); SP9 scores from `report.json`
  directly, so it does not block on SP8.
