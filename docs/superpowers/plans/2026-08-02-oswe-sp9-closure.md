# SP9 Honest NodeGoat Campaign Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish the existing NodeGoat campaign as a reproducible canonical SP9 baseline, triage its six extra findings, record the mixed gate result, and merge the completed branch locally.

**Architecture:** Preserve the audit reports unchanged. Preserve scorer behavior except for the explicitly approved post-review matcher hardening: SQL and generic injection cannot satisfy NoSQL truth, and path suffixes require a segment boundary. Promote the routes-run score to the single canonical baseline, keep the data-run score as a named supplementary artifact, and explain the observed zero multi-file-chain signal instead of changing the measurement after the run.

**Tech Stack:** Node.js >= 20, zero-dependency ESM helpers, `node:test`, JSON benchmark artifacts, Markdown documentation, PowerShell, Git.

## Global Constraints

- Do not change auditor, schema, or prompt. The only scorer-behavior exception is the approved post-review
  matcher hardening, protected by two negative tests and required to leave both saved SP9 scores unchanged.
- Do not run a new NodeGoat audit or perform dynamic exploitation.
- Do not aggregate the routes and data reports after observation.
- Keep the canonical scorer output unedited and reproducible from the saved routes report.
- State `multi_file_chains = 0` as an open validation gap.
- Do not start SP10; the current campaign does not justify an App Graph.

---

## File map

- Modify `benchmark/nodegoat-truth.json`: correct only the cross-file description; keep all seven entries and the denominator unchanged.
- Create `benchmark/results/nodegoat-baseline.json`: canonical byte-for-byte scorer output for the routes report.
- Create `benchmark/results/nodegoat-data-supplemental.json`: non-canonical scorer output for the data report.
- Retire `benchmark/results/nodegoat-routes-baseline.json` and `benchmark/results/nodegoat-data-baseline.json` after equality checks.
- Modify `benchmark/BENCHMARK.md`: publish SP9 metrics, extra-finding triage, limitations, and architecture decision.
- Modify `benchmark/score-nodegoat.test.mjs`: add the two negative matcher regression tests.
- Modify `benchmark/score-nodegoat.mjs`: apply only the approved class and path matcher hardening.
- Modify `README.md`: update the verified test count from 375 to 382 and the benchmark-suite count from 55 to 62.

### Task 1: Canonicalize the campaign artifacts

**Files:**
- Modify: `benchmark/nodegoat-truth.json:4`
- Create: `benchmark/results/nodegoat-baseline.json`
- Create: `benchmark/results/nodegoat-data-supplemental.json`
- Retire: `benchmark/results/nodegoat-routes-baseline.json`
- Retire: `benchmark/results/nodegoat-data-baseline.json`

**Interfaces:**
- Consumes: `scoreNodegoat(report, truth)` through `benchmark/score-nodegoat.mjs` CLI.
- Produces: one canonical raw score and one explicitly supplementary raw score; both retain the scorer's existing JSON shape.

- [ ] **Step 1: Correct the ground-truth description without changing its data**

Replace the false statement that every entry crosses files with this exact factual scope:

```text
Five entries have distinct route_file and sink file values and exercise cross-file reachability. The open-redirect and missing-access-control entries are both routed and sunk in app/routes/index.js.
```

Keep `excluded_classes` and all seven `vulns[]` objects byte-for-byte unchanged.

- [ ] **Step 2: Generate the canonical routes score**

Run:

```powershell
node benchmark/score-nodegoat.mjs --report .oswe/reports/oswe-report-2026-06-23-1059-nodegoat-routes.json --truth benchmark/nodegoat-truth.json --out benchmark/results/nodegoat-baseline.json
```

Expected stdout:

```text
recall=1.000 found=7/7 chains=1 multi_file_chains=0 structural_missed=0 reasoning_missed=0
```

- [ ] **Step 3: Prove the canonical score equals the existing routes score**

Run:

```powershell
$canonicalHash = (Get-FileHash -Algorithm SHA256 -LiteralPath 'benchmark/results/nodegoat-baseline.json').Hash
$routesHash = (Get-FileHash -Algorithm SHA256 -LiteralPath 'benchmark/results/nodegoat-routes-baseline.json').Hash
if ($canonicalHash -ne $routesHash) { throw 'canonical routes score differs from observed routes score' }
```

Expected: exit 0 with no output.

- [ ] **Step 4: Generate and verify the supplementary data score**

Run:

```powershell
node benchmark/score-nodegoat.mjs --report .oswe/reports/oswe-report-2026-06-23-1110-nodegoat-data.json --truth benchmark/nodegoat-truth.json --out benchmark/results/nodegoat-data-supplemental.json
$supplementalHash = (Get-FileHash -Algorithm SHA256 -LiteralPath 'benchmark/results/nodegoat-data-supplemental.json').Hash
$dataHash = (Get-FileHash -Algorithm SHA256 -LiteralPath 'benchmark/results/nodegoat-data-baseline.json').Hash
if ($supplementalHash -ne $dataHash) { throw 'supplementary data score differs from observed data score' }
```

Expected scorer stdout:

```text
recall=0.143 found=1/7 chains=0 multi_file_chains=0 structural_missed=6 reasoning_missed=0
```

- [ ] **Step 5: Retire only the two verified temporary names**

Resolve and verify the two exact paths are inside `E:\claude-oswe\benchmark\results`, then run:

```powershell
Remove-Item -LiteralPath 'benchmark/results/nodegoat-routes-baseline.json'
Remove-Item -LiteralPath 'benchmark/results/nodegoat-data-baseline.json'
```

Expected: the canonical and supplementary files remain; the two old untracked names are absent.

- [ ] **Step 6: Validate JSON and scorer regression tests**

Run:

```powershell
Get-Content -Raw benchmark/nodegoat-truth.json | ConvertFrom-Json | Out-Null
Get-Content -Raw benchmark/results/nodegoat-baseline.json | ConvertFrom-Json | Out-Null
Get-Content -Raw benchmark/results/nodegoat-data-supplemental.json | ConvertFrom-Json | Out-Null
node --test benchmark/score-nodegoat.test.mjs
```

Expected: JSON parsing exits 0 and all 7 NodeGoat scorer tests pass.

- [ ] **Step 7: Commit the truth correction and score artifacts**

```powershell
git add -- benchmark/nodegoat-truth.json benchmark/results/nodegoat-baseline.json benchmark/results/nodegoat-data-supplemental.json
git commit -m "fix(sp9): canonicalize NodeGoat campaign baseline"
```

### Task 2: Publish the honest SP9 result

**Files:**
- Modify: `benchmark/BENCHMARK.md:181`
- Modify: `README.md:11,33-34,275`

**Interfaces:**
- Consumes: the canonical and supplementary JSON artifacts from Task 1 plus the local NodeGoat source/tutorial evidence.
- Produces: the public interpretation of SP9 and accurate repository test counts.

- [ ] **Step 1: Add the canonical result table to `benchmark/BENCHMARK.md`**

Append an `SP9 — NodeGoat real-app validation` section containing exactly these canonical values:

```markdown
| signal | result |
|---|---:|
| documented source-to-sink set | 7 |
| found | 7 |
| recall | **1.000** |
| extra findings | 6 |
| accepted chains | 1 |
| multi-file chains | **0** |
| structural misses | 0 |
| reasoning misses | 0 |
```

Identify `.oswe/reports/oswe-report-2026-06-23-1059-nodegoat-routes.json` as the source report and
`results/nodegoat-baseline.json` as its raw canonical score. Explain that the data-only run is a scope
control, not a second headline baseline.

- [ ] **Step 2: Add the six-entry triage table**

Record these outcomes without modifying the score:

```markdown
| class / sink | triage | reason |
|---|---|---|
| `authorization` / `allocations-dao.js` | confirmed, outside declared set | NodeGoat A4 documents the route-param IDOR; `allocations.js` uses `req.params.userId` instead of the session id. |
| `idor` / `benefits-dao.js` | overlap | Same A7 missing-function-level-access-control root cause already represented by `ng-a7-missing-access-control`; this finding follows it to the arbitrary-user update sink. |
| `xss` / `memos.html` | noisy as reported | `server.js` globally sets `marked({sanitize:true})`; the finding omitted that sanitizer. NodeGoat still documents an A9 vulnerable-`marked` risk, but this report did not prove the required sanitizer bypass and was only downgraded to `likely`. |
| `xss` / `research.js` | confirmed, outside declared set | Attacker-selected upstream HTML is written to a `text/html` response; distinct impact on the documented SSRF flow. |
| `nosql-injection` / `user-dao.js` | confirmed primitive, impact overstated | JSON bodies allow a Mongo operator as `userName`, but the separate plaintext-password equality remains; query manipulation is present while an authentication bypass is not proven. |
| `weak-crypto` / `user-dao.js` | confirmed, outside declared set | NodeGoat A2 explicitly documents plaintext password storage and the inactive bcrypt fix. |
```

Summarize the precision read as four confirmed additional primitives/issues, one overlap, and one noisy
proof; explicitly avoid computing precision against the deliberately incomplete seven-entry denominator.

- [ ] **Step 3: Record the gate and SP10 decision**

State all four points:

```text
Real-app recall on the declared set is validated at 1.000.
Cross-file findings exist, including route-to-DAO flows.
The only accepted chain is the same-file contributions eval chain, so multi-file proof-graph engagement is not validated.
No misses exist to support a structural-miss diagnosis; SP10 App Graph is not justified by this campaign.
```

Label the outcome `mixed`, not an unconditional pass.

- [ ] **Step 4: Add maintainer-only deterministic reproduction commands**

Document both exact `score-nodegoat.mjs` commands from Task 1 as maintainer-only reproduction from saved
local reports, not clone-clean reproduction. State that `.oswe/` is gitignored, publish the SHA-256 hash
of each required report, and record the local NodeGoat checkout commit if its own Git metadata exposes
one; otherwise state that no checkout commit was recorded. Clarify that the checked-in score artifacts
contain no source code, secrets, or exploit payloads.

- [ ] **Step 5: Update every README test count**

Make these exact replacements:

```text
375 passing -> 382 passing
375 unit tests -> 382 unit tests
320 pipeline + 55 benchmark -> 320 pipeline + 62 benchmark
55 benchmark-engine tests -> 62 benchmark-engine tests
```

Do not change the existing NodeGoat RCE description beyond avoiding any new multi-file-chain claim.

- [ ] **Step 6: Check documentation consistency**

Run:

```powershell
rg -n '375|55 benchmark' README.md benchmark/BENCHMARK.md
rg -n 'multi-file|multi_file|App Graph|SP10|1\.000' benchmark/BENCHMARK.md
git diff --check
```

Expected: the first command finds no stale count; the second finds the explicit mixed gate and decision;
`git diff --check` exits 0.

- [ ] **Step 7: Commit the published result**

```powershell
git add -- README.md benchmark/BENCHMARK.md
git commit -m "docs(sp9): publish honest NodeGoat validation result"
```

### Task 3: Verify and integrate SP9

**Files:**
- Verify only; no planned content changes.

**Interfaces:**
- Consumes: all SP9 commits and saved campaign reports.
- Produces: fresh verification evidence and a local merge into `master`.

- [ ] **Step 1: Reproduce both score artifacts into an isolated verification directory**

```powershell
$verifyDir = 'E:\claude-oswe\.oswe\tmp\sp9-verify'
New-Item -ItemType Directory -Force -Path $verifyDir | Out-Null
node benchmark/score-nodegoat.mjs --report .oswe/reports/oswe-report-2026-06-23-1059-nodegoat-routes.json --truth benchmark/nodegoat-truth.json --out "$verifyDir\nodegoat-baseline.json"
node benchmark/score-nodegoat.mjs --report .oswe/reports/oswe-report-2026-06-23-1110-nodegoat-data.json --truth benchmark/nodegoat-truth.json --out "$verifyDir\nodegoat-data-supplemental.json"
if ((Get-FileHash "$verifyDir\nodegoat-baseline.json").Hash -ne (Get-FileHash 'benchmark/results/nodegoat-baseline.json').Hash) { throw 'canonical score is not reproducible' }
if ((Get-FileHash "$verifyDir\nodegoat-data-supplemental.json").Hash -ne (Get-FileHash 'benchmark/results/nodegoat-data-supplemental.json').Hash) { throw 'supplementary score is not reproducible' }
```

Expected: both scorer summaries match Task 1 and both hash comparisons succeed.

- [ ] **Step 2: Run the full pipeline suite**

Run from `skills/audit/scripts`:

```powershell
node --test
```

Expected: 320 tests, 320 pass, 0 fail.

- [ ] **Step 3: Run the full benchmark suite**

Run from `benchmark`:

```powershell
node --test
```

Expected: 62 tests, 62 pass, 0 fail.

- [ ] **Step 4: Run repository consistency checks**

Run from the repository root:

```powershell
node .github/scripts/check-structure.mjs
git diff --check
git status --short --branch
```

Expected: structure gate passes, diff check exits 0, and the feature branch is clean.

- [ ] **Step 5: Remove only the isolated verification directory**

Resolve `$verifyDir`, confirm it equals `E:\claude-oswe\.oswe\tmp\sp9-verify`, then run:

```powershell
Remove-Item -LiteralPath $verifyDir -Recurse
```

- [ ] **Step 6: Review the complete feature delta**

```powershell
git log --oneline master..HEAD
git diff --stat master...HEAD
git diff --check master...HEAD
```

Expected: eight branch commits (truth, scorer, closure design, implementation plan, worktree setup,
canonical artifacts, published result, final-review matcher/reproduction fix), no unrelated files, and no
whitespace errors.

- [ ] **Step 7: Finish the branch and merge locally**

Invoke `superpowers:finishing-a-development-branch`, select local merge, then merge
`feat/oswe-sp9-closure-execution` into `master`. Re-run the full verification commands required by that
skill after the merge. Do not push unless separately authorized.
