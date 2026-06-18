# OSWE Plugin — SP3: Budget-Allocated Coverage Design

**Status:** approved (review converged)
**Date:** 2026-06-18
**Depends on:** merged MVP + Phase 2 + HTML report + Hybrid Precision (the `oswe` plugin on `master`).
**Branch (implementation):** `feat/oswe-sp3-budget-coverage` (off `master`).

## 0. Context & thesis

`oswe` is LLM-orchestrated: the expensive step is the per-partition `oswe-analyzer` pass. The pipeline
caps that at a hard **budget of 12 partitions** — on a large monorepo (dozens of modules), everything
beyond partition #12 is dumped into Coverage as an opaque "not analyzed" wall, with no statement about
*which* surface was dropped or *why*.

**The trap SP3 must avoid: solving this by raising the cap.** Going 12→40 multiplies LLM spend ~3× on a
monorepo without any guarantee the budget lands where an attacker strikes. The real deliverable of SP3
is **not more partitions — it is a prioritization/budget layer upstream of `analyze`** that decides
*which* partitions deserve the expensive analyzer pass, and turns the opaque wall into **ranked,
justified, auditable coverage gaps.**

**Pivot property — scorer errors are safe by construction.** A mis-rank does not produce a silent false
negative; it produces a *declared gap*. The worst case of an imperfect scorer is a partition reported as
an honest, classified gap. So the scorer does not need to be *precise* — it needs to be **reproducible,
free, and conservative in the risk-increasing direction.** This points straight at a deterministic
scorer (no LLM in the nominal path), consistent with the project's "determinism where it matters" DNA.

This spec covers the deterministic prioritization layer only. The throughput axis (max-4 concurrency)
and the lead-grain generalization (SP1-style) are explicitly out of scope (§9).

## 1. Goal

1. recon enumerates **all** candidate partitions (it already produces a deterministic file→partition
   map); a new deterministic stage scores every partition and **allocates a fixed analyzer budget to
   the top-N**, reporting the rest as **classified, self-justified coverage gaps**.
2. The scorer is **deterministic and zero-runtime-dependency** (a tested Node helper), fed by
   per-stack token inventories curated by humans in the reference pages.
3. The scorer is **conservative**: ambiguity ranks *up*. Co-presence of source+sink with no nearby auth
   marker — the cheap proxy for "unauthenticated surface" — is a strong upward signal, fail-safe.
4. Each gap carries its **score + the proxy counts that justify it**, so a deprioritized partition is
   auditable in the report's Coverage section, not a black box.
5. **An unsupported/unscannable stack is reported as a distinct, prominent class** (surface *unknown*),
   never folded into "low predicted surface" (surface *assessed low*).
6. **Zero regression:** a repo with **≤ budget supported** partitions behaves exactly as today (all
   analyzed). Unsupported partitions are already skipped today, so reporting them as a prominent
   `unsupported-stack` class is not a regression (§3.4, §7). The layer only changes behavior when
   *supported* partitions exceed the budget.

## 2. Hard constraints (inherited from the project)

- **Zero runtime dependency.** Both new helpers run with **no `node_modules`**. The `surface` block is
  **JSON** (parsed by `JSON.parse`), not YAML: Node ≥ 20 has no native YAML parser, and a hand-rolled
  one fails in the *unsafe* direction (a silent indentation slip drops a sink → under-rank →
  under-analyze). `JSON.parse` fails **loud and total**.
- **Node ≥ 20**, ESM, the same exit-code contract as the other helpers (`0` ok / `1` invalid input /
  `2` IO|usage).
- **The deterministic core is sacred.** No changes to `apply-verdicts.mjs`, `validate-batch.mjs`,
  `confine-path.mjs`, `validate-output.mjs`, `aggregate-findings.mjs`, the gating logic, or the
  finding/chain schemas. SP3 grafts a stage *between* recon and analyze; everything downstream of
  analyze is untouched.
- **Reproducible coverage is the headline invariant.** Same input → same allocation, always. No LLM in
  the nominal scoring path; explicit total ordering (no reliance on upstream emission order).

## 3. Components

### 3.1 `surface` blocks in the reference pages

Each `skills/audit/references/<stack>.md` gains one fenced block with the info-string `surface`
(so the structure gate can locate it), containing **JSON** — declarative token inventories only:

````markdown
```surface
{
  "sources":   ["request.args", "request.form", "request.get_json", "request.cookies", "request.headers"],
  "sinks":     ["render_template_string", "pickle.loads", "yaml.load", "os.system", "subprocess.", "eval(", "cursor.execute"],
  "sanitizers":["shlex.quote", "yaml.safe_load", "escape("],
  "auth_markers":["@login_required", "@permission_required", "login_required(", "@roles_required"]
}
```
````

- **Declarative only.** Each value is a list of literal tokens. No regex language, no logic, no weights
  in the block. The block answers "which tokens count for this stack"; the helper (§3.3) answers "how
  they score". This preserves the SP3 boundary: **semantic data (human-curated) separated from
  deterministic decision (tested Node).**
- **Curation discipline INVERTS between categories, because their failure directions are opposite.**
  `sources`/`sinks`/`sanitizers` only ever *add* score → over-inclusion over-ranks → over-analyzes →
  **safe** (the accepted failure mode). So those lists may be **loose** (a stray token just over-ranks).
  But `auth_markers` is a **suppressor** (§3.3): its presence *removes* the unauth bonus → lowers score
  → under-ranks → under-analyzes → the **one unsafe direction**. Therefore `auth_markers` must be
  **strict — only tokens that prove enforcement** (`@login_required`, `@permission_required`, middleware
  guard calls), **never the mere presence of a user/session object.** Tokens like `session[` (a session
  *write*, e.g. `session["x"]=...`) or `request.user` (Django: present even for `AnonymousUser`, proves
  no control) match by substring without proving any gate → they would falsely suppress the fail-safe.
  They are **excluded by design** (note their absence from the example above, which an earlier draft
  wrongly included).
- Humans keep the surrounding prose (the pedagogical reference); the scanner reads **only** the block.
- Single source of truth — no generated artifact, no second copy to drift, no build step. (Rejected the
  `validators.mjs`-style generation: that pattern exists to remove AJV from the *runtime*; here the
  transform is near-identity and the scanner is already zero-dep, so generation buys nothing and adds a
  drift surface.)

### 3.2 New helper: `surface-scan.mjs` (files + blocks → count vectors; pure function of the FS)

```
node surface-scan.mjs --file <input.json> --out <vectors.json>
```

- `--file` input JSON: `{ "projectDir": "<abs>", "partitions": [ { "partition_id", "stack", "files": ["<repo-rel path>"] } ] }`
  — the **deterministic** half of recon's output (the factual file→partition map; recon already
  enumerates files per partition). SP3 takes this factual half and does its **own** deterministic
  counting on top; it never consumes recon's LLM-*interpreted* counts.
- Loads the `surface` block for each partition's `stack` from `references/<stack>.md` (parse the
  ` ```surface ` fence as JSON). A partition whose `stack` has **no matching surface block**
  (unsupported/unknown stack) is marked **`scannable: false`** — this is the §1.5 distinction.
- For each **scannable** partition, confine each file path to `projectDir` (reuse `confine-path`
  logic), read it, and count tokens per category. The vector carries, per category, a **file-count**
  (number of files containing ≥1 token of that category), a **total-hits** tally, and — critically —
  the **source∧auth co-location count** `source_and_auth_files` (number of files containing ≥1 source
  **AND** ≥1 auth marker, decided per file in the same single read — one `&&`, one extra integer, zero
  added I/O):
  `{ partition_id, stack, scannable: true, files: <n>, sources, sinks, sanitizers, auth_markers, source_and_auth_files, source_hits, sink_hits, auth_hits }`
  (`sources`/`sinks`/… are file-counts; `*_hits` are total occurrences; `source_and_auth_files` is the
  intersection — §3.3's fail-safe depends on it).
- **Matching discipline mirrors §3.1's inverted curation.** `sources`/`sinks`/`sanitizers` match by
  plain case-sensitive `String.includes` (loose is safe — over-match only over-ranks; e.g. `eval(`
  matching `retrieval(` is a harmless over-rank). **`auth_markers` match on a word boundary**
  (`\b<token>\b`-style, not bare substring) — because an auth marker is a *suppressor* (§3.3), a loose
  match would falsely suppress the fail-safe (the one unsafe direction), so auth matching is the strict
  one.
- **Wall-clock note ("cheap" = zero quota, not zero I/O).** The scan reads every in-scope file once —
  on a very large monorepo that is real I/O (bounded, no LLM, no quota). The short-circuit applies
  **only to the file-counts** (`sources`/`sinks`/`auth_markers`/`source_and_auth_files`: stop scanning a
  file for a category once its first token hits — presence is binary, so this is safe and bounded).
  **`sink_hits` stays a true, uncapped total at read time** — it is *not* per-file-capped, because
  §3.3's size-vs-danger guard depends on seeing the full concentration (the 1-file-30-`eval()` case);
  the only cap on `sink_hits` is at *scoring* (`min(sink_hits, DENSITY_CAP)`), never at read. Counting
  the full `sink_hits` is trivial — the file is already read in full for the other categories. The scan
  is free in *quota*, linear and bounded in *wall-clock* — name it so a reader doesn't read "cheap" as
  "instant".
- For each **unscannable** partition: `{ partition_id, stack, scannable: false, files: <n> }` (no
  counts — the surface is *unknown*, not *low*).
- Exit `0` ok / `1` malformed input (bad partitions[] / unreadable surface block) / `2` IO|usage.
- **Unit-tested** on fixtures: a partition with source+sink+no-auth → high counts; an auth-gated
  partition → auth_markers>0; an unsupported-stack partition → `scannable:false`; a file escaping the
  root → rejected; a missing surface block → that stack's partitions `scannable:false`.

### 3.3 New helper: `allocate-budget.mjs` (count vectors + budget → top-N + gaps; pure function of counts)

```
node allocate-budget.mjs --file <input.json> --out <allocation.json>
```

- `--file` input JSON: `{ "budget": 12, "vectors": [ <count vector> ], "sarifLeadsByPartition": { "<pid>": { "count": <n>, "max_severity": "<sev>" } } }`
  (the `sarifLeadsByPartition` map is **optional**; absent → the SARIF term is zero everywhere).
- **Budget = the partition budget (default 12, configurable).** This is the *coverage* limit SP3
  attacks. It is **NOT** the max-4 analyzer concurrency — that is the orthogonal *throughput* limit,
  unchanged, applied by the orchestrator when dispatching analyzers *within* the chosen top-N (§9).
- **Score — presence-binary + capped density, NOT raw file-count (deterministic, integer):** a raw
  `W_SOURCE*sources + W_SINK*sinks` over file-counts would let a **large-and-flat** partition outrank a
  **small-and-deadly** one (30 shallow source files = 30 > a 1-file partition with 30 `eval()` behind an
  open route = sinks-file-count 1) → under-rank the dangerous concentrate → the **unsafe** direction.
  So size must not proxy for danger. For a scannable vector:
  - **structural presence (binary):** `hasSource = sources>0`, `hasSink = sinks>0`.
    `base = (hasSource?W_SOURCE:0) + (hasSink?W_SINK:0)`. A partition's *structure* (does it have a
    source? a sink?) is binary, independent of how many files carry it.
  - **co-presence bonus:** if `hasSource && hasSink` add `W_COPRESENT` (source+sink together is a live
    attack surface, worth more than either alone).
  - **auth fail-safe (ambiguity → rank up), on per-file CO-LOCATION not a global ratio:** if
    `hasSource && hasSink && source_and_auth_files < sources` add `W_UNAUTH` — i.e. **at least one
    source-bearing file has no auth marker of its own** → treat the partition as unauthenticated-reachable.
    **Why co-location, not `auth_markers < sources`:** the two global file-counts are *independent
    populations*, so auth markers living in **non-source** files (a vendored auth lib, middleware,
    helpers, tests that merely mention `@login_required`) inflate `auth_markers` above `sources` while
    every actual route stays open — re-suppressing the fail-safe through the back door (10 open source
    files + 11 auth-mentioning non-source files → `11 < 10` false → bonus cancelled → the open routes get
    gapped). Measuring the **intersection** (`source_and_auth_files`, §3.2) asks the right question —
    *are the source files themselves gated?* — file by file. (`auth_markers===0` ⇒ `source_and_auth_files===0`
    ⇒ fires, the trivial sub-case.)
  - **capped density term:** add `W_DENSITY * min(sink_hits, DENSITY_CAP)` — rewards a *concentration*
    of dangerous sinks (the 30-`eval()` file ranks up) **without** letting raw size grow the score
    unbounded (the cap stops a huge flat partition from winning on volume). Sinks only; source density
    is not a danger signal on its own.
  - **sanitizers do NOT subtract.** A sanitizer's presence does not prove safety (the analyzer decides);
    subtracting would push toward under-analysis (unsafe). Carried in the justification only.
  - **SARIF as additive backstop, never constitutive.** `W_LEAD * min(sarif_count, LEAD_CAP)` is the
    additive term, **zero when no SARIF is supplied**, so the no-SARIF run is the reproducible contract;
    adding SARIF is a *declared input change* (same input → same output still holds). Its purpose: the
    token scan's **only unsafe error class is the false-negative by indirection** (a sink behind a
    wrapper/alias, invisible to `includes`). Semgrep's dataflow catches some of those, so the SARIF term
    lifts exactly the partitions the scan would under-rank. It patches the one unsafe hole; it does not
    replace the floor.
- **The auth asymmetry is the load-bearing subtlety (still worth naming).** Three of the four categories
  fail safe (over-count → over-rank → over-analyze). **`auth_markers` is the sole exception** — it
  suppresses, so its failure direction is unsafe. That is *why* its curation is strict (§3.1), its match
  is word-boundary (§3.2), and its fail-safe is keyed on per-file **co-location** (above) rather than a
  global count. **Note (no longer a load-bearing contract):** because the fail-safe now measures gating
  *file by file* (`source_and_auth_files`), it no longer assumes the partition is auth-*homogeneous*.
  recon's "partition by authentication boundary" (§2) remains a *comfort* (cleaner partitions, tidier
  reports) but is no longer required for the fail-safe to be correct — the measurement, not the
  partitioning, carries it.
- **Total deterministic ordering (protects the pivot property) — on a CONTENT key, not an emission-order
  id:** sort scannable vectors by **`(score DESC, content_key ASC)`** where `content_key` is a
  **content hash** = `sha256` (via built-in `node:crypto`, zero-dep) of the partition's
  **lexicographically-sorted, newline-joined repo-relative file paths** — a pure function of content,
  bounded in size (a thousand-file partition yields a 64-char key, not a megabyte sort-key). Ties at the `budget`/`budget+1` frontier therefore break on *what the partition
  contains*, never on `partition_id` order. **Why not `partition_id`:** if recon assigns ids in emission
  order (`p1`, `p2`, … as it emits them) and that order varies run-to-run (recon is LLM-orchestrated —
  file→partition *content* is factual, emission *order* is not), a `partition_id`-based tie-break would
  re-inherit exactly the non-reproducibility it's meant to cure (same two partitions, ids permuted, the
  *other* one gapped). The content key closes that door. (`partition_id` SHOULD also be content-derived
  — a normalized module path — for stable reporting; the tie-break does not rely on it being so.)
- **Allocation:**
  - **Unscannable** vectors do **not** compete for the budget (the analyzer has no reference for an
    unsupported stack, so spending budget there cannot help) and are emitted as a distinct gap class
    `unsupported-stack` with `surface_assessed: false`.
  - The top-`budget` scannable vectors (by the total order) → `analyze[]`.
  - The remaining scannable vectors → gap class `deprioritized` with `surface_assessed: true`, each
    carrying its `score` + full count vector as justification.
- **Output:** `{ ok, analyze: [ { partition_id, score } ], gaps: [ { partition_id, gap_class, score?, counts?, reason } ] }`
  where `gap_class ∈ { "deprioritized", "unsupported-stack" }`.
- Exit `0` ok / `1` malformed input (bad budget/vectors) / `2` IO|usage.
- **Unit-tested on synthetic count vectors (no disk):** budget≥#scannable → empty `deprioritized` gaps
  (zero-regression); a source+sink+no-auth vector outranks an auth-gated one; **a small-and-deadly
  vector (sinks file-count 1, sink_hits 30) is NEVER ranked below a large-and-flat one (sources
  file-count 30)** — assert `score(deadly) >= score(flat)` **and** a deterministic order, *not* a strict
  `>` (the capped density term lets a flat partition reaching `sink_hits ≥ DENSITY_CAP` tie the
  concentrate's density bonus; the design guarantees the concentrate is never *under*-ranked, and ties
  resolve on `content_key` — asserting strict `>` would make the test fragile to the §4 tunable
  weights); **a mixed partition where auth markers live only in non-source files
  (`auth_markers ≥ sources` but `source_and_auth_files < sources`) still gets the unauth fail-safe** —
  the co-location rule (the back-door case the global ratio would have missed); ties break by
  **`content_key`** (content hash), reproducible at the frontier and independent of input order; an
  unscannable vector never lands in `analyze` and
  always surfaces as `unsupported-stack`; the SARIF term is zero when the map is absent and lifts a
  partition when present (capped); sanitizers never lower a score.

### 3.4 SKILL.md integration — new §2.5 "Prioritize & allocate budget"

Between §2 (Partition) and §3 (Analyze):

- After recon/partition produces the file→partition map, write it (+ `budget`, default 12, overridable
  by a future flag) to a temp file and run `surface-scan.mjs` → count vectors, then `allocate-budget.mjs`
  → `{ analyze, gaps }` (same temp-file + `trap` hygiene as every other helper).
- §3 dispatches `oswe-analyzer` subagents **only for the partitions in `analyze[]`**, still **max 4
  concurrent** (unchanged). Everything in `gaps[]` is recorded for Coverage — never analyzed, never
  silently dropped.
- **When SARIF leads are present (hybrid mode):** the orchestrator passes the per-partition lead
  count/severity as `sarifLeadsByPartition` so the additive term applies. Leads assigned to a
  *deprioritized* partition are reported as `lead not analyzed (deprioritized)` — the precision ledger
  still accounts for every lead (consistent with the hybrid spec).
- **Zero-regression rule (explicit, grounded on today's baseline).** Establish the baseline first:
  **today, a partition of an unsupported stack is already NOT analyzed** — SKILL §7 Coverage already
  lists `unsupported stack` as a coverage-gap reason, and there is no reference page for the analyzer to
  work against. So SP3 does **not** newly drop unsupported partitions; it reports the *same* partitions
  under the prominent `unsupported-stack` class. Therefore zero-regression holds precisely: **every
  partition analyzed today is still analyzed** (supported, and ≤ budget → all selected), and **every
  partition skipped today is still skipped** (unsupported → now a clearer, ranked label). The behavior
  only changes when *supported* partitions exceed the budget — exactly the case SP3 exists to handle.

### 3.5 §7 Report — Coverage section gains ranked, classified gaps

Coverage now distinguishes three things instead of one opaque "not analyzed" list:
- **Analyzed** (top-N), as today.
- **Deprioritized (surface assessed low)** — ranked by score, each line carrying its proxy counts:
  e.g. *"`payments-admin`: score 2 — 0 sources, 1 sink, 4 auth-markers → predicted low unauth surface."*
  Auditable: a reader can see *why* it was deferred and judge whether to re-run with a larger budget.
- **Unsupported stack (surface NOT assessed)** — a distinct, prominent class. This is the dangerous
  "unseen surface" direction and must never read like a low score. e.g. *"`legacy-perl/`: unsupported
  stack — surface not assessed; not covered by this audit."*

**Coverage-honesty caveat (no-SARIF runs).** The `deprioritized` line must carry the standing caveat
that, **without a SARIF input**, the token scan's one uncovered blind spot is the false-negative by
indirection (§3.3): a sink reached through a wrapper/alias is invisible to `includes`, so a *low*
deprioritized score may reflect an aliased/indirected sink, **not** a genuinely thin surface. A SARIF
input backstops this; a no-SARIF run does not. State it so a reader never reads "low score" as "proven
safe" — the same coverage-honesty discipline the rest of the report follows.

### 3.6 `check-structure.mjs` gate — extend the contract

For each supported stack, assert `references/<stack>.md`:
- contains exactly one ` ```surface ` fence that **parses as JSON** with **non-empty** `sources`,
  `sinks`, and `auth_markers` arrays (sanitizers may be empty);
- **fixture link:** at least one `sinks` token from the block appears in that stack's
  `test-fixtures/<stack>/vulnerable/` tree — so a sink documented in prose but forgotten in the block
  (or a block that drifts from reality) breaks CI. The gate forces block *completeness against a real
  case*; it cannot force prose↔block agreement (that is the human craft of the reference). **Scope of
  this guard (stated honestly):** matching *one* token is a **total-drift smoke test** — it catches "the
  block is empty / wired to the wrong stack / fell out of sync wholesale". It does **not** catch
  per-token typos or a single missing sink (those would need a token-by-token fixture coverage matrix,
  out of scope). It is a tripwire, not a proof of completeness.

## 4. Scoring weights (initial, documented)

Named constants in `allocate-budget.mjs`, chosen so the ordering matches the conservative intent
(precise values tunable; the *ordering* they induce is what's tested, not the absolute magnitudes):
`W_SOURCE=1, W_SINK=2, W_COPRESENT=3, W_UNAUTH=4, W_DENSITY=1, W_LEAD=2`, with `DENSITY_CAP=10` and
`LEAD_CAP=10`. Rationale: structural presence is binary (a sink's *presence* is worth `W_SINK`
regardless of file-count, so size never proxies for danger); co-presence and the unauth fail-safe
dominate so a source+sink+no-auth partition reliably outranks partitions with only one signal or with
auth present; the capped density term (`W_DENSITY*min(sink_hits,10)`) lets a *concentration* of sinks
rank up without unbounded size reward; a SARIF-confirmed lead (`W_LEAD`, capped) matches a sink's weight
(it *is* a dataflow-confirmed sink) and only ever adds. Tests assert the **induced ordering** (the §3.3
guards: small-deadly > large-flat, unauth > authed, mixed-still-fail-safe), not the magnitudes.

## 5. Testing strategy

- `surface-scan.mjs`: the §3.2 cases (count vectors on fixtures; unscannable on unsupported stack;
  confinement; missing/!parseable surface block → loud failure).
- `allocate-budget.mjs`: the §3.3 cases on **synthetic count vectors** (no disk) — zero-regression at
  budget≥#scannable, conservative ordering, deterministic tie-break, unscannable handling, additive
  SARIF term, sanitizers-never-lower.
- **Surface-block validity** is covered by the extended `check-structure.mjs` (JSON-parses, required
  non-empty keys, fixture link) — run in CI.
- **Zero-regression E2E — scoped precisely to avoid a benign CI false-red.** Zero-regression means the
  **analyzed set and the findings** are identical (every fixture is ≤ budget and fully supported → the
  allocator selects all of them, nothing downstream changes). It does **not** mean the report text is
  byte-identical: the **Coverage section wording changes** (the old single "not analyzed" list becomes
  the three classes analyzed / deprioritized / unsupported-stack). Any fixture whose `EXPECTED.md` has a
  Coverage line will diverge on *label*. So the E2E asserts unchanged **findings + chains + analyzed
  set**, and the `EXPECTED.md` files receive a **one-time update of their Coverage labels** to the new
  classes — an *expected, reviewed change*, not a regression. (Stated so the E2E gate blocks for the
  right reason and isn't mislabeled.)
- New tests live under `skills/audit/scripts/test/` (picked up by the existing CI `node --test` step);
  target: keep the suite green and add the new helper tests on top.

## 6. Security considerations

- `surface-scan` reads repo files; every path is confined to `projectDir` (reuse `confine-path` logic)
  — a partition file list cannot be used to read outside the root.
- The `surface` blocks are **trusted** (they ship with the plugin, under `references/`), not
  attacker-controlled — they are curated reference data, same trust level as the rest of the plugin.
- The scanner reads audited-repo file *contents* only to count tokens; it never executes them and never
  writes them anywhere but the count vector (integers + the partition id). No repo content leaves the
  vector.
- The allocation decision is deterministic and carries no secrets; gaps cite `partition_id` + integer
  counts only.

## 7. Backward compatibility & rollout

- A repo with ≤ budget **supported** partitions is byte-for-byte today's behavior (all analyzed; empty
  `deprioritized` list). **Unsupported partitions are not a regression:** they were already skipped
  today (coverage-gap reason `unsupported stack`, SKILL §7) — SP3 reports the same partitions under the
  prominent `unsupported-stack` class, never analyzed before, still not analyzed (see §3.4's grounded
  zero-regression rule). The `deprioritized` class only populates when *supported* partitions exceed the
  budget — the case SP3 exists to handle.
- Ship behind `feat/oswe-sp3-budget-coverage`; merge `--no-ff` after the new helper suites, the extended
  gate, and the zero-regression E2E are green — mirroring prior phases.

## 8. Success criteria

1. `surface` blocks added to all 5 reference pages; `check-structure.mjs` asserts presence + JSON
   validity + non-empty `sources`/`sinks`/`auth_markers` + fixture link; CI green.
2. `surface-scan.mjs` and `allocate-budget.mjs` implemented, zero-dep, unit-tested (scan on fixtures,
   allocate on synthetic vectors); the conservative ordering, deterministic tie-break, and
   unscannable-vs-low-surface distinction are all asserted by tests.
3. SKILL §2.5 dispatches analyzers only for `analyze[]`, max-4 concurrency unchanged; Coverage reports
   the three classes (analyzed / deprioritized-with-counts / unsupported-stack).
4. Zero-regression: existing fixtures (≤ budget) pass unchanged end-to-end.
5. `node --test`, `check-structure.mjs`, validators-in-sync, and `claude plugin validate . --strict`
   all green.

## 9. Out of scope (future / explicitly deferred)

- **Raising the partition budget itself** — SP3 is the allocation layer; the default budget stays 12.
- **Throughput / wall-clock** (max-4 concurrency, streaming, resume) — orthogonal axis; coverage first,
  parallelism later, never the reverse.
- **Cheap-model tiebreak on the grey band** — left as a clean seam behind an **off-by-default flag**
  (it makes coverage selection non-reproducible). Not built here; first **instrument** the deterministic
  baseline (log analyzed partitions that return empty + deprioritized neighbors that would have been
  better) to *measure* mis-ranks before deciding if it's even needed. Measure-first / YAGNI.
- **Lead-grain budgeting** (SP1-style triage of thousands of individual SARIF leads) — the same budget
  mechanism generalizes down to lead grain later; SP3 operates at partition grain.
- **Demoting legitimately auth-gated internal/admin tools** (eval/exec-heavy ops scripts that the
  unauth fail-safe over-ranks) — a known, *accepted* failure mode (the conservative rule fails toward
  over-coverage of low-value, the right direction for a security tool). A future "auth-gated AND no
  internal privilege boundary" proxy could demote them; noted, not built.
- **Per-token block↔fixture coverage matrix** — the floor's last residual unsafe leak. §3.6's
  fixture-link is a *total-drift* tripwire (one token matches), so a contributor who adds a sink to the
  prose **and** the vulnerable fixture but forgets the `surface` block leaves that sink uncounted →
  partitions whose only sink is the forgotten one are silently under-ranked (the unsafe direction),
  while the gate stays green (another block token still matches the fixture). Closing it needs a
  token-by-token block↔fixture coverage check (every documented sink in a fixture must appear in the
  block). Deferred from SP3, but named here so the last floor leak isn't lost.
