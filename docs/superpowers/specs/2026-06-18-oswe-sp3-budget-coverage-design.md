# OSWE Plugin — SP3: Budget-Allocated Coverage Design

**Status:** approved-design (pending written-spec review)
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
6. **Zero regression:** a repo with **≤ budget** scannable partitions behaves exactly as today (all
   analyzed). The layer only changes behavior when scannable partitions exceed the budget.

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
  "auth_markers":["@login_required", "@permission_required", "session[", "request.user", "flask_login"]
}
```
````

- **Declarative only.** Each value is a list of literal substrings (matched case-sensitively as plain
  `String.includes`). No regex language, no logic, no weights in the block. The block answers "which
  tokens count for this stack"; the helper (§3.3) answers "how they score". This preserves the SP3
  boundary: **semantic data (human-curated) separated from deterministic decision (tested Node).**
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
  logic), read it, and count **presence-weighted occurrences** of each category's tokens
  (`String.includes` per token per file; count = number of files containing ≥1 token of that
  category, plus a total-hits tally). Emits a count vector:
  `{ partition_id, stack, scannable: true, files: <n>, sources, sinks, sanitizers, auth_markers, source_hits, sink_hits }`.
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
- **Score (deterministic, documented; pure integer arithmetic):** for a scannable vector,
  - `base = W_SOURCE*sources + W_SINK*sinks + W_LEAD*sarif_count` (weights are named constants in the
    file; documented; no ML).
  - **co-presence bonus:** if `sources>0 && sinks>0` add `W_COPRESENT` (a partition with both is a live
    attack surface, worth more than the sum).
  - **auth fail-safe (ambiguity → rank up):** if `sources>0 && sinks>0 && auth_markers===0` add
    `W_UNAUTH` (the cheap proxy for unauthenticated surface; conservative — we'd rather over-analyze a
    partition that turns out authed than under-analyze an open one).
  - **sanitizers do NOT subtract.** A sanitizer's presence does not prove safety (the analyzer decides);
    subtracting would push toward under-analysis (unsafe). Sanitizers are carried in the justification
    only.
  - **SARIF as additive backstop, never constitutive.** `W_LEAD*sarif_count` is the additive term and
    it is **zero when no SARIF is supplied**, so the no-SARIF run is the reproducible contract; adding
    SARIF is a *declared input change* (same input → same output still holds). Its purpose: grep's only
    unsafe error class is the **false-negative by indirection** (a sink behind a wrapper/alias, invisible
    to `includes`). Semgrep's dataflow catches some of those, so the SARIF term lifts exactly the
    partitions the token scan would under-rank. It patches the one unsafe hole; it does not replace the
    floor.
- **Total deterministic ordering (protects the pivot property):** sort scannable vectors by
  **`(score DESC, partition_id ASC)`** — an explicit total order. Never rely on `Array.sort` stability
  or recon's emission order (LLM-orchestrated → emission order not guaranteed stable run-to-run; the
  *file→partition content* is factual but the *order* is not). Ties break on `partition_id` so the
  selection at the `budget`/`budget+1` frontier is reproducible.
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
  (zero-regression); a source+sink+no-auth vector outranks an auth-gated one; ties break by
  `partition_id` (reproducible frontier); an unscannable vector never lands in `analyze` and always
  surfaces as `unsupported-stack`; the SARIF term is zero when the map is absent and lifts a partition
  when present; sanitizers never lower a score.

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
- **Zero-regression rule (explicit):** if `analyze[]` contains every scannable partition (i.e. scannable
  count ≤ budget), the run is behaviorally identical to today.

### 3.5 §7 Report — Coverage section gains ranked, classified gaps

Coverage now distinguishes three things instead of one opaque "not analyzed" list:
- **Analyzed** (top-N), as today.
- **Deprioritized (surface assessed low)** — ranked by score, each line carrying its proxy counts:
  e.g. *"`payments-admin`: score 2 — 0 sources, 1 sink, 4 auth-markers → predicted low unauth surface."*
  Auditable: a reader can see *why* it was deferred and judge whether to re-run with a larger budget.
- **Unsupported stack (surface NOT assessed)** — a distinct, prominent class. This is the dangerous
  "unseen surface" direction and must never read like a low score. e.g. *"`legacy-perl/`: unsupported
  stack — surface not assessed; not covered by this audit."*

### 3.6 `check-structure.mjs` gate — extend the contract

For each supported stack, assert `references/<stack>.md`:
- contains exactly one ` ```surface ` fence that **parses as JSON** with **non-empty** `sources`,
  `sinks`, and `auth_markers` arrays (sanitizers may be empty);
- **fixture link:** at least one `sinks` token from the block appears in that stack's
  `test-fixtures/<stack>/vulnerable/` tree — so a sink documented in prose but forgotten in the block
  (or a block that drifts from reality) breaks CI. The gate forces block *completeness against a real
  case*; it cannot force prose↔block agreement (that is the human craft of the reference).

## 4. Scoring weights (initial, documented)

Named constants in `allocate-budget.mjs`, chosen so the ordering matches the conservative intent
(precise values tunable; the *ordering* they induce is what's tested, not the absolute scores):
`W_SOURCE=1, W_SINK=2, W_LEAD=2, W_COPRESENT=3, W_UNAUTH=4`. Rationale: a sink is worth more than a
source; a SARIF-confirmed lead matches a sink's weight (it *is* a dataflow-confirmed sink); co-presence
and the unauth fail-safe dominate so a source+sink+no-auth partition reliably outranks partitions with
only one signal or with auth present. Tests assert the **induced ordering**, not the magnitudes.

## 5. Testing strategy

- `surface-scan.mjs`: the §3.2 cases (count vectors on fixtures; unscannable on unsupported stack;
  confinement; missing/!parseable surface block → loud failure).
- `allocate-budget.mjs`: the §3.3 cases on **synthetic count vectors** (no disk) — zero-regression at
  budget≥#scannable, conservative ordering, deterministic tie-break, unscannable handling, additive
  SARIF term, sanitizers-never-lower.
- **Surface-block validity** is covered by the extended `check-structure.mjs` (JSON-parses, required
  non-empty keys, fixture link) — run in CI.
- **Zero-regression E2E:** the existing stack fixtures (≤ budget partitions each) must produce the same
  audit result as today — the allocation step selects all of them, changing nothing downstream. The 6
  fixtures + their `EXPECTED.md` pass unchanged.
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

- A repo with ≤ budget scannable partitions is byte-for-byte today's behavior (all analyzed; empty
  `deprioritized` list). The new Coverage classes only populate when partitions exceed the budget or an
  unsupported stack is present.
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
