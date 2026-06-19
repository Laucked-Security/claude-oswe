# OSWE Plugin — SP5 v1: Throughput & Resume Design

**Status:** approved (review converged — 2 rounds)
**Date:** 2026-06-18
**Depends on:** merged MVP + Phase 2 + HTML report + Hybrid Precision (SP1+SP2) + Budget-Allocated Coverage (SP3) + E2E replay smoke (the `oswe` plugin on `master`).
**Branch (implementation):** `feat/oswe-sp5-throughput-resume` (off `master`).

## 0. Context & thesis

The plugin's pipeline is solid for small repos but fragile for the real product target: large monorepos
where `/oswe:audit` runs for many minutes, the analyzer/verifier dispatches dominate wall-clock, and a
single network glitch or user `Ctrl-C` throws away all in-flight work. SP3 fixed *coverage* selection
(budget allocation); this sub-project fixes *throughput resilience*.

**Three capabilities, in this order:**
1. **Configurable concurrency** — replace the hardcoded `max 4 concurrent` analyzer dispatches with
   `--concurrency N` (1 ≤ N ≤ 16, default 4), parsed deterministically.
2. **Per-run checkpoint** — `.oswe/checkpoints/<run-id>/` persists across kill/crash, purged at clean
   exit. Bounded fenêtre de persistance des secrets (same trust model as `.oswe/tmp/`, extended
   temporally to cover the resume case).
3. **Implicit resume** — running `/oswe:audit <scope>` after a kill picks up where it left off because
   helpers detect their own cached output by digest. Same command, no flag.

**Pivot property** (the user's words): *tuer un run, relancer la même commande, obtenir le même
rapport sans refaire les étapes validées*. This is the contract every design decision below preserves.

**Explicitly not in v1:** streaming partial reports, automatic back-off on rate-limit, cross-run cache,
`--persist-cache` flag, adaptive concurrency, dedicated cleanup command. All deferred — §9.

## 1. Goal

1. `/oswe:audit` accepts `--concurrency N` (and the existing `--sarif`/scope args), parsed by a new
   deterministic helper that fails loud on invalid input. The SKILL never interprets arg strings.
2. A new lifecycle helper resolves `run-id` deterministically *before* any expensive work: 0 compatible
   incomplete checkpoint → fresh `run-id`; 1 → resume; **>1 → fail-closed** with a cleanup instruction
   (no heuristic choice).
3. The 4 idempotable deterministic helpers and the agent (analyzer/verifier) responses are checkpointed
   under `.oswe/checkpoints/<run-id>/`. On any subsequent helper invocation in the same `<run-id>`, an
   input-digest + helper-version match short-circuits to the cached output.
4. Clean exit finalizes: marks the manifest `completed: true`, then removes the checkpoint dir. Kill
   or crash leaves it intact for the next run to discover.
5. **Zero regression** for the small-repo path: a fresh run with no existing checkpoint and `--concurrency`
   omitted (default 4) is byte-equivalent to today's pipeline output (same findings, same chain, same
   report — the new lifecycle steps add ~3 spawnSync calls but no behavioral change).

## 2. Hard constraints (inherited from the project)

- **Zero runtime dependency.** Both new helpers run with **no `node_modules`** (`sha256` via
  `node:crypto`; `JSON.parse`; `fs`/`path`/`url`).
- **No LLM in the lifecycle.** Args parsing, run-id resolution, digest matching, finalize — all
  deterministic Node code. The LLM never "interprets" an arg string or a checkpoint state.
- **Fail-loud.** Invalid args → exit 1, no fallback. Ambiguous resume → exit 1 with cleanup
  instructions, no heuristic. A cache match that's been tampered with (manifest missing, digest
  mismatch within cached file) → exit 1, not silent recompute.
- **The deterministic core is sacred.** No changes to `apply-verdicts.mjs` logic,
  `validate-batch.mjs`, `confine-path.mjs`, `validate-output.mjs`, any schema, the Critical-gating
  rule, or the JSON-out report. SP5 v1 wraps each helper with a cache-check seam but does NOT
  modify their logic — the seam is purely additive (an early-return when the cache key matches).
- **Reproducibility on the resume path.** Same scope + same args + same FS state + same helper
  versions ⇒ same final report. The cache key MUST cover all four dimensions; missing any one is a
  staleness bug (the spec's central failure mode).
- **Hygiene parity with `.oswe/tmp/`.** Checkpoints contain NOT-yet-redacted findings (analyzer
  responses may quote secrets verbatim). Same trust model: workspace must be trusted,
  `.oswe/checkpoints/` is gitignored (`.oswe/` already is), bounded lifetime (= kill→resume window).

## 3. Components

### 3.1 New helper: `parse-audit-args.mjs`

```
node parse-audit-args.mjs --file <input.json> --out <out.json>
```

**Input** (`--file`): `{ "raw_args": "<the raw $ARGUMENTS string from the slash command>" }`.

**Output** (`--out`): `{ ok, error, scope, sarifPath, concurrency }`.

**Parsing contract:**
- `--concurrency N` : integer, **strict** (`/^\d+$/`, then `parseInt`, then range check). `1 ≤ N ≤ 16`.
  Default 4. Invalid → exit 1, no fallback.
- `--sarif <path>` : extracted as-is (path string). NOT confined here — confinement remains
  `confine-path.mjs`/`ingest-sarif.mjs`'s job. Just lexical extraction.
- Anything else = `scope` positional. **Multiple positionals → exit 1** (`"too many positional
  arguments"`).
- `scope` may be absent (= `null` ⇒ project root, today's behavior).
- Exit `0` ok / `1` invalid args / `2` IO|usage.

**Why a dedicated helper (not extending `confine-path`):** confine-path has a narrow contract (one
path → one real confined path). Widening it to multi-arg parsing pollutes its role as a
path-traversal gate, which must stay minimal. New helper, new scope.

**Unit-tested** (≥ 8 cases): default concurrency 4 when omitted; `--concurrency 8` parses ok;
`--concurrency 0` and `--concurrency 17` exit 1; `--concurrency abc` and `--concurrency 4.5` exit 1
(strict integer); `--sarif x.sarif src/api` parses both; two positionals exit 1; empty input parses
to all-null/default.

### 3.2 New helper: `checkpoint-lifecycle.mjs`

```
# Resolve mode (called once per audit, after parse-audit-args + confine-path)
node checkpoint-lifecycle.mjs --file <input.json> --out <out.json>

# Finalize mode (called once at end of clean exit)
node checkpoint-lifecycle.mjs --finalize --run-id <id> --project-dir <abs>
```

**Resolve mode — Input** (`--file`): `{ "projectDir": "<abs>", "scope_realpath": "<abs or null>",
"sarif_realpath": "<abs or null>", "concurrency": <int> }`.
(All paths are post-`confine-path`. Lifecycle runs **after** confinement, with normalized canonical
paths — this matters because two equivalent-but-textually-different scope inputs must match.)

**Resolve mode — Output** (`--out`): `{ ok, error, run_id, mode, checkpoint_dir }` where
`mode ∈ {"new","resume"}`.

**Resolution algorithm (the fail-closed contract):**
1. Compute `invocation_digest = sha256(JSON.stringify({scope_realpath, sarif_realpath,
   concurrency, schema_version: 1}))` — a hash of the **canonical post-confine form**, not the raw
   arg string. Two textually-different but semantically-identical invocations match.
2. Scan `<projectDir>/.oswe/checkpoints/*/manifest.json` (each `<run-id>` dir holds one).
3. A manifest is **compatible** iff: `manifest.invocation_digest === invocation_digest`
   AND `manifest.completed === false` (a `completed: true` manifest is a terminated run, not
   resumable).
4. **0 compatible** → create `<run-id> = sha256(Date.now() + crypto.randomBytes(16)).slice(0,16)`,
   create `<projectDir>/.oswe/checkpoints/<run-id>/`, write initial manifest with the §3.2.1 shape,
   `mode: "new"`.
5. **1 compatible** → reuse that `<run-id>`, `mode: "resume"`.
6. **>1 compatible** → **exit 1** with error: `"ambiguous resume: N compatible incomplete checkpoints
   under .oswe/checkpoints/ ; please `rm -rf .oswe/checkpoints/` and re-run to start fresh, OR keep
   the one you want and remove the others."` Never heuristic-choose.

**Finalize mode — Behavior:**
1. Read `<projectDir>/.oswe/checkpoints/<run-id>/manifest.json`. If missing → exit 0 (idempotent;
   already cleaned up).
2. Write the manifest back with `completed: true` (atomic write: `.tmp-<pid>` then `rename`).
3. Recursively remove `<projectDir>/.oswe/checkpoints/<run-id>/`.
4. **If step 3 fails** (e.g. Windows file-lock on a `.json`): emit warning on stderr `"finalize:
   could not remove <dir>; run `rm -rf .oswe/checkpoints/<run-id>` manually to clean up"`. Still
   **exit 0**. The `completed: true` from step 2 ensures the next resume scan ignores this manifest
   (compatible-check requires `completed: false`), so a failed removal doesn't break the next audit.

**Exit codes (resolve mode):** `0` ok / `1` invalid input | ambiguous resume / `2` IO|usage.
**Exit codes (finalize mode):** `0` always (even on partial-cleanup failure — see above).

#### 3.2.1 Manifest schema (committed at `skills/audit/schemas/checkpoint-manifest.schema.json` — 9th schema)

```jsonc
{
  "schema_version": 1,             // integer, the manifest-format version
  "run_id": "<16-hex>",
  "started_at": "2026-06-18T12:34:56Z",   // ISO-8601 UTC
  "completed": false,              // flipped to true by --finalize
  "scope_realpath": "<abs|null>",  // post-confine
  "sarif_realpath": "<abs|null>",  // post-confine; null when --sarif omitted
  "concurrency": 4,                // 1..16
  "invocation_digest": "<64-hex>"  // sha256 over canonical form (§3.2 step 1)
}
```
`additionalProperties: false`. All fields required. **Validated by `validate-output.mjs` via a new
kind `"checkpoint-manifest"`** so a malformed manifest fails loud (the same gate every other JSON
artifact passes).

**Unit-tested** (≥ 10 cases): no existing checkpoints → new run-id; one compatible → resume same id;
one compatible+one completed → resume the incomplete one (completed ignored); two compatibles → exit
1 with cleanup message; mismatched invocation_digest (different concurrency / scope) → new run-id;
mismatched scope_realpath (different absolute path) → new run-id; finalize flips completed and
removes dir; finalize tolerates missing dir (idempotent); finalize on a dir with locked file emits
warning + exit 0; manifest with `additionalProperties` fails validate-output.

### 3.3 Extension: `surface-scan.mjs` emits `file_content_digest` per vector

**Why an extension to surface-scan (not a new helper):** the file-content digest is purely a function
of *what surface-scan already reads*. Adding a separate helper would re-read every file twice.

**Vector shape gains one field:**
```jsonc
{
  // ... existing fields (sources, sinks, ..., content_key, ...)
  "file_content_digest": "<64-hex>"
}
```
Computed as **sha256 of the byte-concatenation of `(sha256(file_i) || NUL)` for each file `i` in
the partition, in the partition's `content_key` (sorted-paths) order**. So a single byte change in
any file under the partition flips the digest; a file rename without a content change also flips it
(via `content_key`). Compact and order-independent for the same file set, sensitive to both content
and identity.

**Why surface-scan is NOT cached:** it observes FS state, and the FS state is precisely what its
output digest depends on. Caching a helper whose input includes the state it observes creates a
paradox (the cache key would have to read the file to detect change, which is the same I/O as
running). Decision: surface-scan recomputes always, but its output (carrying `file_content_digest`)
becomes the staleness input for every downstream cache. Cheap because it's local grep, no LLM.

**Existing `content_key` field is unchanged** — it stays the tie-breaker for allocate-budget's
deterministic order. The new `file_content_digest` is purely for cache invalidation.

**New tests** (extend the existing surface-scan suite): same partition with different file contents
emits different `file_content_digest`; same partition with same content emits the same digest twice;
order of files in input doesn't affect digest (sorted internally); `scannable: false` partitions
don't carry `file_content_digest` (no files were readable to digest).

### 3.4 Per-helper checkpoint contract (4 idempotable helpers + agent responses)

**The 4 cached helpers:** `allocate-budget`, `aggregate-findings`, `apply-verdicts`, `render-html`.

**Each gains one new optional flag pair:**
```
node <helper>.mjs --file <in> --out <out> [--checkpoint-dir <abs>]
```

**When `--checkpoint-dir` is provided:**
1. Compute `input_digest = sha256(canonical JSON-stringify of input)` (recursive key-sort).
2. Compute `helper_version_digest = sha256(this-helper's own file contents)` — read via
   `readFileSync(fileURLToPath(import.meta.url))`. Detects code changes between kill and resume.
3. Lookup `<checkpoint-dir>/<helper-name>/<input_digest>-<helper_version_digest>.json`.
4. **Cache hit:** parse the cached file, write its `output` field to `--out`, log
   `"<helper>: cache hit"` to stderr, exit 0.
5. **Cache miss:** run the helper as normal. **After successful output**, write `{ input_digest,
   helper_version_digest, output: <the JSON written to --out>, generated_at: "<ISO>" }` to the
   cache path (atomic `.tmp-<pid>` then rename, same pattern as render-html).

**When `--checkpoint-dir` is absent:** behavior is identical to today (zero-regression for the
small-repo path).

**Agent response caching (not a helper — orchestrated by the SKILL):** after each successful
`validate-output analyzer-response <r>` (or `verifier-response`), the SKILL writes the validated
response to `<checkpoint-dir>/agent-responses/<kind>-<target_id>-<input_digest>.json`. Before
dispatching the next analyzer/verifier, the SKILL checks if such a cached response exists for the
target — if yes, skip the dispatch.

**Input digest for agent responses** = sha256 of the canonical form of the **dispatch input** to the
agent: for analyzer, `{partition_id, files: [...], file_content_digest, references_loaded: [...]}`
(the partition assignment + the file_content_digest from §3.3 + which reference pages are loaded).
For verifier, `{batch_id, expected_targets: [...], finding_or_chain_data}`. Crucially the
`file_content_digest` is in the analyzer input digest, so a file edit between kill and resume
invalidates every analyzer cache for affected partitions — the staleness fix from review #2.

**Why digesting the **agent dispatch input**, not the model output:** the cache exists to skip the
*dispatch* (the expensive LLM call), so the key is whatever determines what would be re-asked. The
model output isn't deterministic, so it can't be the key; but if we asked the model the same
question (same input digest), we accept the cached answer.

## 4. SKILL.md integration (5 surgical edits, with the corrected sequence)

The order matters — the user's review caught that lifecycle MUST run after confine-path, because
it depends on canonical post-confine paths.

### Edit 1 — new §0 (very top, before existing §1 Entry & recon)
```markdown
### 0. Parse invocation args (deterministic)
First, normalize `$ARGUMENTS` into a structured form via the tested helper. Do NOT parse arg
strings by hand:
`( trap 'rm -f ".../parse-args-<token>.json" ".../parse-args-out-<token>.json"' EXIT;
  node "${CLAUDE_PLUGIN_ROOT}/skills/audit/scripts/parse-audit-args.mjs"
    --file "<token>.json" --out "<token>-out.json" )`
The input file is `{"raw_args": "${ARGUMENTS}"}`. On exit 0, read `{scope, sarifPath, concurrency}`.
On exit 1, abort the audit with the printed message (invalid args, e.g. concurrency out of range).
```

### Edit 2 — extend §1 Entry & recon (after existing confine-path step)
After scope and sarifPath are confined (existing confine-path calls), add:

```markdown
### 0.5 Resolve run-id and checkpoint dir (deterministic)
Now that paths are confined and canonical, resolve the run lifecycle:
`( trap 'rm -f ".../lifecycle-in-<token>.json" ".../lifecycle-out-<token>.json"' EXIT;
  node "${CLAUDE_PLUGIN_ROOT}/skills/audit/scripts/checkpoint-lifecycle.mjs"
    --file "<token>.json" --out "<token>-out.json" )`
Input: `{projectDir, scope_realpath, sarif_realpath, concurrency}`. On exit 0, read `{run_id, mode,
checkpoint_dir}` into orchestration state. On exit 1 (ambiguous resume), abort with the printed
cleanup instruction. **If `mode: "resume"`, note this in the final report** so the reader knows the
audit picked up from a prior interrupted run.

**SECURITY NOTE for the prose**: `.oswe/checkpoints/<run-id>/` mirrors `.oswe/tmp/`'s trust model —
it holds NOT-yet-redacted intermediates (including agent responses that may quote secrets verbatim).
It is purged at clean exit (§7 Report) and only persists between a kill and the next resume.
```

### Edit 3 — §3 Analyze + §6 Verify: configurable concurrency + agent response cache
- Replace the literal `max 4 concurrent` in §3 with `max <concurrency> concurrent` (where
  `<concurrency>` is the value resolved in §0).
- Before each analyzer dispatch (§3) and each verifier batch dispatch (§6), check
  `<checkpoint_dir>/agent-responses/<kind>-<target_id>-<input_digest>.json`. If present, use it and
  skip the dispatch. After each successful `validate-output` of a freshly-dispatched response, write
  it to that path (atomic).

### Edit 4 — Pass `--checkpoint-dir` to the 4 cacheable helpers
Wherever the SKILL invokes `allocate-budget`, `aggregate-findings`, `apply-verdicts`, or
`render-html`, append `--checkpoint-dir "${checkpoint_dir}"` to the existing `--file`/`--out` args.
Helpers without `--checkpoint-dir` behave exactly as today.

### Edit 5 — §7 Report (very end, after render-html succeeds)
Add as the last orchestration step, on the **clean exit path only**:
```markdown
### 7.5 Finalize the run checkpoint
After the report (`.md` + `.html`) is written successfully, finalize the checkpoint:
`node "${CLAUDE_PLUGIN_ROOT}/skills/audit/scripts/checkpoint-lifecycle.mjs"
  --finalize --run-id "${run_id}" --project-dir "${CLAUDE_PROJECT_DIR}"`
This flips the manifest to `completed: true` and removes the run's checkpoint dir. **On any abort
earlier in the pipeline, DO NOT finalize** — the checkpoint must remain on disk for the next
`/oswe:audit` invocation to discover and resume from.
```

## 5. Testing strategy

- **`parse-audit-args.mjs`** — 8+ unit tests per §3.1.
- **`checkpoint-lifecycle.mjs`** — 10+ unit tests per §3.2.
- **Manifest schema** — covered by validate-output's existing `<kind>` flow + the regenerate-validators
  CI gate (the new schema must regenerate `validators.mjs` in sync).
- **`surface-scan.mjs` extension** — 4 new tests for `file_content_digest` per §3.3.
- **4 cached helpers** — for each, 2 new tests: cache miss writes the artifact + cache hit
  short-circuits with same `--out` content (no recompute). 8 tests total.
- **E2E replay** — extend the existing `e2e-replay.test.mjs` with **one additional assertion path**:
  run the full pipeline with `--checkpoint-dir <tmp>`, kill simulated mid-way by invoking only the
  first 4 helpers, then re-invoke the full pipeline → assert that the 4 cached helpers all log
  "cache hit" on stderr and the final report matches. (This is what proves the pivot property at
  the assembly level, not just per-helper.)
- **Zero-regression E2E** — the existing fixtures with NO `--checkpoint-dir` produce byte-identical
  helper outputs (the existing 190 tests still pass unchanged).

## 6. Security considerations

- **Path traversal:** the new helpers receive paths but they're all post-confine (lifecycle takes
  `scope_realpath` already confined; `--checkpoint-dir` is computed by lifecycle from `projectDir`,
  not user input). `parse-audit-args` does not touch the FS.
- **Cache poisoning:** a tampered cache file (wrong `input_digest` inside) is detected by re-computing
  the key from the input and comparing — a mismatch is treated as cache miss (recompute) rather than
  loud failure, to be resilient against partial-write corruption. **BUT** a manifest with the wrong
  schema (additionalProperties present, missing required field) → validate-output rejects → exit 1.
- **Secret persistence:** explicitly bounded to `kill → resume` window. Workspace must already be
  trusted (existing SKILL doctrine). Gitignored via `.oswe/`. No new posture; just extended duration.
- **Finalize race:** if `/oswe:audit` is killed *during* `checkpoint-lifecycle --finalize` (after
  step 2's `completed: true` write, before step 3's `rm -rf`): the manifest says completed, the dir
  still exists. Next resume scan skips it (compatible requires `completed: false`). Stale dir
  remains on disk forever unless user cleans up. Acceptable — the `--finalize` stderr warning
  documents the cleanup command.
- **`--concurrency 16` cap:** chosen empirically as a safe ceiling — too low loses throughput, too
  high risks API rate-limit auto-DOS on the maintainer's quota. If a real workload needs higher,
  it's a v2 conversation (back-off auto, §9).

## 7. Backward compatibility & rollout

- A run with no existing checkpoint and `--concurrency` omitted (so default = 4) produces the same
  helper outputs as today. The new lifecycle steps (parse-args, lifecycle-resolve, lifecycle-finalize)
  add ~3 short spawnSync calls but don't change behavior — confirmed by the e2e-replay test which
  asserts the report content, not the number of spawnSync calls (it'll still pass).
- The 4 helpers gain `--checkpoint-dir` as an **optional** flag; when omitted, no caching code path
  runs.
- Ship behind `feat/oswe-sp5-throughput-resume`; merge `--no-ff` after the unit tests + the extended
  e2e-replay are green + `claude plugin validate --strict` green, mirroring prior phases.

## 8. Success criteria

1. `parse-audit-args.mjs` exists, fails loud on invalid input, unit-tested, schema-gated by
   `validate-output` via a future kind if desired (optional — its output schema is small and direct).
2. `checkpoint-lifecycle.mjs` exists with resolve + finalize modes, fail-closed on ambiguous resume,
   `--finalize` is idempotent, manifest schema committed as `checkpoint-manifest.schema.json` (9th
   schema), validated by validate-output (`<kind>` `"checkpoint-manifest"`), regenerated
   `validators.mjs` in sync.
3. `surface-scan.mjs` emits `file_content_digest` per vector; existing tests still pass; 4 new tests
   added.
4. 4 cacheable helpers accept `--checkpoint-dir`, write on miss, short-circuit on hit; agent
   response caching wired in SKILL §3 and §6.
5. SKILL.md gains §0 (parse-args), §0.5 (lifecycle resolve), §7.5 (lifecycle finalize); §3 + §6
   plumb concurrency + agent-response cache; the prose is faithful to the helper contracts.
6. e2e-replay extended: a kill-then-resume scenario asserts cache hits on the 4 helpers and a final
   report identical to the no-kill run.
7. All gates green: `node --test` in skills/audit/scripts + benchmark, structure gate, regen-check
   for the new schema, `claude plugin validate . --strict` (now in CI).

## 9. Out of scope (future SP5 v2+)

- **Streaming partial reports** during the run.
- **Automatic back-off** on API rate-limit (today: helper just fails, user re-runs and resume picks
  up; tomorrow: helpful but needs retry+backoff infra).
- **Cross-run cache** / `--persist-cache` flag.
- **Adaptive concurrency** that learns the right N for the host.
- **Resume after >24h** — `helper_version_digest` will invalidate stale caches anyway if any helper
  was edited; no special handling needed.
- **Dedicated `oswe-clean-checkpoints` CLI** — `rm -rf .oswe/checkpoints/` suffices.
- **Multi-run-id manifest browser** — the fail-closed contract makes this unnecessary (the user
  cleans up to disambiguate).
- **Concurrency higher than 16** — gate on real workload need.
