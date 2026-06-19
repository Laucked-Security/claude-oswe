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

- **Zero runtime dependency.** All new helpers (`parse-audit-args`, `checkpoint-lifecycle`,
  `agent-response-cache`) run with **no `node_modules`** (`sha256` via `node:crypto`; `JSON.parse`;
  `fs`/`path`/`url`).
- **No LLM in the lifecycle.** Args parsing, run-id resolution, digest matching, finalize — all
  deterministic Node code. The LLM never "interprets" an arg string or a checkpoint state.
- **Fail-loud differs by artifact type** (resolved per Fix #5 from review):
  - **Manifest corruption** (manifest missing/malformed/`additionalProperties`) → **exit 1** with
    cleanup instruction. The manifest is the directory-level structural artifact; malformation is
    unambiguous broken state and must not be papered over.
  - **Per-helper cache file corruption** (a `.json` cache file with mismatched-internal `input_digest`
    or unparseable JSON) → **silent recompute + overwrite**. A single corrupted cache file should
    not fail the audit; the work is recoverable by just doing it.
  - **Agent response cache file corruption** → **silent miss + re-dispatch**. Same logic as helper
    caches; the dispatch is expensive but recoverable.
  Net effect: bad infrastructure (a broken manifest) fails loud; bad payload (a corrupted single
  cache entry) is silently recovered. §6 Security elaborates with examples.
- **The deterministic core is sacred.** No changes to `apply-verdicts.mjs` verdict logic,
  `validate-batch.mjs`, `confine-path.mjs`, any existing schema
  (analyzer-response, verifier-response, chain, finding, report-summary, sarif-lead,
  verdict-application), the Critical-gating rule, or the JSON-out report. SP5 v1 wraps each
  helper with a cache-check seam but does NOT modify their logic — the seam is purely additive
  (an early-return when the cache key matches).

  **Additive surface (allowed in SP5 v1, Fix #3 from review):** `validate-output.mjs` gains
  exactly one new `--kind`: `checkpoint-manifest`, dispatching to one new schema
  `checkpoint-manifest.schema.json` registered in `build-validators.mjs`'s EXPORT_NAME map.
  This is the same additive pattern every prior schema addition has used (the 7 existing kinds
  were all added the same way). It does not touch any existing kind, schema, or the verdict
  logic. **It also does not affect agent caching** — agent-response-cache (§3.5) re-uses the
  **existing** `analyzer-response` / `verifier-response` kinds for its in-helper re-validation.
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

**Tokenization grammar (minimal shell-like — fixes review #3):** the `raw_args` string is
tokenized BEFORE flag parsing. Whitespace separates tokens; **double quotes group a token** so paths
containing spaces work via `--sarif "my project/x.sarif"` or `"src api"`. No escapes, no single
quotes, no backslash handling — minimal grammar, easy to test, easy to document.
- A token starts at a non-whitespace char (or `"`).
- If the token starts with `"`, it ends at the matching `"`; the surrounding quotes are stripped.
  An unterminated quote → **exit 1** (`"unterminated quoted token: <fragment>"`).
- Otherwise the token ends at the next whitespace.
- Empty `raw_args` (or whitespace-only) → all defaults (scope=null, sarifPath=null, concurrency=4).

**Parsing contract** (applied to the tokenized list):
- `--concurrency N` : integer, **strict** (`/^\d+$/`, then `parseInt`, then range check). `1 ≤ N ≤ 16`.
  Default 4. Invalid → exit 1, no fallback.
- `--sarif <path>` : extracted as-is (path string). NOT confined here — confinement remains
  `confine-path.mjs`/`ingest-sarif.mjs`'s job. Just lexical extraction.
- Anything else = `scope` positional. **Multiple positionals → exit 1** (`"too many positional
  arguments"`).
- `scope` may be absent (= `null` ⇒ project root, today's behavior).
- Exit `0` ok / `1` invalid args (unterminated quote, bad concurrency, multiple positionals,
  unknown flag) / `2` IO|usage.

**Why a dedicated helper (not extending `confine-path`):** confine-path has a narrow contract (one
path → one real confined path). Widening it to multi-arg parsing pollutes its role as a
path-traversal gate, which must stay minimal. New helper, new scope.

**Unit-tested** (≥ 12 cases): default concurrency 4 when omitted; `--concurrency 8` parses ok;
`--concurrency 0` and `--concurrency 17` exit 1; `--concurrency abc` and `--concurrency 4.5` exit 1
(strict integer); `--sarif x.sarif src/api` parses both; two positionals exit 1; empty input parses
to all-null/default. **Plus quoting grammar (Fix #3):** `"path with spaces"` parses as a single
positional; `--sarif "my project/x.sarif"` extracts the quoted path; unterminated `"foo` → exit 1;
double-quote inside an unquoted token (`fo"o`) treated as part of the token (no special meaning
mid-token, matches typical shell-like behavior); single quotes (`'foo'`) are NOT special (parsed as
literal chars of the token).

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

**Cacheable helpers, by CLI shape:**
- **3 JSON-in/JSON-out helpers** (standard `--file`/`--out` contract): `allocate-budget`,
  `aggregate-findings`, `apply-verdicts`.
- **1 multi-input helper** (special contract, §3.4.1): `render-html` (`--md` + `--summary` → `--out`).

**Standard contract** — each of the 3 JSON-in/JSON-out helpers gains one new optional flag:
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

#### 3.4.1 render-html — special caching contract (Fix #2 from review)

render-html's real CLI is `--md <markdown> --summary <summary.json> --out <html>` (two inputs, one
output). The standard `--file`/`--out` flow doesn't fit. Special contract:

1. `input_digest = sha256(md_content || "\x00" || canonicalize(summary_json))` — concatenate the
   raw Markdown bytes, a NUL separator, and the canonical JSON-stringified summary. Any change in
   either invalidates the cache.
2. `helper_version_digest` and lookup path are the same as standard.
3. **Cache hit:** write the cached `html_output` bytes to `--out`, log `"render-html: cache hit"`,
   exit 0.
4. **Cache miss:** render as normal, then write `{ input_digest, helper_version_digest, html_output:
   "<the rendered HTML>", generated_at: "<ISO>" }` to the cache path.

The cache wrapper format is the same as the standard helpers; only the payload type differs (HTML
string vs JSON object) and the input-digest computation is two-stream instead of one.

### 3.5 New helper: `agent-response-cache.mjs`

Why a dedicated helper rather than SKILL prose computing digests: §2 "No LLM in the lifecycle".
Digest matching is deterministic Node code, not LLM interpretation. The SKILL just calls this helper
twice per agent dispatch (lookup before, store after).

**Two modes:**

```
# Before dispatching an analyzer/verifier — check for a cached validated response.
node agent-response-cache.mjs --lookup --file <input.json> --out <out.json>

# After validate-output successfully validated a fresh response — store it.
node agent-response-cache.mjs --store --file <input.json>
```

**Lookup mode — Input:** `{ "checkpoint_dir": "<abs>", "plugin_root": "<abs>",
"kind": "analyzer-response"|"verifier-response", "target_id": "<partition-id-or-batch-id>",
"dispatch_input": { ...the canonical dispatch payload... } }`.

**`plugin_root` is the SKILL-supplied source of truth (Fix #1 from round 5 review).** The SKILL
sets `plugin_root: "${CLAUDE_PLUGIN_ROOT}"` (the env var Claude Code exports for the plugin's own
root) in every helper invocation. The helper then computes `realpath(plugin_root)` once and rejects
any `agent_contract_files` entry whose `realpath()` doesn't have it as a prefix — same fail-closed
posture as `confine-path.mjs`. Why explicit in input rather than `process.env` or
`import.meta.url`: (a) explicit input is testable without env-mocking (the existing helper test
pattern); (b) it matches every other helper in the repo (confine-path takes `projectDir`
explicitly, never reads env); (c) `import.meta.url` would silently rebind if the helper file ever
moved, masking the bug. Same field is required in **store** mode for the same reason.

For analyzer dispatches, `dispatch_input` MUST include `{partition_id, files: [...sorted],
file_content_digest, references_loaded: [...sorted], agent_contract_files: [...sorted abs paths]}`.
The `file_content_digest` from §3.3 covers user-code staleness (kill→edit→resume on the same files
invalidates the cache). The new `agent_contract_files` (Fix #1 from round 4 review) closes the
**plugin-side staleness gap**: `references_loaded` only listed *which* reference files were loaded
(paths), not their contents — so editing `references/php.md` to add a new sink pattern would have
returned a stale analyzer response. The contract files for the analyzer MUST include:

- The analyzer subagent definition file (`agents/oswe-analyzer.md`).
- Every `skills/audit/references/<lang>.md` actually loaded for the partition.
- `skills/audit/SKILL.md` itself (the orchestration prose dictates how the analyzer is invoked
  and what shape of response is expected).

For verifier batches, `dispatch_input` MUST include `{batch_id, expected_targets: [...sorted by
target_type then target_id], finding_or_chain_canonical: {...}, agent_contract_files: [...sorted
abs paths]}`. The canonical form covers per-batch input. The new `agent_contract_files` covers
the verifier-side plugin staleness — same rationale as analyzer:

- The verifier subagent definition file (`agents/oswe-verifier.md`).
- `skills/audit/SKILL.md` (§6 of SKILL.md is the verifier's invocation contract).
- Any reference files the verifier consults at adjudication time (today: none directly, but the
  SKILL author lists them if/when that changes — fail-closed: include if in doubt).

**How the helper uses these:** for both kinds, the helper reads each path in
`agent_contract_files` (sorted), computes `agent_context_digest = sha256(byte-concat of
sha256(file_i) || NUL, in sorted order)`, and includes that digest in `input_digest`'s preimage
alongside the rest of `dispatch_input`. **Editing any plugin-side contract file therefore
invalidates every cache that referenced it — deterministically, with no LLM involvement.** Paths
must be under `CLAUDE_PLUGIN_ROOT` (the helper rejects any path that escapes — same posture as
`confine-path.mjs`'s realpath check); they're plugin-trusted code, never untrusted repo content.

**Lookup mode — Output:** `{ ok, hit: bool, cached_response?: {...} }`. On hit, the SKILL uses
`cached_response` and **skips the dispatch** (re-validation is **not** skipped — see next paragraph).
On miss, the SKILL dispatches the agent as today.

**CRITICAL — `--lookup` re-validates `cached_response` against the kind's schema before reporting a
hit (Fix #1 from review).** A cache JSON file may have the correct `input_digest` and parse fine,
but a tampered or accidentally-corrupted `validated_response` field would otherwise bypass
schema-gating — the discipline that has founded this project since MVP. So inside the helper:
after the input_digest matches, the helper imports `validate(kind, cached_response)` from
`./validate-output.mjs` (which already exports it for in-process reuse — that's how
`aggregate-findings.test.mjs` and `render-html.mjs` use it). If the validation fails: log
`"agent-cache: stored response invalid for kind <kind>, treating as miss"` on stderr, return
`{ ok: true, hit: false }`. The SKILL re-dispatches and the fresh response goes through the normal
validate-output gate before being re-stored. **This means the schema-gate discipline is preserved
end-to-end, including the cache path** — a cached response is never trusted past the same gate a
live response must pass.

**Store mode — Input:** `{ "checkpoint_dir": "<abs>", "plugin_root": "<abs>", "kind": "...",
"target_id": "...", "dispatch_input": {...}, "validated_response": {...} }`. Store mode also
requires `plugin_root` (same confinement check on `agent_contract_files` paths).

Computes `input_digest = sha256(canonical(dispatch_input))`, writes
`<checkpoint_dir>/agent-responses/<kind>-<target_id>-<input_digest>.json` atomically with
`{ input_digest, kind, target_id, validated_response, generated_at: "<ISO>" }`.

**Exit codes:** lookup `0` always (hit or miss is in the output, not the exit) / `2` IO|usage; store
`0` ok / `2` IO|usage. Both are "infrastructure" — they don't fail an audit. (If the cache breaks,
the SKILL just re-dispatches.)

**Why this contract makes sense:** the SKILL builds `dispatch_input` AS IT WOULD HAVE for the
actual dispatch, plus calls the cache helper with that payload. So the LLM does the same work either
way — the only LLM-side change is calling the cache helper twice (lookup, store) per dispatch.
Digest computation, file I/O, and atomic write are all in Node.

**Unit-tested** (≥ 9 cases): store-then-lookup hits; lookup with no prior store misses;
lookup with different `dispatch_input` (e.g. flipped one file) misses; lookup with different `kind`
or `target_id` misses; store is idempotent (rewriting same key with same value is a no-op);
malformed cache file on disk → treated as miss (recompute), see §6;
**`right input_digest, invalid cached_response shape` → miss (Fix #1 from round 3 review)** —
craft a cache file where the wrapper's `input_digest` matches the live input but `cached_response`
violates the kind's schema (e.g. analyzer-response with `findings` removed); assert exit 0,
`hit: false`, and the helper's stderr names the kind. Together with a parallel test using a
tampered finding field, this confirms the cache cannot bypass schema-gating.
**Plus two `agent_contract_files` staleness tests (Fix #1 from round 4 review):**
(a) edit a `references/<lang>.md` file listed in `agent_contract_files` between store and lookup
→ miss (different `agent_context_digest`); (b) edit `SKILL.md` between store and lookup → miss.
Both confirm plugin-side contract changes invalidate the cache automatically.
**Plus one `plugin_root` confinement test (Fix #1 from round 5 review):** an
`agent_contract_files` entry pointing outside `plugin_root` (e.g. `/tmp/evil.md`) → exit 2 with
the rejected path quoted on stderr. This matches the same fail-closed posture as `confine-path.mjs`
and proves the SKILL-supplied `plugin_root` is actually enforced. (Test count: ≥ 10.)

**Agent response caching — a dedicated helper, NOT SKILL prose.** Computing a sha256 inside the SKILL
prose would put digest-matching in the LLM, contradicting §2's "No LLM in the lifecycle." So caching
agent responses is delegated to a new helper §3.5 below. The SKILL just calls it like any other
helper (lookup before dispatch; store after validate-output succeeds).

## 4. SKILL.md integration (5 surgical edits, with the corrected sequence)

The order matters — the user's review caught that lifecycle MUST run after confine-path, because
it depends on canonical post-confine paths.

### Edit 1 — new §0 (very top, before existing §1 Entry & recon)

**Bootstrap-ordering fix (Fix #2 from review).** The current SKILL §1's first action is
`rm -rf .oswe/tmp && mkdir -p .oswe/tmp`. The new §0 below uses temp files itself
(parse-audit-args input/output), so §0 MUST own the bootstrap purge — otherwise it writes into a
non-existent dir. So Edit 1 (a) prepends the temp-purge to §0 and (b) deletes the redundant purge
line from §1 (it's covered by §0 now). The trust model is unchanged — `.oswe/tmp/` is still
purged at audit start, still purged on any abort.

```markdown
### 0. Bootstrap & parse invocation args (deterministic)
First, purge and re-create the temp dir (this used to be the first action of §1; it moved up so
later §0 helpers can use it):
`rm -rf "${CLAUDE_PROJECT_DIR}/.oswe/tmp" && mkdir -p "${CLAUDE_PROJECT_DIR}/.oswe/tmp"`.

Then normalize `$ARGUMENTS` into a structured form via the tested helper. Do NOT parse arg
strings by hand:
`( trap 'rm -f ".../parse-args-<token>.json" ".../parse-args-out-<token>.json"' EXIT;
  node "${CLAUDE_PLUGIN_ROOT}/skills/audit/scripts/parse-audit-args.mjs"
    --file "<token>.json" --out "<token>-out.json" )`
The input file is `{"raw_args": "${ARGUMENTS}"}`. On exit 0, read `{scope, sarifPath, concurrency}`.
On exit 1, abort the audit with the printed message (invalid args, e.g. concurrency out of range).
On any abort here or later, `.oswe/tmp/` is purged as today.
```

(In §1 Entry & recon, the existing `**First, purge temp:**` bullet is removed since §0 now owns it.)

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

### Edit 3 — §3 Analyze + §6 Verify: configurable concurrency + agent response cache (via §3.5 helper)
- Replace the literal `max 4 concurrent` in §3 with `max <concurrency> concurrent` (where
  `<concurrency>` is the value resolved in §0).
- Before each analyzer dispatch (§3) and each verifier batch dispatch (§6), call
  `agent-response-cache.mjs --lookup` (§3.5) with the dispatch input. The input JSON MUST include
  `"plugin_root": "${CLAUDE_PLUGIN_ROOT}"` alongside `checkpoint_dir`, `kind`, `target_id`, and
  `dispatch_input` (see §3.5 round-5 Fix #1 — the helper rejects `agent_contract_files` that escape
  `plugin_root`). On `hit: true`, USE the `cached_response` and skip the dispatch (re-validation
  was already done **inside the helper** against the kind's schema — see §3.5 Fix #1). On miss
  (including the helper's own "stored response failed re-validation" miss), dispatch as today.
- After each successful `validate-output` of a freshly-dispatched analyzer-response or
  verifier-response, call `agent-response-cache.mjs --store` with the same dispatch input and the
  validated response. This populates the cache for any subsequent resume.

### Edit 4 — Pass `--checkpoint-dir` to the 4 cacheable helpers
Wherever the SKILL invokes `allocate-budget`, `aggregate-findings`, `apply-verdicts`, or
`render-html`, append `--checkpoint-dir "${checkpoint_dir}"` to the existing invocation. The
existing positional/named args are unchanged (Fix #2 from round 4 review — earlier wording
incorrectly said "`--file`/`--out` args" for all four, but **render-html uses
`--md --summary --out`**, not `--file --out`, per §3.4.1). Helpers without `--checkpoint-dir`
behave exactly as today.

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

- **`parse-audit-args.mjs`** — 12+ unit tests per §3.1 (including the quoting grammar tests).
- **`checkpoint-lifecycle.mjs`** — 10+ unit tests per §3.2.
- **Manifest schema** — covered by validate-output's existing `<kind>` flow + the regenerate-validators
  CI gate (the new schema must regenerate `validators.mjs` in sync).
- **`surface-scan.mjs` extension** — 4 new tests for `file_content_digest` per §3.3.
- **3 JSON-in/JSON-out cached helpers** + **render-html special contract** — for each, 2 new tests:
  cache miss writes the artifact + cache hit short-circuits with same `--out` content (no recompute).
  8 tests total (2 × 4 helpers).
- **`agent-response-cache.mjs`** — 10+ unit tests per §3.5 (store-then-lookup hit, lookup with no
  store misses, different dispatch_input misses, different kind/target_id misses, idempotent store,
  corrupted cache file → miss).
- **E2E replay** — extend the existing `e2e-replay.test.mjs` (or a new sibling
  `e2e-replay-resume.test.mjs`) with a **second-run scenario**. The original test runs the full
  pipeline once. The new scenario does TWO complete pipeline runs with the SAME `--checkpoint-dir`,
  **without** calling `checkpoint-lifecycle --finalize` between them (simulates "the first run
  reached every helper, then was killed before finalize"). Assertions on the second run:
  - All 4 cached helpers (`allocate-budget`, `aggregate-findings`, `apply-verdicts`, `render-html`)
    log `"cache hit"` on stderr (or equivalent cache-hit marker).
  - The final report (MD + HTML) matches the first run's output byte-for-byte.
  - `agent-response-cache --lookup` returns `hit: true` for the analyzer + verifier dispatch points.

  This is what proves the pivot property at the assembly level. **Earlier draft incorrectly proposed
  asserting render-html cache-hit after a "first 4 helpers" partial run — but render-html is
  pipeline step 14, not in the first 4, so the cache wouldn't have been populated. Fix #4 from
  review.** A real mid-way kill scenario (partial cache population, partial cache hits on resume)
  is more realistic but more fragile to write; deferred to a v2 hardening pass.

  Cleanup: the test calls `checkpoint-lifecycle --finalize` at the end of the second run.
- **Zero-regression E2E** — the existing fixtures with NO `--checkpoint-dir` produce byte-identical
  helper outputs (the existing 190 tests still pass unchanged).

## 6. Security considerations

- **Path traversal:** the new helpers receive paths but they're all post-confine (lifecycle takes
  `scope_realpath` already confined; `--checkpoint-dir` is computed by lifecycle from `projectDir`,
  not user input). `parse-audit-args` does not touch the FS.
- **Cache poisoning — two distinct behaviors by artifact type (consistent with §2 Fix #5):**
  - *Per-helper cache file* (`.json` under `<helper-name>/`) or *agent response cache file* (under
    `agent-responses/`) tampered/corrupted: detected by **any** of three independent gates —
    (a) `JSON.parse` failing on the cache wrapper,
    (b) re-computing `input_digest` from the live input and comparing to the cached file's
    internal `input_digest` (mismatch),
    (c) **for agent-response caches only:** `validate(kind, cached_response)` failing (the
    payload's shape no longer satisfies the kind's JSON schema — Fix #3 from round 4 review;
    matches the in-helper check from §3.5 Fix #1). Any gate firing → **silent miss + recompute
    + overwrite**. The audit proceeds; the corrupted file is replaced with a fresh valid one.
    Resilient against partial-write corruption (atomic `.tmp-<pid>` then rename mitigates this
    in practice but the silent-miss is the belt + suspenders).
  - *Manifest* (`<run-id>/manifest.json`) tampered (missing required field, `additionalProperties`,
    unparseable JSON): **exit 1** via `validate-output`'s `checkpoint-manifest` kind. The manifest
    is the directory-level structural artifact; if it's broken, the run lifecycle is broken — no
    silent recovery. The error message includes the cleanup instruction
    (`rm -rf .oswe/checkpoints/<run-id>/`).
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
4. 3 JSON-in/JSON-out cacheable helpers (`allocate-budget`, `aggregate-findings`, `apply-verdicts`)
   accept `--checkpoint-dir`, write on miss, short-circuit on hit. `render-html` follows the special
   §3.4.1 contract (input_digest from `md_content || NUL || canonical(summary)`, cached HTML
   bytes). `agent-response-cache.mjs` (new helper §3.5) provides `--lookup`/`--store` for
   analyzer/verifier responses; SKILL §3 + §6 invoke it (lookup before dispatch, store after
   validate-output).
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
