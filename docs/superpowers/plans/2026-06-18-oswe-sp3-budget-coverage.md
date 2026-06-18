# OSWE SP3 — Budget-Allocated Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic prioritization/budget layer upstream of `analyze` so a large repo's audit spends its 12-partition analyzer budget on the highest-attack-surface partitions and reports the rest as ranked, justified, auditable coverage gaps — instead of an opaque "not analyzed" wall at #12.

**Architecture:** Two new zero-dependency Node helpers grafted between recon and analyze. `surface-scan.mjs` reads each partition's files + its stack's `surface` token block (a JSON fence curated in the existing reference pages) and emits a deterministic count vector (pure function of the FS). `allocate-budget.mjs` scores those vectors (presence-binary + capped sink-density + per-file source∧auth co-location fail-safe), sorts on a content-hash total order, and splits at the budget into `analyze[]` + classified `gaps[]` (pure function of counts). The deterministic decision core (verdicts, gating, schemas) is untouched; SP3 only changes which partitions get dispatched.

**Tech Stack:** Node ≥ 20, ESM, `node --test`, zero runtime dependencies (`node:crypto` is built-in). Spec: `docs/superpowers/specs/2026-06-18-oswe-sp3-budget-coverage-design.md`.

---

## File Structure

**New files:**
- `skills/audit/scripts/allocate-budget.mjs` — pure scorer/allocator (count vectors + budget → analyze + gaps).
- `skills/audit/scripts/test/allocate-budget.test.mjs` — its tests (synthetic vectors, no disk).
- `skills/audit/scripts/surface-scan.mjs` — FS scanner (partition files + surface block → count vector).
- `skills/audit/scripts/test/surface-scan.test.mjs` — its tests (temp-dir fixtures).

**Modified files:**
- `skills/audit/references/{php,node,python,java,dotnet}.md` — each gains one ` ```surface ` JSON block.
- `.github/scripts/check-structure.mjs` — new section asserting each reference's surface block (JSON, non-empty `sources`/`sinks`/`auth_markers`) + fixture-link.
- `skills/audit/SKILL.md` — new §2.5 (prioritize & allocate) + §7 Coverage three-class reporting + no-SARIF caveat.

**Conventions (from the existing helpers — match them):**
- ESM, `export function …` then a `if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) { … }` CLI block. Exit `0` ok / `1` invalid input / `2` IO|usage.
- Tests: `node:test` + `node:assert/strict`; temp dirs via `mkdtempSync(join(tmpdir(), …))`; write **real files** when a path must pass `confinePath` (it calls `realpathSync`).
- `confinePath(projectDir, arg)` is exported from `./confine-path.mjs`; it returns the real confined path or throws (ENOENT / escape).
- New helpers live in `skills/audit/scripts/` so the existing CI `node --test` step picks up their tests. No schema changes, no `validators.mjs` regeneration (SP3 touches no schema).

---

## Task 1: `allocate-budget.mjs` — pure scorer/allocator (TDD)

Build the pure core first: it depends on nothing (count vectors in → allocation out), so it is the most isolated and testable unit.

**Files:**
- Create: `skills/audit/scripts/allocate-budget.mjs`
- Test: `skills/audit/scripts/test/allocate-budget.test.mjs`

- [ ] **Step 1: Write the failing test**

Create `skills/audit/scripts/test/allocate-budget.test.mjs`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import { allocate, scoreVector } from "../allocate-budget.mjs";

// A scannable count vector. content_key stands in for surface-scan's sha256 (any stable string works).
const vec = (id, over = {}) => ({
  partition_id: id, stack: "python", scannable: true, files: 1,
  sources: 0, sinks: 0, sanitizers: 0, auth_markers: 0, source_and_auth_files: 0,
  source_hits: 0, sink_hits: 0, auth_hits: 0, content_key: id, ...over
});

test("budget >= scannable count -> everything analyzed, no deprioritized gaps (zero-regression)", () => {
  const r = allocate([vec("a", { sources: 1, sinks: 1 }), vec("b", { sinks: 1 })], 12);
  assert.equal(r.ok, true);
  assert.equal(r.analyze.length, 2);
  assert.equal(r.gaps.filter((g) => g.gap_class === "deprioritized").length, 0);
});

test("source+sink+no-auth outranks an auth-gated source+sink", () => {
  const open = vec("open", { sources: 1, sinks: 1, source_and_auth_files: 0 });
  const gated = vec("gated", { sources: 1, sinks: 1, auth_markers: 1, source_and_auth_files: 1 });
  assert.ok(scoreVector(open) > scoreVector(gated)); // W_UNAUTH only on the open one
});

test("small-and-deadly is NEVER ranked below large-and-flat (>=, not strict >)", () => {
  const deadly = vec("deadly", { sources: 1, sinks: 1, source_and_auth_files: 0, sink_hits: 30 });
  const flat = vec("flat", { sources: 30, sinks: 1, source_and_auth_files: 0, sink_hits: 1 });
  assert.ok(scoreVector(deadly) >= scoreVector(flat)); // capped density may tie, never invert
});

test("mixed partition: auth markers only in NON-source files still fires the unauth fail-safe", () => {
  // sources=10, auth_markers=11 (global ratio would suppress), but source_and_auth_files=0 (no source file gated)
  const mixed = vec("mixed", { sources: 10, sinks: 1, auth_markers: 11, source_and_auth_files: 0 });
  const baseline = vec("base", { sources: 10, sinks: 1, auth_markers: 0, source_and_auth_files: 0 });
  assert.equal(scoreVector(mixed), scoreVector(baseline)); // co-location, not global count, decides
});

test("a fully-gated partition (every source file has auth) does NOT get the unauth bonus", () => {
  const gated = vec("g", { sources: 3, sinks: 1, auth_markers: 3, source_and_auth_files: 3 });
  const open = vec("o", { sources: 3, sinks: 1, auth_markers: 0, source_and_auth_files: 0 });
  assert.ok(scoreVector(open) > scoreVector(gated));
});

test("ties break deterministically on content_key (ascending), independent of input order", () => {
  const x = vec("x", { sources: 1, sinks: 1, content_key: "bbb" });
  const y = vec("y", { sources: 1, sinks: 1, content_key: "aaa" });
  const r1 = allocate([x, y], 1).analyze.map((a) => a.partition_id);
  const r2 = allocate([y, x], 1).analyze.map((a) => a.partition_id);
  assert.deepEqual(r1, r2);          // same selection regardless of input order
  assert.deepEqual(r1, ["y"]);        // content_key "aaa" < "bbb" wins the single slot
});

test("unscannable vectors never enter analyze and surface as unsupported-stack gaps", () => {
  const r = allocate([{ partition_id: "u", stack: "perl", scannable: false, files: 3 }, vec("a", { sinks: 1 })], 12);
  assert.deepEqual(r.analyze.map((a) => a.partition_id), ["a"]);
  const g = r.gaps.find((x) => x.partition_id === "u");
  assert.equal(g.gap_class, "unsupported-stack");
});

test("SARIF term is zero when absent and lifts a partition when present (capped)", () => {
  const v = vec("s", { sources: 1, sinks: 1, source_and_auth_files: 1, auth_markers: 1 }); // gated, no unauth bonus
  const base = scoreVector(v);
  const lifted = scoreVector(v, { count: 3 });
  assert.ok(lifted > base);
  const capped = scoreVector(v, { count: 9999 });
  assert.equal(capped, scoreVector(v, { count: 10 })); // LEAD_CAP=10
});

test("sanitizers never lower a score", () => {
  const without = vec("a", { sources: 1, sinks: 1 });
  const withSan = vec("b", { sources: 1, sinks: 1, sanitizers: 5 });
  assert.equal(scoreVector(withSan), scoreVector(without));
});

test("deprioritized gaps carry score + counts; over-budget partitions land there", () => {
  const vs = [vec("hi", { sources: 1, sinks: 1, source_and_auth_files: 0 }), vec("lo", { sinks: 0, sources: 0 })];
  const r = allocate(vs, 1);
  assert.equal(r.analyze.length, 1);
  const dep = r.gaps.find((g) => g.gap_class === "deprioritized");
  assert.equal(typeof dep.score, "number");
  assert.ok(dep.counts && typeof dep.counts.sinks === "number");
});

test("invalid budget and non-array vectors are rejected (ok:false)", () => {
  assert.equal(allocate([], 0).ok, false);
  assert.equal(allocate("nope", 12).ok, false);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/audit/scripts && node --test test/allocate-budget.test.mjs`
Expected: FAIL — module `allocate-budget.mjs` not found.

- [ ] **Step 3: Write the implementation**

Create `skills/audit/scripts/allocate-budget.mjs`:

```js
// SP3 budget allocator. PURE function of count vectors — no FS, no LLM, no network.
// Scores each scannable partition and splits at the budget into analyze[] + classified gaps[].
// CLI: node allocate-budget.mjs --file <input.json> --out <allocation.json>
//   input: { "budget": 12, "vectors": [ <count vector> ], "sarifLeadsByPartition"?: { "<pid>": { "count": <n> } } }
//   exit 0 ok / 1 invalid input / 2 IO|usage.
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";

// Documented weights (§4). Tests assert the INDUCED ORDERING, not these magnitudes — they are tunable.
const W_SOURCE = 1, W_SINK = 2, W_COPRESENT = 3, W_UNAUTH = 4, W_DENSITY = 1, W_LEAD = 2;
const DENSITY_CAP = 10, LEAD_CAP = 10;

// Score a scannable vector. Presence-binary structure + capped sink-density + per-file co-location
// unauth fail-safe + additive (zero-when-absent) SARIF term. Size never proxies for danger.
export function scoreVector(v, sarif) {
  const hasSource = (v.sources || 0) > 0;
  const hasSink = (v.sinks || 0) > 0;
  let score = (hasSource ? W_SOURCE : 0) + (hasSink ? W_SINK : 0);
  if (hasSource && hasSink) score += W_COPRESENT;
  // unauth fail-safe: at least one source-bearing file has NO auth marker of its own (co-location,
  // not the global auth_markers<sources ratio — auth in non-source files must not suppress this).
  if (hasSource && hasSink && (v.source_and_auth_files || 0) < (v.sources || 0)) score += W_UNAUTH;
  score += W_DENSITY * Math.min(v.sink_hits || 0, DENSITY_CAP);              // capped: concentration, not size
  const leads = sarif ? (sarif.count || 0) : 0;                              // additive backstop, 0 when absent
  score += W_LEAD * Math.min(leads, LEAD_CAP);
  // sanitizers deliberately do NOT subtract (a sanitizer's presence does not prove safety).
  return score;
}

const cmpStr = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const countsOf = (v) => ({
  sources: v.sources || 0, sinks: v.sinks || 0, sanitizers: v.sanitizers || 0,
  auth_markers: v.auth_markers || 0, source_and_auth_files: v.source_and_auth_files || 0,
  sink_hits: v.sink_hits || 0
});

export function allocate(vectors, budget, sarifLeadsByPartition = {}) {
  if (!Array.isArray(vectors)) return { ok: false, error: "vectors must be an array", analyze: [], gaps: [] };
  if (!Number.isInteger(budget) || budget < 1) return { ok: false, error: "budget must be a positive integer", analyze: [], gaps: [] };

  const scannable = vectors.filter((v) => v.scannable !== false);
  const unscannable = vectors.filter((v) => v.scannable === false);

  const scored = scannable.map((v) => ({ v, score: scoreVector(v, sarifLeadsByPartition[v.partition_id]) }));
  // Total deterministic order: score DESC, then content_key ASC (pure-content tie-break — never input order).
  scored.sort((a, b) => (b.score - a.score) || cmpStr(a.v.content_key, b.v.content_key));

  const analyze = [], gaps = [];
  scored.forEach((s, i) => {
    if (i < budget) analyze.push({ partition_id: s.v.partition_id, score: s.score });
    else gaps.push({
      partition_id: s.v.partition_id, gap_class: "deprioritized", score: s.score,
      counts: countsOf(s.v),
      reason: "deprioritized: analyzer budget exhausted; lower predicted attack surface"
    });
  });
  // Unscannable partitions do NOT compete for budget (no reference -> the analyzer can't help) and are
  // reported as a DISTINCT prominent class: surface UNKNOWN, never folded into "low surface".
  for (const v of unscannable) {
    gaps.push({ partition_id: v.partition_id, gap_class: "unsupported-stack", stack: v.stack || "unknown",
      reason: `unsupported stack "${v.stack || "unknown"}" — surface not assessed; not covered by this audit` });
  }
  return { ok: true, error: null, analyze, gaps };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const fi = args.indexOf("--file"), oi = args.indexOf("--out");
  if (fi === -1 || !args[fi + 1] || oi === -1 || !args[oi + 1]) {
    process.stderr.write("usage: allocate-budget.mjs --file <input.json> --out <allocation.json>\n"); process.exit(2);
  }
  let input;
  try { input = JSON.parse(readFileSync(args[fi + 1], "utf8")); }
  catch (e) { process.stderr.write("cannot read --file: " + e.message + "\n"); process.exit(2); }
  const r = allocate(input.vectors, input.budget, input.sarifLeadsByPartition || {});
  try { writeFileSync(args[oi + 1], JSON.stringify(r, null, 2)); }
  catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
  process.exit(r.ok ? 0 : 1);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/audit/scripts && node --test test/allocate-budget.test.mjs`
Expected: all PASS (11 tests).

- [ ] **Step 5: Full suite green**

Run: `cd skills/audit/scripts && node --test`
Expected: all PASS (existing + 11 new).

- [ ] **Step 6: Commit**

```bash
git add skills/audit/scripts/allocate-budget.mjs skills/audit/scripts/test/allocate-budget.test.mjs
git commit -m "feat(sp3): allocate-budget.mjs — pure scorer/allocator (presence-binary + co-location fail-safe)"
```

---

## Task 2: `surface-scan.mjs` — FS scanner (TDD)

**Files:**
- Create: `skills/audit/scripts/surface-scan.mjs`
- Test: `skills/audit/scripts/test/surface-scan.test.mjs`

Depends on `confine-path.mjs` (exists). Reads a partition's files + a stack's `surface` block.

- [ ] **Step 1: Write the failing test**

Create `skills/audit/scripts/test/surface-scan.test.mjs`. The scanner confines paths with `realpathSync`, so the test writes **real files** into a temp project dir and a temp references dir.

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseSurfaceBlock, scanPartition, contentKey } from "../surface-scan.mjs";

const BLOCK = {
  sources: ["request.args", "request.get_json"],
  sinks: ["render_template_string", "eval(", "os.system"],
  sanitizers: ["shlex.quote"],
  auth_markers: ["@login_required", "login_required("]
};

function project(filesByName) {
  const root = mkdtempSync(join(tmpdir(), "oswe-surface-"));
  for (const [rel, body] of Object.entries(filesByName)) {
    const abs = join(root, rel);
    mkdirSync(join(abs, ".."), { recursive: true });
    writeFileSync(abs, body);
  }
  return root;
}

test("parseSurfaceBlock extracts the JSON from a ```surface fence; null when absent", () => {
  const md = "# ref\nprose\n```surface\n{ \"sources\": [\"x\"], \"sinks\": [], \"sanitizers\": [], \"auth_markers\": [] }\n```\nmore prose";
  assert.deepEqual(parseSurfaceBlock(md).sources, ["x"]);
  assert.equal(parseSurfaceBlock("no block here"), null);
});

test("a source+sink file with no auth marker -> counts set, source_and_auth_files 0", () => {
  const root = project({ "app.py": "x = request.args\nrender_template_string(x)\n" });
  const v = scanPartition({ partition_id: "p", stack: "python", files: ["app.py"] }, BLOCK, root);
  assert.equal(v.scannable, true);
  assert.equal(v.sources, 1);
  assert.equal(v.sinks, 1);
  assert.equal(v.auth_markers, 0);
  assert.equal(v.source_and_auth_files, 0);
  assert.ok(typeof v.content_key === "string" && v.content_key.length === 64); // sha256 hex
});

test("source∧auth co-location: a file with BOTH source and auth marker increments source_and_auth_files", () => {
  const root = project({ "v.py": "@login_required\ndef f(): return request.args\nrender_template_string(1)\n" });
  const v = scanPartition({ partition_id: "p", stack: "python", files: ["v.py"] }, BLOCK, root);
  assert.equal(v.sources, 1);
  assert.equal(v.auth_markers, 1);
  assert.equal(v.source_and_auth_files, 1); // the source file is itself gated
});

test("auth markers in a NON-source file do not raise source_and_auth_files", () => {
  const root = project({
    "open.py": "x = request.args\nos.system(x)\n",        // source+sink, ungated
    "mw.py": "@login_required\ndef guard(): pass\n"        // auth marker, but no source
  });
  const v = scanPartition({ partition_id: "p", stack: "python", files: ["open.py", "mw.py"] }, BLOCK, root);
  assert.equal(v.sources, 1);
  assert.equal(v.auth_markers, 1);
  assert.equal(v.source_and_auth_files, 0); // the source file (open.py) is NOT gated
});

test("sink_hits is a TRUE total (not per-file capped) so density survives", () => {
  const root = project({ "dense.py": "eval(1); eval(2); eval(3); eval(4); eval(5)\n" });
  const v = scanPartition({ partition_id: "p", stack: "python", files: ["dense.py"] }, BLOCK, root);
  assert.equal(v.sinks, 1);        // file-count (presence)
  assert.equal(v.sink_hits, 5);    // true total occurrences
});

test("auth matching is strict (word-boundary): a longer identifier does not match", () => {
  const root = project({ "x.py": "login_required_NOT_a_decorator = 1\n" });
  const v = scanPartition({ partition_id: "p", stack: "python", files: ["x.py"] }, BLOCK, root);
  assert.equal(v.auth_markers, 0); // "login_required(" needs the "(", bare token not matched mid-identifier
});

test("an unreadable/escaping file is skipped, not fatal (cannot raise risk by skipping)", () => {
  const root = project({ "real.py": "render_template_string(request.args)\n" });
  const v = scanPartition({ partition_id: "p", stack: "python", files: ["real.py", "../escapes.py", "missing.py"] }, BLOCK, root);
  assert.equal(v.scannable, true);
  assert.equal(v.sinks, 1); // real.py counted; the escaping/missing files silently skipped
});

test("no surface block (unsupported stack) -> scannable:false, no counts", () => {
  const root = project({ "a.pl": "system($x)\n" });
  const v = scanPartition({ partition_id: "p", stack: "perl", files: ["a.pl"] }, null, root);
  assert.equal(v.scannable, false);
  assert.equal(v.sources, undefined);
});

test("contentKey is order-independent and stable", () => {
  assert.equal(contentKey(["b.py", "a.py"]), contentKey(["a.py", "b.py"]));
  assert.equal(contentKey(["a.py"]).length, 64);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/audit/scripts && node --test test/surface-scan.test.mjs`
Expected: FAIL — module `surface-scan.mjs` not found.

- [ ] **Step 3: Write the implementation**

Create `skills/audit/scripts/surface-scan.mjs`:

```js
// SP3 surface scanner. Reads a partition's files + its stack's `surface` token block and emits a
// deterministic count vector. PURE function of the filesystem; no LLM, no network.
// CLI: node surface-scan.mjs --file <input.json> --out <vectors.json>
//   input: { "projectDir": "<abs>", "referencesDir": "<abs>", "partitions": [ { "partition_id", "stack", "files": [...] } ] }
//   exit 0 ok / 1 malformed input / 2 IO|usage.
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { confinePath } from "./confine-path.mjs";

// Extract the ```surface JSON block from a reference markdown string. Returns the parsed object,
// or null if no block. Throws (loud) on a present-but-malformed block — JSON.parse fail-fast.
export function parseSurfaceBlock(md) {
  const m = /```surface\s*\n([\s\S]*?)\n```/.exec(md);
  if (!m) return null;
  return JSON.parse(m[1]);
}

export function loadSurfaceBlock(stack, referencesDir) {
  let md;
  try { md = readFileSync(join(referencesDir, `${stack}.md`), "utf8"); }
  catch { return null; } // no reference page -> unsupported stack
  return parseSurfaceBlock(md);
}

// content hash of a partition's file list: pure-content, order-independent, bounded (64 hex chars).
export function contentKey(files) {
  return createHash("sha256").update([...files].sort().join("\n")).digest("hex");
}

// loose substring (sources/sinks/sanitizers): over-match only over-ranks -> safe.
const hasSub = (text, token) => text.includes(token);
const countSub = (text, token) => {
  if (!token) return 0;
  let n = 0, i = 0;
  while ((i = text.indexOf(token, i)) !== -1) { n++; i += token.length; }
  return n;
};
// strict (auth_markers): the token must not be the prefix of a longer identifier. If the token ends in
// a word char, require the following char to be non-word (or end of file). Avoids the `\b@...` pitfall
// (a leading `@` breaks \b), and prevents a loose auth match from falsely suppressing the fail-safe.
const hasAuth = (text, token) => {
  let i = 0;
  const lastIsWord = /\w/.test(token[token.length - 1]);
  while ((i = text.indexOf(token, i)) !== -1) {
    const after = text[i + token.length];
    if (!lastIsWord || after === undefined || !/\w/.test(after)) return true;
    i += token.length;
  }
  return false;
};

export function scanPartition(partition, block, projectDir) {
  if (!block) {
    return { partition_id: partition.partition_id, stack: partition.stack, scannable: false, files: partition.files.length };
  }
  const S = block.sources || [], K = block.sinks || [], N = block.sanitizers || [], A = block.auth_markers || [];
  let sources = 0, sinks = 0, sanitizers = 0, auth_markers = 0, source_and_auth_files = 0;
  let source_hits = 0, sink_hits = 0, auth_hits = 0;
  for (const rel of partition.files) {
    let text;
    try { text = readFileSync(confinePath(projectDir, rel), "utf8"); }
    catch { continue; } // unreadable / escaping / missing: skip (skipping a file we can't read cannot raise risk)
    const fSource = S.some((t) => hasSub(text, t));   // .some short-circuits -> presence is bounded
    const fSink = K.some((t) => hasSub(text, t));
    const fSan = N.some((t) => hasSub(text, t));
    const fAuth = A.some((t) => hasAuth(text, t));
    if (fSource) sources++;
    if (fSink) sinks++;
    if (fSan) sanitizers++;
    if (fAuth) auth_markers++;
    if (fSource && fAuth) source_and_auth_files++;
    if (fSource) source_hits += S.reduce((a, t) => a + countSub(text, t), 0);
    if (fSink) sink_hits += K.reduce((a, t) => a + countSub(text, t), 0); // TRUE total, never per-file capped
    if (fAuth) auth_hits += A.reduce((a, t) => a + countSub(text, t), 0);
  }
  return {
    partition_id: partition.partition_id, stack: partition.stack, scannable: true,
    files: partition.files.length, sources, sinks, sanitizers, auth_markers,
    source_and_auth_files, source_hits, sink_hits, auth_hits,
    content_key: contentKey(partition.files)
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const fi = args.indexOf("--file"), oi = args.indexOf("--out");
  if (fi === -1 || !args[fi + 1] || oi === -1 || !args[oi + 1]) {
    process.stderr.write("usage: surface-scan.mjs --file <input.json> --out <vectors.json>\n"); process.exit(2);
  }
  let input;
  try { input = JSON.parse(readFileSync(args[fi + 1], "utf8")); }
  catch (e) { process.stderr.write("cannot read --file: " + e.message + "\n"); process.exit(2); }
  if (typeof input.projectDir !== "string" || typeof input.referencesDir !== "string" || !Array.isArray(input.partitions)) {
    process.stderr.write("bad input: projectDir, referencesDir (strings) and partitions[] required\n"); process.exit(1);
  }
  const blocks = new Map();
  const vectors = [];
  try {
    for (const p of input.partitions) {
      if (!blocks.has(p.stack)) blocks.set(p.stack, loadSurfaceBlock(p.stack, input.referencesDir));
      vectors.push(scanPartition(p, blocks.get(p.stack), input.projectDir));
    }
  } catch (e) { process.stderr.write("scan failed (malformed surface block?): " + e.message + "\n"); process.exit(1); }
  try { writeFileSync(args[oi + 1], JSON.stringify({ ok: true, vectors }, null, 2)); }
  catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
  process.exit(0);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/audit/scripts && node --test test/surface-scan.test.mjs`
Expected: all PASS (9 tests).

- [ ] **Step 5: Full suite green**

Run: `cd skills/audit/scripts && node --test`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add skills/audit/scripts/surface-scan.mjs skills/audit/scripts/test/surface-scan.test.mjs
git commit -m "feat(sp3): surface-scan.mjs — files + surface block -> deterministic count vector"
```

---

## Task 3: `surface` blocks in all 5 references + extend the structure gate

**Files:**
- Modify: `skills/audit/references/{python,php,node,java,dotnet}.md` (append one ` ```surface ` block each)
- Modify: `.github/scripts/check-structure.mjs` (new section 7)

The token lists below are derived from each reference's existing `## Sources` / `## Dangerous sinks` / `## Auth boundaries` prose. **Auth discipline is strict (enforcement only):** a forgeable input that the reference lists as an *anti-pattern* (e.g. Java's `X-User-Role` header, .NET's `admin` cookie) is a **source**, never an `auth_marker`.

- [ ] **Step 1: Append the `surface` block to `skills/audit/references/python.md`**

Append (the leading blank line keeps it separated from the prose):

````markdown

```surface
{
  "sources": ["request.args", "request.form", "request.values", "request.json", "request.get_json", "request.data", "request.cookies", "request.headers", "request.files", "request.GET", "request.POST", "request.body", "request.COOKIES", "request.META", "request.FILES"],
  "sinks": ["render_template_string", "Template(", "pickle.loads", "pickle.load", "yaml.load", "marshal.loads", "os.system", "subprocess.call", "subprocess.run", "subprocess.Popen", "os.popen", "eval(", "exec(", "cursor.execute", ".raw(", ".extra(", "RawSQL", "send_file", "send_from_directory", "lxml.etree"],
  "sanitizers": ["shlex.quote", "yaml.safe_load", "markupsafe.escape", "os.path.basename"],
  "auth_markers": ["@login_required", "@permission_required", "login_required(", "PermissionRequiredMixin"]
}
```
````

- [ ] **Step 2: Append the `surface` block to `skills/audit/references/php.md`**

````markdown

```surface
{
  "sources": ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER", "php://input", "getallheaders(", "$request->input(", "$request->all(", "$request->query(", "$request->request->get(", "$request->query->get(", "$request->headers->get("],
  "sinks": ["mysqli_query", "->query(", "DB::raw", "DB::select", "whereRaw", "system(", "exec(", "shell_exec", "passthru", "proc_open", "popen(", "eval(", "unserialize(", "include(", "require(", "include_once", "require_once", "move_uploaded_file", "file_put_contents", "preg_replace"],
  "sanitizers": ["htmlspecialchars", "escapeshellarg", "escapeshellcmd", "prepare(", "bindParam", "intval("],
  "auth_markers": ["Auth::check", "Auth::user", "->middleware('auth", "Gate::allows", "Gate::authorize", "$this->authorize(", "#[IsGranted"]
}
```
````

- [ ] **Step 3: Append the `surface` block to `skills/audit/references/node.md`**

````markdown

```surface
{
  "sources": ["req.query", "req.body", "req.params", "req.headers", "req.cookies", "req.files", "@Query(", "@Body(", "@Param(", "@Headers(", "@Req("],
  "sinks": ["child_process.exec", "execSync", ".spawn(", "execFile", "eval(", "new Function", "vm.runInNewContext", "$where", "$ne", "$gt", "$regex", "child_process", "require(", ".query(", "sequelize.query", "res.sendFile"],
  "sanitizers": ["mongo-sanitize", "escape(", "parameterized", "?"],
  "auth_markers": ["passport.authenticate", "@UseGuards", "ensureAuthenticated", "req.isAuthenticated(", "requireAuth", "@Roles("]
}
```
````

- [ ] **Step 4: Append the `surface` block to `skills/audit/references/java.md`**

Note: `request.getHeader("X-User-Role")`, `X-Forwarded-User`, `alg:none` are **forgeable inputs / anti-patterns** in the prose — they are **sources**, not auth markers.

````markdown

```surface
{
  "sources": ["@RequestParam", "@RequestBody", "@PathVariable", "@RequestHeader", "@CookieValue", "@ModelAttribute", "getParameter", "getHeader", "getCookies", "getInputStream", "getQueryString", "getReader", "X-User-Role", "X-Forwarded-User"],
  "sinks": ["ObjectInputStream", ".readObject(", "XMLDecoder", "XStream", "@JsonTypeInfo", "Yaml.load", "parseExpression(", ".getValue(", "MVEL.eval", "Runtime.getRuntime().exec", "ProcessBuilder", "Statement.execute", "createNativeQuery", "nativeQuery", "createQuery", "DocumentBuilder", "SAXParser"],
  "sanitizers": ["PreparedStatement", "setString(", "ESAPI", "OWASP", "getCanonicalPath"],
  "auth_markers": ["@PreAuthorize", "@Secured", "@RolesAllowed", "SecurityFilterChain", "@EnableWebSecurity"]
}
```
````

- [ ] **Step 5: Append the `surface` block to `skills/audit/references/dotnet.md`**

Note: `Request.Cookies["admin"]` is a **forgeable source** (anti-pattern in the prose), not an auth marker.

````markdown

```surface
{
  "sources": ["Request.Query", "Request.Form", "Request.Body", "Request.Cookies", "Request.Headers", "Request.RouteValues", "Request.QueryString", "Request.Params", "[FromBody]", "[FromQuery]", "[FromForm]", "[FromRoute]"],
  "sinks": ["BinaryFormatter", "NetDataContractSerializer", "LosFormatter", "ObjectStateFormatter", "TypeNameHandling", "JavaScriptSerializer", "Process.Start", "ProcessStartInfo", "UseShellExecute", "SqlCommand", "ExecuteReader", "ExecuteNonQuery", "FromSqlRaw", "ExecuteSqlRaw", "XmlDocument", "XmlReader", "Path.Combine"],
  "sanitizers": ["SqlParameter", "Parameters.Add", "HttpUtility.HtmlEncode", "AntiXss"],
  "auth_markers": ["[Authorize]", "User.IsInRole", "RequireAuthorization", "[Authorize("]
}
```
````

- [ ] **Step 6: Extend `check-structure.mjs` with section 7 (surface-block validity + fixture link)**

Read `.github/scripts/check-structure.mjs`. It has numbered sections; section 6 (`sarif-rule-map.json validity`) is the last, followed by the final `console.log("")` / FAIL-or-PASS block. The file already has `STACKS = ["php", "node", "python", "java", "dotnet"]`, the `read(p)` helper (reads a repo-relative file), `walk(dir)`, and `ok`/`bad`. INSERT this new section AFTER section 6 and BEFORE the final `console.log("")`:

```js
console.log("7) surface blocks (SP3): present, valid JSON, non-empty sources/sinks/auth_markers, fixture-linked");
for (const s of STACKS) {
  const refPath = `skills/audit/references/${s}.md`;
  let md;
  try { md = read(refPath); } catch { bad(`${refPath}: unreadable`); continue; }
  const m = /```surface\s*\n([\s\S]*?)\n```/.exec(md);
  if (!m) { bad(`${refPath}: missing \`\`\`surface block`); continue; }
  let block;
  try { block = JSON.parse(m[1]); } catch (e) { bad(`${refPath}: surface block is not valid JSON: ${e.message}`); continue; }
  for (const key of ["sources", "sinks", "auth_markers"]) {
    Array.isArray(block[key]) && block[key].length > 0
      ? ok(`${s}.md surface.${key} (${block[key].length})`)
      : bad(`${refPath}: surface.${key} must be a non-empty array`);
  }
  // fixture link (total-drift tripwire): at least one sinks token appears in the vulnerable fixture tree.
  const fixDir = join(ROOT, `test-fixtures/${s}/vulnerable`);
  if (!existsSync(fixDir)) { bad(`${refPath}: no vulnerable fixture to link against`); continue; }
  const fixText = walk(fixDir).filter((p) => !/EXPECTED\.md$/.test(p)).map((p) => { try { return readFileSync(p, "utf8"); } catch { return ""; } }).join("\n");
  (block.sinks || []).some((t) => fixText.includes(t))
    ? ok(`${s}.md surface.sinks linked to a vulnerable fixture`)
    : bad(`${refPath}: no surface.sinks token appears in test-fixtures/${s}/vulnerable (block drifted from reality?)`);
}
```

Note: `existsSync` and `readFileSync` must be imported at the top of `check-structure.mjs`. Check the existing imports (`import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";`) — they are already there from the original gate. `join` and `ROOT` are also already defined. If any is missing, add it.

- [ ] **Step 7: Run the gate**

Run: `node .github/scripts/check-structure.mjs`
Expected: prints section 7 with `ok` lines for all 5 stacks (3 keys + fixture-link each); final `PASS: structure & consistency checks green.`

If a stack's fixture-link fails, a `surface.sinks` token doesn't appear in that stack's `test-fixtures/<stack>/vulnerable/` — fix the block so at least one sink token matches the real vulnerable fixture (it documents a sink the fixture actually exercises).

- [ ] **Step 8: Commit**

```bash
git add skills/audit/references/*.md .github/scripts/check-structure.mjs
git commit -m "feat(sp3): surface token blocks in all 5 references + structure-gate validation"
```

---

## Task 4: SKILL.md integration — §2.5 allocate + §7 Coverage classes

**Files:**
- Modify: `skills/audit/SKILL.md`

Declarative orchestration prose; the gate is content-conformance to the helper contracts, not code tests.

- [ ] **Step 1: Insert §2.5 between `### 2. Partition & prioritize` and `### 3. Analyze`**

Read `skills/audit/SKILL.md`. After the `### 2. Partition & prioritize` section (which ends with the SARIF lead-assignment bullet) and before `### 3. Analyze`, insert:

```markdown
### 2.5 Prioritize & allocate the analyzer budget (deterministic)
The analyzer pass is the expensive step, capped at a **budget of 12 partitions**. Do **not** raise the
cap; **allocate** it deterministically so the budget lands on the highest-attack-surface partitions and
the rest become ranked, justified gaps (never an opaque wall).

- Build the **file→partition map** from §2 (factual: `{ partition_id, stack, files: [repo-rel paths] }`
  per partition) and write `{ "projectDir": "<CLAUDE_PROJECT_DIR>", "referencesDir":
  "<CLAUDE_PLUGIN_ROOT>/skills/audit/references", "partitions": [...] }` to a literal temp file. Run,
  under the usual `trap`:
  `node "${CLAUDE_PLUGIN_ROOT}/skills/audit/scripts/surface-scan.mjs" --file <in> --out <vectors>` →
  per-partition deterministic count vectors (exit 1 = malformed input/surface block → fix; 2 = IO).
- Then allocate. Write `{ "budget": 12, "vectors": [...from surface-scan...], "sarifLeadsByPartition":
  { "<pid>": { "count": <n> } } }` (the `sarifLeadsByPartition` map only when SARIF leads were ingested
  — §1; omit otherwise so the SARIF term is zero) to a temp file and run
  `node "${CLAUDE_PLUGIN_ROOT}/skills/audit/scripts/allocate-budget.mjs" --file <in> --out <alloc>` →
  `{ analyze: [ { partition_id, score } ], gaps: [ { partition_id, gap_class, ... } ] }`.
- §3 dispatches `oswe-analyzer` subagents **only for the partitions in `analyze[]`**, still **max 4
  concurrent** (the budget is the *coverage* limit; max-4 is the orthogonal *throughput* limit — both
  apply). Everything in `gaps[]` is recorded for Coverage (§7) — never analyzed, never silently dropped.
- **Leads on a deprioritized partition** (hybrid mode) are reported as `lead not analyzed
  (deprioritized)` — the precision ledger still accounts for every lead.
- **Zero-regression:** when the number of supported partitions ≤ budget, `analyze[]` contains all of
  them and the run is behaviorally identical to today (empty `deprioritized` list).
```

- [ ] **Step 2: Extend `### 7. Report` Coverage with the three classes**

In `### 7. Report`, in the Coverage description, insert:

```markdown
- **Coverage is now reported in three classes from the §2.5 allocation, not one opaque "not analyzed"
  list:**
  - **Analyzed** — the partitions in `analyze[]` (top-N by attack-surface score).
  - **Deprioritized (surface assessed low)** — each `gaps[]` entry with `gap_class:"deprioritized"`,
    ranked by `score`, **with its proxy counts** (e.g. *"`admin-tools`: score 3 — 1 source, 1 sink, 3
    auth-markers, all source files gated → low predicted unauth surface"*) so the deferral is auditable
    and a reader can decide whether to re-run with a larger budget.
  - **Unsupported stack (surface NOT assessed)** — each `gap_class:"unsupported-stack"` entry, a
    **distinct, prominent** line: the surface is *unknown*, not *low*. Never present it as a low score.
- **Coverage-honesty caveat (no-SARIF runs):** state that without a SARIF input the token scan's one
  blind spot is the false-negative by indirection (a sink reached via a wrapper/alias is invisible to
  substring matching), so a **low `deprioritized` score is not proof of a thin surface** — a SARIF
  input backstops this; a no-SARIF run does not.
```

- [ ] **Step 3: Verify the insertions**

Run: `node -e "const f=require('fs').readFileSync('skills/audit/SKILL.md','utf8'); for (const s of ['2.5 Prioritize & allocate','surface-scan.mjs','allocate-budget.mjs','Deprioritized (surface assessed low)','Unsupported stack (surface NOT assessed)']) if(!f.includes(s)) throw new Error('missing: '+s); console.log('SKILL.md has all SP3 insertions')"`
Expected: prints the confirmation.

- [ ] **Step 4: Plugin validation (local gate)**

Run: `claude plugin validate . --strict` if available; else `node .github/scripts/check-structure.mjs` (expect PASS). Do not fail the task solely because `claude` is absent.

- [ ] **Step 5: Commit**

```bash
git add skills/audit/SKILL.md
git commit -m "feat(sp3): SKILL §2.5 budget allocation + §7 three-class Coverage reporting"
```

---

## Task 5: Zero-regression verification + final sweep

**Files:** none created; verification + any one-time `EXPECTED.md` reconciliation.

- [ ] **Step 1: Full unit sweep**

Run:
```bash
( cd skills/audit/scripts && node --test ) && node .github/scripts/check-structure.mjs && ( cd benchmark && node --test )
```
Expected: scripts suite green (existing + the 20 new SP3 tests), structure gate `PASS` (incl. section 7), benchmark suite green. Report the `pass N / fail N` lines.

- [ ] **Step 2: Confirm no `EXPECTED.md` Coverage divergence on the existing fixtures**

The 6 stack fixtures are each single-stack, supported, and ≤ budget (1–2 partitions), so §2.5 selects all of them: `analyze[]` = every partition, `deprioritized` empty, no `unsupported-stack`. Their findings/chains are unchanged. Verify each `test-fixtures/<stack>/vulnerable/EXPECTED.md` Coverage line still matches what the audit would emit (expected: **no change**, because there are no gaps to reclassify).

Run (sanity — list the EXPECTED.md Coverage lines to eyeball):
```bash
grep -rA2 -i "coverage" test-fixtures/*/vulnerable/EXPECTED.md
```
Expected: each shows the partitions analyzed with no gaps. **If** any EXPECTED.md asserts a gap that would now be reclassified, update its Coverage wording to the new class (a one-time, reviewed label change — not a regression; see spec §5). For the current single-stack fixtures, no change is expected.

- [ ] **Step 3: Regen-in-sync check (mirror CI's regen-check job)**

SP3 touches no schema, so `validators.mjs` must be unchanged.
Run: `cd skills/audit/scripts && git diff --quiet -- validators.mjs && echo "validators.mjs untouched (correct — SP3 touches no schema)" || echo "UNEXPECTED validators.mjs change"`
Expected: `validators.mjs untouched`.

- [ ] **Step 4: Update the test-count badge + Development section in README**

In `README.md`, bump the test count (the SP3 helpers add 20 tests: 11 allocate + 9 surface-scan). Update the badge `![Tests: N passing]` and the `**N unit tests** (… pipeline + … benchmark)` line and the `# … pipeline tests` comment to the new pipeline total (run `( cd skills/audit/scripts && node --test )` and read the `pass N` line for the exact number).

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs(readme): refresh test count for SP3 surface-scan + allocate-budget helpers"
```

---

## Self-Review notes (spec coverage)

- Spec §3.1 surface blocks (JSON, strict auth, fixture-derived tokens) → Task 3 (all 5 stacks, forgeable
  inputs excluded from auth_markers). §3.2 surface-scan (file/total counts, source_and_auth_files
  co-location, word-boundary auth, true uncapped sink_hits, confinement, unscannable) → Task 2. §3.3
  allocate (presence-binary + capped density, co-location fail-safe, content-hash total-order tie-break,
  unscannable distinct class) → Task 1. §3.4 SKILL §2.5 → Task 4 step 1. §3.5 three-class Coverage +
  no-SARIF caveat → Task 4 step 2. §3.6 gate (JSON validity + non-empty keys + fixture-link tripwire) →
  Task 3 step 6. §4 weights → Task 1 (named constants). §5 testing + zero-regression scope → Tasks 1,2,5.
  §6 security (confinement, no content leaves the vector) → Task 2 (confinePath + integer-only vector).
  §7 zero-regression grounded → Task 5 step 2. §8 success criteria → Task 5 sweep. §9 out-of-scope →
  nothing built (cheap-model seam, lead-grain, demote-internal, per-token matrix all deferred).
- Type/name consistency: `scanPartition`/`parseSurfaceBlock`/`loadSurfaceBlock`/`contentKey` (surface-scan),
  `allocate`/`scoreVector` (allocate-budget); the count-vector shape (`sources`/`sinks`/`sanitizers`/
  `auth_markers`/`source_and_auth_files`/`source_hits`/`sink_hits`/`auth_hits`/`content_key`/`scannable`)
  is identical between the two helpers and the tests; `gap_class ∈ {deprioritized, unsupported-stack}`.
- The auth-asymmetry safety (the one unsafe direction) is enforced in three places that must agree:
  strict token lists (Task 3), word-boundary matching (Task 2 `hasAuth`), and the co-location fail-safe
  (Task 1 `scoreVector`). All three are present and consistent.
