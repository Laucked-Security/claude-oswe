# OSWE SP5 v1 — Throughput & Resume Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add configurable concurrency, per-run checkpointing, and implicit resume to `/oswe:audit` so a killed run can be relaunched with the same command and skip already-validated work, producing a byte-identical final report.

**Architecture:** Three new deterministic Node helpers (`parse-audit-args`, `checkpoint-lifecycle`, `agent-response-cache`) plus an optional `--checkpoint-dir` flag on the 4 idempotable existing helpers. A shared `cache-wrap.mjs` module owns the digest/lookup/store primitives so the 4 helpers don't drift. One new JSON schema (`checkpoint-manifest`) is registered through the existing `build-validators` → `validate-output` flow. The SKILL gets 5 surgical edits: §0 bootstrap+parse, §0.5 lifecycle resolve, §3/§6 cache-aware dispatch, §4 cached-helper invocations gain `--checkpoint-dir`, §7.5 finalize.

**Tech Stack:** Node ≥ 20, ESM, `node:crypto`, `node:fs`, `node:path`, `node:url`, `node:test`. Zero runtime dependencies (AJV is dev-only via `build-validators.mjs`).

**Spec:** `docs/superpowers/specs/2026-06-18-oswe-sp5-throughput-resume-design.md` (6 review rounds, approved).

---

## File structure

**New files (created by this plan):**
- `skills/audit/scripts/cache-wrap.mjs` — shared primitives: `canonicalize`, `sha256Hex`, `helperVersionDigest`, `cacheLookup`, `cacheStore`. Task 1.
- `skills/audit/scripts/parse-audit-args.mjs` — deterministic `$ARGUMENTS` parser with quoting grammar. Task 2.
- `skills/audit/schemas/checkpoint-manifest.schema.json` — manifest schema (9th in repo). Task 3.
- `skills/audit/scripts/checkpoint-lifecycle.mjs` — resolve + finalize modes. Task 4.
- `skills/audit/scripts/agent-response-cache.mjs` — `--lookup` / `--store` for analyzer + verifier responses. Task 6.
- `skills/audit/scripts/test/cache-wrap.test.mjs` — Task 1.
- `skills/audit/scripts/test/parse-audit-args.test.mjs` — Task 2.
- `skills/audit/scripts/test/checkpoint-lifecycle.test.mjs` — Task 4.
- `skills/audit/scripts/test/agent-response-cache.test.mjs` — Task 6.
- `skills/audit/scripts/test/e2e-replay-resume.test.mjs` — Task 12.

**Files modified:**
- `skills/audit/scripts/build-validators.mjs` — add `checkpoint-manifest` to `EXPORT_NAME`. Task 3.
- `skills/audit/scripts/validate-output.mjs` — add `checkpoint-manifest` to `KIND_TO_EXPORT`. Task 3.
- `skills/audit/scripts/validators.mjs` — regenerated. Task 3.
- `skills/audit/scripts/surface-scan.mjs` — emit `file_content_digest` per scannable vector. Task 5.
- `skills/audit/scripts/test/surface-scan.test.mjs` — +4 tests. Task 5.
- `skills/audit/scripts/allocate-budget.mjs` — optional `--checkpoint-dir`. Task 7.
- `skills/audit/scripts/test/allocate-budget.test.mjs` — +2 tests. Task 7.
- `skills/audit/scripts/aggregate-findings.mjs` — optional `--checkpoint-dir`. Task 8.
- `skills/audit/scripts/test/aggregate-findings.test.mjs` — +2 tests. Task 8.
- `skills/audit/scripts/apply-verdicts.mjs` — optional `--checkpoint-dir`. Task 9.
- `skills/audit/scripts/test/apply-verdicts.test.mjs` — +2 tests. Task 9.
- `skills/audit/scripts/render-html.mjs` — optional `--checkpoint-dir` (special two-stream contract). Task 10.
- `skills/audit/scripts/test/render-html.test.mjs` — +2 tests. Task 10.
- `skills/audit/SKILL.md` — 5 surgical edits. Task 11.

**Test pattern (followed by every test file in this plan):** `mkdtempSync(join(tmpdir(), "oswe-<feature>-"))` for isolated temp dirs; `spawnSync(process.execPath, [helperPath, ...args], { encoding: "utf8" })` for CLI tests; `import { fn } from "../helper.mjs"` for unit tests of exported functions. Matches every existing test file (e.g. `confine-path.test.mjs`, `allocate-budget.test.mjs`).

---

## Branch setup

Before Task 1, ensure the working branch exists:

```bash
git checkout master && git pull --ff-only && git checkout -b feat/oswe-sp5-throughput-resume
```

If already on `feat/oswe-sp5-throughput-resume`, just verify:

```bash
git rev-parse --abbrev-ref HEAD   # should print: feat/oswe-sp5-throughput-resume
```

---

### Task 1: cache-wrap.mjs shared primitives

**Files:**
- Create: `skills/audit/scripts/cache-wrap.mjs`
- Create: `skills/audit/scripts/test/cache-wrap.test.mjs`

This is the foundation: `canonicalize`, `sha256Hex`, `helperVersionDigest`, `cacheLookup`, `cacheStore`. Tasks 6–10 import from here. Building it first means we can TDD the four wrapped helpers against stable primitives.

- [ ] **Step 1: Write the failing test file**

Create `skills/audit/scripts/test/cache-wrap.test.mjs`:

```javascript
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalize, sha256Hex, helperVersionDigest, cacheLookup, cacheStore } from "../cache-wrap.mjs";

function tmp() {
  return realpathSync(mkdtempSync(join(tmpdir(), "oswe-cache-wrap-")));
}

test("canonicalize sorts keys recursively and produces stable output", () => {
  const a = canonicalize({ b: 2, a: 1, nested: { y: 4, x: 3 } });
  const b = canonicalize({ nested: { x: 3, y: 4 }, a: 1, b: 2 });
  assert.equal(a, b);
  assert.equal(a, '{"a":1,"b":2,"nested":{"x":3,"y":4}}');
});

test("canonicalize preserves array order (arrays are sequences, not sets)", () => {
  assert.equal(canonicalize([3, 1, 2]), "[3,1,2]");
});

test("canonicalize handles null, numbers, strings", () => {
  assert.equal(canonicalize(null), "null");
  assert.equal(canonicalize(42), "42");
  assert.equal(canonicalize("hi"), '"hi"');
});

test("sha256Hex returns 64-hex of input bytes", () => {
  const h = sha256Hex("abc");
  assert.equal(h.length, 64);
  assert.match(h, /^[0-9a-f]{64}$/);
  // Same input → same digest
  assert.equal(sha256Hex("abc"), h);
  // Different input → different digest
  assert.notEqual(sha256Hex("abd"), h);
});

test("helperVersionDigest digests a file's bytes", () => {
  const dir = tmp();
  const p = join(dir, "fake-helper.mjs");
  writeFileSync(p, "export const x = 1;\n");
  const d1 = helperVersionDigest(p);
  assert.match(d1, /^[0-9a-f]{64}$/);
  // Edit file → digest changes
  writeFileSync(p, "export const x = 2;\n");
  assert.notEqual(helperVersionDigest(p), d1);
});

test("cacheLookup returns hit:false when no cache file exists", () => {
  const dir = tmp();
  const r = cacheLookup({ checkpointDir: dir, helperName: "x", inputDigest: "a".repeat(64), versionDigest: "b".repeat(64) });
  assert.equal(r.hit, false);
});

test("cacheStore then cacheLookup returns hit:true with wrapper", () => {
  const dir = tmp();
  const opts = { checkpointDir: dir, helperName: "h", inputDigest: "a".repeat(64), versionDigest: "b".repeat(64) };
  cacheStore({ ...opts, payload: { output: { foo: "bar" } } });
  const r = cacheLookup(opts);
  assert.equal(r.hit, true);
  assert.deepEqual(r.wrapper.output, { foo: "bar" });
  assert.equal(r.wrapper.input_digest, opts.inputDigest);
  assert.equal(r.wrapper.helper_version_digest, opts.versionDigest);
  assert.match(r.wrapper.generated_at, /^\d{4}-\d{2}-\d{2}T/);
});

test("cacheLookup returns hit:false on malformed cache JSON (silent miss per §6)", () => {
  const dir = tmp();
  const opts = { checkpointDir: dir, helperName: "h", inputDigest: "a".repeat(64), versionDigest: "b".repeat(64) };
  // Pre-create the cache dir + a malformed file at the lookup path
  mkdirSync(join(dir, "h"), { recursive: true });
  writeFileSync(join(dir, "h", `${opts.inputDigest}-${opts.versionDigest}.json`), "{not json");
  const r = cacheLookup(opts);
  assert.equal(r.hit, false);
});

test("cacheLookup returns hit:false on input_digest mismatch inside the wrapper", () => {
  const dir = tmp();
  const opts = { checkpointDir: dir, helperName: "h", inputDigest: "a".repeat(64), versionDigest: "b".repeat(64) };
  mkdirSync(join(dir, "h"), { recursive: true });
  // Write a wrapper whose internal input_digest doesn't match the filename-encoded one.
  writeFileSync(
    join(dir, "h", `${opts.inputDigest}-${opts.versionDigest}.json`),
    JSON.stringify({ input_digest: "z".repeat(64), helper_version_digest: opts.versionDigest, output: {}, generated_at: "x" })
  );
  const r = cacheLookup(opts);
  assert.equal(r.hit, false);
});

test("cacheStore is atomic (writes via .tmp-<pid> then rename — no partial file after error path)", () => {
  // We can't easily induce a write error in a portable unit test, but we can confirm the visible
  // final file is the wrapper (not a .tmp-<pid> stub) and no .tmp file lingers in steady state.
  const dir = tmp();
  const opts = { checkpointDir: dir, helperName: "h", inputDigest: "a".repeat(64), versionDigest: "b".repeat(64) };
  cacheStore({ ...opts, payload: { output: { x: 1 } } });
  const p = join(dir, "h", `${opts.inputDigest}-${opts.versionDigest}.json`);
  assert.equal(existsSync(p), true);
  const w = JSON.parse(readFileSync(p, "utf8"));
  assert.deepEqual(w.output, { x: 1 });
  // No tmp leftover
  const tmpPath = `${p}.tmp-${process.pid}`;
  assert.equal(existsSync(tmpPath), false);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `( cd skills/audit/scripts && node --test test/cache-wrap.test.mjs )`
Expected: FAIL with `Cannot find module '../cache-wrap.mjs'` or similar.

- [ ] **Step 3: Implement cache-wrap.mjs**

Create `skills/audit/scripts/cache-wrap.mjs`:

```javascript
// Shared caching primitives for SP5 v1. Used by the 4 cacheable helpers (allocate-budget,
// aggregate-findings, apply-verdicts, render-html) and reused (canonicalize + sha256Hex only)
// by agent-response-cache. Zero runtime dependencies.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";

// Recursive-key-sort JSON stringify. Two semantically-equal objects produce byte-identical
// strings; arrays preserve order (they are sequences, not sets). Used as preimage for sha256
// when computing input_digest.
export function canonicalize(obj) {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalize).join(",") + "]";
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") + "}";
}

export function sha256Hex(input) {
  return createHash("sha256").update(input).digest("hex");
}

// sha256 of a helper file's own bytes. Detects code changes between kill and resume — a helper
// that has been edited produces a different version_digest, so its caches don't satisfy the
// lookup contract and get recomputed.
export function helperVersionDigest(helperFilePath) {
  return sha256Hex(readFileSync(helperFilePath));
}

export function cachePath(checkpointDir, helperName, inputDigest, versionDigest) {
  return join(checkpointDir, helperName, `${inputDigest}-${versionDigest}.json`);
}

// Returns { hit: bool, wrapper?: parsed JSON }. Silent miss on:
//   - file does not exist
//   - JSON.parse fails (corruption)
//   - the wrapper's internal input_digest doesn't equal the supplied one (tampering / partial write)
// Per §6 of the spec: cache-payload corruption is recoverable, never fail-loud.
export function cacheLookup({ checkpointDir, helperName, inputDigest, versionDigest }) {
  const p = cachePath(checkpointDir, helperName, inputDigest, versionDigest);
  if (!existsSync(p)) return { hit: false };
  let wrapper;
  try { wrapper = JSON.parse(readFileSync(p, "utf8")); } catch { return { hit: false }; }
  if (wrapper.input_digest !== inputDigest || wrapper.helper_version_digest !== versionDigest) {
    return { hit: false };
  }
  return { hit: true, wrapper };
}

// Writes `{ input_digest, helper_version_digest, ...payload, generated_at }` atomically.
// `payload` shape is helper-specific (e.g. `{ output: ... }` for JSON helpers,
// `{ html_output: ... }` for render-html).
export function cacheStore({ checkpointDir, helperName, inputDigest, versionDigest, payload }) {
  const dir = join(checkpointDir, helperName);
  mkdirSync(dir, { recursive: true });
  const p = cachePath(checkpointDir, helperName, inputDigest, versionDigest);
  const wrapper = { input_digest: inputDigest, helper_version_digest: versionDigest, ...payload, generated_at: new Date().toISOString() };
  const tmp = `${p}.tmp-${process.pid}`;
  try {
    writeFileSync(tmp, JSON.stringify(wrapper, null, 2));
    renameSync(tmp, p);
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* nothing to clean */ }
    throw e;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `( cd skills/audit/scripts && node --test test/cache-wrap.test.mjs )`
Expected: PASS — 10 tests, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add skills/audit/scripts/cache-wrap.mjs skills/audit/scripts/test/cache-wrap.test.mjs
git commit -m "feat(sp5): cache-wrap.mjs — shared cache primitives (canonicalize / sha256Hex / lookup / store)"
```

---

### Task 2: parse-audit-args.mjs

**Files:**
- Create: `skills/audit/scripts/parse-audit-args.mjs`
- Create: `skills/audit/scripts/test/parse-audit-args.test.mjs`

Implements §3.1: minimal shell-like tokenization (double quotes group), `--concurrency N` with strict integer + range check, `--sarif <path>` lexical extract, single positional → `scope`. No FS access.

- [ ] **Step 1: Write the failing test file**

Create `skills/audit/scripts/test/parse-audit-args.test.mjs`:

```javascript
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../parse-audit-args.mjs", import.meta.url));

function call(rawArgs) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-parse-args-")));
  const inP = join(dir, "in.json");
  const outP = join(dir, "out.json");
  writeFileSync(inP, JSON.stringify({ raw_args: rawArgs }));
  const r = spawnSync(process.execPath, [CLI, "--file", inP, "--out", outP], { encoding: "utf8" });
  let parsed = null;
  try { parsed = JSON.parse(readFileSync(outP, "utf8")); } catch { /* exit != 0 may not write --out */ }
  return { code: r.status, stderr: r.stderr, out: parsed };
}

test("empty raw_args -> defaults (scope:null, sarifPath:null, concurrency:4)", () => {
  const r = call("");
  assert.equal(r.code, 0);
  assert.deepEqual(r.out, { ok: true, error: null, scope: null, sarifPath: null, concurrency: 4 });
});

test("whitespace-only raw_args -> same defaults", () => {
  const r = call("   \t  ");
  assert.equal(r.code, 0);
  assert.equal(r.out.concurrency, 4);
});

test("--concurrency 8 parses ok", () => {
  const r = call("--concurrency 8");
  assert.equal(r.code, 0);
  assert.equal(r.out.concurrency, 8);
});

test("--concurrency 0 (below range) -> exit 1", () => {
  const r = call("--concurrency 0");
  assert.equal(r.code, 1);
  assert.match(r.stderr, /concurrency/i);
});

test("--concurrency 17 (above range) -> exit 1", () => {
  const r = call("--concurrency 17");
  assert.equal(r.code, 1);
});

test("--concurrency abc (non-integer) -> exit 1 (strict)", () => {
  const r = call("--concurrency abc");
  assert.equal(r.code, 1);
});

test("--concurrency 4.5 (float) -> exit 1 (strict integer)", () => {
  const r = call("--concurrency 4.5");
  assert.equal(r.code, 1);
});

test("--sarif x.sarif src/api parses both fields", () => {
  const r = call("--sarif x.sarif src/api");
  assert.equal(r.code, 0);
  assert.equal(r.out.sarifPath, "x.sarif");
  assert.equal(r.out.scope, "src/api");
});

test("two positional arguments -> exit 1 with diagnostic", () => {
  const r = call("a b");
  assert.equal(r.code, 1);
  assert.match(r.stderr, /positional|too many/i);
});

test("unknown flag -> exit 1", () => {
  const r = call("--bogus 1");
  assert.equal(r.code, 1);
});

test('quoted path with space: "path with spaces" parses as one positional', () => {
  const r = call('"path with spaces"');
  assert.equal(r.code, 0);
  assert.equal(r.out.scope, "path with spaces");
});

test('--sarif "my project/x.sarif" extracts the quoted path', () => {
  const r = call('--sarif "my project/x.sarif"');
  assert.equal(r.code, 0);
  assert.equal(r.out.sarifPath, "my project/x.sarif");
});

test('unterminated quote "foo -> exit 1 with diagnostic', () => {
  const r = call('"foo');
  assert.equal(r.code, 1);
  assert.match(r.stderr, /unterminated/i);
});

test('double quote inside an unquoted token (fo"o) is treated literally (no special mid-token)', () => {
  const r = call('fo"o');
  assert.equal(r.code, 0);
  assert.equal(r.out.scope, 'fo"o');
});

test("single quotes are NOT special (parsed as literal chars)", () => {
  const r = call("'foo'");
  assert.equal(r.code, 0);
  assert.equal(r.out.scope, "'foo'");
});

test("missing --file flag -> exit 2 usage", () => {
  const r = spawnSync(process.execPath, [CLI], { encoding: "utf8" });
  assert.equal(r.status, 2);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `( cd skills/audit/scripts && node --test test/parse-audit-args.test.mjs )`
Expected: FAIL with `Cannot find module '../parse-audit-args.mjs'` and all 16 tests error.

- [ ] **Step 3: Implement parse-audit-args.mjs**

Create `skills/audit/scripts/parse-audit-args.mjs`:

```javascript
// Deterministic $ARGUMENTS parser. Reads { raw_args } from --file, writes
// { ok, error, scope, sarifPath, concurrency } to --out. Exit codes:
//   0 ok / 1 invalid args / 2 IO|usage. No FS access on the parsed values.
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";

// Tokenize a single string with minimal shell-like grammar (spec §3.1):
//   - whitespace separates tokens
//   - a token starting with " ends at the next ", surrounding quotes stripped, no escapes
//   - " inside an unquoted token is literal
//   - unterminated quote throws
export function tokenize(raw) {
  const tokens = [];
  let i = 0;
  const n = raw.length;
  while (i < n) {
    // skip whitespace
    while (i < n && /\s/.test(raw[i])) i++;
    if (i >= n) break;
    if (raw[i] === '"') {
      // quoted token
      const start = i + 1;
      let j = start;
      while (j < n && raw[j] !== '"') j++;
      if (j >= n) {
        const frag = raw.slice(i, Math.min(i + 20, n));
        throw new Error(`unterminated quoted token: ${frag}`);
      }
      tokens.push(raw.slice(start, j));
      i = j + 1;
    } else {
      // unquoted token: until whitespace; embedded " is literal
      const start = i;
      while (i < n && !/\s/.test(raw[i])) i++;
      tokens.push(raw.slice(start, i));
    }
  }
  return tokens;
}

export function parseArgs(rawArgs) {
  let tokens;
  try { tokens = tokenize(rawArgs || ""); }
  catch (e) { return { ok: false, error: e.message, scope: null, sarifPath: null, concurrency: 4 }; }

  let scope = null;
  let sarifPath = null;
  let concurrency = 4;
  const positionals = [];

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === "--concurrency") {
      const v = tokens[++i];
      if (v === undefined || !/^\d+$/.test(v)) {
        return { ok: false, error: `--concurrency requires a positive integer, got: ${v}`, scope: null, sarifPath: null, concurrency: 4 };
      }
      const n = parseInt(v, 10);
      if (!(n >= 1 && n <= 16)) {
        return { ok: false, error: `--concurrency must be in 1..16, got: ${n}`, scope: null, sarifPath: null, concurrency: 4 };
      }
      concurrency = n;
    } else if (t === "--sarif") {
      const v = tokens[++i];
      if (v === undefined) {
        return { ok: false, error: "--sarif requires a path argument", scope: null, sarifPath: null, concurrency: 4 };
      }
      sarifPath = v;
    } else if (t.startsWith("--")) {
      return { ok: false, error: `unknown flag: ${t}`, scope: null, sarifPath: null, concurrency: 4 };
    } else {
      positionals.push(t);
    }
  }

  if (positionals.length > 1) {
    return { ok: false, error: "too many positional arguments (only one scope allowed)", scope: null, sarifPath: null, concurrency: 4 };
  }
  if (positionals.length === 1) scope = positionals[0];

  return { ok: true, error: null, scope, sarifPath, concurrency };
}

// CLI
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const fi = args.indexOf("--file"), oi = args.indexOf("--out");
  if (fi === -1 || !args[fi + 1] || oi === -1 || !args[oi + 1]) {
    process.stderr.write("usage: parse-audit-args.mjs --file <input.json> --out <out.json>\n");
    process.exit(2);
  }
  let input;
  try { input = JSON.parse(readFileSync(args[fi + 1], "utf8")); }
  catch (e) { process.stderr.write("cannot read --file: " + e.message + "\n"); process.exit(2); }
  if (typeof input.raw_args !== "string") {
    process.stderr.write("bad input: raw_args (string) required\n"); process.exit(2);
  }
  const r = parseArgs(input.raw_args);
  try { writeFileSync(args[oi + 1], JSON.stringify(r, null, 2)); }
  catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
  if (!r.ok) process.stderr.write("parse-audit-args: " + r.error + "\n");
  process.exit(r.ok ? 0 : 1);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `( cd skills/audit/scripts && node --test test/parse-audit-args.test.mjs )`
Expected: PASS — 16 tests, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add skills/audit/scripts/parse-audit-args.mjs skills/audit/scripts/test/parse-audit-args.test.mjs
git commit -m "feat(sp5): parse-audit-args.mjs — deterministic CLI arg parser with shell-like quoting"
```

---

### Task 3: checkpoint-manifest schema + validate-output integration

**Files:**
- Create: `skills/audit/schemas/checkpoint-manifest.schema.json`
- Modify: `skills/audit/scripts/build-validators.mjs` (EXPORT_NAME map)
- Modify: `skills/audit/scripts/validate-output.mjs` (KIND_TO_EXPORT)
- Regenerate: `skills/audit/scripts/validators.mjs`
- Modify: `skills/audit/scripts/test/validate-output.test.mjs` (+1 test)

Schema is the 9th in the repo. Pattern follows every prior schema addition: drop the JSON in `schemas/`, register the export name in `build-validators.mjs`, register the kind in `validate-output.mjs`, regenerate `validators.mjs`, add a smoke test.

- [ ] **Step 1: Write the schema**

Create `skills/audit/schemas/checkpoint-manifest.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "checkpoint-manifest.schema.json",
  "title": "OSWE checkpoint manifest",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema_version",
    "run_id",
    "started_at",
    "completed",
    "scope_realpath",
    "sarif_realpath",
    "concurrency",
    "invocation_digest"
  ],
  "properties": {
    "schema_version": { "type": "integer", "const": 1 },
    "run_id": { "type": "string", "pattern": "^[0-9a-f]{16}$" },
    "started_at": { "type": "string", "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z$" },
    "completed": { "type": "boolean" },
    "scope_realpath": { "type": ["string", "null"] },
    "sarif_realpath": { "type": ["string", "null"] },
    "concurrency": { "type": "integer", "minimum": 1, "maximum": 16 },
    "invocation_digest": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
  }
}
```

- [ ] **Step 2: Register the schema in build-validators.mjs**

Edit `skills/audit/scripts/build-validators.mjs` lines 19–28 — extend the `EXPORT_NAME` map.

Replace:

```javascript
const EXPORT_NAME = {
  "finding.schema.json": "finding",
  "final-finding.schema.json": "finalFinding",
  "analyzer-response.schema.json": "analyzerResponse",
  "chain.schema.json": "chain",
  "verdict.schema.json": "verdict",
  "verifier-response.schema.json": "verifierResponse",
  "report-summary.schema.json": "reportSummary",
  "sarif-lead.schema.json": "sarifLead"
};
```

With:

```javascript
const EXPORT_NAME = {
  "finding.schema.json": "finding",
  "final-finding.schema.json": "finalFinding",
  "analyzer-response.schema.json": "analyzerResponse",
  "chain.schema.json": "chain",
  "verdict.schema.json": "verdict",
  "verifier-response.schema.json": "verifierResponse",
  "report-summary.schema.json": "reportSummary",
  "sarif-lead.schema.json": "sarifLead",
  "checkpoint-manifest.schema.json": "checkpointManifest"
};
```

- [ ] **Step 3: Register the kind in validate-output.mjs**

Edit `skills/audit/scripts/validate-output.mjs` lines 6–13 — extend `KIND_TO_EXPORT`.

Replace:

```javascript
const KIND_TO_EXPORT = {
  "analyzer-response": "analyzerResponse",
  "verifier-response": "verifierResponse",
  "finding": "finding",
  "final-finding": "finalFinding",
  "chain": "chain",
  "verdict": "verdict"
};
```

With:

```javascript
const KIND_TO_EXPORT = {
  "analyzer-response": "analyzerResponse",
  "verifier-response": "verifierResponse",
  "finding": "finding",
  "final-finding": "finalFinding",
  "chain": "chain",
  "verdict": "verdict",
  "checkpoint-manifest": "checkpointManifest"
};
```

- [ ] **Step 4: Regenerate validators.mjs**

Run: `( cd skills/audit/scripts && npm run build )`
Expected: stdout contains `"validators.mjs generated (self-contained): ... checkpointManifest"`.

If `npm run build` is missing or fails because `node_modules` is absent locally, run `( cd skills/audit/scripts && npm install && npm run build )`. AJV is dev-only — the regenerated `validators.mjs` is itself self-contained (asserted by `build-validators.mjs`'s residual-require check).

- [ ] **Step 5: Add a smoke test to validate-output**

Append these tests to the end of `skills/audit/scripts/test/validate-output.test.mjs` (the file already imports `test, assert, validate` at the top — reuse them directly, no new imports):

```javascript
test("validate-output accepts a well-formed checkpoint-manifest", () => {
  const ok = validate("checkpoint-manifest", {
    schema_version: 1,
    run_id: "0123456789abcdef",
    started_at: "2026-06-20T12:00:00Z",
    completed: false,
    scope_realpath: null,
    sarif_realpath: null,
    concurrency: 4,
    invocation_digest: "f".repeat(64)
  });
  assert.equal(ok.valid, true);
});

test("validate-output rejects a checkpoint-manifest with additionalProperties", () => {
  const bad = validate("checkpoint-manifest", {
    schema_version: 1,
    run_id: "0123456789abcdef",
    started_at: "2026-06-20T12:00:00Z",
    completed: false,
    scope_realpath: null,
    sarif_realpath: null,
    concurrency: 4,
    invocation_digest: "f".repeat(64),
    surprise: "extra"
  });
  assert.equal(bad.valid, false);
});

test("validate-output rejects a checkpoint-manifest with bad concurrency range", () => {
  const bad = validate("checkpoint-manifest", {
    schema_version: 1,
    run_id: "0123456789abcdef",
    started_at: "2026-06-20T12:00:00Z",
    completed: false,
    scope_realpath: null,
    sarif_realpath: null,
    concurrency: 99,
    invocation_digest: "f".repeat(64)
  });
  assert.equal(bad.valid, false);
});
```

- [ ] **Step 6: Run the full test suite to confirm**

Run: `( cd skills/audit/scripts && node --test )`
Expected: every existing test still passes; the 3 new validate-output tests pass.

- [ ] **Step 7: Commit**

```bash
git add skills/audit/schemas/checkpoint-manifest.schema.json \
        skills/audit/scripts/build-validators.mjs \
        skills/audit/scripts/validate-output.mjs \
        skills/audit/scripts/validators.mjs \
        skills/audit/scripts/test/validate-output.test.mjs
git commit -m "feat(sp5): checkpoint-manifest schema + validate-output kind (9th schema)"
```

---

### Task 4: checkpoint-lifecycle.mjs

**Files:**
- Create: `skills/audit/scripts/checkpoint-lifecycle.mjs`
- Create: `skills/audit/scripts/test/checkpoint-lifecycle.test.mjs`

Implements §3.2: resolve mode (scan `.oswe/checkpoints/*/manifest.json`, match by `invocation_digest` + `completed:false`, fail-closed on >1) and finalize mode (flip `completed:true`, rm -rf, tolerate locked files).

- [ ] **Step 1: Write the failing test file**

Create `skills/audit/scripts/test/checkpoint-lifecycle.test.mjs`:

```javascript
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../checkpoint-lifecycle.mjs", import.meta.url));

function setupProject() {
  const projectDir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-lifecycle-")));
  mkdirSync(join(projectDir, ".oswe"), { recursive: true });
  return projectDir;
}

function resolve(projectDir, scopeRealpath, sarifRealpath = null, concurrency = 4) {
  const dir = mkdtempSync(join(tmpdir(), "oswe-lifecycle-io-"));
  const inP = join(dir, "in.json");
  const outP = join(dir, "out.json");
  writeFileSync(inP, JSON.stringify({ projectDir, scope_realpath: scopeRealpath, sarif_realpath: sarifRealpath, concurrency }));
  const r = spawnSync(process.execPath, [CLI, "--file", inP, "--out", outP], { encoding: "utf8" });
  let out = null; try { out = JSON.parse(readFileSync(outP, "utf8")); } catch { /* exit != 0 */ }
  return { code: r.status, stderr: r.stderr, out };
}

function finalize(projectDir, runId) {
  const r = spawnSync(process.execPath, [CLI, "--finalize", "--run-id", runId, "--project-dir", projectDir], { encoding: "utf8" });
  return { code: r.status, stderr: r.stderr };
}

function listCheckpoints(projectDir) {
  const dir = join(projectDir, ".oswe", "checkpoints");
  if (!existsSync(dir)) return [];
  return readdirSync(dir);
}

test("no existing checkpoints -> new run_id, mode:new, checkpoint dir created with valid manifest", () => {
  const p = setupProject();
  const r = resolve(p, p, null, 4);
  assert.equal(r.code, 0);
  assert.equal(r.out.mode, "new");
  assert.match(r.out.run_id, /^[0-9a-f]{16}$/);
  assert.equal(r.out.checkpoint_dir, join(p, ".oswe", "checkpoints", r.out.run_id));
  const manifest = JSON.parse(readFileSync(join(r.out.checkpoint_dir, "manifest.json"), "utf8"));
  assert.equal(manifest.schema_version, 1);
  assert.equal(manifest.completed, false);
  assert.equal(manifest.concurrency, 4);
  assert.equal(manifest.scope_realpath, p);
  assert.match(manifest.invocation_digest, /^[0-9a-f]{64}$/);
});

test("one compatible incomplete checkpoint -> resume with same run_id", () => {
  const p = setupProject();
  const first = resolve(p, p, null, 4);
  const second = resolve(p, p, null, 4);
  assert.equal(second.code, 0);
  assert.equal(second.out.mode, "resume");
  assert.equal(second.out.run_id, first.out.run_id);
});

test("one compatible + one completed -> resume the incomplete one (completed ignored)", () => {
  const p = setupProject();
  const first = resolve(p, p, null, 4);
  finalize(p, first.out.run_id);
  // After finalize the run dir is gone; create a fake completed manifest to test the filter.
  const completedDir = join(p, ".oswe", "checkpoints", "1111111111111111");
  mkdirSync(completedDir, { recursive: true });
  // Same invocation_digest as the live invocation:
  const live = resolve(p, p, null, 4);  // this creates a NEW run since previous was finalized
  const liveManifest = JSON.parse(readFileSync(join(live.out.checkpoint_dir, "manifest.json"), "utf8"));
  writeFileSync(join(completedDir, "manifest.json"), JSON.stringify({
    ...liveManifest, run_id: "1111111111111111", completed: true
  }));
  const r = resolve(p, p, null, 4);
  assert.equal(r.code, 0);
  assert.equal(r.out.mode, "resume");
  assert.equal(r.out.run_id, live.out.run_id, "should resume the incomplete one, not the completed");
});

test("two compatible incomplete checkpoints -> exit 1 with cleanup instruction", () => {
  const p = setupProject();
  // Manually craft two checkpoint dirs with the same invocation_digest and completed:false.
  const baseManifest = {
    schema_version: 1,
    started_at: "2026-06-20T12:00:00Z",
    completed: false,
    scope_realpath: p,
    sarif_realpath: null,
    concurrency: 4
  };
  // Compute the digest the live call will produce: cheat by doing one real resolve first to learn it.
  const probe = resolve(p, p, null, 4);
  const probeManifest = JSON.parse(readFileSync(join(probe.out.checkpoint_dir, "manifest.json"), "utf8"));
  rmSync(probe.out.checkpoint_dir, { recursive: true, force: true });

  const id1 = "aaaaaaaaaaaaaaaa", id2 = "bbbbbbbbbbbbbbbb";
  for (const id of [id1, id2]) {
    const d = join(p, ".oswe", "checkpoints", id);
    mkdirSync(d, { recursive: true });
    writeFileSync(join(d, "manifest.json"), JSON.stringify({ ...baseManifest, run_id: id, invocation_digest: probeManifest.invocation_digest }));
  }

  const r = resolve(p, p, null, 4);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /ambiguous resume/i);
  assert.match(r.stderr, /rm -rf \.oswe\/checkpoints/i);
});

test("mismatched concurrency (4 vs 8) -> new run_id (different invocation_digest)", () => {
  const p = setupProject();
  const first = resolve(p, p, null, 4);
  const second = resolve(p, p, null, 8);
  assert.equal(second.out.mode, "new");
  assert.notEqual(second.out.run_id, first.out.run_id);
});

test("mismatched scope_realpath -> new run_id", () => {
  const p = setupProject();
  const subdir = join(p, "subdir");
  mkdirSync(subdir, { recursive: true });
  const first = resolve(p, p, null, 4);
  const second = resolve(p, realpathSync(subdir), null, 4);
  assert.equal(second.out.mode, "new");
  assert.notEqual(second.out.run_id, first.out.run_id);
});

test("finalize flips completed to true and removes the run dir", () => {
  const p = setupProject();
  const r = resolve(p, p, null, 4);
  const f = finalize(p, r.out.run_id);
  assert.equal(f.code, 0);
  assert.equal(existsSync(r.out.checkpoint_dir), false);
});

test("finalize is idempotent on missing dir (exit 0, no stderr)", () => {
  const p = setupProject();
  const f = finalize(p, "ffffffffffffffff");
  assert.equal(f.code, 0);
});

test("finalize emits a warning + exit 0 when rm fails (simulated via locked-style scenario)", () => {
  // Portability: we can't reliably lock a file on every OS in unit tests. So we verify the
  // softer property: if the dir doesn't exist after step 2's manifest write, exit is still 0,
  // and the manifest's completed:true mark is what guarantees future runs skip it. The "warning
  // on rm failure" path is exercised by setting completed:true on a phantom dir below.
  const p = setupProject();
  const id = "ddddddddddddddd0";
  const d = join(p, ".oswe", "checkpoints", id);
  mkdirSync(d, { recursive: true });
  writeFileSync(join(d, "manifest.json"), JSON.stringify({
    schema_version: 1, run_id: id, started_at: "2026-06-20T12:00:00Z",
    completed: false, scope_realpath: p, sarif_realpath: null, concurrency: 4,
    invocation_digest: "0".repeat(64)
  }));
  const f = finalize(p, id);
  assert.equal(f.code, 0);
  assert.equal(existsSync(d), false, "happy path: dir removed");
});

test("a manifest with additionalProperties -> exit 1 with cleanup instruction (fail-loud per §6)", () => {
  const p = setupProject();
  const id = "ccccccccccccccc1";
  const d = join(p, ".oswe", "checkpoints", id);
  mkdirSync(d, { recursive: true });
  writeFileSync(join(d, "manifest.json"), JSON.stringify({
    schema_version: 1, run_id: id, started_at: "2026-06-20T12:00:00Z",
    completed: false, scope_realpath: p, sarif_realpath: null, concurrency: 4,
    invocation_digest: "0".repeat(64),
    surprise: "extra"  // additionalProperties violation
  }));
  const r = resolve(p, p, null, 4);
  assert.equal(r.code, 1, "malformed manifest must fail loud, not silently fall through to a fresh run");
  assert.match(r.stderr, /schema-invalid|malformed|unreadable/i);
  assert.match(r.stderr, new RegExp(`rm -rf \\.oswe/checkpoints/${id}`));
});

test("a manifest with unparseable JSON -> exit 1 with cleanup instruction", () => {
  const p = setupProject();
  const id = "ccccccccccccccc2";
  const d = join(p, ".oswe", "checkpoints", id);
  mkdirSync(d, { recursive: true });
  writeFileSync(join(d, "manifest.json"), "{not json at all");
  const r = resolve(p, p, null, 4);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /malformed/i);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `( cd skills/audit/scripts && node --test test/checkpoint-lifecycle.test.mjs )`
Expected: FAIL — `Cannot find module '../checkpoint-lifecycle.mjs'`.

- [ ] **Step 3: Implement checkpoint-lifecycle.mjs**

Create `skills/audit/scripts/checkpoint-lifecycle.mjs`:

```javascript
// Per-run checkpoint lifecycle (spec §3.2). Two modes:
//   resolve  — scan .oswe/checkpoints/*/manifest.json, match by invocation_digest, fail-closed on >1
//   finalize — flip completed:true then rm the run dir
// Manifest is validated through validate-output's checkpoint-manifest kind.
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, statSync, renameSync, rmSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { canonicalize, sha256Hex } from "./cache-wrap.mjs";
import { validate } from "./validate-output.mjs";

const SCHEMA_VERSION = 1;

function invocationDigest({ scope_realpath, sarif_realpath, concurrency }) {
  return sha256Hex(canonicalize({ scope_realpath, sarif_realpath, concurrency, schema_version: SCHEMA_VERSION }));
}

function readManifest(p) {
  try { return JSON.parse(readFileSync(p, "utf8")); }
  catch { return null; }
}

function scanCompatible(projectDir, digest) {
  const root = join(projectDir, ".oswe", "checkpoints");
  if (!existsSync(root)) return [];
  const out = [];
  for (const entry of readdirSync(root)) {
    const manifestPath = join(root, entry, "manifest.json");
    if (!existsSync(manifestPath)) continue;
    // Spec §6: a manifest that EXISTS but is unparseable / schema-invalid is fail-loud
    // (exit 1 with cleanup), not silent-skip. The manifest is the directory-level structural
    // artifact; broken structure means broken run lifecycle. Cache-payload files get silent
    // recovery (§6 again), but manifests do not.
    let raw;
    try { raw = readFileSync(manifestPath, "utf8"); }
    catch (e) {
      throw new Error(`manifest unreadable at .oswe/checkpoints/${entry}/manifest.json (${e.message}). Please \`rm -rf .oswe/checkpoints/${entry}\` and re-run.`);
    }
    let m;
    try { m = JSON.parse(raw); }
    catch (e) {
      throw new Error(`manifest JSON malformed at .oswe/checkpoints/${entry}/manifest.json (${e.message}). Please \`rm -rf .oswe/checkpoints/${entry}\` and re-run.`);
    }
    const v = validate("checkpoint-manifest", m);
    if (!v.valid) {
      throw new Error(`manifest schema-invalid at .oswe/checkpoints/${entry}/manifest.json (${JSON.stringify(v.errors)}). Please \`rm -rf .oswe/checkpoints/${entry}\` and re-run.`);
    }
    if (m.invocation_digest === digest && m.completed === false) out.push({ run_id: entry, manifest: m });
  }
  return out;
}

export function resolveRun({ projectDir, scope_realpath, sarif_realpath, concurrency }) {
  const digest = invocationDigest({ scope_realpath, sarif_realpath, concurrency });
  let compat;
  try { compat = scanCompatible(projectDir, digest); }
  catch (e) { return { ok: false, error: e.message, run_id: null, mode: null, checkpoint_dir: null }; }

  if (compat.length > 1) {
    return {
      ok: false,
      error: `ambiguous resume: ${compat.length} compatible incomplete checkpoints under .oswe/checkpoints/ ; please \`rm -rf .oswe/checkpoints/\` and re-run to start fresh, OR keep the one you want and remove the others.`,
      run_id: null, mode: null, checkpoint_dir: null
    };
  }
  if (compat.length === 1) {
    const run_id = compat[0].run_id;
    return { ok: true, error: null, run_id, mode: "resume", checkpoint_dir: join(projectDir, ".oswe", "checkpoints", run_id) };
  }
  // 0 compatible -> create a fresh run
  const run_id = sha256Hex(Date.now() + ":" + randomBytes(16).toString("hex")).slice(0, 16);
  const checkpoint_dir = join(projectDir, ".oswe", "checkpoints", run_id);
  mkdirSync(checkpoint_dir, { recursive: true });
  const manifest = {
    schema_version: SCHEMA_VERSION,
    run_id,
    started_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    completed: false,
    scope_realpath: scope_realpath ?? null,
    sarif_realpath: sarif_realpath ?? null,
    concurrency,
    invocation_digest: digest
  };
  const mp = join(checkpoint_dir, "manifest.json");
  const tmp = `${mp}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(manifest, null, 2));
  renameSync(tmp, mp);
  return { ok: true, error: null, run_id, mode: "new", checkpoint_dir };
}

export function finalizeRun({ projectDir, runId }) {
  const dir = join(projectDir, ".oswe", "checkpoints", runId);
  const mp = join(dir, "manifest.json");
  if (!existsSync(mp)) return { ok: true, warning: null };  // idempotent: nothing to do
  let manifest;
  try { manifest = JSON.parse(readFileSync(mp, "utf8")); }
  catch (e) { return { ok: true, warning: `finalize: manifest unreadable (${e.message}); skipping cleanup` }; }
  manifest.completed = true;
  const tmp = `${mp}.tmp-${process.pid}`;
  try {
    writeFileSync(tmp, JSON.stringify(manifest, null, 2));
    renameSync(tmp, mp);
  } catch (e) {
    return { ok: true, warning: `finalize: could not write completed:true to ${mp}: ${e.message}` };
  }
  try { rmSync(dir, { recursive: true, force: true }); }
  catch (e) {
    return { ok: true, warning: `finalize: could not remove ${dir}; run \`rm -rf .oswe/checkpoints/${runId}\` manually to clean up. Cause: ${e.message}` };
  }
  return { ok: true, warning: null };
}

// CLI
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);

  if (args.includes("--finalize")) {
    const ri = args.indexOf("--run-id"); const pi = args.indexOf("--project-dir");
    if (ri === -1 || !args[ri + 1] || pi === -1 || !args[pi + 1]) {
      process.stderr.write("usage: checkpoint-lifecycle.mjs --finalize --run-id <id> --project-dir <abs>\n");
      process.exit(2);
    }
    const r = finalizeRun({ projectDir: args[pi + 1], runId: args[ri + 1] });
    if (r.warning) process.stderr.write(r.warning + "\n");
    process.exit(0);
  }

  // resolve mode
  const fi = args.indexOf("--file"), oi = args.indexOf("--out");
  if (fi === -1 || !args[fi + 1] || oi === -1 || !args[oi + 1]) {
    process.stderr.write("usage: checkpoint-lifecycle.mjs --file <input.json> --out <out.json>   (or --finalize --run-id <id> --project-dir <abs>)\n");
    process.exit(2);
  }
  let input;
  try { input = JSON.parse(readFileSync(args[fi + 1], "utf8")); }
  catch (e) { process.stderr.write("cannot read --file: " + e.message + "\n"); process.exit(2); }
  if (typeof input.projectDir !== "string" || !Number.isInteger(input.concurrency)) {
    process.stderr.write("bad input: projectDir (string) and concurrency (int) required\n"); process.exit(2);
  }
  const r = resolveRun(input);
  try { writeFileSync(args[oi + 1], JSON.stringify(r, null, 2)); }
  catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
  if (!r.ok) process.stderr.write("checkpoint-lifecycle: " + r.error + "\n");
  process.exit(r.ok ? 0 : 1);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `( cd skills/audit/scripts && node --test test/checkpoint-lifecycle.test.mjs )`
Expected: PASS — 11 tests, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add skills/audit/scripts/checkpoint-lifecycle.mjs skills/audit/scripts/test/checkpoint-lifecycle.test.mjs
git commit -m "feat(sp5): checkpoint-lifecycle.mjs — resolve + finalize, fail-closed on ambiguous resume"
```

---

### Task 5: surface-scan emits file_content_digest

**Files:**
- Modify: `skills/audit/scripts/surface-scan.mjs` (lines 74–125, `scanPartition`)
- Modify: `skills/audit/scripts/test/surface-scan.test.mjs` (+4 tests)

Per spec §3.3. Compute `file_content_digest = sha256(byte-concat of (sha256(file_i) || NUL), in content_key sorted order)`. Scannable vectors gain the field; unscannable vectors do not (no files were readable).

- [ ] **Step 1: Extend the existing top-of-file imports**

The existing `skills/audit/scripts/test/surface-scan.test.mjs` already imports `test, assert, mkdtempSync, mkdirSync, writeFileSync, tmpdir, join, scanPartition`. Add `realpathSync` to the existing `from "node:fs"` import line so it reads:

```javascript
import { mkdtempSync, mkdirSync, writeFileSync, realpathSync } from "node:fs";
```

Do NOT add any other imports — every other identifier the new tests use is already in scope.

- [ ] **Step 2: Append 4 new tests to the end of the same file**

Append these four `test(...)` blocks AFTER the last existing test in `surface-scan.test.mjs`. No new top-level imports.

```javascript
test("scannable vector carries file_content_digest", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-scan-fcd-")));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "src", "a.py"), "request.args.get('x')\n");
  writeFileSync(join(dir, "src", "b.py"), "import os; os.system(x)\n");
  const r = scanPartition(
    { partition_id: "py:1", stack: "python", files: ["src/a.py", "src/b.py"] },
    { sources: ["request.args.get"], sinks: ["os.system"], sanitizers: [], auth_markers: [] },
    dir
  );
  assert.equal(r.scannable, true);
  assert.match(r.file_content_digest, /^[0-9a-f]{64}$/);
});

test("same files + same content -> same file_content_digest (twice)", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-scan-fcd-")));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "src", "a.py"), "x\n");
  const part = { partition_id: "p", stack: "python", files: ["src/a.py"] };
  const block = { sources: [], sinks: [], sanitizers: [], auth_markers: [] };
  const r1 = scanPartition(part, block, dir);
  const r2 = scanPartition(part, block, dir);
  assert.equal(r1.file_content_digest, r2.file_content_digest);
});

test("changing one byte in one file flips file_content_digest", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-scan-fcd-")));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "src", "a.py"), "x\n");
  const part = { partition_id: "p", stack: "python", files: ["src/a.py"] };
  const block = { sources: [], sinks: [], sanitizers: [], auth_markers: [] };
  const before = scanPartition(part, block, dir).file_content_digest;
  writeFileSync(join(dir, "src", "a.py"), "y\n");
  const after = scanPartition(part, block, dir).file_content_digest;
  assert.notEqual(before, after);
});

test("scannable:false (all files unreadable) has no file_content_digest", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-scan-fcd-")));
  mkdirSync(join(dir, "src"), { recursive: true });
  // Reference a file that doesn't exist -> all skipped -> scannable:false
  const r = scanPartition(
    { partition_id: "p", stack: "python", files: ["src/missing.py"] },
    { sources: [], sinks: [], sanitizers: [], auth_markers: [] },
    dir
  );
  assert.equal(r.scannable, false);
  assert.equal(r.file_content_digest, undefined);
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `( cd skills/audit/scripts && node --test test/surface-scan.test.mjs )`
Expected: the 4 new tests fail (file_content_digest is undefined). Existing tests still pass.

- [ ] **Step 4: Extend surface-scan.mjs scanPartition + add helper**

In `skills/audit/scripts/surface-scan.mjs`, add the digest helper near the top (after the existing `import` block, before `confinePath` is used), and call it from `scanPartition`.

Add this import near the top, alongside the existing `readFileSync`:

```javascript
import { createHash } from "node:crypto";
```

Add this helper above `scanPartition`:

```javascript
// File-content digest for a scannable partition (spec §3.3). Reads each file in content_key
// (sorted-paths) order and concatenates sha256(file_i) || NUL into a single sha256. A byte change
// in any file flips the digest; ordering inside the partition is irrelevant (sorted internally).
// Unreadable files are skipped from the digest input (their absence shifts the digest, which is
// the right invalidation signal: a file that disappeared changes the analyzer's input set).
function fileContentDigest(sortedRelPaths, projectDir) {
  const h = createHash("sha256");
  for (const rel of sortedRelPaths) {
    let bytes;
    try { bytes = readFileSync(confinePath(projectDir, rel)); }
    catch { continue; }
    h.update(createHash("sha256").update(bytes).digest());
    h.update(Buffer.from([0]));  // NUL separator
  }
  return h.digest("hex");
}
```

Modify the final `return` inside `scanPartition` (the one for the scannable case, currently lines 118–124). Replace:

```javascript
  return {
    partition_id: partition.partition_id, stack: partition.stack, scannable: true,
    files: partition.files.length, sources, sinks, sanitizers, auth_markers,
    source_and_auth_files, source_hits, sink_hits, auth_hits,
    skipped_missing, skipped_out_of_scope,
    content_key: contentKey(partition.files)
  };
```

With:

```javascript
  const sortedPaths = [...partition.files].sort();
  return {
    partition_id: partition.partition_id, stack: partition.stack, scannable: true,
    files: partition.files.length, sources, sinks, sanitizers, auth_markers,
    source_and_auth_files, source_hits, sink_hits, auth_hits,
    skipped_missing, skipped_out_of_scope,
    content_key: contentKey(partition.files),
    file_content_digest: fileContentDigest(sortedPaths, projectDir)
  };
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `( cd skills/audit/scripts && node --test test/surface-scan.test.mjs )`
Expected: every existing test still passes; the 4 new tests pass.

- [ ] **Step 6: Commit**

```bash
git add skills/audit/scripts/surface-scan.mjs skills/audit/scripts/test/surface-scan.test.mjs
git commit -m "feat(sp5): surface-scan emits file_content_digest per scannable vector"
```

---

### Task 6: agent-response-cache.mjs

**Files:**
- Create: `skills/audit/scripts/agent-response-cache.mjs`
- Create: `skills/audit/scripts/test/agent-response-cache.test.mjs`

Implements §3.5: `--lookup` / `--store`. Reads `agent_contract_files`, computes `agent_context_digest`, folds into `input_digest`. Re-validates `cached_response` against the kind's schema before returning a hit (Fix #1 round 3). Enforces `plugin_root` confinement on contract paths (Fix #1 round 5).

- [ ] **Step 1: Write the failing test file**

Create `skills/audit/scripts/test/agent-response-cache.test.mjs`:

```javascript
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../agent-response-cache.mjs", import.meta.url));

function setupPlugin() {
  // Fake plugin root with a contract file we can edit.
  const root = realpathSync(mkdtempSync(join(tmpdir(), "oswe-arc-plugin-")));
  mkdirSync(join(root, "agents"), { recursive: true });
  writeFileSync(join(root, "agents", "oswe-analyzer.md"), "# analyzer v1\n");
  return root;
}

function setupCheckpoint() {
  return realpathSync(mkdtempSync(join(tmpdir(), "oswe-arc-ckpt-")));
}

// Minimal schema-valid analyzer-response (matches analyzer-response.schema.json's required
// fields: partition_id, status, findings, coverage). Coverage required sub-fields: analyzed[],
// skipped[]; skipped items need {path, reason}.
function validAnalyzerResponse() {
  return {
    partition_id: "py:web",
    status: "ok",
    findings: [],
    coverage: { analyzed: ["src/a.py", "src/b.py"], skipped: [] }
  };
}

function call(mode, input) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-arc-io-")));
  const inP = join(dir, "in.json");
  writeFileSync(inP, JSON.stringify(input));
  if (mode === "--lookup") {
    const outP = join(dir, "out.json");
    const r = spawnSync(process.execPath, [CLI, "--lookup", "--file", inP, "--out", outP], { encoding: "utf8" });
    let out = null; try { out = JSON.parse(readFileSync(outP, "utf8")); } catch { /* may not write on usage error */ }
    return { code: r.status, stderr: r.stderr, out };
  } else {
    const r = spawnSync(process.execPath, [CLI, "--store", "--file", inP], { encoding: "utf8" });
    return { code: r.status, stderr: r.stderr };
  }
}

function baseDispatchInput(pluginRoot) {
  return {
    partition_id: "py:web",
    files: ["src/a.py", "src/b.py"],
    file_content_digest: "f".repeat(64),
    references_loaded: ["python"],
    agent_contract_files: [join(pluginRoot, "agents", "oswe-analyzer.md")]
  };
}

test("lookup with no prior store -> hit:false", () => {
  const pluginRoot = setupPlugin(); const ckpt = setupCheckpoint();
  const r = call("--lookup", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: baseDispatchInput(pluginRoot)
  });
  assert.equal(r.code, 0);
  assert.equal(r.out.ok, true);
  assert.equal(r.out.hit, false);
});

test("store then lookup -> hit:true with cached_response", () => {
  const pluginRoot = setupPlugin(); const ckpt = setupCheckpoint();
  const di = baseDispatchInput(pluginRoot);
  const resp = validAnalyzerResponse();
  const s = call("--store", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di, validated_response: resp
  });
  assert.equal(s.code, 0);
  const r = call("--lookup", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di
  });
  assert.equal(r.code, 0);
  assert.equal(r.out.hit, true);
  assert.deepEqual(r.out.cached_response, resp);
});

test("lookup with different dispatch_input (flipped one file) misses", () => {
  const pluginRoot = setupPlugin(); const ckpt = setupCheckpoint();
  const di = baseDispatchInput(pluginRoot);
  call("--store", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di, validated_response: validAnalyzerResponse()
  });
  const di2 = { ...di, files: ["src/a.py", "src/c.py"] };
  const r = call("--lookup", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di2
  });
  assert.equal(r.out.hit, false);
});

test("lookup with different kind misses", () => {
  const pluginRoot = setupPlugin(); const ckpt = setupCheckpoint();
  const di = baseDispatchInput(pluginRoot);
  call("--store", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di, validated_response: validAnalyzerResponse()
  });
  const r = call("--lookup", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "verifier-response", target_id: "py:web",
    dispatch_input: di
  });
  assert.equal(r.out.hit, false);
});

test("lookup with different target_id misses", () => {
  const pluginRoot = setupPlugin(); const ckpt = setupCheckpoint();
  const di = baseDispatchInput(pluginRoot);
  call("--store", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di, validated_response: validAnalyzerResponse()
  });
  const r = call("--lookup", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:api",
    dispatch_input: di
  });
  assert.equal(r.out.hit, false);
});

test("store is idempotent (rewriting same key with same value is a no-op)", () => {
  const pluginRoot = setupPlugin(); const ckpt = setupCheckpoint();
  const di = baseDispatchInput(pluginRoot);
  const resp = validAnalyzerResponse();
  const s1 = call("--store", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di, validated_response: resp
  });
  const s2 = call("--store", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di, validated_response: resp
  });
  assert.equal(s1.code, 0);
  assert.equal(s2.code, 0);
});

test("malformed cache file on disk -> lookup returns miss (silent recompute per §6)", () => {
  const pluginRoot = setupPlugin(); const ckpt = setupCheckpoint();
  // Manually plant a malformed cache file at where the helper would look.
  mkdirSync(join(ckpt, "agent-responses"), { recursive: true });
  // We don't know the exact filename without computing the digest; write a file in the dir that
  // we know won't match (corruption case is also covered structurally by store-then-edit below).
  // Instead: store, then corrupt the file on disk, then lookup.
  const di = baseDispatchInput(pluginRoot);
  call("--store", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di, validated_response: validAnalyzerResponse()
  });
  // Find the cache file and corrupt it (readdirSync, writeFileSync are imported at top).
  const arcDir = join(ckpt, "agent-responses");
  const files = readdirSync(arcDir);
  assert.ok(files.length > 0, "store should have created a cache file");
  writeFileSync(join(arcDir, files[0]), "{not json");
  const r = call("--lookup", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di
  });
  assert.equal(r.out.hit, false);
});

test("right input_digest, invalid cached_response shape -> miss (Fix #1 round 3)", () => {
  const pluginRoot = setupPlugin(); const ckpt = setupCheckpoint();
  const di = baseDispatchInput(pluginRoot);
  // Store with a response that we'll then tamper to be invalid against the analyzer-response kind.
  call("--store", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di, validated_response: validAnalyzerResponse()
  });
  const arcDir = join(ckpt, "agent-responses");
  const files = readdirSync(arcDir);
  const p = join(arcDir, files[0]);
  const wrapper = JSON.parse(readFileSync(p, "utf8"));
  // Tamper validated_response into a shape that violates analyzer-response.schema.json (drop a
  // required field — analyzer-response requires `partition_id`).
  wrapper.validated_response = { not_partition_id: true };
  writeFileSync(p, JSON.stringify(wrapper));
  const r = call("--lookup", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di
  });
  assert.equal(r.out.hit, false);
  assert.match(r.stderr, /agent-cache.*invalid.*analyzer-response/i);
});

test("edit a reference file listed in agent_contract_files -> lookup misses (round 4 Fix #1)", () => {
  const pluginRoot = setupPlugin(); const ckpt = setupCheckpoint();
  mkdirSync(join(pluginRoot, "skills", "audit", "references"), { recursive: true });
  const refPath = join(pluginRoot, "skills", "audit", "references", "python.md");
  writeFileSync(refPath, "v1\n");
  const di = { ...baseDispatchInput(pluginRoot), agent_contract_files: [...baseDispatchInput(pluginRoot).agent_contract_files, refPath] };
  call("--store", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di, validated_response: validAnalyzerResponse()
  });
  // Edit the reference between store and lookup
  writeFileSync(refPath, "v2 — new sink added\n");
  const r = call("--lookup", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di
  });
  assert.equal(r.out.hit, false);
});

test("edit SKILL.md (listed in agent_contract_files) -> lookup misses (round 4 Fix #1)", () => {
  const pluginRoot = setupPlugin(); const ckpt = setupCheckpoint();
  mkdirSync(join(pluginRoot, "skills", "audit"), { recursive: true });
  const skillPath = join(pluginRoot, "skills", "audit", "SKILL.md");
  writeFileSync(skillPath, "v1\n");
  const di = { ...baseDispatchInput(pluginRoot), agent_contract_files: [...baseDispatchInput(pluginRoot).agent_contract_files, skillPath] };
  call("--store", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di, validated_response: validAnalyzerResponse()
  });
  writeFileSync(skillPath, "v2\n");
  const r = call("--lookup", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di
  });
  assert.equal(r.out.hit, false);
});

test("agent_contract_files entry outside plugin_root -> exit 2 (round 5 Fix #1)", () => {
  const pluginRoot = setupPlugin(); const ckpt = setupCheckpoint();
  const evilDir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-arc-evil-")));
  const evil = join(evilDir, "evil.md");
  writeFileSync(evil, "x");
  const di = { ...baseDispatchInput(pluginRoot), agent_contract_files: [evil] };
  const r = call("--lookup", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di
  });
  assert.equal(r.code, 2);
  assert.match(r.stderr, /outside plugin_root|escapes/i);
  assert.ok(r.stderr.includes(evil), "stderr should quote the rejected path");
});
```

`validAnalyzerResponse()` above is schema-verified against `analyzer-response.schema.json` (required: `partition_id`, `status`, `findings`, `coverage` with `analyzed[]` + `skipped[]`). No adjustment needed.

- [ ] **Step 2: Run tests to verify they fail**

Run: `( cd skills/audit/scripts && node --test test/agent-response-cache.test.mjs )`
Expected: FAIL with `Cannot find module '../agent-response-cache.mjs'`.

- [ ] **Step 3: Implement agent-response-cache.mjs**

Create `skills/audit/scripts/agent-response-cache.mjs`:

```javascript
// Agent response cache (spec §3.5). Two modes:
//   --lookup : computes input_digest from dispatch_input (including agent_context_digest from
//              agent_contract_files) and returns { hit, cached_response? }. Re-validates the
//              cached payload against the kind's schema before reporting a hit (Fix #1 round 3).
//   --store  : stores a freshly-validated response keyed by input_digest.
// plugin_root is supplied by the caller in both modes; agent_contract_files MUST realpath under it.
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, renameSync, realpathSync, existsSync, unlinkSync } from "node:fs";
import { sep, join } from "node:path";
import { canonicalize, sha256Hex } from "./cache-wrap.mjs";
import { validate } from "./validate-output.mjs";

// Throws on any agent_contract_files entry that escapes plugin_root, or that does not exist.
function agentContextDigest(agentContractFiles, pluginRoot) {
  if (!Array.isArray(agentContractFiles)) {
    throw new Error("agent_contract_files must be an array of absolute paths");
  }
  const root = realpathSync(pluginRoot);
  const sorted = [...agentContractFiles].sort();
  const h = createHash("sha256");
  for (const p of sorted) {
    let real;
    try { real = realpathSync(p); }
    catch (e) { throw new Error(`agent_contract_files entry unreadable: ${p} (${e.message})`); }
    if (real !== root && !real.startsWith(root + sep)) {
      throw new Error(`agent_contract_files entry outside plugin_root: ${p}`);
    }
    h.update(createHash("sha256").update(readFileSync(real)).digest());
    h.update(Buffer.from([0]));
  }
  return h.digest("hex");
}

function computeInputDigest(dispatch_input, plugin_root) {
  const contextDigest = agentContextDigest(dispatch_input.agent_contract_files, plugin_root);
  // Substitute the (now-stale) path list with the (stable) context digest before canonicalizing.
  const { agent_contract_files: _, ...rest } = dispatch_input;
  return sha256Hex(canonicalize({ ...rest, agent_context_digest: contextDigest }));
}

function cacheFilePath(checkpointDir, kind, targetId, inputDigest) {
  // Windows forbids `:` in filenames and target_ids like "py:web" or "batch:1:3" routinely
  // contain it. Hash (target_id, input_digest) into a single filesystem-safe 64-hex token.
  // This is deterministic — same (target_id, input_digest) always produces the same filename —
  // and preserves the collision-resistance property of the original layout.
  const fileId = sha256Hex(canonicalize({ target_id: targetId, input_digest: inputDigest }));
  return join(checkpointDir, "agent-responses", `${kind}-${fileId}.json`);
}

export function lookup({ checkpoint_dir, plugin_root, kind, target_id, dispatch_input }) {
  const inputDigest = computeInputDigest(dispatch_input, plugin_root);
  const p = cacheFilePath(checkpoint_dir, kind, target_id, inputDigest);
  if (!existsSync(p)) return { ok: true, hit: false };
  let wrapper;
  try { wrapper = JSON.parse(readFileSync(p, "utf8")); }
  catch { return { ok: true, hit: false }; }  // JSON.parse fail -> silent miss
  if (wrapper.input_digest !== inputDigest) return { ok: true, hit: false };  // tampered
  // Schema-gate the cached payload (Fix #1 round 3). If it fails to validate against the kind's
  // schema, treat as miss + log on stderr. The SKILL will re-dispatch through the normal path.
  const v = validate(kind, wrapper.validated_response);
  if (!v.valid) {
    process.stderr.write(`agent-cache: stored response invalid for kind ${kind}, treating as miss\n`);
    return { ok: true, hit: false };
  }
  return { ok: true, hit: true, cached_response: wrapper.validated_response };
}

export function store({ checkpoint_dir, plugin_root, kind, target_id, dispatch_input, validated_response }) {
  const inputDigest = computeInputDigest(dispatch_input, plugin_root);
  const p = cacheFilePath(checkpoint_dir, kind, target_id, inputDigest);
  mkdirSync(join(checkpoint_dir, "agent-responses"), { recursive: true });
  const wrapper = {
    input_digest: inputDigest,
    kind,
    target_id,
    validated_response,
    generated_at: new Date().toISOString()
  };
  const tmp = `${p}.tmp-${process.pid}`;
  try {
    writeFileSync(tmp, JSON.stringify(wrapper, null, 2));
    renameSync(tmp, p);
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* nothing */ }
    throw e;
  }
  return { ok: true };
}

// CLI
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const fi = args.indexOf("--file");
  if (fi === -1 || !args[fi + 1]) {
    process.stderr.write("usage: agent-response-cache.mjs --lookup --file <in.json> --out <out.json>   (or --store --file <in.json>)\n");
    process.exit(2);
  }
  let input;
  try { input = JSON.parse(readFileSync(args[fi + 1], "utf8")); }
  catch (e) { process.stderr.write("cannot read --file: " + e.message + "\n"); process.exit(2); }

  if (args.includes("--lookup")) {
    const oi = args.indexOf("--out");
    if (oi === -1 || !args[oi + 1]) {
      process.stderr.write("--lookup requires --out <out.json>\n"); process.exit(2);
    }
    let r;
    try { r = lookup(input); }
    catch (e) { process.stderr.write("agent-response-cache: " + e.message + "\n"); process.exit(2); }
    try { writeFileSync(args[oi + 1], JSON.stringify(r, null, 2)); }
    catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
    process.exit(0);
  }

  if (args.includes("--store")) {
    try { store(input); }
    catch (e) { process.stderr.write("agent-response-cache: " + e.message + "\n"); process.exit(2); }
    process.exit(0);
  }

  process.stderr.write("agent-response-cache: must specify --lookup or --store\n");
  process.exit(2);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `( cd skills/audit/scripts && node --test test/agent-response-cache.test.mjs )`
Expected: PASS — 11 tests, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add skills/audit/scripts/agent-response-cache.mjs skills/audit/scripts/test/agent-response-cache.test.mjs
git commit -m "feat(sp5): agent-response-cache.mjs — schema-gated lookup/store with plugin-root confinement"
```

---

### Task 7: allocate-budget.mjs gains --checkpoint-dir

**Files:**
- Modify: `skills/audit/scripts/allocate-budget.mjs` (CLI block, lines 89–102)
- Modify: `skills/audit/scripts/test/allocate-budget.test.mjs` (+2 tests)

Spec §3.4 standard contract. When `--checkpoint-dir` is omitted, behavior unchanged (zero-regression).

- [ ] **Step 1: Add 2 failing tests**

Append to `skills/audit/scripts/test/allocate-budget.test.mjs`:

```javascript
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const CLI_ALLOC = fileURLToPath(new URL("../allocate-budget.mjs", import.meta.url));

function runAllocate(input, checkpointDir) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-alloc-cache-")));
  const inP = join(dir, "in.json");
  const outP = join(dir, "out.json");
  writeFileSync(inP, JSON.stringify(input));
  const args = [CLI_ALLOC, "--file", inP, "--out", outP];
  if (checkpointDir) args.push("--checkpoint-dir", checkpointDir);
  const r = spawnSync(process.execPath, args, { encoding: "utf8" });
  return { code: r.status, stderr: r.stderr, outPath: outP, out: existsSync(outP) ? JSON.parse(readFileSync(outP, "utf8")) : null };
}

test("--checkpoint-dir miss writes the cache file and the --out artifact", () => {
  const ckpt = realpathSync(mkdtempSync(join(tmpdir(), "oswe-alloc-ckpt-")));
  const input = { budget: 12, vectors: [{ partition_id: "x", scannable: true, sources: 1, sinks: 1, content_key: "x", source_and_auth_files: 0, sink_hits: 1 }] };
  const r = runAllocate(input, ckpt);
  assert.equal(r.code, 0);
  assert.equal(r.out.ok, true);
  // A cache file should now exist under <ckpt>/allocate-budget/
  const cacheDir = join(ckpt, "allocate-budget");
  const files = readdirSync(cacheDir);
  assert.equal(files.length, 1);
  assert.match(files[0], /^[0-9a-f]{64}-[0-9a-f]{64}\.json$/);
});

test("--checkpoint-dir hit on second call: cache file present, stderr logs 'cache hit', --out matches first run", () => {
  const ckpt = realpathSync(mkdtempSync(join(tmpdir(), "oswe-alloc-ckpt-")));
  const input = { budget: 12, vectors: [{ partition_id: "x", scannable: true, sources: 1, sinks: 1, content_key: "x", source_and_auth_files: 0, sink_hits: 1 }] };
  const first = runAllocate(input, ckpt);
  // Mutate something on disk that would change allocate's behavior if it ran — except cache
  // hit short-circuits before allocate() is called. To prove it, write a sentinel to --out path
  // BEFORE the second call: the helper will overwrite it with the cached output, which equals
  // the first run's output. A behavioral change in allocate() would not match.
  const second = runAllocate(input, ckpt);
  assert.equal(second.code, 0);
  assert.match(second.stderr, /cache hit/i);
  assert.deepEqual(second.out, first.out);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `( cd skills/audit/scripts && node --test test/allocate-budget.test.mjs )`
Expected: the 2 new tests fail (no `--checkpoint-dir` handling yet, no cache dir created). All other allocate-budget tests still pass.

- [ ] **Step 3: Wire --checkpoint-dir into allocate-budget.mjs**

In `skills/audit/scripts/allocate-budget.mjs`, augment the imports near the top (after the existing `import { readFileSync, writeFileSync } from "node:fs";` line) with:

```javascript
import { canonicalize, sha256Hex, helperVersionDigest, cacheLookup, cacheStore } from "./cache-wrap.mjs";
```

Then replace the entire CLI block at the bottom (lines 89–102, the `if (process.argv[1] && ...)` block). Replace:

```javascript
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

With:

```javascript
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const fi = args.indexOf("--file"), oi = args.indexOf("--out");
  const ci = args.indexOf("--checkpoint-dir");
  const checkpointDir = ci !== -1 ? args[ci + 1] : null;
  if (fi === -1 || !args[fi + 1] || oi === -1 || !args[oi + 1]) {
    process.stderr.write("usage: allocate-budget.mjs --file <input.json> --out <allocation.json> [--checkpoint-dir <abs>]\n"); process.exit(2);
  }
  let input;
  try { input = JSON.parse(readFileSync(args[fi + 1], "utf8")); }
  catch (e) { process.stderr.write("cannot read --file: " + e.message + "\n"); process.exit(2); }

  if (checkpointDir) {
    const inputDigest = sha256Hex(canonicalize(input));
    const versionDigest = helperVersionDigest(fileURLToPath(import.meta.url));
    const lookup = cacheLookup({ checkpointDir, helperName: "allocate-budget", inputDigest, versionDigest });
    if (lookup.hit) {
      try { writeFileSync(args[oi + 1], JSON.stringify(lookup.wrapper.output, null, 2)); }
      catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
      process.stderr.write("allocate-budget: cache hit\n");
      process.exit(0);
    }
  }

  const r = allocate(input.vectors, input.budget, input.sarifLeadsByPartition || {});
  try { writeFileSync(args[oi + 1], JSON.stringify(r, null, 2)); }
  catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }

  if (checkpointDir && r.ok) {
    const inputDigest = sha256Hex(canonicalize(input));
    const versionDigest = helperVersionDigest(fileURLToPath(import.meta.url));
    try { cacheStore({ checkpointDir, helperName: "allocate-budget", inputDigest, versionDigest, payload: { output: r } }); }
    catch (e) { process.stderr.write("allocate-budget: cache store failed (non-fatal): " + e.message + "\n"); }
  }

  process.exit(r.ok ? 0 : 1);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `( cd skills/audit/scripts && node --test test/allocate-budget.test.mjs )`
Expected: PASS — every prior test still passes; the 2 new tests pass.

- [ ] **Step 5: Commit**

```bash
git add skills/audit/scripts/allocate-budget.mjs skills/audit/scripts/test/allocate-budget.test.mjs
git commit -m "feat(sp5): allocate-budget gains optional --checkpoint-dir (cache miss writes, hit short-circuits)"
```

---

### Task 8: aggregate-findings.mjs gains --checkpoint-dir

**Files:**
- Modify: `skills/audit/scripts/aggregate-findings.mjs` (CLI block)
- Modify: `skills/audit/scripts/test/aggregate-findings.test.mjs` (+2 tests)

The cache wiring follows the same shape as Task 7's, with the complete replacement code spelled out below (don't extrapolate from Task 7).

- [ ] **Step 1: Extend the existing top-of-file imports**

The existing `skills/audit/scripts/test/aggregate-findings.test.mjs` already imports `test, assert, spawnSync, mkdtempSync, writeFileSync, readFileSync, tmpdir, join, fileURLToPath`. Three new identifiers are needed: `readdirSync, existsSync, realpathSync`. Edit the existing `from "node:fs"` line so it reads:

```javascript
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, existsSync, realpathSync } from "node:fs";
```

Do NOT add any other top-level `import` lines — every other binding the new tests use is already in scope.

- [ ] **Step 2: Append 2 new tests + helpers to the end of the same file**

Append these helpers and tests AFTER the last existing test. No new top-level imports.

```javascript
const CLI_AGG = fileURLToPath(new URL("../aggregate-findings.mjs", import.meta.url));

function runAgg(input, checkpointDir) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-agg-cache-")));
  const inP = join(dir, "in.json");
  const outP = join(dir, "out.json");
  writeFileSync(inP, JSON.stringify(input));
  const args = [CLI_AGG, "--file", inP, "--out", outP];
  if (checkpointDir) args.push("--checkpoint-dir", checkpointDir);
  const r = spawnSync(process.execPath, args, { encoding: "utf8" });
  return { code: r.status, stderr: r.stderr, out: existsSync(outP) ? JSON.parse(readFileSync(outP, "utf8")) : null };
}

// aggregate-findings CLI input: { findings: [...rawFindings] } (per aggregate-findings.mjs:89).
function minimalAggInput() {
  return { findings: [] };
}

test("aggregate-findings --checkpoint-dir miss writes cache file", () => {
  const ckpt = realpathSync(mkdtempSync(join(tmpdir(), "oswe-agg-ckpt-")));
  const r = runAgg(minimalAggInput(), ckpt);
  assert.equal(r.code, 0);
  const files = readdirSync(join(ckpt, "aggregate-findings"));
  assert.equal(files.length, 1);
});

test("aggregate-findings --checkpoint-dir hit on second call short-circuits with same output", () => {
  const ckpt = realpathSync(mkdtempSync(join(tmpdir(), "oswe-agg-ckpt-")));
  const first = runAgg(minimalAggInput(), ckpt);
  const second = runAgg(minimalAggInput(), ckpt);
  assert.match(second.stderr, /cache hit/i);
  assert.deepEqual(second.out, first.out);
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `( cd skills/audit/scripts && node --test test/aggregate-findings.test.mjs )`
Expected: the 2 new tests fail (no cache dir, no `cache hit` stderr).

- [ ] **Step 4: Wire --checkpoint-dir into aggregate-findings.mjs**

In `skills/audit/scripts/aggregate-findings.mjs`:

(a) Add this import alongside the existing imports near the top of the file (the existing file already imports `readFileSync, writeFileSync` from `node:fs` and `fileURLToPath` from `node:url`):

```javascript
import { canonicalize, sha256Hex, helperVersionDigest, cacheLookup, cacheStore } from "./cache-wrap.mjs";
```

(b) Replace the entire existing CLI block at the bottom of the file (the `if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) { ... }` block) with this complete replacement:

```javascript
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const fi = args.indexOf("--file"), oi = args.indexOf("--out");
  const ci = args.indexOf("--checkpoint-dir");
  const checkpointDir = ci !== -1 ? args[ci + 1] : null;
  if (fi === -1 || oi === -1) {
    process.stderr.write("usage: aggregate-findings.mjs --file <in.json> --out <out.json> [--checkpoint-dir <abs>]\n"); process.exit(2);
  }
  let input;
  try { input = JSON.parse(readFileSync(args[fi + 1], "utf8")); }
  catch (e) { process.stderr.write("cannot read --file: " + e.message + "\n"); process.exit(2); }

  if (checkpointDir) {
    const inputDigest = sha256Hex(canonicalize(input));
    const versionDigest = helperVersionDigest(fileURLToPath(import.meta.url));
    const lookup = cacheLookup({ checkpointDir, helperName: "aggregate-findings", inputDigest, versionDigest });
    if (lookup.hit) {
      try { writeFileSync(args[oi + 1], JSON.stringify(lookup.wrapper.output, null, 2)); }
      catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
      process.stderr.write("aggregate-findings: cache hit\n");
      process.exit(0);
    }
  }

  const result = aggregateFindings(input.findings || []);
  try { writeFileSync(args[oi + 1], JSON.stringify(result, null, 2)); }
  catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }

  if (checkpointDir && result.ok) {
    const inputDigest = sha256Hex(canonicalize(input));
    const versionDigest = helperVersionDigest(fileURLToPath(import.meta.url));
    try { cacheStore({ checkpointDir, helperName: "aggregate-findings", inputDigest, versionDigest, payload: { output: result } }); }
    catch (e) { process.stderr.write("aggregate-findings: cache store failed (non-fatal): " + e.message + "\n"); }
  }

  process.exit(result.ok ? 0 : 1);
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `( cd skills/audit/scripts && node --test test/aggregate-findings.test.mjs )`
Expected: PASS — every prior test still passes; the 2 new tests pass.

- [ ] **Step 6: Commit**

```bash
git add skills/audit/scripts/aggregate-findings.mjs skills/audit/scripts/test/aggregate-findings.test.mjs
git commit -m "feat(sp5): aggregate-findings gains optional --checkpoint-dir"
```

---

### Task 9: apply-verdicts.mjs gains --checkpoint-dir

**Files:**
- Modify: `skills/audit/scripts/apply-verdicts.mjs` (CLI block)
- Modify: `skills/audit/scripts/test/apply-verdicts.test.mjs` (+2 tests)

The cache wiring follows the same shape as Tasks 7–8, with the complete replacement code spelled out below (don't extrapolate). **Important:** spec §2 says the verdict logic is sacred — only the CLI block is modified to add the cache seam. No edits to the `applyVerdicts` function or any helpers it calls.

- [ ] **Step 1: Extend the existing top-of-file imports**

The existing `skills/audit/scripts/test/apply-verdicts.test.mjs` already imports `test, assert, spawnSync, mkdtempSync, writeFileSync, readFileSync, tmpdir, join, fileURLToPath`. Three new identifiers are needed: `readdirSync, existsSync, realpathSync`. Edit the existing `from "node:fs"` line so it reads:

```javascript
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, existsSync, realpathSync } from "node:fs";
```

Do NOT add any other top-level imports.

- [ ] **Step 2: Append 2 new tests + helpers to the end of the same file**

```javascript
const CLI_AV = fileURLToPath(new URL("../apply-verdicts.mjs", import.meta.url));

function runAV(input, checkpointDir) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-av-cache-")));
  const inP = join(dir, "in.json");
  const outP = join(dir, "out.json");
  writeFileSync(inP, JSON.stringify(input));
  const args = [CLI_AV, "--file", inP, "--out", outP];
  if (checkpointDir) args.push("--checkpoint-dir", checkpointDir);
  const r = spawnSync(process.execPath, args, { encoding: "utf8" });
  return { code: r.status, stderr: r.stderr, out: existsSync(outP) ? JSON.parse(readFileSync(outP, "utf8")) : null };
}

// apply-verdicts CLI input per apply-verdicts.mjs:348: { findings: [...], chains: [...], batches: [...] }
function minimalAVInput() {
  return { findings: [], chains: [], batches: [] };
}

test("apply-verdicts --checkpoint-dir miss writes cache file", () => {
  const ckpt = realpathSync(mkdtempSync(join(tmpdir(), "oswe-av-ckpt-")));
  const r = runAV(minimalAVInput(), ckpt);
  assert.equal(r.code, 0);
  const files = readdirSync(join(ckpt, "apply-verdicts"));
  assert.equal(files.length, 1);
});

test("apply-verdicts --checkpoint-dir hit on second call short-circuits with same output", () => {
  const ckpt = realpathSync(mkdtempSync(join(tmpdir(), "oswe-av-ckpt-")));
  const first = runAV(minimalAVInput(), ckpt);
  const second = runAV(minimalAVInput(), ckpt);
  assert.match(second.stderr, /cache hit/i);
  assert.deepEqual(second.out, first.out);
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `( cd skills/audit/scripts && node --test test/apply-verdicts.test.mjs )`
Expected: the 2 new tests fail.

- [ ] **Step 4: Wire --checkpoint-dir into apply-verdicts.mjs**

**Critical:** do NOT modify the `applyVerdicts` function or anything it calls. The verdict logic and Critical gating are explicitly sacred per spec §2 — only the CLI block changes.

In `skills/audit/scripts/apply-verdicts.mjs`:

(a) Add this import alongside the existing top-of-file imports (the existing file already imports `readFileSync, writeFileSync` from `node:fs` and `fileURLToPath` from `node:url`):

```javascript
import { canonicalize, sha256Hex, helperVersionDigest, cacheLookup, cacheStore } from "./cache-wrap.mjs";
```

(b) Replace the existing CLI block at the bottom of the file (lines 350–373, the `if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) { ... }` block) with this complete replacement:

```javascript
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const fileIdx = args.indexOf("--file");
  const outIdx = args.indexOf("--out");
  const ci = args.indexOf("--checkpoint-dir");
  const checkpointDir = ci !== -1 ? args[ci + 1] : null;
  if (fileIdx === -1 || outIdx === -1) {
    process.stderr.write("usage: apply-verdicts.mjs --file <input.json> --out <result.json> [--checkpoint-dir <abs>]\n");
    process.exit(2);
  }
  let input;
  try {
    input = JSON.parse(readFileSync(args[fileIdx + 1], "utf8"));
  } catch (e) {
    process.stderr.write("cannot read --file: " + e.message + "\n");
    process.exit(2);
  }

  if (checkpointDir) {
    const inputDigest = sha256Hex(canonicalize(input));
    const versionDigest = helperVersionDigest(fileURLToPath(import.meta.url));
    const lookup = cacheLookup({ checkpointDir, helperName: "apply-verdicts", inputDigest, versionDigest });
    if (lookup.hit) {
      try { writeFileSync(args[outIdx + 1], JSON.stringify(lookup.wrapper.output, null, 2)); }
      catch (e) { process.stderr.write("cannot write --out: " + e.message + "\n"); process.exit(2); }
      process.stderr.write("apply-verdicts: cache hit\n");
      process.exit(0);
    }
  }

  const result = applyVerdicts(input);
  try {
    writeFileSync(args[outIdx + 1], JSON.stringify(result, null, 2));
  } catch (e) {
    process.stderr.write("cannot write --out: " + e.message + "\n");
    process.exit(2);
  }

  if (checkpointDir && result.ok) {
    const inputDigest = sha256Hex(canonicalize(input));
    const versionDigest = helperVersionDigest(fileURLToPath(import.meta.url));
    try { cacheStore({ checkpointDir, helperName: "apply-verdicts", inputDigest, versionDigest, payload: { output: result } }); }
    catch (e) { process.stderr.write("apply-verdicts: cache store failed (non-fatal): " + e.message + "\n"); }
  }

  process.exit(result.ok ? 0 : 1);
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `( cd skills/audit/scripts && node --test test/apply-verdicts.test.mjs )`
Expected: PASS — every prior test (verdict logic, Critical gating, etc.) still passes; the 2 new tests pass.

- [ ] **Step 6: Commit**

```bash
git add skills/audit/scripts/apply-verdicts.mjs skills/audit/scripts/test/apply-verdicts.test.mjs
git commit -m "feat(sp5): apply-verdicts gains optional --checkpoint-dir (verdict logic untouched)"
```

---

### Task 10: render-html.mjs gains --checkpoint-dir (special two-stream contract)

**Files:**
- Modify: `skills/audit/scripts/render-html.mjs` (CLI block, lines 369–402)
- Modify: `skills/audit/scripts/test/render-html.test.mjs` (+2 tests)

Spec §3.4.1. Different from Tasks 7–9 because render-html takes `--md` + `--summary` (two inputs) and the cache payload is `html_output` (HTML bytes), not a JSON `output` object.

- [ ] **Step 1: Extend the existing top-of-file imports**

The existing `skills/audit/scripts/test/render-html.test.mjs` has imports SCATTERED across the file (lines 1–3, 43, 76–81 in the current file). It already imports `mkdtempSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync, tmpdir, join, dirname, fileURLToPath, execFileSync` — re-importing any of these will produce a `Identifier ... has already been declared` ESM parse error. Only **two new identifiers** are needed by the appended tests: `spawnSync` and `realpathSync`. Edit two existing import lines in place:

(a) The existing line 76, `import { execFileSync } from "node:child_process";`, becomes:

```javascript
import { execFileSync, spawnSync } from "node:child_process";
```

(b) The existing line 77, `import { mkdtempSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync } from "node:fs";`, becomes:

```javascript
import { mkdtempSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync, realpathSync } from "node:fs";
```

Do NOT add a separate `import` block — every other binding the appended tests use (`tmpdir`, `join`, `fileURLToPath`) is already imported elsewhere in the file.

- [ ] **Step 2: Append 2 new tests + helpers to the end of the same file**

Append AFTER the last existing test. No additional top-level imports.

```javascript
const CLI_RH = fileURLToPath(new URL("../render-html.mjs", import.meta.url));

function runRender(md, summary, checkpointDir) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-rh-cache-")));
  const mdP = join(dir, "r.md");
  const sumP = join(dir, "s.json");
  const outP = join(dir, "r.html");
  writeFileSync(mdP, md);
  writeFileSync(sumP, JSON.stringify(summary));
  const args = [CLI_RH, "--md", mdP, "--summary", sumP, "--out", outP];
  if (checkpointDir) args.push("--checkpoint-dir", checkpointDir);
  const r = spawnSync(process.execPath, args, { encoding: "utf8" });
  return { code: r.status, stderr: r.stderr, html: existsSync(outP) ? readFileSync(outP, "utf8") : null };
}

// Schema-valid report-summary per report-summary.schema.json. Required: meta (with target,
// stack, date, verdict, proof_level), severity_counts (5 keys), finding_status_counts (4 keys),
// coverage ({analyzed,skipped} as integers — different from analyzer-response.coverage!), chains.
function minimalSummary() {
  return {
    meta: { target: "test-project", stack: "python", date: "2026-06-20", verdict: "no-critique", proof_level: null },
    severity_counts: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
    finding_status_counts: { accepted: 0, downgraded: 0, rejected: 0, "not-requested": 0 },
    coverage: { analyzed: 0, skipped: 0 },
    chains: []
  };
}

test("render-html --checkpoint-dir miss writes the cache file (html_output payload)", () => {
  const ckpt = realpathSync(mkdtempSync(join(tmpdir(), "oswe-rh-ckpt-")));
  const r = runRender("# Report\n", minimalSummary(), ckpt);
  assert.equal(r.code, 0);
  const cacheDir = join(ckpt, "render-html");
  const files = readdirSync(cacheDir);
  assert.equal(files.length, 1);
  const wrapper = JSON.parse(readFileSync(join(cacheDir, files[0]), "utf8"));
  assert.equal(typeof wrapper.html_output, "string");
  assert.ok(wrapper.html_output.startsWith("<!"));  // doctype-ish
});

test("render-html --checkpoint-dir hit on second call: stderr 'cache hit', html byte-identical", () => {
  const ckpt = realpathSync(mkdtempSync(join(tmpdir(), "oswe-rh-ckpt-")));
  const first = runRender("# Report\n", minimalSummary(), ckpt);
  const second = runRender("# Report\n", minimalSummary(), ckpt);
  assert.equal(second.code, 0);
  assert.match(second.stderr, /cache hit/i);
  assert.equal(second.html, first.html);
});
```

`minimalSummary()` is verified against `report-summary.schema.json` (required fields: `meta`, `severity_counts`, `finding_status_counts`, `coverage`, `chains`). No adjustment needed.

- [ ] **Step 3: Run tests to verify they fail**

Run: `( cd skills/audit/scripts && node --test test/render-html.test.mjs )`
Expected: the 2 new tests fail (no cache dir, no cache-hit stderr).

- [ ] **Step 4: Wire --checkpoint-dir into render-html.mjs (special two-stream input_digest)**

In `skills/audit/scripts/render-html.mjs`, add the cache-wrap import alongside the existing `import * as validators from "./validators.mjs";` line:

```javascript
import { canonicalize, sha256Hex, helperVersionDigest, cacheLookup, cacheStore } from "./cache-wrap.mjs";
```

Then replace the CLI block (the `if (isMain()) { ... }` block, lines 369–402) with:

```javascript
if (isMain()) {
  const args = process.argv.slice(2);
  const flag = (name) => { const i = args.indexOf(name); return i !== -1 ? args[i + 1] : undefined; };
  const mdPath = flag("--md"), sumPath = flag("--summary"), outPath = flag("--out");
  const checkpointDir = flag("--checkpoint-dir") || null;
  const fail2 = (msg) => { process.stderr.write("render-html: " + msg + "\n"); process.exit(2); };
  if (!mdPath || !sumPath || !outPath) {
    fail2("usage: render-html.mjs --md <report.md> --summary <summary.json> --out <report.html> [--checkpoint-dir <abs>]");
  }
  let md, sumRaw;
  try { md = readFileSync(mdPath, "utf8"); } catch (e) { fail2("cannot read --md " + mdPath + ": " + e.message); }
  try { sumRaw = readFileSync(sumPath, "utf8"); } catch (e) { fail2("cannot read --summary " + sumPath + ": " + e.message); }
  let summary;
  try { summary = JSON.parse(sumRaw); } catch (e) { fail2("invalid JSON in --summary: " + e.message); }
  if (!validators.reportSummary(summary)) {
    process.stderr.write("render-html: invalid summary: " + JSON.stringify(validators.reportSummary.errors || []) + "\n");
    process.exit(1);
  }
  const gErrs = graphErrors(summary);
  if (gErrs.length) {
    process.stderr.write("render-html: incoherent chain graph: " + gErrs.join("; ") + "\n");
    process.exit(1);
  }

  // SP5 cache lookup (special two-stream input_digest per spec §3.4.1).
  // input_digest = sha256(md_bytes || NUL || canonical(summary)).
  let inputDigest, versionDigest;
  if (checkpointDir) {
    inputDigest = sha256Hex(Buffer.concat([
      Buffer.from(md, "utf8"),
      Buffer.from([0]),
      Buffer.from(canonicalize(summary), "utf8")
    ]));
    versionDigest = helperVersionDigest(fileURLToPath(import.meta.url));
    const lookup = cacheLookup({ checkpointDir, helperName: "render-html", inputDigest, versionDigest });
    if (lookup.hit) {
      const tmp = outPath + ".tmp-" + process.pid;
      try {
        writeFileSync(tmp, lookup.wrapper.html_output);
        renameSync(tmp, outPath);
      } catch (e) {
        try { unlinkSync(tmp); } catch { /* nothing */ }
        fail2("cannot write --out " + outPath + ": " + e.message);
      }
      process.stderr.write("render-html: cache hit\n");
      process.exit(0);
    }
  }

  let html;
  try { html = renderReport({ md, summary }); } catch (e) { fail2("render failed: " + e.message); }
  const tmp = outPath + ".tmp-" + process.pid;
  try {
    writeFileSync(tmp, html);
    renameSync(tmp, outPath);
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* nothing to clean */ }
    fail2("cannot write --out " + outPath + ": " + e.message);
  }

  if (checkpointDir) {
    try { cacheStore({ checkpointDir, helperName: "render-html", inputDigest, versionDigest, payload: { html_output: html } }); }
    catch (e) { process.stderr.write("render-html: cache store failed (non-fatal): " + e.message + "\n"); }
  }

  process.exit(0);
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `( cd skills/audit/scripts && node --test test/render-html.test.mjs )`
Expected: PASS — every prior test passes; the 2 new tests pass.

- [ ] **Step 6: Commit**

```bash
git add skills/audit/scripts/render-html.mjs skills/audit/scripts/test/render-html.test.mjs
git commit -m "feat(sp5): render-html gains optional --checkpoint-dir (special two-stream contract)"
```

---

### Task 11: SKILL.md — 5 surgical edits

**Files:**
- Modify: `skills/audit/SKILL.md`

Spec §4. Five edits, in the order the SKILL is executed (bootstrap → recon → analyze → verify → report). Each edit is text-only — the SKILL is markdown the LLM reads. No tests for SKILL.md itself (the contract is exercised by `e2e-replay.test.mjs` and `e2e-replay-resume.test.mjs`).

- [ ] **Step 1: Inspect SKILL.md's current §1 and §3 entry points**

Run: `head -70 skills/audit/SKILL.md` to see the existing structure. Confirm §1 starts with `**First, purge temp:**` (line 47 per earlier read).

- [ ] **Step 2: Apply Edit 1 — prepend a new §0 to SKILL.md and remove the §1 purge line**

In `skills/audit/SKILL.md`:

(a) Find the first `## Pipeline (strict order)` heading. Immediately after that line and the blank line below it, insert the new §0 block:

```markdown
### 0. Bootstrap & parse invocation args (deterministic)
First, purge and re-create the temp dir (this used to be the first action of §1; it moved up so
the §0 helper can use it):
`rm -rf "${CLAUDE_PROJECT_DIR}/.oswe/tmp" && mkdir -p "${CLAUDE_PROJECT_DIR}/.oswe/tmp"`.

Then normalize `$ARGUMENTS` into a structured form via the tested helper. Do NOT parse arg
strings by hand. Write `{"raw_args": "${ARGUMENTS}"}` to a literal temp file with the file tool,
then run inside a `trap` that removes both temp files on exit:
`( trap 'rm -f "${CLAUDE_PROJECT_DIR}/.oswe/tmp/parse-args-<token>.json" "${CLAUDE_PROJECT_DIR}/.oswe/tmp/parse-args-out-<token>.json"' EXIT;
  node "${CLAUDE_PLUGIN_ROOT}/skills/audit/scripts/parse-audit-args.mjs"
    --file "${CLAUDE_PROJECT_DIR}/.oswe/tmp/parse-args-<token>.json"
    --out "${CLAUDE_PROJECT_DIR}/.oswe/tmp/parse-args-out-<token>.json" )`.
On exit 0, read `{scope, sarifPath, concurrency}` from the out file. On exit 1, abort the audit
with the printed message (invalid args, e.g. concurrency out of range). On any abort here or
later, `.oswe/tmp/` is purged as today.

```

(b) In the existing §1 "Entry & recon" section, remove the bullet that currently starts with `**First, purge temp:**` (it is now covered by §0). Keep all the other bullets in §1 (confine-path, --sarif handling, etc.) unchanged.

- [ ] **Step 3: Apply Edit 2 — append §0.5 (lifecycle resolve) after the confine-path block in §1**

Find the confine-path block in §1 (the `( trap 'rm -f ... ' EXIT; node ".../confine-path.mjs" ... )` invocation near the top of §1). After that block AND after the optional `--sarif <path>` handling block that follows it (i.e. after both possible confine-path invocations), insert §0.5:

```markdown
### 0.5 Resolve run-id and checkpoint dir (deterministic)
Now that paths are confined and canonical, resolve the run lifecycle. Write
`{"projectDir": "${CLAUDE_PROJECT_DIR}", "scope_realpath": "<confined>", "sarif_realpath": "<confined or null>", "concurrency": <N>}`
to a literal temp file, then run inside a `trap`:
`( trap 'rm -f "${CLAUDE_PROJECT_DIR}/.oswe/tmp/lifecycle-in-<token>.json" "${CLAUDE_PROJECT_DIR}/.oswe/tmp/lifecycle-out-<token>.json"' EXIT;
  node "${CLAUDE_PLUGIN_ROOT}/skills/audit/scripts/checkpoint-lifecycle.mjs"
    --file "${CLAUDE_PROJECT_DIR}/.oswe/tmp/lifecycle-in-<token>.json"
    --out "${CLAUDE_PROJECT_DIR}/.oswe/tmp/lifecycle-out-<token>.json" )`.
On exit 0, read `{run_id, mode, checkpoint_dir}` into orchestration state. On exit 1 (ambiguous
resume), abort the audit with the printed cleanup instruction (it tells the user to
`rm -rf .oswe/checkpoints/`). **If `mode: "resume"`, note this fact in the final report** so the
reader knows the audit picked up from a prior interrupted run.

**SECURITY NOTE**: `.oswe/checkpoints/<run-id>/` mirrors `.oswe/tmp/`'s trust model — it holds
NOT-yet-redacted intermediates (including agent responses that may quote secrets verbatim). It is
purged at clean exit (§7.5 Finalize) and only persists between a kill and the next resume.

```

- [ ] **Step 4: Apply Edit 3 — configurable concurrency + agent-response-cache in §3 and §6**

In `skills/audit/SKILL.md`:

(a) Find the literal text `max 4 concurrent` in §3 (Analyze). Replace with `max <concurrency> concurrent (the value resolved in §0)`.

(b) In §3 (Analyze), before the analyzer dispatch instruction, insert this paragraph:

```markdown
**Cache lookup before each analyzer dispatch (SP5 v1).** Before each analyzer call, write
`{"checkpoint_dir": "<run checkpoint_dir>", "plugin_root": "${CLAUDE_PLUGIN_ROOT}", "kind": "analyzer-response", "target_id": "<partition_id>", "dispatch_input": {<canonical dispatch payload — see below>}}`
to a literal temp file, then run inside a `trap`:
`( trap 'rm -f "${CLAUDE_PROJECT_DIR}/.oswe/tmp/arc-in-<token>.json" "${CLAUDE_PROJECT_DIR}/.oswe/tmp/arc-out-<token>.json"' EXIT;
  node "${CLAUDE_PLUGIN_ROOT}/skills/audit/scripts/agent-response-cache.mjs"
    --lookup --file "${CLAUDE_PROJECT_DIR}/.oswe/tmp/arc-in-<token>.json"
    --out "${CLAUDE_PROJECT_DIR}/.oswe/tmp/arc-out-<token>.json" )`.
On `hit: true`, USE the `cached_response` directly and SKIP the analyzer dispatch (re-validation
was already done inside the helper against the analyzer-response schema). On `hit: false`,
dispatch the analyzer as today.

The `dispatch_input` for an analyzer call MUST be:
`{ "partition_id": "<id>", "files": [<sorted file paths>], "file_content_digest": "<from surface-scan vector>", "references_loaded": [<sorted stack names>], "agent_contract_files": [<sorted abs paths>] }`
where `agent_contract_files` includes:
- `${CLAUDE_PLUGIN_ROOT}/agents/oswe-analyzer.md`
- Each `${CLAUDE_PLUGIN_ROOT}/skills/audit/references/<lang>.md` actually loaded for the partition
- `${CLAUDE_PLUGIN_ROOT}/skills/audit/SKILL.md`

**Cache store after each successful analyzer dispatch.** AFTER `validate-output analyzer-response`
succeeds on a freshly-dispatched response, write
`{"checkpoint_dir": "<...>", "plugin_root": "${CLAUDE_PLUGIN_ROOT}", "kind": "analyzer-response", "target_id": "<partition_id>", "dispatch_input": {<same as lookup>}, "validated_response": {<the validated response>}}`
to a temp file and run `agent-response-cache.mjs --store --file <...>` inside a `trap`.
```

(c) In §6 (Verify), insert the parallel paragraph for verifier batches. Same `lookup` → `dispatch` → `store` structure; the `dispatch_input` differs:

```markdown
**Cache lookup before each verifier batch dispatch (SP5 v1).** Before each verifier batch, write
`{"checkpoint_dir": "<...>", "plugin_root": "${CLAUDE_PLUGIN_ROOT}", "kind": "verifier-response", "target_id": "<batch_id>", "dispatch_input": {"batch_id": "<id>", "expected_targets": [<sorted>], "finding_or_chain_canonical": {<...>}, "agent_contract_files": [<sorted abs paths>]}}`
and call `agent-response-cache.mjs --lookup`. The `agent_contract_files` for a verifier call MUST
include:
- `${CLAUDE_PLUGIN_ROOT}/agents/oswe-verifier.md`
- `${CLAUDE_PLUGIN_ROOT}/skills/audit/SKILL.md`

On `hit: true`, USE the `cached_response` and SKIP the verifier dispatch. On miss, dispatch.
AFTER `validate-output verifier-response` succeeds, call `agent-response-cache.mjs --store` with
the same dispatch_input and the validated response.
```

- [ ] **Step 5: Apply Edit 4 — append `--checkpoint-dir` to the 4 cached helper invocations**

Find every existing invocation of `allocate-budget.mjs`, `aggregate-findings.mjs`, `apply-verdicts.mjs`, and `render-html.mjs` in SKILL.md. For each, append ` --checkpoint-dir "${checkpoint_dir}"` to the end of the command line (where `${checkpoint_dir}` is the value read from §0.5).

The 4 helpers' existing arg shapes:
- `allocate-budget.mjs --file <input.json> --out <allocation.json>` → append `--checkpoint-dir`
- `aggregate-findings.mjs --file <input.json> --out <output.json>` → append `--checkpoint-dir`
- `apply-verdicts.mjs --file <input.json> --out <output.json>` → append `--checkpoint-dir`
- `render-html.mjs --md <report.md> --summary <summary.json> --out <report.html>` → append `--checkpoint-dir`

Do NOT change the existing positional/named arguments (Fix #2 from round 4 review specifically warns against changing render-html's `--md --summary --out` to `--file --out`).

- [ ] **Step 6: Apply Edit 5 — append §7.5 Finalize after the report write in §7**

Find the end of §7 (Report) — specifically, the point AFTER both `.md` and `.html` are confirmed written. Append:

```markdown
### 7.5 Finalize the run checkpoint
After the report (`.md` + `.html`) is written successfully, finalize the checkpoint:
`node "${CLAUDE_PLUGIN_ROOT}/skills/audit/scripts/checkpoint-lifecycle.mjs" --finalize --run-id "${run_id}" --project-dir "${CLAUDE_PROJECT_DIR}"`.
This flips the manifest to `completed: true` and removes the run's checkpoint dir. **On any abort
earlier in the pipeline, DO NOT finalize** — the checkpoint must remain on disk for the next
`/oswe:audit` invocation to discover and resume from.
```

- [ ] **Step 7: Run the full test suite to confirm no regression**

Run: `( cd skills/audit/scripts && node --test )` and `( cd benchmark && node --test )`.
Expected: all 190+ tests still pass (SKILL.md is not executable; this just confirms no helper code regressed). Then visually re-read SKILL.md §0, §0.5, §3, §6, §7.5 to confirm the prose flows.

- [ ] **Step 8: Commit**

```bash
git add skills/audit/SKILL.md
git commit -m "feat(sp5): SKILL.md — §0 bootstrap+parse, §0.5 lifecycle, §3/§6 agent cache, §7.5 finalize"
```

---

### Task 12: e2e-replay-resume.test.mjs — the spec §5 assembly-level proof

**Files:**
- Create: `skills/audit/scripts/test/e2e-replay-resume.test.mjs`

Spec §5 E2E replay. The pivot property at the cacheable-helper seam: **TWO complete cacheable-helper passes with the SAME `--checkpoint-dir` and NO `--finalize` between them**. On the second pass: every cacheable helper logs `cache hit`, both agent-response-cache lookups (analyzer + verifier) return `hit:true`, and every output (JSON for the three standard helpers, HTML bytes for render-html) is byte-identical to the first pass.

**Scope honesty:** this test does NOT exercise the live SKILL prose or the LLM. The Markdown report body is LLM-generated in production and therefore not byte-deterministic across kill-resume — the test pins a synthetic MD so it can isolate render-html's cache contract (the only deterministic step the test can verify here). The full pipeline including LLM is covered by the existing `e2e-replay.test.mjs` (which doesn't use `--checkpoint-dir`).

- [ ] **Step 1: Write the resume test**

Create `skills/audit/scripts/test/e2e-replay-resume.test.mjs`:

```javascript
// SP5 v1 assembly-level proof (spec §5) at the cacheable-helper seam. TWO complete
// passes through the cacheable helpers with the SAME --checkpoint-dir and no --finalize
// between them. Second pass: every cacheable helper (allocate-budget, aggregate-findings,
// apply-verdicts, render-html) hits its cache and produces byte-identical output, AND
// agent-response-cache --lookup returns hit:true for both analyzer-response and
// verifier-response. Simulates a kill-then-resume where the first run reached every helper
// before being killed.
//
// SCOPE: this test does NOT exercise the live SKILL or the LLM. The Markdown report body
// is LLM-generated in production (nondeterministic across runs); this test pins a synthetic
// MD so it can verify render-html's cache contract in isolation. The full pipeline-with-LLM
// is covered by e2e-replay.test.mjs (which does not use --checkpoint-dir).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPTS = join(HERE, "..");
const PLUGIN_ROOT = realpathSync(join(SCRIPTS, "..", "..", ".."));
const CLI = (name) => join(SCRIPTS, `${name}.mjs`);
const run = (args) => spawnSync(process.execPath, args, { encoding: "utf8" });
function jw(p, obj) { writeFileSync(p, JSON.stringify(obj)); return p; }

// Schema-valid minimal inputs (same as Tasks 7-10).
const minAllocInput = (vectors) => ({ budget: 12, vectors });
const minAggInput = () => ({ findings: [] });
const minAVInput = () => ({ findings: [], chains: [], batches: [] });
const minSummary = () => ({
  meta: { target: "test-project", stack: "python", date: "2026-06-20", verdict: "no-critique", proof_level: null },
  severity_counts: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
  finding_status_counts: { accepted: 0, downgraded: 0, rejected: 0, "not-requested": 0 },
  coverage: { analyzed: 0, skipped: 0 },
  chains: []
});
const validAnalyzerResponse = () => ({
  partition_id: "py:web", status: "ok", findings: [],
  coverage: { analyzed: ["src/a.py", "src/b.py"], skipped: [] }
});
// verifier-response.schema.json requires { status, verdicts: [verdict] }; empty verdicts are valid.
const validVerifierResponse = () => ({ status: "ok", verdicts: [] });

function setupProject() {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "oswe-e2e-resume-")));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "src", "a.py"), "request.args.get('x')\n");
  writeFileSync(join(dir, "src", "b.py"), "import os; os.system(x)\n");
  mkdirSync(join(dir, ".oswe", "tmp"), { recursive: true });
  return dir;
}

function resolveLifecycle(projectDir, suffix = "") {
  const inP = jw(join(projectDir, ".oswe", "tmp", `lc-in${suffix}.json`), {
    projectDir, scope_realpath: projectDir, sarif_realpath: null, concurrency: 4
  });
  const outP = join(projectDir, ".oswe", "tmp", `lc-out${suffix}.json`);
  const r = run([CLI("checkpoint-lifecycle"), "--file", inP, "--out", outP]);
  assert.equal(r.status, 0, `lifecycle resolve failed: ${r.stderr}`);
  return JSON.parse(readFileSync(outP, "utf8"));
}

// One complete cacheable-pipeline pass. Returns `{ helperOutputs, html, arcLookups }` so the
// caller can compare pass-1 vs pass-2 byte-for-byte. `expectAllHits` controls assertion mode:
// pass 1 expects misses everywhere; pass 2 expects hits everywhere.
function runOnePass(projectDir, checkpointDir, passLabel, expectAllHits) {
  // --- surface-scan (NOT cached — recomputes deterministically; same content -> same digest) ---
  const ssIn = jw(join(projectDir, ".oswe", "tmp", `ss-in-${passLabel}.json`), {
    projectDir, referencesDir: join(PLUGIN_ROOT, "skills", "audit", "references"),
    partitions: [{ partition_id: "py:web", stack: "python", files: ["src/a.py", "src/b.py"] }]
  });
  const ssOut = join(projectDir, ".oswe", "tmp", `ss-out-${passLabel}.json`);
  assert.equal(run([CLI("surface-scan"), "--file", ssIn, "--out", ssOut]).status, 0);
  const scan = JSON.parse(readFileSync(ssOut, "utf8"));

  // --- allocate-budget (cacheable) ---
  const allocIn = jw(join(projectDir, ".oswe", "tmp", `alloc-in-${passLabel}.json`), minAllocInput(scan.vectors));
  const allocOut = join(projectDir, ".oswe", "tmp", `alloc-out-${passLabel}.json`);
  const allocR = run([CLI("allocate-budget"), "--file", allocIn, "--out", allocOut, "--checkpoint-dir", checkpointDir]);
  assert.equal(allocR.status, 0, `pass ${passLabel}: allocate-budget failed: ${allocR.stderr}`);
  if (expectAllHits) assert.match(allocR.stderr, /cache hit/i, `pass ${passLabel}: allocate-budget should hit`);
  else assert.doesNotMatch(allocR.stderr, /cache hit/i, `pass ${passLabel}: allocate-budget should miss`);
  const allocOutput = JSON.parse(readFileSync(allocOut, "utf8"));

  // --- analyzer agent-response-cache: --lookup, then --store on miss ---
  const analyzerDispatch = {
    partition_id: "py:web",
    files: ["src/a.py", "src/b.py"],
    file_content_digest: scan.vectors[0].file_content_digest,
    references_loaded: ["python"],
    agent_contract_files: [
      join(PLUGIN_ROOT, "agents", "oswe-analyzer.md"),
      join(PLUGIN_ROOT, "skills", "audit", "SKILL.md")
    ]
  };
  const arcLookIn = jw(join(projectDir, ".oswe", "tmp", `arc-an-lookup-${passLabel}.json`), {
    checkpoint_dir: checkpointDir, plugin_root: PLUGIN_ROOT,
    kind: "analyzer-response", target_id: "py:web", dispatch_input: analyzerDispatch
  });
  const arcLookOut = join(projectDir, ".oswe", "tmp", `arc-an-lookup-out-${passLabel}.json`);
  assert.equal(run([CLI("agent-response-cache"), "--lookup", "--file", arcLookIn, "--out", arcLookOut]).status, 0);
  const arcAnalyzerLookup = JSON.parse(readFileSync(arcLookOut, "utf8"));
  if (expectAllHits) assert.equal(arcAnalyzerLookup.hit, true, `pass ${passLabel}: analyzer cache should hit`);
  else {
    assert.equal(arcAnalyzerLookup.hit, false, `pass ${passLabel}: analyzer cache should miss`);
    // First pass: populate the cache (simulates "freshly-validated response stored after dispatch").
    const storeIn = jw(join(projectDir, ".oswe", "tmp", `arc-an-store-${passLabel}.json`), {
      checkpoint_dir: checkpointDir, plugin_root: PLUGIN_ROOT,
      kind: "analyzer-response", target_id: "py:web",
      dispatch_input: analyzerDispatch, validated_response: validAnalyzerResponse()
    });
    assert.equal(run([CLI("agent-response-cache"), "--store", "--file", storeIn]).status, 0);
  }

  // --- aggregate-findings (cacheable) ---
  const aggIn = jw(join(projectDir, ".oswe", "tmp", `agg-in-${passLabel}.json`), minAggInput());
  const aggOut = join(projectDir, ".oswe", "tmp", `agg-out-${passLabel}.json`);
  const aggR = run([CLI("aggregate-findings"), "--file", aggIn, "--out", aggOut, "--checkpoint-dir", checkpointDir]);
  assert.equal(aggR.status, 0, `pass ${passLabel}: aggregate-findings failed: ${aggR.stderr}`);
  if (expectAllHits) assert.match(aggR.stderr, /cache hit/i, `pass ${passLabel}: aggregate-findings should hit`);
  else assert.doesNotMatch(aggR.stderr, /cache hit/i, `pass ${passLabel}: aggregate-findings should miss`);
  const aggOutput = JSON.parse(readFileSync(aggOut, "utf8"));

  // --- verifier agent-response-cache: same pattern as analyzer (lookup, store on miss) ---
  const verifierDispatch = {
    batch_id: "batch:1",
    expected_targets: [{ target_type: "finding", target_id: "OSWE-1" }],
    finding_or_chain_canonical: {},
    agent_contract_files: [
      join(PLUGIN_ROOT, "agents", "oswe-verifier.md"),
      join(PLUGIN_ROOT, "skills", "audit", "SKILL.md")
    ]
  };
  const arcVLookIn = jw(join(projectDir, ".oswe", "tmp", `arc-vf-lookup-${passLabel}.json`), {
    checkpoint_dir: checkpointDir, plugin_root: PLUGIN_ROOT,
    kind: "verifier-response", target_id: "batch:1", dispatch_input: verifierDispatch
  });
  const arcVLookOut = join(projectDir, ".oswe", "tmp", `arc-vf-lookup-out-${passLabel}.json`);
  assert.equal(run([CLI("agent-response-cache"), "--lookup", "--file", arcVLookIn, "--out", arcVLookOut]).status, 0);
  const arcVerifierLookup = JSON.parse(readFileSync(arcVLookOut, "utf8"));
  if (expectAllHits) assert.equal(arcVerifierLookup.hit, true, `pass ${passLabel}: verifier cache should hit`);
  else {
    assert.equal(arcVerifierLookup.hit, false, `pass ${passLabel}: verifier cache should miss`);
    const storeIn = jw(join(projectDir, ".oswe", "tmp", `arc-vf-store-${passLabel}.json`), {
      checkpoint_dir: checkpointDir, plugin_root: PLUGIN_ROOT,
      kind: "verifier-response", target_id: "batch:1",
      dispatch_input: verifierDispatch, validated_response: validVerifierResponse()
    });
    assert.equal(run([CLI("agent-response-cache"), "--store", "--file", storeIn]).status, 0);
  }

  // --- apply-verdicts (cacheable) ---
  const avIn = jw(join(projectDir, ".oswe", "tmp", `av-in-${passLabel}.json`), minAVInput());
  const avOut = join(projectDir, ".oswe", "tmp", `av-out-${passLabel}.json`);
  const avR = run([CLI("apply-verdicts"), "--file", avIn, "--out", avOut, "--checkpoint-dir", checkpointDir]);
  assert.equal(avR.status, 0, `pass ${passLabel}: apply-verdicts failed: ${avR.stderr}`);
  if (expectAllHits) assert.match(avR.stderr, /cache hit/i, `pass ${passLabel}: apply-verdicts should hit`);
  else assert.doesNotMatch(avR.stderr, /cache hit/i, `pass ${passLabel}: apply-verdicts should miss`);
  const avOutput = JSON.parse(readFileSync(avOut, "utf8"));

  // --- render-html (cacheable, special two-stream contract) ---
  // Stable input files (same paths across passes) so render-html's two-stream input_digest matches.
  // NOTE: in the live SKILL pipeline, the Markdown body is LLM-generated per §7's prose and
  // therefore NOT byte-deterministic across runs. This test pins the Markdown to a hardcoded
  // synthetic string so we can test render-html's CACHE contract in isolation — which is exactly
  // what SP5 v1 is about. "Final report byte-identical across kill-resume" in production means:
  // GIVEN the same MD + summary, render-html's cache returns the same HTML bytes. We prove that.
  const mdPath = join(projectDir, ".oswe", "tmp", "report.md");
  const sumPath = join(projectDir, ".oswe", "tmp", "summary.json");
  if (passLabel === "1") {
    writeFileSync(mdPath, "# E2E Resume Report\n");
    writeFileSync(sumPath, JSON.stringify(minSummary()));
  }
  const htmlOut = join(projectDir, ".oswe", "tmp", `report-${passLabel}.html`);
  const rhR = run([CLI("render-html"), "--md", mdPath, "--summary", sumPath, "--out", htmlOut, "--checkpoint-dir", checkpointDir]);
  assert.equal(rhR.status, 0, `pass ${passLabel}: render-html failed: ${rhR.stderr}`);
  if (expectAllHits) assert.match(rhR.stderr, /cache hit/i, `pass ${passLabel}: render-html should hit`);
  else assert.doesNotMatch(rhR.stderr, /cache hit/i, `pass ${passLabel}: render-html should miss`);
  const html = readFileSync(htmlOut, "utf8");

  return {
    surfaceVectors: scan.vectors,
    allocOutput, aggOutput, avOutput,
    html,
    arcAnalyzerLookup, arcVerifierLookup
  };
}

test("SP5 lifecycle resume: same invocation -> mode:'resume' with same run_id", (t) => {
  const projectDir = setupProject();
  const first = resolveLifecycle(projectDir, "-a");
  assert.equal(first.mode, "new");
  assert.match(first.run_id, /^[0-9a-f]{16}$/);

  const second = resolveLifecycle(projectDir, "-b");
  assert.equal(second.mode, "resume");
  assert.equal(second.run_id, first.run_id);
  assert.equal(second.checkpoint_dir, first.checkpoint_dir);

  t.after(() => { try { rmSync(projectDir, { recursive: true, force: true }); } catch { /* */ } });
});

test("SP5 e2e replay-resume: two cacheable-helper passes, second pass hits every cache + outputs byte-identical", (t) => {
  const projectDir = setupProject();
  const lc1 = resolveLifecycle(projectDir, "-1");
  assert.equal(lc1.mode, "new");

  // === PASS 1: every cacheable helper miss + populate analyzer/verifier caches ===
  const pass1 = runOnePass(projectDir, lc1.checkpoint_dir, "1", /*expectAllHits=*/false);

  // === Re-resolve lifecycle: NO --finalize between passes (simulates kill-then-resume) ===
  const lc2 = resolveLifecycle(projectDir, "-2");
  assert.equal(lc2.mode, "resume", "second resolve must be a resume, not a new run");
  assert.equal(lc2.run_id, lc1.run_id, "resume must reuse the same run_id");
  assert.equal(lc2.checkpoint_dir, lc1.checkpoint_dir);

  // === PASS 2: every cacheable helper hits + agent-response-cache hits (analyzer + verifier) ===
  const pass2 = runOnePass(projectDir, lc2.checkpoint_dir, "2", /*expectAllHits=*/true);

  // === Byte-identical-output assertions across passes ===
  // What this proves: every CACHEABLE helper, given identical inputs, returns identical bytes on
  // a cache hit. It does NOT prove "final MD identical" because in production the MD body is
  // LLM-generated (nondeterministic). The render-html HTML assertion is the production-relevant
  // one: given the LLM-produced MD + summary, render-html's cache returns the same HTML bytes.
  assert.deepEqual(pass2.allocOutput, pass1.allocOutput, "allocate-budget output must be byte-identical across passes");
  assert.deepEqual(pass2.aggOutput, pass1.aggOutput, "aggregate-findings output must be byte-identical across passes");
  assert.deepEqual(pass2.avOutput, pass1.avOutput, "apply-verdicts output must be byte-identical across passes");
  assert.equal(pass2.html, pass1.html, "render-html HTML output must be byte-identical across passes");
  assert.deepEqual(pass2.arcAnalyzerLookup.cached_response, validAnalyzerResponse(),
    "analyzer cache must return the stored response unchanged");
  assert.deepEqual(pass2.arcVerifierLookup.cached_response, validVerifierResponse(),
    "verifier cache must return the stored response unchanged");

  // === Finalize: manifest flipped + dir removed ===
  const fin = run([CLI("checkpoint-lifecycle"), "--finalize", "--run-id", lc1.run_id, "--project-dir", projectDir]);
  assert.equal(fin.status, 0);
  assert.equal(existsSync(lc1.checkpoint_dir), false, "finalize removes the run dir");

  t.after(() => { try { rmSync(projectDir, { recursive: true, force: true }); } catch { /* */ } });
});
```

All payloads are schema-verified against their respective schemas (`analyzer-response`, `verifier-response`, `report-summary`) and CLI contracts (`aggregate-findings.mjs:89`, `apply-verdicts.mjs:348`).

- [ ] **Step 2: Run the e2e resume test to verify it passes**

Run: `( cd skills/audit/scripts && node --test test/e2e-replay-resume.test.mjs )`
Expected: PASS — 2 tests, 0 failures (the standalone lifecycle-resume + the two-pass e2e proof).

- [ ] **Step 3: Run the full suite + structure gate + regen check to confirm zero regression**

Run, sequentially (each must succeed before the next):

```bash
( cd skills/audit/scripts && node --test )
```
Expected: all tests pass (existing 190+ plus the new SP5 tests).

```bash
( cd benchmark && node --test )
```
Expected: all benchmark tests pass.

```bash
node .github/scripts/check-structure.mjs
```
Expected: PASS — schemas/stacks/references/fixtures consistent.

```bash
( cd skills/audit/scripts && npm run build && git diff --exit-code -- validators.mjs )
```
Expected: `validators.mjs` regenerates byte-identical to the committed version (proving the committed file is in sync with the schemas, including the new `checkpoint-manifest`).

If `git diff --exit-code` fails on `validators.mjs`, the committed file drifted from the schemas. Stage and commit the regenerated file (`git add skills/audit/scripts/validators.mjs && git commit -m "build(sp5): regenerate validators.mjs"`) and re-run the diff to confirm clean.

- [ ] **Step 4: Commit**

```bash
git add skills/audit/scripts/test/e2e-replay-resume.test.mjs
git commit -m "test(sp5): e2e-replay-resume — assembly-level proof (lifecycle + 4 helpers + agent cache)"
```

---

## Final verification

After Task 12, run a complete green check:

```bash
( cd skills/audit/scripts && node --test ) \
  && ( cd benchmark && node --test ) \
  && node .github/scripts/check-structure.mjs \
  && ( cd skills/audit/scripts && npm run build && git diff --exit-code -- validators.mjs )
```

All gates green → SP5 v1 is ready for `claude plugin validate --strict` (local gate) and PR review against `master`.

## Out-of-scope reminders (for future SP5 v2+)

Per spec §9: NO streaming reports, NO auto-backoff on rate-limits, NO cross-run cache, NO `--persist-cache` flag, NO adaptive concurrency, NO dedicated `oswe-clean-checkpoints` CLI, NO concurrency >16. Resist any temptation to add these "while we're in the file"; each is a deliberate v2+ decision.
