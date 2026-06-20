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
