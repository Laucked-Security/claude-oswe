import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../agent-response-cache.mjs", import.meta.url));

function setupPlugin() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "oswe-arc-plugin-")));
  mkdirSync(join(root, "agents"), { recursive: true });
  writeFileSync(join(root, "agents", "oswe-analyzer.md"), "# analyzer v1\n");
  return root;
}

function setupCheckpoint() {
  return realpathSync(mkdtempSync(join(tmpdir(), "oswe-arc-ckpt-")));
}

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
  mkdirSync(join(ckpt, "agent-responses"), { recursive: true });
  const di = baseDispatchInput(pluginRoot);
  call("--store", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di, validated_response: validAnalyzerResponse()
  });
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
  call("--store", {
    checkpoint_dir: ckpt, plugin_root: pluginRoot, kind: "analyzer-response", target_id: "py:web",
    dispatch_input: di, validated_response: validAnalyzerResponse()
  });
  const arcDir = join(ckpt, "agent-responses");
  const files = readdirSync(arcDir);
  const p = join(arcDir, files[0]);
  const wrapper = JSON.parse(readFileSync(p, "utf8"));
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
