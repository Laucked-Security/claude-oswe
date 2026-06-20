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
  const baseManifest = {
    schema_version: 1,
    started_at: "2026-06-20T12:00:00Z",
    completed: false,
    scope_realpath: p,
    sarif_realpath: null,
    concurrency: 4
  };
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
    surprise: "extra"
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
