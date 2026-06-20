// Per-run checkpoint lifecycle (spec §3.2). Two modes:
//   resolve  — scan .oswe/checkpoints/*/manifest.json, match by invocation_digest, fail-closed on >1
//   finalize — flip completed:true then rm the run dir
// Manifest is validated through validate-output's checkpoint-manifest kind.
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, renameSync, rmSync } from "node:fs";
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

const RUN_ID_PATTERN = /^[0-9a-f]{16}$/;

export function finalizeRun({ projectDir, runId }) {
  // Reject any runId that doesn't match the run-id grammar (sha256-slice hex) BEFORE any FS access.
  // The helper is normally called with a run_id resolveRun() emitted (always valid), but the public
  // CLI is callable with arbitrary input — refuse `--run-id ..` or `--run-id /etc` outright so
  // rmSync can never target a path-traversal-crafted directory.
  if (typeof runId !== "string" || !RUN_ID_PATTERN.test(runId)) {
    return { ok: false, warning: `finalize: invalid run-id ${JSON.stringify(runId)} (must match ^[0-9a-f]{16}$); no FS access performed` };
  }
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
    // r.ok===false means we refused the call (bad runId shape); exit 2 = usage.
    // r.ok===true (with or without warning) = infrastructure path completed; exit 0.
    process.exit(r.ok ? 0 : 2);
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
