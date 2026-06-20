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
