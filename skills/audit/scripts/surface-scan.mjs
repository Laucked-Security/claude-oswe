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

// `stack` is recon-derived (LLM read of the audited repo) → UNTRUSTED as a lookup key. references/ is
// trusted in CONTENT, not as a join target: a stack like "../../../etc/x" must never escape referencesDir.
// Validate the name before the join (path-traversal guard distinct from the partition-file confinement);
// a non-matching name → null → the partition is reported unscannable (surface unknown), which is fail-safe.
const STACK_RE = /^[a-z0-9_-]+$/;
export function loadSurfaceBlock(stack, referencesDir) {
  if (typeof stack !== "string" || !STACK_RE.test(stack)) return null;
  let md;
  try { md = readFileSync(join(referencesDir, `${stack}.md`), "utf8"); }
  catch { return null; } // no reference page -> unsupported stack
  return parseSurfaceBlock(md);
}

// Tie-break key = sha256 of the partition's sorted FILE-PATH SET — NOT the file bytes. This is
// deliberate: the tie-break must stay stable when the code inside the files changes (only "which files
// are in this partition" may move it). DO NOT "fix" this to hash file contents — that would make the
// coverage selection flip on any edit, destroying the reproducibility this key exists to guarantee.
// Order-independent (sorted) and bounded (64 hex chars).
export function contentKey(files) {
  return createHash("sha256").update([...files].sort().join("\n")).digest("hex");
}

// loose substring (sources/sinks/sanitizers): over-match only over-ranks -> safe.
const hasSub = (text, token) => Boolean(token) && text.includes(token);
const countSub = (text, token) => {
  if (!token) return 0;
  let n = 0, i = 0;
  while ((i = text.indexOf(token, i)) !== -1) { n++; i += token.length; }
  return n;
};
// strict (auth_markers): the token must be bounded on BOTH sides — not embedded in a longer identifier
// on either end. A loose auth match falsely SUPPRESSES the fail-safe (the one unsafe direction), so this
// is the strict category. Both-side boundary, not the right side only: `xx@login_required` (left
// word-char) and `login_requiredX` (right word-char) must BOTH be rejected. Avoids the `\b@...` pitfall
// (a leading `@` breaks a naive `\b`). Erring strict is safe here: a missed auth marker just means no
// suppression → the partition ranks UP → over-analyzed → safe.
const hasAuth = (text, token) => {
  // Empty-token guard: indexOf("",0)===0 with i += 0 would infinite-loop. Mirror countSub/hasSub —
  // a hung scan on a typo'd block is the worst failure mode for a security tool. Defensive even
  // though check-structure section 7 also rejects empty per-token strings.
  if (!token) return false;
  const lastIsWord = /\w/.test(token[token.length - 1]);
  let i = 0;
  while ((i = text.indexOf(token, i)) !== -1) {
    const before = text[i - 1];
    const after = text[i + token.length];
    const beforeOk = i === 0 || !/\w/.test(before);
    const afterOk = !lastIsWord || after === undefined || !/\w/.test(after);
    if (beforeOk && afterOk) return true;
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
