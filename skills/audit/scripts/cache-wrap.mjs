// Shared caching primitives for SP5 v1. Used by the 4 cacheable helpers (allocate-budget,
// aggregate-findings, apply-verdicts, render-html) and reused (canonicalize + sha256Hex only)
// by agent-response-cache. Zero runtime dependencies.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, renameSync, mkdirSync, unlinkSync } from "node:fs";
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

// Returns { hit: bool, wrapper?: parsed JSON }. Silent miss on ANY of:
//   - file does not exist
//   - JSON.parse fails (corruption)
//   - wrapper's internal input_digest != supplied (tampering / partial write)
//   - wrapper's internal helper_version_digest != supplied (helper code changed)
//   - `requiredPayloadKey` was passed AND the wrapper does not own that key (payload corruption
//     that happened to keep the digest fields intact — without this check the caller would
//     pass `undefined` to writeFileSync and crash exit 2 instead of silently recomputing,
//     contradicting spec §6's "cache-payload corruption is recoverable, never fail-loud").
// Per §6 of the spec: cache-payload corruption is recoverable, never fail-loud.
export function cacheLookup({ checkpointDir, helperName, inputDigest, versionDigest, requiredPayloadKey }) {
  const p = cachePath(checkpointDir, helperName, inputDigest, versionDigest);
  let raw;
  try { raw = readFileSync(p, "utf8"); }
  catch { return { hit: false }; }   // ENOENT / EBUSY / etc. — silent miss per spec §6
  let wrapper;
  try { wrapper = JSON.parse(raw); } catch { return { hit: false }; }
  if (wrapper.input_digest !== inputDigest || wrapper.helper_version_digest !== versionDigest) {
    return { hit: false };
  }
  if (requiredPayloadKey && !Object.prototype.hasOwnProperty.call(wrapper, requiredPayloadKey)) {
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
