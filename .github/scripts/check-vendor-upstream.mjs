#!/usr/bin/env node
// Upstream gate for the vendored tree-sitter parser — dev/CI only, zero deps, Node >= 20.
// check-vendor.mjs proves the committed files match MANIFEST.json; this proves MANIFEST.json's files are
// what skills/audit/scripts/build-grammars.mjs would vendor from the pinned npm packages. It compares
// CONTENT, not the committed bytes: each tree-sitter-<id>.wasm.gz is gunzipped and its sha256 compared
// with node_modules/tree-sitter-wasms/out/tree-sitter-<id>.wasm (gzip output may differ across zlib
// builds, the grammar inside may not), and the loader / runtime are compared byte-for-byte with the
// web-tree-sitter files build-grammars.mjs copies:
//   web-tree-sitter.mjs <- web-tree-sitter/tree-sitter.js     tree-sitter.wasm <- web-tree-sitter/tree-sitter.wasm
// Any mismatch, or a file missing on either side, is a violation.
// Run from the repo root after `npm ci` in skills/audit/scripts:  node .github/scripts/check-vendor-upstream.mjs
// Exit 0 = all good; exit 1 = a violation (printed); exit 2 = could not run (node_modules / packages absent).
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const VENDOR_DIR = join(ROOT, "skills", "audit", "vendor", "tree-sitter");
export const NODE_MODULES = join(ROOT, "skills", "audit", "scripts", "node_modules");
const PACKAGES = ["web-tree-sitter", "tree-sitter-wasms"];

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

// Returns null when the comparison cannot run (a package is not installed), else
// [{ file, ok, detail }] — one row per committed grammar plus the loader and the runtime.
export function compareVendorToUpstream(vendorDir = VENDOR_DIR, nodeModules = NODE_MODULES) {
  if (!PACKAGES.every((p) => existsSync(join(nodeModules, p, "package.json")))) return null;
  const pairs = [
    ["web-tree-sitter.mjs", join(nodeModules, "web-tree-sitter", "tree-sitter.js"), false],
    ["tree-sitter.wasm", join(nodeModules, "web-tree-sitter", "tree-sitter.wasm"), false]
  ];
  const grammars = existsSync(vendorDir) ? readdirSync(vendorDir).filter((f) => /^tree-sitter-.+\.wasm\.gz$/.test(f)).sort() : [];
  for (const f of grammars) {
    pairs.push([f, join(nodeModules, "tree-sitter-wasms", "out", f.slice(0, -".gz".length)), true]);
  }
  return pairs.map(([file, upstream, gzipped]) => {
    const committed = join(vendorDir, file);
    if (!existsSync(committed)) return { file, ok: false, detail: "missing from the vendor directory" };
    if (!existsSync(upstream)) return { file, ok: false, detail: `upstream file missing: ${upstream}` };
    let bytes;
    try { bytes = gzipped ? gunzipSync(readFileSync(committed)) : readFileSync(committed); }
    catch (e) { return { file, ok: false, detail: `cannot gunzip: ${e.message}` }; }
    const mine = sha256(bytes), theirs = sha256(readFileSync(upstream));
    return mine === theirs
      ? { file, ok: true, detail: `sha256 ${mine}` }
      : { file, ok: false, detail: `content sha256 ${mine} differs from upstream ${theirs}` };
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const rows = compareVendorToUpstream();
  if (rows === null) {
    console.error(`check-vendor-upstream could not run: ${PACKAGES.join(" / ")} not installed in ${NODE_MODULES} — run 'npm ci' in skills/audit/scripts first.`);
    process.exit(2);
  }
  console.log("vendored tree-sitter content vs the installed npm packages");
  for (const r of rows) console.log(`  ${r.ok ? "ok" : "XX"}  ${r.file}: ${r.detail}`);
  const failed = rows.filter((r) => !r.ok).length;
  console.log("");
  if (failed) {
    console.error(`FAIL: ${failed} vendored file(s) differ from upstream — run 'npm run build:grammars' in skills/audit/scripts and commit the result.`);
    process.exit(1);
  }
  console.log("PASS: vendored tree-sitter content matches the pinned npm packages.");
}
