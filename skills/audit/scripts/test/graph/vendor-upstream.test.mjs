// Unit test for .github/scripts/check-vendor-upstream.mjs's comparison (the CI regen-check step), run
// against temp dirs shaped like the vendor dir and node_modules — never against the real ones.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { compareVendorToUpstream } from "../../../../../.github/scripts/check-vendor-upstream.mjs";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "oswe-vendor-upstream-"));
  const vendor = join(root, "vendor"), nm = join(root, "node_modules");
  const wts = join(nm, "web-tree-sitter"), wasms = join(nm, "tree-sitter-wasms");
  for (const d of [vendor, wts, join(wasms, "out")]) mkdirSync(d, { recursive: true });
  writeFileSync(join(wts, "package.json"), "{}");
  writeFileSync(join(wasms, "package.json"), "{}");
  writeFileSync(join(wts, "tree-sitter.js"), "export const Parser = 1;");
  writeFileSync(join(wts, "tree-sitter.wasm"), Buffer.from([0, 97, 115, 109]));
  writeFileSync(join(wasms, "out", "tree-sitter-java.wasm"), Buffer.from("java grammar"));
  writeFileSync(join(vendor, "web-tree-sitter.mjs"), "export const Parser = 1;");
  writeFileSync(join(vendor, "tree-sitter.wasm"), Buffer.from([0, 97, 115, 109]));
  // Different gzip settings, same content: still a match (the comparison is on the gunzipped bytes).
  writeFileSync(join(vendor, "tree-sitter-java.wasm.gz"), gzipSync(Buffer.from("java grammar"), { level: 1 }));
  return { root, vendor, nm, wts, wasms };
}
const failures = (rows) => rows.filter((r) => !r.ok).map((r) => r.file);

test("matching loader, runtime and gunzipped grammar -> every row ok", () => {
  const f = fixture();
  try {
    const rows = compareVendorToUpstream(f.vendor, f.nm);
    assert.deepEqual(rows.map((r) => r.file), ["web-tree-sitter.mjs", "tree-sitter.wasm", "tree-sitter-java.wasm.gz"]);
    assert.deepEqual(failures(rows), []);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("a grammar, loader or runtime whose content differs from upstream is a violation", () => {
  const f = fixture();
  try {
    writeFileSync(join(f.vendor, "tree-sitter-java.wasm.gz"), gzipSync(Buffer.from("other grammar")));
    writeFileSync(join(f.wts, "tree-sitter.js"), "export const Parser = 2;");
    writeFileSync(join(f.vendor, "tree-sitter.wasm"), Buffer.from([1]));
    assert.deepEqual(failures(compareVendorToUpstream(f.vendor, f.nm)), ["web-tree-sitter.mjs", "tree-sitter.wasm", "tree-sitter-java.wasm.gz"]);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("a file missing on either side, or a committed grammar that is not gzip, is a violation", () => {
  const f = fixture();
  try {
    writeFileSync(join(f.vendor, "tree-sitter-php.wasm.gz"), gzipSync(Buffer.from("php"))); // no upstream php grammar
    writeFileSync(join(f.vendor, "tree-sitter-tsx.wasm.gz"), "not gzip");
    writeFileSync(join(f.wasms, "out", "tree-sitter-tsx.wasm"), "tsx");
    rmSync(join(f.vendor, "web-tree-sitter.mjs"));
    const rows = compareVendorToUpstream(f.vendor, f.nm);
    assert.deepEqual(failures(rows), ["web-tree-sitter.mjs", "tree-sitter-php.wasm.gz", "tree-sitter-tsx.wasm.gz"]);
    assert.match(rows.find((r) => r.file === "tree-sitter-php.wasm.gz").detail, /upstream file missing/);
    assert.match(rows.find((r) => r.file === "tree-sitter-tsx.wasm.gz").detail, /cannot gunzip/);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("packages not installed -> null (the CLI exits 2)", () => {
  const f = fixture();
  try {
    rmSync(f.wasms, { recursive: true, force: true });
    assert.equal(compareVendorToUpstream(f.vendor, f.nm), null);
    assert.equal(compareVendorToUpstream(f.vendor, join(f.root, "absent")), null);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});
